//! p2p-radio CLI —— V0.1 原型验证工具
//!
//! ```text
//! p2p-radio keygen                        # 生成设备身份（~/.p2p-radio/identity.key）
//! p2p-radio rx --bind 127.0.0.1:9002 --out out.wav
//! p2p-radio tx --peer 127.0.0.1:9002 --in in.wav
//! ```
//! 流程：tx 拨号握手 -> 读 WAV 按 20ms 切帧 -> Opus 编码 -> 加密 -> UDP；
//! rx 收包 -> 解密 -> 抖动缓冲重排 -> Opus 解码 -> 写 WAV。收到 BYE 后 draining 退出。

use anyhow::{bail, Context, Result};
use p2p_audio::{OpusVoiceCoder, FRAME_SAMPLES, SAMPLE_RATE};
use p2p_crypto::IdentityKeypair;
use p2p_transport::{JitterAction, JitterBuffer, PacketEvent, UdpSession};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn identity_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home).join(".p2p-radio").join("identity.key")
}

fn load_or_create_identity() -> Result<IdentityKeypair> {
    use p2p_crypto::IDENTITY_SECRET_LEN;
    let path = identity_path();
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() == 32 {
            bail!("identity 格式已升级（32->64字节，新增握手签名密钥），请删除后重新 keygen");
        }
        if bytes.len() != IDENTITY_SECRET_LEN {
            bail!("identity file corrupt");
        }
        let mut b = [0u8; IDENTITY_SECRET_LEN];
        b.copy_from_slice(&bytes);
        return Ok(IdentityKeypair::from_secret_bytes(&b));
    }
    let id = IdentityKeypair::generate();
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, id.secret_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(id)
}

fn cmd_keygen() -> Result<()> {
    let id = load_or_create_identity()?;
    println!("identity: {}", identity_path().display());
    println!("fingerprint: {}", id.fingerprint());
    println!("(双方线下核对指纹一致，可防范中间人攻击)");
    Ok(())
}

fn read_wav_frames(path: &str) -> Result<Vec<Vec<i16>>> {
    let mut reader = hound::WavReader::open(path)?;
    let spec = reader.spec();
    if spec.sample_rate != SAMPLE_RATE || spec.channels != 1 || spec.bits_per_sample != 16 {
        bail!(
            "need 48kHz mono 16-bit wav, got {}Hz ch={} bits={}",
            spec.sample_rate,
            spec.channels,
            spec.bits_per_sample
        );
    }
    let samples: Vec<i16> = reader.samples::<i16>().collect::<Result<_, _>>()?;
    let mut frames = Vec::new();
    for chunk in samples.chunks(FRAME_SAMPLES) {
        let mut f = chunk.to_vec();
        f.resize(FRAME_SAMPLES, 0);
        frames.push(f);
    }
    Ok(frames)
}

fn cmd_tx(peer: &str, wav_in: &str) -> Result<()> {
    let identity = load_or_create_identity()?;
    println!("[tx] my fingerprint: {}", identity.fingerprint());
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let peer_addr: SocketAddr = peer.parse()?;
    let mut session = UdpSession::dial(socket, peer_addr, &identity, Duration::from_secs(5))?;
    println!("[tx] session established, peer fingerprint: {}", session.peer_fingerprint);
    println!("[tx] *** 请线下核对双方指纹一致 ***");

    let frames = read_wav_frames(wav_in)?;
    println!("[tx] streaming {} frames ({} ms)", frames.len(), frames.len() * 20);
    let mut coder = OpusVoiceCoder::new()?;
    let tick = Duration::from_millis(20);
    for (i, pcm) in frames.iter().enumerate() {
        let t0 = Instant::now();
        let opus = coder.encode_frame(pcm)?;
        let seq = session.send_voice(&opus)?;
        if i % 50 == 0 {
            println!("[tx] sent seq={} opus_bytes={}", seq, opus.len());
        }
        let elapsed = t0.elapsed();
        if elapsed < tick {
            std::thread::sleep(tick - elapsed);
        }
    }
    session.send_bye()?;
    println!("[tx] done, BYE sent");
    Ok(())
}

fn cmd_rx(bind: &str, wav_out: &str) -> Result<()> {
    let identity = load_or_create_identity()?;
    println!("[rx] my fingerprint: {}", identity.fingerprint());
    let socket = UdpSocket::bind(bind)?;
    let mut session = UdpSession::accept(socket, &identity, Duration::from_secs(120))?;
    println!("[rx] session established, peer fingerprint: {}", session.peer_fingerprint);
    println!("[rx] *** 请线下核对双方指纹一致 ***");

    let mut coder = OpusVoiceCoder::new()?;
    let mut jb = JitterBuffer::new();
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(wav_out, spec)?;
    let silence = vec![0i16; FRAME_SAMPLES];

    let tick = Duration::from_millis(20);
    let mut next_tick = None::<Instant>;
    let mut bye_received = false;
    let mut frames_written: u64 = 0;
    let start = Instant::now();

    'outer: loop {
        // 收包（短超时），推入抖动缓冲
        match session.recv_event(Duration::from_millis(5))? {
            Some(PacketEvent::Voice(seq, frame)) => {
                if next_tick.is_none() {
                    next_tick = Some(Instant::now());
                    println!("[rx] first voice packet, starting playout");
                }
                jb.push(seq, frame);
            }
            Some(PacketEvent::Bye) => {
                println!("[rx] BYE received, draining jitter buffer");
                bye_received = true;
            }
            None => {}
        }

        // 20ms 一拍播放
        if let Some(mut t) = next_tick {
            while Instant::now() >= t {
                match jb.pop_or_wait() {
                    JitterAction::Frame(opus) => {
                        let pcm = coder.decode_frame(&opus, false)?;
                        for s in &pcm {
                            writer.write_sample(*s)?;
                        }
                        frames_written += 1;
                    }
                    JitterAction::Lost => {
                        // 丢包：尝试 Opus PLC，失败则静音
                        let pcm = coder.conceal_loss().unwrap_or_else(|_| silence.clone());
                        for s in pcm.iter().take(FRAME_SAMPLES) {
                            writer.write_sample(*s)?;
                        }
                        frames_written += 1;
                        if frames_written.is_multiple_of(50) {
                            println!("[rx] concealed a lost frame");
                        }
                    }
                    JitterAction::NeedMore => {
                        if bye_received {
                            break 'outer;
                        }
                        // 还没攒够：写静音保持时钟
                        for s in &silence {
                            writer.write_sample(*s)?;
                        }
                        frames_written += 1;
                    }
                }
                t += tick;
            }
            next_tick = Some(t);
            // 防螺旋：如果掉队超过 200ms，直接追上现在
            if next_tick.unwrap() + Duration::from_millis(200) < Instant::now() {
                next_tick = Some(Instant::now());
            }
        }

        if bye_received {
            // draining：缓冲空了就退出
            let mut drained = true;
            for _ in 0..8 {
                if let JitterAction::Frame(opus) = jb.pop_or_wait() {
                    let pcm = coder.decode_frame(&opus, false)?;
                    for s in &pcm {
                        writer.write_sample(*s)?;
                    }
                    frames_written += 1;
                    drained = false;
                }
            }
            if drained {
                break 'outer;
            }
        }
        if start.elapsed() > Duration::from_secs(600) {
            bail!("safety timeout");
        }
    }

    writer.finalize()?;
    println!("[rx] done, wrote {} frames to {}", frames_written, wav_out);
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  p2p-radio keygen");
    eprintln!("  p2p-radio tx --peer 127.0.0.1:9002 --in in.wav");
    eprintln!("  p2p-radio rx --bind 127.0.0.1:9002 --out out.wav");
    std::process::exit(1);
}

fn get_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "keygen" => cmd_keygen(),
        "tx" => {
            let peer = get_arg(&args, "--peer").context("missing --peer")?;
            let wav = get_arg(&args, "--in").context("missing --in")?;
            cmd_tx(&peer, &wav)
        }
        "rx" => {
            let bind = get_arg(&args, "--bind").context("missing --bind")?;
            let wav = get_arg(&args, "--out").context("missing --out")?;
            cmd_rx(&bind, &wav)
        }
        _ => usage(),
    }
}
