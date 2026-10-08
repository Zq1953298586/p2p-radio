//! 端到端集成测试：完整媒体+安全链路（不经过真实 UDP socket，
//! 因为某些沙箱环境禁止 UDP send；socket 层本身很薄，已做代码审查）。
//!
//! 链路：PCM -> Opus 编码 -> 会话密钥派生(X3DH简化版) -> ChaCha20-Poly1305
//! 加密(包头做AAD) -> 模拟网络(乱序+丢包) -> 解密验签 -> 抖动缓冲重排 ->
//! Opus 解码/PLC -> PCM

use p2p_audio::{OpusVoiceCoder, FRAME_SAMPLES, SAMPLE_RATE};
use p2p_crypto::{derive_session_keys, decrypt, encrypt, make_nonce, IdentityKeypair};
use p2p_proto::{PacketHeader, PacketType, DEFAULT_TTL, HEADER_LEN};
use p2p_transport::{JitterAction, JitterBuffer};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

fn sine_frame(freq: f32, phase: f32) -> Vec<i16> {
    (0..FRAME_SAMPLES)
        .map(|i| {
            ((((i as f32) / SAMPLE_RATE as f32 * freq * 2.0 * std::f32::consts::PI) + phase).sin()
                * 12000.0) as i16
        })
        .collect()
}

#[test]
fn e2e_voice_pipeline_with_loss_and_reorder() {
    // ---- 1. 双设备身份 + 会话密钥协商 ----
    let id_a = IdentityKeypair::generate();
    let id_b = IdentityKeypair::generate();
    let eph_a = StaticSecret::random_from_rng(OsRng);
    let eph_b = StaticSecret::random_from_rng(OsRng);
    let sid = 0xCAFE_F00D_1234_5678u64;
    let ka = derive_session_keys(
        true, &id_a.secret, &eph_a,
        &id_b.public_bytes(),
        &x25519_dalek::PublicKey::from(&eph_b).to_bytes(),
        sid, [0xAA, 0xBB, 0xCC, 0xDD],
    );
    let kb = derive_session_keys(
        false, &id_b.secret, &eph_b,
        &id_a.public_bytes(),
        &x25519_dalek::PublicKey::from(&eph_a).to_bytes(),
        sid, [0x11, 0x22, 0x33, 0x44],
    );

    // ---- 2. 发送端：250 帧 PCM -> Opus -> 加密打包 ----
    let mut coder_tx = OpusVoiceCoder::new().unwrap();
    let n_frames = 250;
    let mut packets: Vec<(u32, [u8; HEADER_LEN], Vec<u8>)> = Vec::new();
    for i in 0..n_frames {
        let freq = 300.0 + (i as f32) * 3.0; // 扫频
        let pcm = sine_frame(freq, i as f32 * 0.1);
        let opus = coder_tx.encode_frame(&pcm).unwrap();
        let nonce = make_nonce(&ka.tx_nonce_prefix, i);
        let header = PacketHeader {
            ptype: PacketType::Voice,
            session_id: sid,
            seq: i,
            ttl: DEFAULT_TTL,
            timestamp_ms: 1_700_000_000_000 + (i as u64) * 20,
            nonce,
        };
        let hb = header.encode();
        let ct = encrypt(&ka.tx, &nonce, &hb, &opus);
        packets.push((i, hb, ct));
    }

    // ---- 3. 模拟网络：每 5 个一组逆序 + 丢 2 个包 ----
    let mut shuffled: Vec<(u32, [u8; HEADER_LEN], Vec<u8>)> = Vec::new();
    for chunk in packets.chunks(5) {
        let mut c = chunk.to_vec();
        c.reverse();
        shuffled.extend(c);
    }
    let before = shuffled.len();
    shuffled.retain(|(seq, _, _)| *seq != 37 && *seq != 101);
    assert_eq!(before - shuffled.len(), 2);

    // ---- 4. 接收端：解密验签 -> 抖动缓冲 -> 解码 ----
    let mut coder_rx = OpusVoiceCoder::new().unwrap();
    let mut jb = JitterBuffer::new();
    for (seq, hb, ct) in &shuffled {
        let header = PacketHeader::decode(hb).unwrap();
        assert_eq!(header.seq, *seq);
        let pt = decrypt(&kb.rx, &header.nonce, hb, ct).expect("AEAD 必须通过");
        jb.push(*seq, pt);
    }

    let mut played = 0u32;
    let mut lost = 0u32;
    let mut out_pcm: Vec<i16> = Vec::new();
    loop {
        match jb.pop_or_wait() {
            JitterAction::Frame(opus) => {
                out_pcm.extend(coder_rx.decode_frame(&opus, false).unwrap());
                played += 1;
            }
            JitterAction::Lost => {
                let plc = coder_rx.conceal_loss().unwrap();
                out_pcm.extend(plc.iter().take(FRAME_SAMPLES));
                lost += 1;
                played += 1;
            }
            JitterAction::NeedMore => break,
        }
        if played >= n_frames {
            break;
        }
    }

    assert_eq!(played, n_frames, "必须播出全部 250 帧（含 PLC 补的）");
    assert_eq!(lost, 2, "恰好丢 2 帧并被 PLC 覆盖");
    assert_eq!(out_pcm.len(), n_frames as usize * FRAME_SAMPLES);

    // 写出 WAV 供人工/脚本验听
    let out_path = std::env::var("P2P_E2E_OUT").unwrap_or_else(|_| "/tmp/test_out.wav".into());
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut w = hound::WavWriter::create(&out_path, spec).unwrap();
    for s in &out_pcm {
        w.write_sample(*s).unwrap();
    }
    w.finalize().unwrap();
    println!("e2e ok: played={} lost(concealed)={} -> {}", played, lost, out_path);
}
