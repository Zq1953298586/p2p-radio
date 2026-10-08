//! P2P-Radio Android JNI 桥接层
//!
//! Kotlin 侧对应类：`com.p2pradio.core.NativeCore`（静态方法）。
//! 设计原则：JNI 调用一律非阻塞、短平快；panic 永不过边界（catch_unwind 转空值/负数）。
//!
//! 音频流向：
//!   采集：Kotlin AudioRecord -> nativePushPcm(short[960]) -> Opus编码 -> 加密 -> UDP发送
//!   播放：Kotlin 每20ms nativePollPcm() -> short[960] | null -> AudioTrack
//! 抖动缓冲、解密、PLC 全部在 Rust 侧完成，Kotlin 只做 PCM 搬运。

use anyhow::{bail, Context, Result};
use jni::objects::{JClass, JShortArray, JString};
use jni::sys::{jint, jlong, jobject};
use jni::JNIEnv;
use p2p_audio::{OpusVoiceCoder, FRAME_SAMPLES};
use p2p_crypto::IdentityKeypair;
use p2p_transport::{JitterAction, PacketEvent, UdpSession};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

struct SessionState {
    session: UdpSession,
    coder: OpusVoiceCoder,
    jb: p2p_transport::JitterBuffer,
}

/// panic 不过 JNI 边界
fn guard<T>(default: T, f: impl FnOnce() -> Result<T>) -> T {
    let f = std::panic::AssertUnwindSafe(f);
    match std::panic::catch_unwind(f) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            eprintln!("[p2p-jni] error: {:#}", e);
            default
        }
        Err(_) => {
            eprintln!("[p2p-jni] panic caught");
            default
        }
    }
}

fn load_identity(store_dir: &str) -> Result<IdentityKeypair> {
    use p2p_crypto::IDENTITY_SECRET_LEN;
    let dir = PathBuf::from(store_dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("identity.key");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() == 32 {
            bail!("identity 格式已升级，请删除后重新 keygen");
        }
        if bytes.len() != IDENTITY_SECRET_LEN {
            bail!("identity corrupt");
        }
        let mut b = [0u8; IDENTITY_SECRET_LEN];
        b.copy_from_slice(&bytes);
        return Ok(IdentityKeypair::from_secret_bytes(&b));
    }
    let id = IdentityKeypair::generate();
    std::fs::write(&path, id.secret_bytes())?;
    Ok(id)
}

fn jstring_to_rust(env: &mut JNIEnv, s: &JString) -> Result<String> {
    Ok(env.get_string(s)?.to_str()?.to_string())
}

// ---- 身份 ----

/// static String nativeKeygen(String storeDir) -> "指纹"
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativeKeygen(
    mut env: JNIEnv,
    _class: JClass,
    store_dir: JString,
) -> jobject {
    guard(std::ptr::null_mut(), || {
        let dir = jstring_to_rust(&mut env, &store_dir)?;
        let id = load_identity(&dir)?;
        Ok(env.new_string(id.fingerprint())?.into_raw())
    })
}

// ---- 会话 ----

/// static long nativeDial(String storeDir, String ip, int port) -> handle(0=失败)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativeDial(
    mut env: JNIEnv,
    _class: JClass,
    store_dir: JString,
    ip: JString,
    port: jint,
) -> jlong {
    guard(0, || {
        let dir = jstring_to_rust(&mut env, &store_dir)?;
        let ip_str = jstring_to_rust(&mut env, &ip)?;
        let peer: SocketAddr = format!("{}:{}", ip_str, port).parse()?;
        let id = load_identity(&dir)?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let session = UdpSession::dial(socket, peer, &id, Duration::from_secs(8))?;
        let state = Box::new(SessionState {
            session,
            coder: OpusVoiceCoder::new()?,
            jb: p2p_transport::JitterBuffer::new(),
        });
        Ok(Box::into_raw(state) as jlong)
    })
}

/// static long nativeAccept(String storeDir, int bindPort) -> handle(0=失败/超时)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativeAccept(
    mut env: JNIEnv,
    _class: JClass,
    store_dir: JString,
    bind_port: jint,
) -> jlong {
    guard(0, || {
        let dir = jstring_to_rust(&mut env, &store_dir)?;
        let id = load_identity(&dir)?;
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", bind_port))?;
        let session = UdpSession::accept(socket, &id, Duration::from_secs(120))?;
        let state = Box::new(SessionState {
            session,
            coder: OpusVoiceCoder::new()?,
            jb: p2p_transport::JitterBuffer::new(),
        });
        Ok(Box::into_raw(state) as jlong)
    })
}

/// static String nativePeerFingerprint(long handle)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativePeerFingerprint(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jobject {
    guard(std::ptr::null_mut(), || {
        if handle == 0 {
            bail!("bad handle");
        }
        let state = unsafe { &*(handle as *const SessionState) };
        Ok(env
            .new_string(state.session.peer_fingerprint.clone())?
            .into_raw())
    })
}

// ---- 语音 ----

/// static int nativePushPcm(long handle, short[] pcm960) -> seq(-1=失败)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativePushPcm(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pcm: JShortArray,
) -> jint {
    guard(-1, || {
        if handle == 0 {
            bail!("bad handle");
        }
        let state = unsafe { &mut *(handle as *mut SessionState) };
        let mut buf = vec![0i16; FRAME_SAMPLES];
        env.get_short_array_region(&pcm, 0, &mut buf)
            .context("pcm 长度异常")?;
        let opus = state.coder.encode_frame(&buf)?;
        let seq = state.session.send_voice(&opus)?;
        Ok(seq as jint)
    })
}

/// static short[] nativePollPcm(long handle) -> short[960] | null
/// null 表示这一拍没数据（Kotlin 侧直接跳过，保持 20ms 节奏由 Kotlin 定时器控制）
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativePollPcm(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jobject {
    guard(std::ptr::null_mut(), || {
        if handle == 0 {
            bail!("bad handle");
        }
        let state = unsafe { &mut *(handle as *mut SessionState) };
        // 先收包（1ms 超时，非阻塞）
        if let Some(ev) = state.session.recv_event(Duration::from_millis(1))? {
            match ev {
                PacketEvent::Voice(seq, frame) => state.jb.push(seq, frame),
                PacketEvent::Bye => bail!("peer bye"),
            }
        }
        let pcm: Vec<i16> = match state.jb.pop_or_wait() {
            JitterAction::Frame(opus) => state.coder.decode_frame(&opus, false)?,
            JitterAction::Lost => state
                .coder
                .conceal_loss()
                .unwrap_or_else(|_| vec![0i16; FRAME_SAMPLES])
                .into_iter()
                .take(FRAME_SAMPLES)
                .collect(),
            JitterAction::NeedMore => return Ok(std::ptr::null_mut()),
        };
        let arr = env.new_short_array(pcm.len() as i32)?;
        env.set_short_array_region(&arr, 0, &pcm)?;
        Ok(arr.into_raw())
    })
}

/// static void nativeSendBye(long handle)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativeSendBye(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    guard((), || {
        if handle == 0 {
            bail!("bad handle");
        }
        let state = unsafe { &mut *(handle as *mut SessionState) };
        state.session.send_bye()?;
        Ok(())
    })
}

/// static void nativeClose(long handle)
#[no_mangle]
pub extern "system" fn Java_com_p2pradio_core_NativeCore_nativeClose(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut SessionState));
        }
    }
}
