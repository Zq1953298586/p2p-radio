//! P2P-Radio V0.1 传输层：UDP 会话 + 握手状态机
//!
//! ```text
//! 发起方(A)                         接收方(B)
//!   │  HELLO(idA, ephA)               │
//!   │ ──────────────────────────────► │
//!   │        HELLO_ACK(idB, ephB)     │
//!   │ ◄────────────────────────────── │
//!   │  VOICE(seq=0,1,2...)           │
//!   │ ──────────────────────────────► │
//! ```
//! V0.1 只做直连 UDP。NAT 穿透 / Peer Relay 是 Phase 3/4。

use anyhow::{bail, Result};
use p2p_crypto::{
    check_replay_ok, decrypt, derive_session_keys, encrypt, fingerprint_of, handshake_sign_msg,
    make_nonce, random_nonce_prefix, verify_signature, IdentityKeypair, SessionKeys,
};
use p2p_proto::{now_ms, PacketHeader, PacketType, DEFAULT_TTL, HANDSHAKE_PAYLOAD_LEN, HEADER_LEN};
use rand::rngs::OsRng;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use x25519_dalek::StaticSecret;

pub const MAX_DATAGRAM: usize = 2048;

/// 构造签名握手载荷：x_pub(32) || ed_pub(32) || eph_pub(32) || sig(64)
fn build_handshake_payload(
    identity: &IdentityKeypair,
    session_id: u64,
    eph_pub: &[u8; 32],
) -> [u8; HANDSHAKE_PAYLOAD_LEN] {
    let sig = identity.sign(&handshake_sign_msg(session_id, eph_pub));
    let mut p = [0u8; HANDSHAKE_PAYLOAD_LEN];
    p[..32].copy_from_slice(&identity.public_bytes());
    p[32..64].copy_from_slice(&identity.sign_public_bytes());
    p[64..96].copy_from_slice(eph_pub);
    p[96..160].copy_from_slice(&sig);
    p
}

/// 解析并验签握手载荷，返回 (对方 X25519 身份公钥, 对方临时公钥)
fn parse_and_verify_handshake(
    payload: &[u8],
    session_id: u64,
) -> Result<([u8; 32], [u8; 32])> {
    if payload.len() < HANDSHAKE_PAYLOAD_LEN {
        bail!("handshake payload too short");
    }
    let mut id_pub = [0u8; 32];
    let mut sig_pub = [0u8; 32];
    let mut eph_pub = [0u8; 32];
    let mut sig = [0u8; 64];
    id_pub.copy_from_slice(&payload[..32]);
    sig_pub.copy_from_slice(&payload[32..64]);
    eph_pub.copy_from_slice(&payload[64..96]);
    sig.copy_from_slice(&payload[96..160]);
    let msg = handshake_sign_msg(session_id, &eph_pub);
    verify_signature(&sig_pub, &msg, &sig)?;
    Ok((id_pub, eph_pub))
}

pub struct UdpSession {
    pub socket: UdpSocket,
    pub peer: SocketAddr,
    pub session_id: u64,
    pub keys: SessionKeys,
    pub peer_fingerprint: String,
    tx_seq: u32,
    rx_high_seq: u32,
}

impl UdpSession {
    /// 作为发起方：发 HELLO，等 HELLO_ACK，建立会话
    pub fn dial(
        socket: UdpSocket,
        peer: SocketAddr,
        identity: &IdentityKeypair,
        timeout: Duration,
    ) -> Result<Self> {
        use rand::RngCore;
        let mut sid_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut sid_bytes);
        let session_id = u64::from_be_bytes(sid_bytes);

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let eph_pub_bytes = eph_pub.to_bytes();

        let payload = build_handshake_payload(identity, session_id, &eph_pub_bytes);
        let hello = PacketHeader {
            ptype: PacketType::Hello,
            session_id,
            seq: 0,
            ttl: DEFAULT_TTL,
            timestamp_ms: now_ms(),
            nonce: [0u8; 12],
        };
        let mut datagram = hello.encode().to_vec();
        datagram.extend_from_slice(&payload);

        socket.set_read_timeout(Some(timeout))?;
        // 简单重传 3 次
        let mut ack: Option<([u8; 32], [u8; 32])> = None;
        for _ in 0..3 {
            socket.send_to(&datagram, peer)?;
            let mut buf = [0u8; MAX_DATAGRAM];
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if from != peer {
                        continue;
                    }
                    let h = PacketHeader::decode(&buf[..n])?;
                    if h.ptype == PacketType::HelloAck
                        && h.session_id == session_id
                        && n >= HEADER_LEN + HANDSHAKE_PAYLOAD_LEN
                    {
                        // 验签失败 = 伪造或损坏的包：忽略并继续等待真正的 ACK，
                        // 而不是 abort 整个握手
                        if let Ok((id_pub, eph_pub)) =
                            parse_and_verify_handshake(&buf[HEADER_LEN..], session_id)
                        {
                            ack = Some((id_pub, eph_pub));
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        let (peer_id_pub, peer_eph_pub) = ack.ok_or_else(|| anyhow::anyhow!("handshake timeout"))?;

        let tx_prefix = random_nonce_prefix();
        let keys = derive_session_keys(
            true,
            &identity.secret,
            &eph,
            &peer_id_pub,
            &peer_eph_pub,
            session_id,
            tx_prefix,
        )?;
        Ok(Self {
            socket,
            peer,
            session_id,
            peer_fingerprint: fingerprint_of(&peer_id_pub),
            keys,
            tx_seq: 0,
            rx_high_seq: 0,
        })
    }

    /// 作为接收方：等 HELLO，回 HELLO_ACK，建立会话
    pub fn accept(
        socket: UdpSocket,
        identity: &IdentityKeypair,
        timeout: Duration,
    ) -> Result<Self> {
        socket.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = socket.recv_from(&mut buf)?;
        let h = PacketHeader::decode(&buf[..n])?;
        if h.ptype != PacketType::Hello || n < HEADER_LEN + HANDSHAKE_PAYLOAD_LEN {
            bail!("expected HELLO");
        }
        let (peer_id_pub, peer_eph_pub) =
            parse_and_verify_handshake(&buf[HEADER_LEN..], h.session_id)
                .map_err(|e| anyhow::anyhow!("HELLO signature invalid: {:#}", e))?;

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let eph_pub_bytes = eph_pub.to_bytes();

        let payload = build_handshake_payload(identity, h.session_id, &eph_pub_bytes);
        let ack_h = PacketHeader {
            ptype: PacketType::HelloAck,
            session_id: h.session_id,
            seq: 0,
            ttl: DEFAULT_TTL,
            timestamp_ms: now_ms(),
            nonce: [0u8; 12],
        };
        let mut datagram = ack_h.encode().to_vec();
        datagram.extend_from_slice(&payload);
        socket.send_to(&datagram, from)?;

        let tx_prefix = random_nonce_prefix();
        let keys = derive_session_keys(
            false,
            &identity.secret,
            &eph,
            &peer_id_pub,
            &peer_eph_pub,
            h.session_id,
            tx_prefix,
        )?;
        Ok(Self {
            socket,
            peer: from,
            session_id: h.session_id,
            peer_fingerprint: fingerprint_of(&peer_id_pub),
            keys,
            tx_seq: 0,
            rx_high_seq: 0,
        })
    }

    /// 发送一帧语音明文（Opus 帧），返回包序号。
    /// 包头 35 字节同时作为 AEAD 的 associated data，密文与包头绑定。
    pub fn send_voice(&mut self, opus_frame: &[u8]) -> Result<u32> {
        let seq = self.tx_seq;
        self.tx_seq += 1;
        let nonce = make_nonce(&self.keys.tx_nonce_prefix, seq);
        let h = PacketHeader {
            ptype: PacketType::Voice,
            session_id: self.session_id,
            seq,
            ttl: DEFAULT_TTL,
            timestamp_ms: now_ms(),
            nonce,
        };
        let header_bytes = h.encode();
        let ct = encrypt(&self.keys.tx, &nonce, &header_bytes, opus_frame);
        let mut datagram = header_bytes.to_vec();
        datagram.extend_from_slice(&ct);
        self.socket.send_to(&datagram, self.peer)?;
        Ok(seq)
    }

    /// 接收一帧：返回 (seq, Opus 明文帧)。nonce 直接取自包头。
    pub fn recv_voice(&mut self, timeout: Duration) -> Result<(u32, Vec<u8>)> {
        loop {
            match self.recv_event(timeout)? {
                Some(PacketEvent::Voice(seq, frame)) => return Ok((seq, frame)),
                Some(PacketEvent::Bye) => bail!("peer hung up (BYE)"),
                None => bail!("recv timeout"),
            }
        }
    }

    /// 接收一个包事件；超时返回 Ok(None)
    pub fn recv_event(&mut self, timeout: Duration) -> Result<Option<PacketEvent>> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = match self.socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if from != self.peer {
            return Ok(None);
        }
        let h = PacketHeader::decode(&buf[..n])?;
        if h.session_id != self.session_id || h.ttl == 0 {
            return Ok(None);
        }
        match h.ptype {
            PacketType::Bye => Ok(Some(PacketEvent::Bye)),
            PacketType::Voice => {
                check_replay_ok(self.rx_high_seq, h.seq)?;
                let header_bytes = h.encode();
                let pt = decrypt(&self.keys.rx, &h.nonce, &header_bytes, &buf[HEADER_LEN..n])?;
                if h.seq > self.rx_high_seq {
                    self.rx_high_seq = h.seq;
                }
                Ok(Some(PacketEvent::Voice(h.seq, pt)))
            }
            _ => Ok(None),
        }
    }

    /// 发送 BYE（通话结束）
    pub fn send_bye(&mut self) -> Result<()> {
        let h = PacketHeader {
            ptype: PacketType::Bye,
            session_id: self.session_id,
            seq: self.tx_seq,
            ttl: DEFAULT_TTL,
            timestamp_ms: now_ms(),
            nonce: [0u8; 12],
        };
        let datagram = h.encode().to_vec();
        self.socket.send_to(&datagram, self.peer)?;
        Ok(())
    }
}

/// 轻量抖动缓冲：按 seq 重排，窗口内等待，超时则丢包（上层静音/PLC）。
pub struct JitterBuffer {
    window: std::collections::BTreeMap<u32, Vec<u8>>,
    expected: u32,
    max_wait: usize,
}

impl JitterBuffer {
    pub fn new() -> Self {
        Self {
            window: std::collections::BTreeMap::new(),
            expected: 0,
            max_wait: 8, // 最多等 8 帧（160ms）再判定丢失
        }
    }

    pub fn push(&mut self, seq: u32, frame: Vec<u8>) {
        if seq >= self.expected {
            self.window.insert(seq, frame);
        }
    }

    /// 取出一帧用于播放：Some(帧) 或 None（丢包，上层填静音）
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        if let Some(f) = self.window.remove(&self.expected) {
            self.expected += 1;
            return Some(f);
        }
        // expected 缺失：看后面是否攒够了 max_wait 帧，够了就判定丢失、跳过
        let buffered = self.window.keys().filter(|s| **s > self.expected).count();
        if buffered >= self.max_wait {
            self.expected += 1; // 丢一帧
            return None;
        }
        // 还没攒够：返回空信号让调用方决定是等还是先播静音
        // 为简化原型：直接判定需要等待，调用方应继续 push
        None
    }

    /// 调用方每 20ms 调一次：优先 pop，拿不到且窗口未满则返回 NeedMore
    pub fn pop_or_wait(&mut self) -> JitterAction {
        if let Some(f) = self.window.remove(&self.expected) {
            self.expected += 1;
            return JitterAction::Frame(f);
        }
        let buffered = self.window.keys().filter(|s| **s > self.expected).count();
        if buffered >= self.max_wait {
            self.expected += 1;
            return JitterAction::Lost;
        }
        JitterAction::NeedMore
    }
}

pub enum JitterAction {
    Frame(Vec<u8>),
    Lost,     // 丢包：上层填静音或 PLC
    NeedMore, // 数据还没到：上层可选择短暂等待
}

pub enum PacketEvent {
    Voice(u32, Vec<u8>),
    Bye,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_reorder_and_loss() {
        let mut jb = JitterBuffer::new();
        // 乱序到达：2,0,1,4（3 丢失）
        jb.push(2, vec![2]);
        jb.push(0, vec![0]);
        jb.push(1, vec![1]);
        jb.push(4, vec![4]);
        assert!(matches!(jb.pop_or_wait(), JitterAction::Frame(f) if f == vec![0]));
        assert!(matches!(jb.pop_or_wait(), JitterAction::Frame(f) if f == vec![1]));
        assert!(matches!(jb.pop_or_wait(), JitterAction::Frame(f) if f == vec![2]));
        // 3 缺失：继续塞够 8 帧后来判定丢失
        for s in 5..13 {
            jb.push(s, vec![s as u8]);
        }
        assert!(matches!(jb.pop_or_wait(), JitterAction::Lost)); // seq 3 丢包
        assert!(matches!(jb.pop_or_wait(), JitterAction::Frame(f) if f == vec![4]));
    }

    fn valid_handshake() -> (IdentityKeypair, u64, [u8; HANDSHAKE_PAYLOAD_LEN]) {
        let id = IdentityKeypair::generate();
        let session_id = 0x1234_5678_9ABC_DEF0;
        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let mut eph_bytes = [0u8; 32];
        eph_bytes.copy_from_slice(eph_pub.as_bytes());
        let payload = build_handshake_payload(&id, session_id, &eph_bytes);
        (id, session_id, payload)
    }

    #[test]
    fn handshake_accepts_valid() {
        let (id, session_id, payload) = valid_handshake();
        let (id_pub, eph_pub) = parse_and_verify_handshake(&payload, session_id).unwrap();
        assert_eq!(id_pub, id.public_bytes());
        assert_eq!(&eph_pub, &payload[64..96]);
    }

    /// 对抗性测试：任何篡改/截断/伪造的握手载荷都必须被拒绝，且不能 panic。
    /// 信任模型注记：签名只覆盖 session_id || eph_pub；X25519 身份公钥的
    /// 真实性由线下指纹核对保证（见 fingerprint_of）。替换 id_pub 不会
    /// 导致验签失败，但指纹会变化——下面的测试把这一性质钉死。
    #[test]
    fn handshake_rejects_tampering() {
        let (id, session_id, payload) = valid_handshake();

        // 截断：0..160 任意长度都不能 panic，且 <160 必须拒绝
        for len in 0..HANDSHAKE_PAYLOAD_LEN {
            assert!(
                parse_and_verify_handshake(&payload[..len], session_id).is_err(),
                "truncated len={len} was accepted"
            );
        }
        // 全零载荷（伪造者最省事的尝试）
        assert!(parse_and_verify_handshake(&[0u8; HANDSHAKE_PAYLOAD_LEN], session_id).is_err());
        // 随机垃圾
        let mut garbage = [0x5Au8; HANDSHAKE_PAYLOAD_LEN];
        for i in 0..HANDSHAKE_PAYLOAD_LEN {
            garbage[i] = garbage[i].wrapping_add(i as u8);
        }
        assert!(parse_and_verify_handshake(&garbage, session_id).is_err());

        // 签名区逐字节翻转：任何一处篡改都必须拒绝
        for i in 96..160 {
            let mut bad = payload;
            bad[i] ^= 0xFF;
            assert!(
                parse_and_verify_handshake(&bad, session_id).is_err(),
                "tampered sig byte {i} was accepted"
            );
        }
        // 被签名内容（eph_pub）篡改：拒绝
        for i in [64usize, 80, 95] {
            let mut bad = payload;
            bad[i] ^= 0x01;
            assert!(
                parse_and_verify_handshake(&bad, session_id).is_err(),
                "tampered eph_pub byte {i} was accepted"
            );
        }
        // session_id 不一致：拒绝（防跨会话重放握手包）
        assert!(parse_and_verify_handshake(&payload, session_id.wrapping_add(1)).is_err());

        // 替换 X25519 身份公钥：验签仍通过（签名不覆盖它），但指纹必然变化，
        // 线下核对指纹时会暴露。这是设计使然，不是漏洞。
        let attacker = IdentityKeypair::generate();
        let mut swapped = payload;
        swapped[..32].copy_from_slice(&attacker.public_bytes());
        let (id_pub, _) = parse_and_verify_handshake(&swapped, session_id).unwrap();
        assert_eq!(id_pub, attacker.public_bytes());
        assert_ne!(fingerprint_of(&id_pub), id.fingerprint());

        // 尾部多余字节被忽略（dial 路径传进来的是整个 datagram 剩余部分）
        let mut longer = payload.to_vec();
        longer.extend_from_slice(&[0xFFu8; 64]);
        assert!(parse_and_verify_handshake(&longer, session_id).is_ok());
    }
}
