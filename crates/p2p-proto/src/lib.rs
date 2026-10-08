//! P2P-Radio V0.1 数据包协议
//!
//! 包头 35 字节（大端序），后面跟载荷：
//! ```text
//!  version: u8        = 1
//!  ptype:   u8        (0=HELLO, 1=HELLO_ACK, 2=VOICE, 3=BYE)
//!  session_id: u64
//!  seq:     u32       （VOICE 包的包序号；握手包为 0）
//!  ttl:     u8        （多跳预留，V0.1 直连固定为 4）
//!  timestamp_ms: u64  （发送端 unix 毫秒，用于抗重放与抖动评估）
//!  nonce:   [u8;12]   （VOICE 包的 ChaCha20-Poly1305 nonce；握手包为 0）
//! ```
//! VOICE 包载荷 = ChaCha20-Poly1305(明文 Opus 帧)，密文自带 16 字节 tag。
//! 握手包载荷为明文（见 transport 层握手状态机），V0.2 起加入身份签名。

use anyhow::{bail, Result};

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 35;
pub const DEFAULT_TTL: u8 = 4;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Hello = 0,
    HelloAck = 1,
    Voice = 2,
    Bye = 3,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(PacketType::Hello),
            1 => Ok(PacketType::HelloAck),
            2 => Ok(PacketType::Voice),
            3 => Ok(PacketType::Bye),
            _ => bail!("unknown packet type: {}", v),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub ptype: PacketType,
    pub session_id: u64,
    pub seq: u32,
    pub ttl: u8,
    pub timestamp_ms: u64,
    pub nonce: [u8; 12],
}

impl PacketHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = PROTOCOL_VERSION;
        b[1] = self.ptype as u8;
        b[2..10].copy_from_slice(&self.session_id.to_be_bytes());
        b[10..14].copy_from_slice(&self.seq.to_be_bytes());
        b[14] = self.ttl;
        b[15..23].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        b[23..35].copy_from_slice(&self.nonce);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("packet too short: {} < {}", buf.len(), HEADER_LEN);
        }
        if buf[0] != PROTOCOL_VERSION {
            bail!("unsupported protocol version: {}", buf[0]);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[23..35]);
        Ok(PacketHeader {
            ptype: PacketType::from_u8(buf[1])?,
            session_id: u64::from_be_bytes(buf[2..10].try_into().unwrap()),
            seq: u32::from_be_bytes(buf[10..14].try_into().unwrap()),
            ttl: buf[14],
            timestamp_ms: u64::from_be_bytes(buf[15..23].try_into().unwrap()),
            nonce,
        })
    }
}

/// 握手载荷（明文，160 字节）：
/// ```text
///   X25519 身份公钥  (32)
///   Ed25519 身份公钥 (32)
///   临时公钥         (32)
///   Ed25519 签名     (64)  签名对象 = session_id(8BE) || 临时公钥(32)
/// ```
/// 验签失败的一方必须拒绝握手。指纹核对（线下）认证 X25519 公钥，
/// 攻击者替换任一公钥都会导致指纹不匹配或验签失败。
pub const HANDSHAKE_PAYLOAD_LEN: usize = 160;

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = PacketHeader {
            ptype: PacketType::Voice,
            session_id: 0x8F92_1234_ABCD_EF01,
            seq: 424242,
            ttl: DEFAULT_TTL,
            timestamp_ms: 1_729_999_000_123,
            nonce: [7u8; 12],
        };
        let enc = h.encode();
        let dec = PacketHeader::decode(&enc).unwrap();
        assert_eq!(dec.ptype, PacketType::Voice);
        assert_eq!(dec.session_id, h.session_id);
        assert_eq!(dec.seq, 424242);
        assert_eq!(dec.ttl, DEFAULT_TTL);
        assert_eq!(dec.timestamp_ms, h.timestamp_ms);
        assert_eq!(dec.nonce, [7u8; 12]);
    }

    #[test]
    fn reject_bad_version() {
        let mut b = [0u8; HEADER_LEN];
        b[0] = 99;
        assert!(PacketHeader::decode(&b).is_err());
    }
}
