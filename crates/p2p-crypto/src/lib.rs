//! P2P-Radio V0.1 密码学层
//!
//! 设计（简化版 X3DH，不自创密码协议，只组合成熟构件）：
//! - 身份：每台设备两条长期密钥——X25519（DH 密钥协商）+ Ed25519（握手签名），
//!   存于 ~/.p2p-radio/identity.key（64 字节）。
//!   公钥即设备身份，指纹 = SHA256(X25519 公钥) 分组显示，供双方线下核对。
//!   安全绑定逻辑：握手载荷里的 X25519 公钥参与 DH，Ed25519 公钥用于验签；
//!   线下核对指纹即认证了 X25519 公钥，攻击者若替换任一公钥都会导致
//!   指纹不匹配或验签失败——因此一次指纹核对同时锁定两把钥匙。
//! - 会话：每次通话双方各生成临时 X25519 密钥对，三组 DH：
//!   s1 = DH(身份_initiator, 临时_responder)
//!   s2 = DH(临时_initiator, 身份_responder)
//!   s3 = DH(临时_initiator, 临时_responder)
//!   master = HKDF-SHA256(s1||s2||s3)，再派生两个方向密钥。
//! - 握手签名：每条 HELLO/HELLO_ACK 载荷附带 Ed25519 签名，
//!   签名对象 = session_id || 本方临时公钥；验签失败直接拒绝握手。
//! - 语音：ChaCha20-Poly1305 AEAD，nonce = 4 字节会话随机前缀 + 8 字节 seq，
//!   同一方向 seq 严格递增，永不重用；包头 35 字节做 AAD 绑定。通话结束密钥销毁。

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBKEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// identity.key 文件长度：32 (X25519 私钥) + 32 (Ed25519 私钥)
pub const IDENTITY_SECRET_LEN: usize = 64;

/// 设备长期身份密钥对：X25519（协商）+ Ed25519（签名）
pub struct IdentityKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
    pub sign_secret: SigningKey,
    pub sign_public: VerifyingKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sign_secret = SigningKey::generate(&mut OsRng);
        let sign_public = sign_secret.verifying_key();
        Self {
            secret,
            public,
            sign_secret,
            sign_public,
        }
    }

    pub fn from_secret_bytes(b: &[u8; IDENTITY_SECRET_LEN]) -> Self {
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        e.copy_from_slice(&b[32..]);
        let secret = StaticSecret::from(x);
        let public = PublicKey::from(&secret);
        let sign_secret = SigningKey::from_bytes(&e);
        let sign_public = sign_secret.verifying_key();
        Self {
            secret,
            public,
            sign_secret,
            sign_public,
        }
    }

    pub fn secret_bytes(&self) -> [u8; IDENTITY_SECRET_LEN] {
        let mut b = [0u8; IDENTITY_SECRET_LEN];
        b[..32].copy_from_slice(&self.secret.to_bytes());
        b[32..].copy_from_slice(&self.sign_secret.to_bytes());
        b
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn sign_public_bytes(&self) -> [u8; 32] {
        self.sign_public.to_bytes()
    }

    /// 安全指纹：SHA256(X25519 公钥)，4 组 4 hex 字符，如 "9A72 C81F 02BD 7E31"
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public_bytes())
    }

    /// 对握手消息签名
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sign_secret.sign(msg).to_bytes()
    }
}

/// 验签：pubkey=对方 Ed25519 公钥，msg=被签消息，sig=64字节签名。
/// 使用 verify_strict：拒绝弱公钥（低阶点）与非规范 R。
/// 弱公钥可对"几乎任意消息"生成有效签名（见 ed25519-dalek 文档），
/// 普通 verify 会放过全零公钥+全零签名这样的伪造——必须用 strict。
pub fn verify_signature(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| anyhow::anyhow!("bad pubkey: {}", e))?;
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature)
        .map_err(|_| anyhow::anyhow!("signature verification failed"))
}

/// 握手签名对象：session_id(8BE) || 本方临时公钥(32)
pub fn handshake_sign_msg(session_id: u64, eph_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(&session_id.to_be_bytes());
    m.extend_from_slice(eph_pub);
    m
}

pub fn fingerprint_of(pubkey: &[u8; 32]) -> String {
    let h = Sha256::digest(pubkey);
    let hex: String = h[..8].iter().map(|b| format!("{:02X}", b)).collect();
    [
        hex[0..4].to_string(),
        hex[4..8].to_string(),
        hex[8..12].to_string(),
        hex[12..16].to_string(),
    ]
    .join(" ")
}

/// 会话双向密钥
pub struct SessionKeys {
    /// 我发送方向（对方接收方向）
    pub tx: [u8; 32],
    /// 我接收方向（对方发送方向）
    pub rx: [u8; 32],
    /// 我发送方向的 4 字节 nonce 前缀（会话内随机；接收方直接从包头取 nonce）
    pub tx_nonce_prefix: [u8; 4],
}

/// 拒绝弱 X25519 公钥：全零或低阶点。
/// 攻击者若在握手中塞入低阶点，DH 输出将坍缩到 ≤8 种可能，
/// 三组 DH 全弱时整个会话密钥可被离线暴力破解（8^3=512 种）。
/// 线下指纹核对是第一道防线，这里是第二道。
pub fn check_peer_x25519_pubkey(peer_pub: &[u8; 32], role: &str) -> Result<()> {
    if peer_pub == &[0u8; 32] {
        bail!("{role}: zero x25519 public key");
    }
    let edwards = match MontgomeryPoint(*peer_pub).to_edwards(0) {
        Some(p) => p,
        None => bail!("{role}: invalid x25519 public key (u=-1)"),
    };
    if edwards.is_small_order() {
        bail!("{role}: low-order x25519 public key");
    }
    Ok(())
}

/// 建立会话密钥。`initiator` = 我是呼叫方（先发 HELLO）。
/// 调用方需提供：我的身份私钥、我的临时私钥、对方身份公钥、对方临时公钥。
/// 对方公钥先过弱密钥检查，不通过直接返回 Err（握手失败）。
pub fn derive_session_keys(
    initiator: bool,
    my_id: &StaticSecret,
    my_eph: &StaticSecret,
    peer_id_pub: &[u8; 32],
    peer_eph_pub: &[u8; 32],
    session_id: u64,
    nonce_prefix_tx: [u8; 4],
) -> Result<SessionKeys> {
    check_peer_x25519_pubkey(peer_id_pub, "peer identity key")?;
    check_peer_x25519_pubkey(peer_eph_pub, "peer ephemeral key")?;

    let peer_id = PublicKey::from(*peer_id_pub);
    let peer_eph = PublicKey::from(*peer_eph_pub);

    // 三组 DH。注意：无论谁是 initiator，s1/s2/s3 的定义按角色固定，
    // 双方算出相同的值（DH 对称性）。
    let (s1, s2, s3) = if initiator {
        (
            my_id.diffie_hellman(&peer_eph),
            my_eph.diffie_hellman(&peer_id),
            my_eph.diffie_hellman(&peer_eph),
        )
    } else {
        (
            my_eph.diffie_hellman(&peer_id),
            my_id.diffie_hellman(&peer_eph),
            my_eph.diffie_hellman(&peer_eph),
        )
    };
    // responder 视角：s1 = DH(临时_r, 身份_i)，s2 = DH(身份_r, 临时_i)，s3 同。
    // 上面 initiator 分支：s1 = DH(身份_i, 临时_r) == DH(临时_r, 身份_i) ✓

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(s1.as_bytes());
    ikm.extend_from_slice(s2.as_bytes());
    ikm.extend_from_slice(s3.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&session_id.to_be_bytes()), &ikm);
    let mut k_ab = [0u8; 32];
    let mut k_ba = [0u8; 32];
    hk.expand(b"p2p-radio-v1/a-to-b", &mut k_ab).unwrap();
    hk.expand(b"p2p-radio-v1/b-to-a", &mut k_ba).unwrap();

    // initiator(a) -> responder(b) 方向用 k_ab
    let (tx, rx) = if initiator {
        (k_ab, k_ba)
    } else {
        (k_ba, k_ab)
    };
    Ok(SessionKeys {
        tx,
        rx,
        tx_nonce_prefix: nonce_prefix_tx,
    })
}

/// 由 seq 构造 12 字节 nonce：4 字节方向前缀 + 8 字节 seq（大端）
pub fn make_nonce(prefix: &[u8; 4], seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(prefix);
    n[4..12].copy_from_slice(&(seq as u64).to_be_bytes());
    n
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .unwrap();
    buf // 密文 + 16 字节 tag
}

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| anyhow::anyhow!("AEAD decrypt failed (bad key/nonce/aad/ciphertext)"))?;
    Ok(buf)
}

pub fn random_nonce_prefix() -> [u8; 4] {
    use rand::RngCore;
    let mut p = [0u8; 4];
    OsRng.fill_bytes(&mut p);
    p
}

pub fn check_replay_ok(last_seq: u32, seq: u32) -> Result<()> {
    // 允许乱序到达（抖动缓冲会重排），但拒绝明显重放：seq 必须大于 last-1024
    if seq + 1024 < last_seq {
        bail!("probable replay: seq {} far behind {}", seq, last_seq);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_keys_agree() {
        let id_a = IdentityKeypair::generate();
        let id_b = IdentityKeypair::generate();
        let eph_a = StaticSecret::random_from_rng(OsRng);
        let eph_b = StaticSecret::random_from_rng(OsRng);
        let sid = 0x1234_5678_9ABC_DEF0;
        let ka = derive_session_keys(
            true,
            &id_a.secret,
            &eph_a,
            &id_b.public_bytes(),
            &PublicKey::from(&eph_b).to_bytes(),
            sid,
            [1, 2, 3, 4],
        )
        .unwrap();
        let kb = derive_session_keys(
            false,
            &id_b.secret,
            &eph_b,
            &id_a.public_bytes(),
            &PublicKey::from(&eph_a).to_bytes(),
            sid,
            [5, 6, 7, 8],
        )
        .unwrap();
        assert_eq!(ka.tx, kb.rx, "A->B direction must agree");
        assert_eq!(ka.rx, kb.tx, "B->A direction must agree");
        assert_ne!(ka.tx, ka.rx, "directions must use different keys");
    }

    #[test]
    fn aead_roundtrip() {
        let key = [42u8; 32];
        let nonce = make_nonce(&[9, 9, 9, 9], 7);
        let aad = b"header-bytes";
        let pt = b"hello p2p radio";
        let ct = encrypt(&key, &nonce, aad, pt);
        assert_eq!(ct.len(), pt.len() + 16);
        let back = decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(back, pt);
        // 篡改检测
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt(&key, &nonce, aad, &bad).is_err());
        // AAD 绑定：aad 不一致则解密失败（防跨包拼接）
        assert!(decrypt(&key, &nonce, b"other-aad", &ct).is_err());
        // 不同 seq 不同 nonce
        assert_ne!(make_nonce(&[9, 9, 9, 9], 7), make_nonce(&[9, 9, 9, 9], 8));
    }

    #[test]
    fn fingerprint_format() {
        let id = IdentityKeypair::generate();
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 19); // "XXXX XXXX XXXX XXXX"
        assert_eq!(fp.chars().filter(|c| *c == ' ').count(), 3);
    }

    #[test]
    fn identity_serde_roundtrip() {
        let id = IdentityKeypair::generate();
        let bytes = id.secret_bytes();
        assert_eq!(bytes.len(), IDENTITY_SECRET_LEN);
        let id2 = IdentityKeypair::from_secret_bytes(&bytes);
        assert_eq!(id.public_bytes(), id2.public_bytes());
        assert_eq!(id.sign_public_bytes(), id2.sign_public_bytes());
        assert_eq!(id.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn handshake_sign_verify() {
        let id = IdentityKeypair::generate();
        let msg = handshake_sign_msg(0xDEAD_BEEF, &[7u8; 32]);
        let sig = id.sign(&msg);
        // 正常验签通过
        verify_signature(&id.sign_public_bytes(), &msg, &sig).unwrap();
        // 篡改消息 -> 失败
        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert!(verify_signature(&id.sign_public_bytes(), &bad_msg, &sig).is_err());
        // 篡改签名 -> 失败
        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert!(verify_signature(&id.sign_public_bytes(), &msg, &bad_sig).is_err());
        // 用别人的公钥验 -> 失败
        let other = IdentityKeypair::generate();
        assert!(verify_signature(&other.sign_public_bytes(), &msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_weak_ed25519_key() {
        // 全零公钥是低阶点：普通 verify 会放过"全零公钥+全零签名"，
        // verify_strict 必须拒绝。这是库文档明确警告过的陷阱。
        let msg = b"any message at all";
        assert!(verify_signature(&[0u8; 32], msg, &[0u8; 64]).is_err());
        // 正常密钥+正常签名不受影响
        let id = IdentityKeypair::generate();
        let sig = id.sign(msg);
        verify_signature(&id.sign_public_bytes(), msg, &sig).unwrap();
    }

    #[test]
    fn derive_rejects_weak_x25519_keys() {
        let id_a = IdentityKeypair::generate();
        let eph_a = StaticSecret::random_from_rng(OsRng);
        let id_b = IdentityKeypair::generate();
        let eph_b = StaticSecret::random_from_rng(OsRng);
        let eph_b_pub = PublicKey::from(&eph_b).to_bytes();
        let sid = 0xABCD;

        // 对方身份密钥全零 -> 拒绝
        assert!(derive_session_keys(
            true, &id_a.secret, &eph_a, &[0u8; 32], &eph_b_pub, sid, [0; 4]
        )
        .is_err());
        // 对方临时密钥全零 -> 拒绝
        assert!(derive_session_keys(
            true, &id_a.secret, &eph_a, &id_b.public_bytes(), &[0u8; 32], sid, [0; 4]
        )
        .is_err());
        // 对方身份密钥是低阶点（u=1 是 order-4 点）-> 拒绝
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        assert!(check_peer_x25519_pubkey(&low_order, "test").is_err());
        // 正常密钥通过
        check_peer_x25519_pubkey(&id_b.public_bytes(), "test").unwrap();
        check_peer_x25519_pubkey(&eph_b_pub, "test").unwrap();
    }
}
