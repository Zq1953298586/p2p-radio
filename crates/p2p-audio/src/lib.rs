//! P2P-Radio V0.1 音频层：Opus 编解码
//!
//! 固定参数：48kHz 单声道 16-bit，20ms 帧（960 采样），24kbps，VoIP 模式。
//! 这是实时语音的标准甜点：低延迟 + 丢包容忍 + 低带宽。

use anyhow::Result;
use opus::Channels;

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: usize = 1;
pub const FRAME_MS: usize = 20;
pub const FRAME_SAMPLES: usize = SAMPLE_RATE as usize * FRAME_MS / 1000; // 960
pub const BITRATE: i32 = 24_000;

pub struct OpusVoiceCoder {
    enc: opus::Encoder,
    dec: opus::Decoder,
}

impl OpusVoiceCoder {
    pub fn new() -> Result<Self> {
        let mut enc = opus::Encoder::new(
            SAMPLE_RATE,
            Channels::Mono,
            opus::Application::Voip,
        )?;
        enc.set_bitrate(opus::Bitrate::Bits(BITRATE))?;
        let dec = opus::Decoder::new(SAMPLE_RATE, Channels::Mono)?;
        Ok(Self { enc, dec })
    }

    /// 960 个 i16 采样 -> Opus 帧
    pub fn encode_frame(&mut self, pcm: &[i16]) -> Result<Vec<u8>> {
        assert_eq!(pcm.len(), FRAME_SAMPLES);
        let mut out = vec![0u8; 4000];
        let n = self.enc.encode(pcm, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Opus 帧 -> 960 个 i16 采样；fec=true 时尝试包丢失隐藏
    pub fn decode_frame(&mut self, opus_frame: &[u8], fec: bool) -> Result<Vec<i16>> {
        let mut out = vec![0i16; FRAME_SAMPLES * 2]; // 留余量
        let n = self.dec.decode(opus_frame, &mut out, fec)?;
        out.truncate(n * CHANNELS);
        // 补齐到整帧
        out.resize(FRAME_SAMPLES, 0);
        Ok(out)
    }

    /// 丢包隐藏：用空帧触发 Opus PLC
    pub fn conceal_loss(&mut self) -> Result<Vec<i16>> {
        self.decode_frame(&[], true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip() {
        let mut coder = OpusVoiceCoder::new().unwrap();
        // 440Hz 正弦一帧
        let pcm: Vec<i16> = (0..FRAME_SAMPLES)
            .map(|i| ((i as f32 * 440.0 * 2.0 * std::f32::consts::PI / SAMPLE_RATE as f32).sin()
                * 10000.0) as i16)
            .collect();
        let frame = coder.encode_frame(&pcm).unwrap();
        assert!(frame.len() < 200, "24kbps 下 20ms 帧应远小于 200 字节");
        let back = coder.decode_frame(&frame, false).unwrap();
        assert_eq!(back.len(), FRAME_SAMPLES);
        // 能量应对得上（Opus 有损，不做逐采样比对）
        let e_in: f64 = pcm.iter().map(|s| (*s as f64).powi(2)).sum();
        let e_out: f64 = back.iter().map(|s| (*s as f64).powi(2)).sum();
        let ratio = e_out / e_in;
        assert!(ratio > 0.5 && ratio < 2.0, "energy ratio {}", ratio);
    }
}
