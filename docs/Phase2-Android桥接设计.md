# Phase 2 Android App · JNI 桥接设计（预研）

目标：复用 Rust 核心（p2p-proto/crypto/transport/audio），Kotlin 只做 UI 和系统音频，
通过 JNI 桥接。这是"一套核心，多端 UI"路线的关键一步，桌面端（Tauri）和专用硬件以后也吃同一套核心。

## 架构

```
┌─────────────────────────────────────────────┐
│ Kotlin / Android                            │
│  PTT Button UI · 联系人/配对 · 前台服务保活    │
│  AudioRecord(48kHz/mono)采集 · AudioTrack播放  │
├─────────────────────────────────────────────┤
│ JNI 桥 (p2p-jni crate, cdylib)               │
│  keygen / dial / accept /                   │
│  pushPcmFrame(i16[960]) -> opusBytes        │
│  pollEvent() -> VoiceFrame | Bye | None      │
├─────────────────────────────────────────────┤
│ Rust 核心（现有四个 crate，原样复用）          │
│  proto · crypto · transport · audio(Opus)    │
└─────────────────────────────────────────────┘
```

## 关键设计决策

1. **音频编解码放在 Rust 侧**：Kotlin 只负责原始 PCM 采集与播放，
   Opus 编解码复用已验证的 p2p-audio，避免两套实现不一致。
2. **Rust 会话常驻独立线程**：JNI 调用非阻塞；Kotlin 侧每 20ms
   `pollEvent()` 取包，喂给 AudioTrack。网络线程永不阻塞 UI。
3. **前台服务保活**：Android 杀后台是已知最硬的骨头（分析文档已指出）。
   Phase 2 先做到"亮屏+前台服务可用"，Doze 深度优化列为 Phase 2.5。
4. **配对**：设备码（4 组字符）+ QR 二维码，扫码后交换身份公钥，
   通话前显示双方指纹供核对（复用 CLI 已有逻辑）。

## JNI 接口草案（p2p-jni crate）

```rust
// 身份
jni_keygen() -> jstring  // "指纹"
// 会话（返回 session 句柄 long）
jni_dial(peer_ip: jstring, peer_port: jint) -> jlong
jni_accept(bind_port: jint) -> jlong
// 语音
jni_push_pcm(handle: jlong, pcm: jshortArray) -> jbyteArray  // -> 加密包（内部直接发送）
jni_poll_event(handle: jlong) -> jobject  // VoiceEvent{seq, pcm} / ByeEvent / null
jni_close(handle: jlong)
```

注意：`pushPcmFrame` 内部完成 Opus 编码→加密→UDP 发送，一次 JNI 调用走完全链路，
减少跨语言往返。`pollEvent` 内部完成 收包→解密→抖动缓冲→解码，一次调用返回一帧 PCM。

## 构建环境（待搭建）

- Android NDK r25+，targets：aarch64-linux-android（主力）、armv7-linux-androideabi
- cargo-ndk 桥接 Rust cdylib 编译
- Android SDK cmdline-tools + platform-34
- 预计下载 2-3GB，首次搭建约 1-2 小时

## Phase 2 里程碑

| 步骤 | 内容 | 验收 |
|---|---|---|
| 2a | JNI 桥 + Rust 核心交叉编译出 .so | 单元测试在真机/模拟器通过 |
| 2b | Kotlin 最小 UI：配对 + PTT 按钮 + 状态灯 | 两台手机同 WiFi 对讲可用 |
| 2c | 前台服务 + 断线重连 | 锁屏/切后台 5 分钟不断联 |

## 与路线 A（硬件+协议）的关系

这套 JNI 桥接本质是"把 Rust 核心装进另一种外壳"。专用硬件阶段，
同一套核心交叉编译到嵌入式 Linux（ARM），外壳换成物理 PTT 按键——
Phase 2 的工作在 Phase 6 复用率 80% 以上。现在花的功夫不会浪费。
