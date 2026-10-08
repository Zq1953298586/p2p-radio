package com.p2pradio.core

/**
 * Rust 核心的 Kotlin 侧声明，必须与 crates/p2p-jni 的 JNI 函数签名一一对应：
 *   Java_com_p2pradio_core_NativeCore_nativeXxx
 *
 * storeDir：应用私有目录 filesDir.absolutePath，身份密钥存于此（nativeKeygen 创建）。
 * handle：Rust 侧 SessionState 的指针（jlong），0 表示无效。
 */
object NativeCore {

    init {
        System.loadLibrary("p2p_jni")
    }

    /** 生成/加载设备身份，返回指纹 "XXXX XXXX XXXX XXXX" */
    external fun nativeKeygen(storeDir: String): String

    /** 拨号：storeDir, 对方IP, 端口 -> handle（0=失败） */
    external fun nativeDial(storeDir: String, ip: String, port: Int): Long

    /** 接听：在 bindPort 上等 HELLO（最长120秒）-> handle（0=失败/超时） */
    external fun nativeAccept(storeDir: String, bindPort: Int): Long

    /** 对方身份指纹（握手后，用于线下核对） */
    external fun nativePeerFingerprint(handle: Long): String

    /**
     * 推一帧 PCM（必须恰好 960 个采样 = 20ms @48kHz mono）。
     * Rust 侧完成 Opus编码->加密->UDP发送。返回包序号，-1=失败。
     */
    external fun nativePushPcm(handle: Long, pcm: ShortArray): Int

    /**
     * 取一帧 PCM（20ms）。Rust 侧完成 收包->解密->抖动缓冲->解码/PLC。
     * 返回 null 表示这一拍无数据（调用方保持 20ms 节奏继续轮询）。
     */
    external fun nativePollPcm(handle: Long): ShortArray?

    /** 发送 BYE（通话结束） */
    external fun nativeSendBye(handle: Long)

    /** 释放会话 */
    external fun nativeClose(handle: Long)
}
