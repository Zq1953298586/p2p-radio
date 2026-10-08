package com.p2pradio.ui

import android.Manifest
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.p2pradio.core.NativeCore
import kotlin.concurrent.thread

/**
 * Phase 2b 最小可用 UI：配对 + 按住说话 + 状态显示。
 *
 * 流程（以本机为接收方为例）：
 *  1. 启动 -> nativeKeygen 显示本机指纹
 *  2. 点"等待呼叫" -> nativeAccept(9002)（阻塞，放在后台线程）
 *  3. 对方拨入 -> 显示对方指纹 -> 双方线下核对
 *  4. 按住 PTT 按钮 -> AudioRecord 采集 -> nativePushPcm 发送
 *  5. 后台轮询线程每 20ms nativePollPcm() -> AudioTrack 播放
 *
 * 注意：本文件为 Phase 2b 骨架，编译需要 Android SDK（见 scripts/setup-android-env.sh）。
 */
class MainActivity : AppCompatActivity() {

    companion object {
        const val SAMPLE_RATE = 48000
        const val FRAME_SAMPLES = 960 // 20ms
        const val PORT = 9002
    }

    private var handle: Long = 0
    private var storeDir: String = ""
    private var talking = false

    private lateinit var statusText: TextView
    private lateinit var pttButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        storeDir = filesDir.absolutePath

        requestAudioPermission()

        val fp = NativeCore.nativeKeygen(storeDir)
        statusText.text = "本机指纹：$fp\n（把这行发给对方核对）"
    }

    /** 作为接收方：等待对方拨入 */
    private fun startAccept() {
        statusText.text = "等待呼叫中…"
        thread {
            val h = NativeCore.nativeAccept(storeDir, PORT)
            if (h == 0L) {
                runOnUiThread { statusText.text = "等待超时，请重试" }
                return@thread
            }
            handle = h
            val peerFp = NativeCore.nativePeerFingerprint(h)
            runOnUiThread {
                statusText.text = "已连接！对方指纹：$peerFp\n请线下核对一致后再说话"
            }
            startPlayoutLoop()
        }
    }

    /** 作为发起方：拨向对方 */
    private fun startDial(peerIp: String) {
        statusText.text = "拨号中…"
        thread {
            val h = NativeCore.nativeDial(storeDir, peerIp, PORT)
            if (h == 0L) {
                runOnUiThread { statusText.text = "拨号失败：检查IP/网络" }
                return@thread
            }
            handle = h
            val peerFp = NativeCore.nativePeerFingerprint(h)
            runOnUiThread {
                statusText.text = "已连接！对方指纹：$peerFp\n请线下核对一致后再说话"
            }
            startPlayoutLoop()
        }
    }

    /** 按住说话：采集 -> nativePushPcm */
    private fun startTalk() {
        if (handle == 0L) return
        talking = true
        thread {
            val rec = AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                FRAME_SAMPLES * 2 * 4
            )
            rec.startRecording()
            val buf = ShortArray(FRAME_SAMPLES)
            while (talking) {
                val n = rec.read(buf, 0, FRAME_SAMPLES)
                if (n == FRAME_SAMPLES) {
                    NativeCore.nativePushPcm(handle, buf)
                }
            }
            rec.stop()
            rec.release()
        }
    }

    private fun stopTalk() {
        talking = false
    }

    /** 播放循环：每 20ms 取一帧 */
    private fun startPlayoutLoop() {
        thread {
            val track = AudioTrack(
                AudioManager.STREAM_MUSIC,
                SAMPLE_RATE,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                FRAME_SAMPLES * 2 * 4,
                AudioTrack.MODE_STREAM
            )
            track.play()
            while (handle != 0L) {
                val t0 = System.currentTimeMillis()
                val pcm = NativeCore.nativePollPcm(handle)
                if (pcm != null) {
                    track.write(pcm, 0, pcm.size)
                }
                val spent = System.currentTimeMillis() - t0
                if (spent < 20) Thread.sleep(20 - spent)
            }
            track.stop()
            track.release()
        }
    }

    private fun requestAudioPermission() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.RECORD_AUDIO), 1
            )
        }
    }

    override fun onDestroy() {
        if (handle != 0L) {
            NativeCore.nativeSendBye(handle)
            NativeCore.nativeClose(handle)
            handle = 0
        }
        super.onDestroy()
    }
}
