package com.p2pradio.ui

import android.Manifest
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Bundle
import android.view.MotionEvent
import android.widget.Button
import android.widget.EditText
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
 * 注意：编译需要 Android SDK（见 scripts/setup-android-env.sh）。
 */
class MainActivity : AppCompatActivity() {

    companion object {
        const val SAMPLE_RATE = 48000
        const val FRAME_SAMPLES = 960 // 20ms
        const val PORT = 9002
    }

    private var handle: Long = 0
    private var storeDir: String = ""
    @Volatile private var talking = false

    private lateinit var statusText: TextView
    private lateinit var peerIp: EditText
    private lateinit var acceptBtn: Button
    private lateinit var dialBtn: Button
    private lateinit var pttButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status_text)
        peerIp = findViewById(R.id.peer_ip)
        acceptBtn = findViewById(R.id.btn_accept)
        dialBtn = findViewById(R.id.btn_dial)
        pttButton = findViewById(R.id.btn_ptt)

        storeDir = filesDir.absolutePath
        requestAudioPermission()

        val fp = NativeCore.nativeKeygen(storeDir)
        statusText.text = if (fp != null) {
            "本机指纹：$fp\n（把这行发给对方核对）"
        } else {
            "身份初始化失败，请重启应用"
        }

        acceptBtn.setOnClickListener { startAccept() }
        dialBtn.setOnClickListener {
            val ip = peerIp.text.toString().trim()
            if (ip.isEmpty()) {
                statusText.text = "请先输入对方 IP"
            } else {
                startDial(ip)
            }
        }
        pttButton.setOnTouchListener { _, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> startTalk()
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> stopTalk()
            }
            true
        }
    }

    /** 作为接收方：等待对方拨入 */
    private fun startAccept() {
        if (handle != 0L) return
        setStatus("等待呼叫中…")
        thread {
            val h = NativeCore.nativeAccept(storeDir, PORT)
            if (h == 0L) {
                setStatus("等待超时，请重试")
                return@thread
            }
            onConnected(h)
        }
    }

    /** 作为发起方：拨向对方 */
    private fun startDial(peerIp: String) {
        if (handle != 0L) return
        setStatus("拨号中…")
        thread {
            val h = NativeCore.nativeDial(storeDir, peerIp, PORT)
            if (h == 0L) {
                setStatus("拨号失败：检查IP/网络")
                return@thread
            }
            onConnected(h)
        }
    }

    private fun onConnected(h: Long) {
        handle = h
        val peerFp = NativeCore.nativePeerFingerprint(h) ?: "（读取失败）"
        setStatus("已连接！对方指纹：$peerFp\n请线下核对一致后再说话")
        startPlayoutLoop()
    }

    private fun setStatus(s: String) {
        runOnUiThread { statusText.text = s }
    }

    /** 按住说话：采集 -> nativePushPcm */
    private fun startTalk() {
        val h = handle
        if (h == 0L || talking) return
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
                    NativeCore.nativePushPcm(h, buf)
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
        val h = handle
        handle = 0
        if (h != 0L) {
            NativeCore.nativeSendBye(h)
            NativeCore.nativeClose(h) // 恰好一次；之后不再使用 h
        }
        super.onDestroy()
    }
}
