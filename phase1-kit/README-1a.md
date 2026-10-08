# Phase 1a 单机联调（今晚就能跑，不用等第二台设备）

**要什么**：你的台式机，WSL2 里一个终端开两个窗口。就这么多。

**为什么先做 1a**：开发机沙箱禁 UDP，真机 socket 层还没验证过。
1a 用你电脑的真实网络栈跑一遍握手+语音——这是 Phase 1 地基的一半，
而且今晚就能做，不用等第二台设备。

---

## 步骤

### 1. 把 phase1-kit 整个文件夹拷进 WSL2

比如放到 `~/phase1-kit`，然后：

```bash
cd ~/phase1-kit && chmod +x p2p-radio 1a-rx.sh 1a-tx.sh
# 如果没有 test-voice.wav（比如从 git 仓库 clone 的），先生成：
# python3 make-test-voice.py
```

### 2. 开两个终端窗口，都 cd 到 phase1-kit

### 3. 窗口一（A机/接收方）：

```bash
bash 1a-rx.sh
```

会先显示 A 机的指纹（形如 `A571 86C1 4966 F3DD`），**抄下来**，
然后停在"开始接收"别动。

### 4. 窗口二（B机/发送方）：

```bash
bash 1a-tx.sh
```

会先显示 B 机的指纹，**抄下来**，然后开始发送 5 秒测试语音。

### 5. 核对指纹（关键！）

- 窗口一显示的 `peer fingerprint` == 窗口二抄的 B 机指纹？
- 窗口二显示的 `peer fingerprint` == 窗口一抄的 A 机指纹？

都对 → 说明握手和密钥协商在真实 socket 上跑通了。
不对 → 停下来，把两边的完整输出发我。

### 6. 听 out.wav

B 机发完后，文件夹里会出现 `out.wav`，戴耳机听：
- 前 2 秒应该是音调升高的"哔——"声
- 中间 1 秒静音
- 后 2 秒是和弦音

能听清这个结构 → 语音链路通了。告诉我体感（一句话就行）。

---

## 如果报错

| 现象 | 怎么办 |
|---|---|
| `handshake timeout` | 把两个窗口的完整输出发我 |
| `Permission denied` | 先跑 `chmod +x p2p-radio 1a-rx.sh 1a-tx.sh` |
| 其他任何报错 | 原样截图/复制发我，不要自己改 |

---

## 做完之后

把三样东西发我：①两边的指纹是否对上 ②out.wav 能不能听清 ③体感。
三样都 OK → Phase 1a 验收通过，我们进 Phase 1b（两台真机同 WiFi）。
