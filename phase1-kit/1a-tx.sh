#!/bin/bash
# Phase 1a 单机联调 - B机（发送方）
# 用法：先跑 1a-rx.sh，另开一个终端再跑这个
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
export HOME="$DIR/homeB"   # 模拟"B设备"，身份隔离
mkdir -p "$HOME"
echo "=== B机身份 ==="
"$DIR/p2p-radio" keygen
echo ""
echo "=== 开始发送 ==="
"$DIR/p2p-radio" tx --peer 127.0.0.1:9002 --in "$DIR/test-voice.wav"
