#!/bin/bash
# Phase 1a 单机联调 - A机（接收方）
# 用法：bash 1a-rx.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
export HOME="$DIR/homeA"   # 模拟"A设备"，身份隔离
mkdir -p "$HOME"
echo "=== A机身份 ==="
"$DIR/p2p-radio" keygen
echo ""
echo "=== 开始接收（不要关这个窗口）==="
"$DIR/p2p-radio" rx --bind 127.0.0.1:9002 --out "$DIR/out.wav"
