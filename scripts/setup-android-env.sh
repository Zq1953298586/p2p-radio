#!/bin/bash
# Phase 2a Android 交叉编译环境一键搭建
# 适用：网络能正常访问 dl.google.com 的机器（如用户桌面电脑开代理后，或海外 VPS）
# 用法：bash scripts/setup-android-env.sh
set -e

SDK_ROOT="$HOME/android-sdk"
NDK_VERSION="26.1.10909125"  # r26d

echo "=== 1/5 下载 Android cmdline-tools ==="
mkdir -p "$SDK_ROOT/cmdline-tools"
cd "$SDK_ROOT/cmdline-tools"
if [ ! -f tools.zip ]; then
  curl -L -o tools.zip \
    https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
fi
unzip -q -o tools.zip
rm -rf latest && mv cmdline-tools latest

echo "=== 2/5 安装 NDK + platform-tools ==="
export PATH="$SDK_ROOT/cmdline-tools/latest/bin:$PATH"
yes | sdkmanager --licenses >/dev/null 2>&1 || true
sdkmanager "ndk;$NDK_VERSION" "platform-tools" "platforms;android-34"
export ANDROID_NDK_HOME="$SDK_ROOT/ndk/$NDK_VERSION"
echo "NDK: $ANDROID_NDK_HOME"

echo "=== 3/5 Rust android target + cargo-ndk ==="
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk --locked || true

echo "=== 4/5 交叉编译 libopus（aarch64）==="
# p2p-audio 的 opus-sys 需要 pkg-config 能找到 android 版 libopus
OPUS_SRC=/tmp/opus-android
if [ ! -d "$OPUS_SRC" ]; then
  curl -L -o /tmp/opus.tar.gz https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz
  mkdir -p "$OPUS_SRC" && tar xzf /tmp/opus.tar.gz -C "$OPUS_SRC" --strip-components=1
fi
TC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
PREFIX="$HOME/android-deps/aarch64"
mkdir -p "$PREFIX"
cd "$OPUS_SRC"
make distclean >/dev/null 2>&1 || true
./configure --host=aarch64-linux-android \
  CC="$TC/bin/aarch64-linux-android21-clang" \
  --prefix="$PREFIX" --disable-shared --enable-static >/dev/null
make -j$(nproc) >/dev/null && make install >/dev/null
echo "libopus -> $PREFIX"

echo "=== 5/5 交叉编译 libp2p_jni.so ==="
cd ~/workspace/p2p-radio
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
cargo ndk -t aarch64-linux-android \
  --platform 21 \
  -o apps/android/app/src/main/jniLibs \
  build -p p2p-jni --release

echo "=== 完成 ==="
ls -la apps/android/app/src/main/jniLibs/arm64-v8a/
echo "下一步：用 Android Studio 打开 apps/android，连接真机，Run。"
