# Curtain ndk-build application settings for the hev-socks5-tunnel native engine.
# Device coverage matches the app's supported ABIs; armeabi-v7a / x86 are not
# built for the opt-in inspection VPN.

APP_OPTIM := release
APP_PLATFORM := android-35
APP_ABI := arm64-v8a x86_64
APP_CFLAGS := -O3
# 16 KB page-size compatibility (Android 15+ devices)
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
NDK_TOOLCHAIN_VERSION := clang
