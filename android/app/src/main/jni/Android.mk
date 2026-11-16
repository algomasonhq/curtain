# Curtain ndk-build entry point. The hev-socks5-tunnel checkout (third-party,
# see THIRD_PARTY_NOTICES.md) is included as-is: its Android.mk resolves its own
# sources and third-part modules relative to its own directory ($(call my-dir)
# is evaluated while that makefile is being parsed), and its module guards make
# a nested include safe. The library (hev-socks5-tunnel) is built from
# jni/Application.mk settings: arm64-v8a + x86_64, APP_PLATFORM android-35,
# flexible page sizes for 16 KB compatibility.

TOP_PATH := $(call my-dir)

include $(TOP_PATH)/hev-socks5-tunnel/Android.mk
