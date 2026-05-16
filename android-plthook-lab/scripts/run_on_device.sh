#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ABI=${ABI:-x86_64}
REMOTE_DIR=${REMOTE_DIR:-/data/local/tmp/android-plthook-lab}

adb shell "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
adb push "$ROOT_DIR/libs/$ABI/libtarget.so" "$REMOTE_DIR/libtarget.so"
adb push "$ROOT_DIR/libs/$ABI/claimcheck" "$REMOTE_DIR/claimcheck"
adb shell "cd '$REMOTE_DIR' && chmod 755 ./claimcheck && LD_LIBRARY_PATH='$REMOTE_DIR' ./claimcheck"

