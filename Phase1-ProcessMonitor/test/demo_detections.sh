#!/usr/bin/env bash
#
# demo_detections.sh — generate the two headline Phase 1 detections so you can
# watch the monitor react in real time.
#
# HOW TO USE (two terminals):
#   Terminal A:  cd Phase1-ProcessMonitor && make && \
#                sudo ./build/vanguard_monitor vgtarget
#   Terminal B:  cd Phase1-ProcessMonitor && ./test/demo_detections.sh
#
# This script is safe: it uses a harmless demo dylib (test/demo_inject.c) and a
# renamed copy of /bin/sleep as the "protected" process. It triggers:
#   1. TASK-PORT access to the protected process (the OpenProcess analogue)
#   2. a DYLD_INSERT_LIBRARIES injection at exec
# and you should see one ALERT line in Terminal A for each.
#
set -euo pipefail

TARGET_NAME="vgtarget"          # must match the arg you pass to the monitor
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
DYLIB="$TMP/vanguard_demo.dylib"
TARGET_BIN="$TMP/$TARGET_NAME"
CAT_COPY="$TMP/cat_copy"
TARGET_PID=""

cleanup() { [ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

[ "$(uname)" = "Darwin" ] || { echo "This demo only runs on macOS."; exit 1; }

echo "==> building the harmless demo dylib"
clang -dynamiclib -o "$DYLIB" "$HERE/demo_inject.c"

echo "==> starting a 'protected' target process named '$TARGET_NAME'"
# Copy /bin/sleep off the sealed system volume: the copy is no longer a
# platform binary, so (a) its path contains our target name and (b) SIP will
# not strip DYLD_* from non-system binaries in the injection step below.
cp /bin/sleep "$TARGET_BIN"
"$TARGET_BIN" 600 &
TARGET_PID=$!
echo "    target pid=$TARGET_PID  path=$TARGET_BIN"
echo "    monitor should be running as:  sudo ./build/vanguard_monitor $TARGET_NAME"
sleep 1

echo
echo "==> [1/2] TASK-PORT access on the protected process (vmmap -> task_for_pid)"
echo "    EXPECT in Terminal A:  ALERT GET_TASK ... target=$TARGET_PID(...$TARGET_NAME) <== PROTECTED PROCESS"
sudo /usr/bin/vmmap "$TARGET_PID" >/dev/null 2>&1 || true
sleep 1

echo
echo "==> [2/2] DYLD_INSERT_LIBRARIES injection at exec"
echo "    EXPECT in Terminal A:  ALERT EXEC+INJECT ... via=DYLD_INSERT_LIBRARIES=$DYLIB"
cp /bin/cat "$CAT_COPY"
DYLD_INSERT_LIBRARIES="$DYLIB" "$CAT_COPY" /etc/hostname >/dev/null 2>&1 || true
sleep 1

echo
echo "==> done. Two ALERT lines should now be visible in the monitor terminal."
echo "    (You'll also see routine INFO EXEC/FORK/EXIT lines from this script itself.)"
