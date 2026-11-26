#!/usr/bin/env bash
# Tested this on my machine where afl-fuzz is not installed just point to binary. 
# -Q or qemu mode does not really matter because I've just recompiled with afl-clang-fast 

# afl binary path 
AFL_FUZZ="./AFLplusplus/afl-fuzz"

# target binary and arguments. 
TARGET_BINARY="./dataset/CVE-2021-46023/afl/mruby"
TARGET_ARGS=(@@)

INPUT_DIR="./seeds"
OUTPUT_DIR="${TARGET_BINARY##*/}_output"

# Fuzzing time limit (hours)
TIME_LIMIT=12

# Memory limit
MEM_LIMIT="none"

# Qemu mode for uninstrumented binaries, set to "-Q" if not insturmentd; nothing if instrumented
QEMU_MODE=""

###############################################################################
#TIME_LIMIT_SECONDS=$(( TIME_LIMIT * 3600 ))
TIME_LIMIT_SECONDS=30

if [[ ! -x "$AFL_FUZZ" ]]; then
  echo "[!] Error with afl-fuzz"
  exit 1
fi

if [[ ! -x "$TARGET_BINARY" ]]; then
  echo "[!] Error with target binary"
  exit 1
fi

if  [[ -z "$(ls -A "$INPUT_DIR" 2>/dev/null)" ]]; then
  echo "[!] Error with seed directory"
  exit 1
fi

mkdir "$OUTPUT_DIR"

CMD=("$AFL_FUZZ")
[[ -n "$QEMU_MODE" ]] && CMD+=("$QEMU_MODE")
CMD+=(-i "$INPUT_DIR" -o "$OUTPUT_DIR")
CMD+=(-V "$TIME_LIMIT_SECONDS")
CMD+=(-m "$MEM_LIMIT")
CMD+=(-- "$TARGET_BINARY")
CMD+=(-- "$TARGET_BINARY" "${TARGET_ARGS[@]}")

exec "${CMD[@]}"

