#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MBEDTLS_DIR="$SCRIPT_DIR/mbedtls-3.6.6"
CONFIG_H="$SCRIPT_DIR/3ds_mbedtls_config.h"
BUILD_DIR="$MBEDTLS_DIR/build3ds"
LIB_DIR="$SCRIPT_DIR/lib3/lib"
DEVKITARM="${DEVKITARM:-/opt/devkitpro/devkitARM}"
DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
PORTLIBS_LIB="$DEVKITPRO/portlibs/3ds/lib"
NO_INSTALL="${NO_INSTALL:-0}"

mkdir -p "$BUILD_DIR" "$LIB_DIR"

CC="$DEVKITARM/bin/arm-none-eabi-gcc"
AR="$DEVKITARM/bin/arm-none-eabi-ar"

CFLAGS=(
  -g -Og
  -mword-relocations
  -march=armv6k
  -mtune=mpcore
  -mfloat-abi=hard
  -mtp=soft
  -D__3DS__
  -DMBEDTLS_CONFIG_FILE="\"$CONFIG_H\""
  -I"$MBEDTLS_DIR/include"
  -I"$MBEDTLS_DIR/library"
  -I"$DEVKITPRO/libctru/include"
  -ffunction-sections
  -fdata-sections
  -w
)

echo "=== Compiling mbedTLS 3.6.6 for Nintendo 3DS ==="
ERRORS=0
OBJS=()

for src in "$MBEDTLS_DIR/library/"*.c; do
    base=$(basename "$src" .c)
    out="$BUILD_DIR/${base}.o"
    OBJS+=("$out")
    if "$CC" "${CFLAGS[@]}" -c "$src" -o "$out" 2>/tmp/mbed3ds_err.txt; then
        echo "  OK  $base"
    else
        echo "  FAIL $base"
        cat /tmp/mbed3ds_err.txt
        ERRORS=$((ERRORS + 1))
    fi
done

# Also compile the 3DS hardware entropy poll
HW_SRC="$SCRIPT_DIR/3ds_hw_poll.c"
HW_OUT="$BUILD_DIR/3ds_hw_poll.o"
OBJS+=("$HW_OUT")
if "$CC" "${CFLAGS[@]}" -c "$HW_SRC" -o "$HW_OUT" 2>/tmp/mbed3ds_err.txt; then
    echo "  OK  3ds_hw_poll"
else
    echo "  FAIL 3ds_hw_poll"
    cat /tmp/mbed3ds_err.txt
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "=== Archiving ==="
"$AR" rcs "$LIB_DIR/libmbedtls36.a" "${OBJS[@]}"
echo "Created: $LIB_DIR/libmbedtls36.a"

echo ""
if [ "$NO_INSTALL" = "1" ]; then
    echo "=== Skipping devkitPro install (NO_INSTALL=1) ==="
else
    echo "=== Installing to devkitpro portlibs ==="
    if cp "$LIB_DIR/libmbedtls36.a" "$PORTLIBS_LIB/" 2>/dev/null || sudo cp "$LIB_DIR/libmbedtls36.a" "$PORTLIBS_LIB/"; then
        echo "Installed: $PORTLIBS_LIB/libmbedtls36.a"
    else
        echo "WARNING: Could not install to portlibs — link step will fail unless you copy manually."
    fi
fi

echo ""
echo "=== Done. Total errors: $ERRORS ==="
exit $ERRORS
