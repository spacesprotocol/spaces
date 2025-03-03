#!/bin/bash
set -e

if [ -z "$CC" ]; then
    OS_TYPE=$(uname)
    if [ "$OS_TYPE" = "Darwin" ]; then
        if [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then
            CC="/opt/homebrew/opt/llvm/bin/clang"
        else
            echo "Homebrew LLVM clang not found at /opt/homebrew/opt/llvm/bin/clang."
            echo "Please specify the clang path using the CC environment variable."
            exit 1
        fi
    elif [ "$OS_TYPE" = "Linux" ]; then
        if command -v clang >/dev/null 2>&1; then
            CC=$(command -v clang)
        else
            echo "clang not found in your PATH."
            echo "Please specify the clang path using the CC environment variable."
            exit 1
        fi
    else
        echo "Unsupported OS: $OS_TYPE. Please specify the clang path using the CC environment variable."
        exit 1
    fi
fi

echo "Using CC: $CC"

CC="$CC" wasm-pack build --target nodejs --features wasm --no-default-features

NEW_NAME="@spacesprotocol/veritas"
PACKAGE_JSON="./pkg/package.json"

# Update the "name" and "license" fields in package.json using jq
if [ -f "$PACKAGE_JSON" ]; then
    jq --arg newName "$NEW_NAME" --arg license "Apache-2.0" '.name = $newName | .license = $license' "$PACKAGE_JSON" > "${PACKAGE_JSON}.tmp" && \
    mv "${PACKAGE_JSON}.tmp" "$PACKAGE_JSON"
else
    echo "Error: $PACKAGE_JSON not found."
    exit 1
fi
