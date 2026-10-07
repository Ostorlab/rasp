#!/usr/bin/env bash
# Prints the SHA-256 digest of a keystore's signing certificate, for --dart-define=RASP_CERT_SHA256.
# Usage: tool/cert_digest.sh [keystore] [alias] [storepass]
set -euo pipefail
keystore="${1:-$HOME/.android/debug.keystore}"
alias="${2:-androiddebugkey}"
storepass="${3:-android}"
keytool -list -v -keystore "$keystore" -alias "$alias" -storepass "$storepass" \
  | awk '/SHA256:/ {gsub(":", "", $2); print tolower($2)}'
