#!/bin/zsh

set -e

cd "$(dirname "$0")/.."

echo "Paste vless:// link and press Enter."
echo "If you already copied the link, press Enter on an empty line to use clipboard."
read "VLESS_LINK?> "

if [ -z "$VLESS_LINK" ]; then
  VLESS_LINK="$(/usr/bin/pbpaste)"
fi

node scripts/macos-vless-diagnose.mjs "$VLESS_LINK" "$@"

echo ""
echo "Done. Press Enter to close."
read
