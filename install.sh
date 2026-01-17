#!/bin/bash
# Hardstop installer for macOS/Linux

DEST="$HOME/.claude/plugins/hardstop"
SOURCE="$(cd "$(dirname "$0")" && pwd)"

echo "Installing to: $DEST"

mkdir -p "$DEST"

# Copy files, excluding dev/build artifacts
rsync -av --exclude='.git' --exclude='.venv' --exclude='.pytest_cache' --exclude='__pycache__' --exclude='install.sh' --exclude='install.ps1' "$SOURCE/" "$DEST/"

echo "Hardstop plugin installed successfully!"
echo ""
echo "Verify with: /hs help"
