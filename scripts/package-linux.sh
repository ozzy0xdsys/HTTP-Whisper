#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/dist"
stage="$dist/HTTP-Whisper-linux-x86_64"
archive="$dist/HTTP-Whisper-linux-x86_64.tar.gz"

cd "$root"
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release

rm -rf "$stage"
mkdir -p "$stage"
install -m 755 target/release/http-whisper "$stage/HTTP-Whisper"
install -m 644 README.md LICENSE "$stage/"
tar -C "$dist" -czf "$archive" "$(basename "$stage")"
sha256sum "$archive" > "$archive.sha256"
printf 'Package ready: %s\n' "$archive"
