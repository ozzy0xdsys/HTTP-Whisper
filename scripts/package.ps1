$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'

Push-Location $root
try {
    cargo test
    cargo clippy --all-targets -- -D warnings
    cargo build --release
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    Copy-Item -Force (Join-Path $root 'target\release\http-whisper.exe') (Join-Path $dist 'HTTP-Whisper.exe')
    Copy-Item -Force (Join-Path $root 'README.md') $dist
    Copy-Item -Force (Join-Path $root 'LICENSE') $dist
    Write-Host "Package ready: $dist"
} finally {
    Pop-Location
}
