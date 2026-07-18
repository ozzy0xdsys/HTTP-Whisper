$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'

Push-Location $root
try {
    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    cargo build --locked --release
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $executable = Join-Path $dist 'HTTP-Whisper.exe'
    Copy-Item -Force (Join-Path $root 'target\release\http-whisper.exe') $executable
    $hash = (Get-FileHash $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  HTTP-Whisper.exe" | Set-Content -NoNewline (Join-Path $dist 'HTTP-Whisper.exe.sha256')
    Copy-Item -Force (Join-Path $root 'README.md') $dist
    Copy-Item -Force (Join-Path $root 'LICENSE') $dist
    Write-Host "Package ready: $dist"
} finally {
    Pop-Location
}
