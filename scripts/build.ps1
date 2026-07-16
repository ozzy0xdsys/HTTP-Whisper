param(
    [switch]$Release
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    cargo fmt --check
    cargo test
    cargo clippy --all-targets -- -D warnings
    if ($Release) {
        cargo build --release
    } else {
        cargo build
    }
} finally {
    Pop-Location
}
