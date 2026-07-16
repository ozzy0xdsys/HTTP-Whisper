# Contributing

Install stable Rust with the `x86_64-pc-windows-msvc` target.

```powershell
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Keep proxy and replay tests local and deterministic. Do not contact public services from tests. Never commit generated certificates, private keys, captures, HAR files, session databases, or real credentials.
