# Windows Packaging

Run `scripts\package.ps1` from the repository root. It builds an optimized native executable and writes a portable package to `dist`.

The application stores upgrade-safe runtime data under `%LOCALAPPDATA%\HTTP Whisper\HTTP Whisper`. Uninstalling the portable executable does not remove captured data or the local CA from the current-user certificate store.
