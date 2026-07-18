# Architecture

HTTP Whisper is a single native Rust application with clear boundaries:

- `ui`: XP-style egui/eframe desktop shell, dialogs, table, inspectors, and worker events.
- `capture`: hudsucker HTTP/HTTPS and WebSocket proxy handlers on a Tokio worker runtime.
- `certificate`: rcgen local CA generation plus current-user Windows trust installation.
- `windows_proxy`: reversible WinINET and Firefox policy configuration, crash recovery, and current-user Windows startup registration.
- `model`: serializable request, response, exchange, WebSocket, and event types.
- `platform`: Windows loopback socket ownership and system-idle telemetry, with Linux-safe fallbacks.
- `threat`: stateful evidence scoring for HTTP and WebSocket traffic warnings.
- `rules`: host/path/method matching, automatic responses, and text rewriting.
- `storage`: content-addressed bodies and SQLite exchange persistence.
- `replay`: asynchronous request replay.
- `export`: redacted cURL, JSON, and HAR output.
- `filtering`: text, field, wildcard, and numeric session filters.

The UI remains on the main thread. Capture and replay run off the UI thread and publish typed events through channels. The UI-owned threat analyzer correlates those events over time, attaches serializable findings before persistence, and never blocks or modifies traffic. Windows proxy state is written to `proxy-restore.json` before mutation so a later capture can recover from an interrupted process.
