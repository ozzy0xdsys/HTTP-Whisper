# Architecture

HTTP Whisper is a single native Rust application with clear boundaries:

- `ui`: XP-style egui/eframe desktop shell, dialogs, table, inspectors, and worker events.
- `capture`: hudsucker HTTP/HTTPS and WebSocket proxy handlers on a Tokio worker runtime.
- `certificate`: rcgen local CA generation plus current-user Windows trust installation.
- `windows_proxy`: reversible WinINET and Firefox policy configuration, crash recovery, and current-user Windows startup registration.
- `model`: serializable request, response, exchange, WebSocket, and event types.
- `platform`: Windows loopback socket ownership and system-idle telemetry, with Linux-safe fallbacks.
- `threat`: stateful evidence scoring for HTTP and WebSocket traffic warnings.
- `baseline`: persistent per-process behavior learning and deviation assessment.
- `guard`: outbound secret detection plus warn, redact, and block enforcement.
- `protocol`: WebSocket protocol inference, correlation, schemas, and protobuf descriptors.
- `dossier`: durable host observations and optional DNS/RDAP enrichment.
- `investigation`: human-readable session explanations and process timelines.
- `capsule`: sanitized gzip capture bundles with optional authenticated encryption.
- `experiment`: semantic comparison of before and after capture windows.
- `rule_debugger`: rule condition simulation, effect previews, and hit counts.
- `websocket_replay`: isolated replay connections for captured WebSocket frames.
- `rules`: host/path/method matching, automatic responses, and text rewriting.
- `storage`: content-addressed bodies and SQLite exchange persistence.
- `replay`: asynchronous request replay.
- `export`: redacted cURL, JSON, and HAR output.
- `filtering`: text, field, wildcard, and numeric session filters.

The UI remains on the main thread. Capture, replay, public host lookups, and bypass polling run off the UI thread and publish typed events through channels. The UI-owned analyzers correlate events, infer WebSocket structure, compare learned behavior, update host dossiers, and attach serializable evidence before persistence. The Data Guard is intentionally enforced in the capture worker before outbound traffic is forwarded; threat scoring itself remains observational. Windows proxy state is written to `proxy-restore.json` before mutation so a later capture can recover from an interrupted process.

See [Investigation Workbench](investigation-workbench.md) for feature boundaries and persisted data.
