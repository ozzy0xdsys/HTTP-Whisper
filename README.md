# HTTP Whisper

HTTP Whisper is a native Windows and Linux HTTP, HTTPS, and WebSocket debugging proxy written in Rust. It uses a compact classic Windows XP-style desktop interface. Windows proxy, certificate, and Firefox setup is automatic while capture is active; Linux uses manual browser or desktop proxy setup.

## Features

- Native Rust HTTP/1.1 and HTTP/2 MITM proxy powered by `hudsucker`
- Automatic current-user Windows HTTP/HTTPS proxy configuration and restoration
- Crash-recovery snapshot for interrupted Windows proxy changes
- Automatic local CA generation and current-user Root store installation
- Automatic Firefox system-proxy policy and enterprise-root trust
- Optional current-user Windows startup registration and cross-platform launch-time auto-connect
- Local `mitm.it` certificate install page while capture is running
- Live HTTP requests and responses with raw Authorization headers visible in the inspector
- Live incoming and outgoing WebSocket messages
- Binary WebSocket decoding for UTF-8, gzip, zlib, raw deflate, and zlib-stream
- Stateful suspicious-traffic warnings with scored evidence and warning symbols
- Windows PID/executable attribution and system-idle correlation for proxied traffic
- Host/path/method automatic response rules with wildcard and `re:` regular-expression matching
- HTTP and decoded WebSocket text replacement rules with regex capture replacements
- Case-sensitive and case-insensitive response replacements
- Multiline Disallowed domains editor with wildcard and `re:` matching
- Filtering by text and fields such as method, host, path, status, duration, process, PID, content type, and risk
- Background request replay with captured replay results
- Pinning, URL copy, JSON/HAR/cURL export APIs, body storage, and SQLite session storage
- Redacted Authorization, cookie, and proxy credentials in exported data

## Windows Build

Install the stable Rust toolchain with the MSVC target, then run:

```powershell
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

Run the application:

```powershell
cargo run
```

Create an optimized executable:

```powershell
.\scripts\package.ps1
```

The packaged executable is written to `dist\HTTP-Whisper.exe`.

## Linux Build

Install Rust and the development libraries used by `eframe`, then run:

```bash
sudo apt-get install libxkbcommon-dev libwayland-dev libx11-dev libxi-dev \
  libxcursor-dev libxrandr-dev libxinerama-dev libgl1-mesa-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
./scripts/package-linux.sh
```

The packaged archive is written to `dist/HTTP-Whisper-linux-x86_64.tar.gz`. GitHub releases include this archive alongside `HTTP-Whisper.exe` and their SHA-256 files.

## Windows Capture

Click **Start Capture**. HTTP Whisper will:

1. Generate or load its local CA under `%LOCALAPPDATA%\HTTP Whisper\HTTP Whisper\certificates\rust-mitm`.
2. Trust the CA in the current user's Windows Root certificate store.
3. Save the current Windows proxy settings to a recovery snapshot.
4. Configure Windows HTTP/HTTPS traffic and Firefox system proxy mode for `127.0.0.1:8899`.
5. Restore the previous settings when capture stops or the application closes.

Firefox must be restarted after its enterprise policy is installed if it was already open. The automatic policy makes Firefox use the Windows system proxy and trust the Windows current-user Root store, so HSTS sites do not require or permit certificate exceptions. Some Windows accounts protect Firefox's policy registry; on those machines, the first capture shows a UAC prompt for this one-time Firefox integration step. Normal capture remains unelevated.

With capture running, `http://mitm.it/` is handled locally by HTTP Whisper and serves the current HTTP Whisper CA as DER or PEM. If Firefox shows a public proxy warning page, Firefox is not using HTTP Whisper yet; accept the UAC prompt if shown, fully close Firefox, reopen it, and try `http://mitm.it/` again.

## Linux Capture

Start capture, configure your browser or desktop HTTP and HTTPS proxy as `127.0.0.1:8899`, then open `http://mitm.it/` through that proxy and install the CA in the browser or Linux trust store. Linux desktop proxy settings, CA stores, and startup methods vary by distribution, so HTTP Whisper leaves those system changes manual and restores nothing it did not change.

## Startup

On Windows, open **File > Settings** to enable **Start HTTP Whisper** and **Auto-connect** independently. Start HTTP Whisper adds the current executable to the current user's Windows startup registry entry without requiring administrator rights. Auto-connect is available on both platforms and starts capture immediately whenever the app launches.

Enable both options to launch HTTP Whisper at Windows sign-in and begin capturing automatically. Moving the executable is supported: the startup path is refreshed whenever HTTP Whisper runs or Settings are saved.

## Automatic Responses

Open **Tools > Auto Responses**. A rule can match method, host, and path:

```text
Method: POST
Host: api.example.com
Path: /api/login
```

Method, host, and path support `*` wildcards. Prefix a value with `re:` to use a regular expression, such as `re:^api\d+\.example\.com$` or `re:^/users/\d+$`. Matching requests receive the configured local status, content type, and body without contacting the upstream server.

## Response Rewrites

Open **Tools > Response Rewrites**. For example:

```text
Host: api.example.com
Find: user123
Replace: admin123
```

Every rewrite requires a host. It is applied to every textual HTTP response and every decoded WebSocket text or supported compressed binary message for matching hosts, without method or path restrictions. Host supports `*` wildcards and `re:` notation. WebSocket binary messages are re-encoded in their original format after replacement.

Prefix Find with `re:` for regex replacement. Capture groups can be referenced from Replace with `$1` or `${name}`. Use an inline flag such as `re:(?i)user123` for case-insensitive matching. The filter bar and Hidden Hosts list accept the same `re:` notation.

## WebSockets

WebSocket messages appear as `WS` rows. `OUT` means client-to-server and `IN` means server-to-client. Selecting a row shows its URL, direction, opcode, decoded format, matched rewrite rule, byte size, and payload.

## Suspicious Traffic Warnings

Traffic warnings are enabled by default under **File > Settings**. Suspicious rows show a warning symbol in the Alert column; hover over it for evidence or select the row and open **Warnings**. Scores combine independent indicators, so an ordinary API request with a missing User-Agent remains a notice while stronger or repeated evidence becomes a visible warning.

Warning risk never changes row or column colors; suspicious-traffic warnings appear only as the triangle in the Alert column. Table coloring is configured independently under **File > Settings > Colors**. Rules can match a Host or Status code using exact text, `*` wildcards, or `re:` notation, then color either the entire row or only the matched Host/Status column. The default **HTTP status** preset colors `5xx` rows pale red, `4xx` Status cells pale yellow, and `3xx` Status cells pale blue. Text on colored cells automatically uses the exact inverse RGB color of its background. Every rule and color can be edited, added, disabled, or removed, and the normal blue selection color always takes priority.

The detector observes raw IP destinations, random-looking hosts, repeated first-seen destinations, fixed-interval HTTP and WebSocket beaconing, long-running WebSocket activity, C2-style paths, URL shorteners and commonly abused hosting/tunnel services, unusual processes and User-Agents, malformed headers, proxy and tunneling indicators, large uploads, encoded outbound messages, outbound traffic spikes, repeated failures followed by alternate destinations, TLS validation failures, and credentials, cookies, files, screenshots, or system information sent over plaintext HTTP. On Windows, HTTP Whisper resolves loopback connections to their PID and executable and can warn when suspicious outbound traffic occurs after the configured system-idle threshold.

Use filters such as `warning:true`, `risk:high`, `score:>=30`, `process:powershell.exe`, or `pid:1234` to isolate findings.

Warnings are heuristic evidence, not a malware verdict. HTTP Whisper can inspect only traffic routed through its proxy. It does not currently monitor system DNS queries, verify domain registration age, inspect traffic that bypasses the proxy, or expose successful upstream certificate metadata; certificate warnings are available when TLS validation fails. Process attribution and system-idle detection are currently Windows-only.

## Data And Security

On Windows, settings, certificates, bodies, and session metadata are stored under `%LOCALAPPDATA%\HTTP Whisper\HTTP Whisper`. On Linux they use the platform application-data directory, normally under `~/.local/share`. These files can contain sensitive traffic and credentials. Raw headers remain visible inside the local inspector, while exports redact Authorization, proxy authorization, cookies, and set-cookie values.

Only inspect systems and traffic that you own or are explicitly authorized to inspect.

## License

HTTP Whisper is licensed under the MIT License.
