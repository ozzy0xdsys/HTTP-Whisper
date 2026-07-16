# HTTP Whisper

HTTP Whisper is a native Windows HTTP, HTTPS, and WebSocket debugging proxy written in Rust. It uses a classic Windows XP-style desktop interface and automatically prepares Windows and Firefox for local interception while capture is active.

## Features

- Native Rust HTTP/1.1 and HTTP/2 MITM proxy powered by `hudsucker`
- Automatic current-user Windows HTTP/HTTPS proxy configuration and restoration
- Crash-recovery snapshot for interrupted Windows proxy changes
- Automatic local CA generation and current-user Root store installation
- Automatic Firefox system-proxy policy and enterprise-root trust
- Optional current-user Windows startup registration and launch-time auto-connect
- Local `mitm.it` certificate install page while capture is running
- Live HTTP requests and responses with raw Authorization headers visible in the inspector
- Live incoming and outgoing WebSocket messages
- Binary WebSocket decoding for UTF-8, gzip, zlib, raw deflate, and zlib-stream
- Host/path/method automatic response rules with wildcard and `re:` regular-expression matching
- HTTP and decoded WebSocket text replacement rules with regex capture replacements
- Case-sensitive and case-insensitive response replacements
- Default hiding of `detectportal.firefox.com`
- Multiline Disallowed domains editor with wildcard and `re:` matching
- Filtering by text and fields such as method, host, path, status, duration, process, and content type
- Background request replay with captured replay results
- Pinning, URL copy, JSON/HAR/cURL export APIs, body storage, and SQLite session storage
- Redacted Authorization, cookie, and proxy credentials in exported data

## Build

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

## Capture

Click **Start Capture**. HTTP Whisper will:

1. Generate or load its local CA under `%LOCALAPPDATA%\HTTP Whisper\HTTP Whisper\certificates\rust-mitm`.
2. Trust the CA in the current user's Windows Root certificate store.
3. Save the current Windows proxy settings to a recovery snapshot.
4. Configure Windows HTTP/HTTPS traffic and Firefox system proxy mode for `127.0.0.1:8899`.
5. Restore the previous settings when capture stops or the application closes.

Firefox must be restarted after its enterprise policy is installed if it was already open. The automatic policy makes Firefox use the Windows system proxy and trust the Windows current-user Root store, so HSTS sites do not require or permit certificate exceptions. Some Windows accounts protect Firefox's policy registry; on those machines, the first capture shows a UAC prompt for this one-time Firefox integration step. Normal capture remains unelevated.

With capture running, `http://mitm.it/` is handled locally by HTTP Whisper and serves the current HTTP Whisper CA as DER or PEM. If Firefox shows a public proxy warning page, Firefox is not using HTTP Whisper yet; accept the UAC prompt if shown, fully close Firefox, reopen it, and try `http://mitm.it/` again.

## Startup

Open **Tools > Settings** to enable **Start HTTP Whisper** and **Auto-connect** independently. Start HTTP Whisper adds the current executable to the current user's Windows startup registry entry without requiring administrator rights. Auto-connect starts capture immediately whenever the app launches, using the configured host, port, certificate, Firefox, and Windows proxy settings.

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

## Data And Security

Settings, certificates, bodies, and session metadata are stored under `%LOCALAPPDATA%\HTTP Whisper\HTTP Whisper`. These files can contain sensitive traffic and credentials. Raw headers remain visible inside the local inspector, while exports redact Authorization, proxy authorization, cookies, and set-cookie values.

Only inspect systems and traffic that you own or are explicitly authorized to inspect.

## License

HTTP Whisper is licensed under the MIT License.
