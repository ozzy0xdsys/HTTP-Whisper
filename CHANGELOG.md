# Changelog

## 0.7.3 - 2026-07-18

- Automatically render table text using the exact inverse RGB color of each configured background.
- Apply the same inverse text calculation to table-color previews in Settings.

## 0.7.2 - 2026-07-18

- Replace threat-driven row fills with independent Host and Status code table-color rules.
- Add whole-row and matched-column color targets with editable colors and wildcard or regex matching.
- Add a default HTTP status preset for `3xx`, `4xx`, and `5xx` responses.
- Show suspicious-traffic warnings only through the Alert column warning icon.

## 0.7.1 - 2026-07-18

- Add configurable row highlighting for suspicious and high-risk traffic.
- Add Balanced, Subtle, High contrast, and Custom highlight presets, with Balanced enabled by default.
- Keep selected rows visually distinct from risk highlighting.

## 0.7.0 - 2026-07-18

- Add stateful suspicious-traffic detection for HTTP, HTTPS, and WebSocket sessions.
- Add warning symbols, warning counts, risk scores, evidence tooltips, and a dedicated inspector view.
- Detect beaconing, raw IP destinations, random-looking domains, C2-style paths, unusual processes and User-Agents, malformed headers, plaintext secrets, large or encoded uploads, failover behavior, public tunnels, and traffic spikes.
- Resolve loopback proxy connections to their owning Windows PID and executable, and correlate suspicious outbound traffic with Windows system-idle time.
- Add `risk:`, `score:`, `warning:`, `process:`, and `pid:` session filters.

## 0.6.1 - 2026-07-18

- Remove the interactive breakpoint editor introduced in 0.6.0, including Forward, Drop, and header editing.
- Restore the simpler classic workflow from 0.5.1 while keeping all earlier capture and rewrite features.
- Add an official Linux x86_64 release archive and repeatable Linux packaging script.
- Keep automatic system proxy, Firefox policy, CA trust, and sign-in startup integration on Windows; Linux displays the manual setup path instead.

## 0.6.0 - 2026-07-17 (superseded)

- Introduced interactive traffic breakpoints with Forward, Drop, and advanced header editing.
- Superseded by 0.6.1, which removes this workflow and restores the simpler classic interface.

## 0.5.1 - 2026-07-17

- Remove the Refined XP interface and its style selector.
- Restore the compact Tahoma-based Classic XP interface as the only UI.
- Preserve all capture, rewrite, WebSocket, certificate, Firefox, and startup features.

## 0.5.0 - 2026-07-17

- Added an experimental Refined XP interface with an in-app Classic XP fallback.

## 0.4.1 - 2026-07-16

- Keep the Disallowed domains editor as a persistent multiline draft while Settings is open.
- Allow Enter and blank lines during editing, then normalize entries only when Settings is saved.

## 0.4.0 - 2026-07-16

- Add a Start with Windows setting backed by the current-user Run registry key.
- Add an Auto-connect setting that starts capture on the first UI frame after launch.
- Refresh the registered startup executable path whenever the app runs or Settings are saved.

## 0.3.2 - 2026-07-16

- Require a host match for every response rewrite.
- Keep response rewrites unrestricted by method and path.
- Support wildcard and `re:` host patterns in response rewrites.

## 0.3.1 - 2026-07-16

- Replace the expanding two-column rule layout with fixed-size, clipped panels.
- Make Response Rewrites global across all textual HTTP responses and decoded WebSocket messages.
- Reduce response-rewrite inputs to Find and Replace only.

## 0.3.0 - 2026-07-16

- Add opt-in `re:` regular expressions to filters, hidden hosts, and rule match fields.
- Add regex response rewrites with numbered and named capture replacements.
- Keep multiline Body, Find, Replace, and Hidden Hosts editors at fixed heights with vertical scrolling.
- Remove the old virtual environment, development caches, compatibility naming, and conversion backup note from the Rust workspace.

## 0.2.2

- Serve a local `http://mitm.it/` certificate install page from the Rust proxy.
- Add DER and PEM CA download endpoints for Firefox and Windows manual import.
- Make Certificate Manager repair Firefox proxy and enterprise-root integration too.
- Clarify Firefox setup and the public proxy warning case.

## 0.2.1

- Request one-time UAC approval when Windows protects Firefox's policy registry.
- Keep normal proxy capture and restoration in the current user context.
- Report the exact certificate, Firefox policy, proxy, or recovery operation on failure.

## 0.2.0 - 2026-07-12

- Rebuilt the application as a native Rust executable.
- Recreated the classic Windows XP interface with egui/eframe.
- Replaced the previous embedded proxy with a hudsucker HTTP/HTTPS/WebSocket MITM proxy.
- Added Rust-generated CA certificates and automatic current-user Windows trust.
- Added reversible WinINET and Firefox proxy/trust policy configuration with crash recovery.
- Preserved automatic responses, response rewrites, hidden hosts, raw Authorization display, body previews, filtering, pinning, and inspectors.
- Added incoming/outgoing live WebSocket rows and binary decoding for UTF-8, gzip, zlib, raw deflate, and zlib-stream.
- Applied response rewrite rules to decoded WebSocket messages and re-encoded modified frames.
- Implemented background replay, redacted exports, content-addressed body storage, and SQLite session persistence.
- Added local-only end-to-end proxy and rewrite tests.
