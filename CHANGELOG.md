# Changelog

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
