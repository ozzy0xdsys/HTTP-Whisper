# Investigation Workbench

The Investigation Workbench extends HTTP Whisper's Classic capture table without replacing it. Open it from **Tools > Investigation Workbench** or the toolbar.

## Analysis Flow

1. The capture worker attributes proxied traffic and applies the outbound Data Guard.
2. The UI analyzer scores suspicious behavior, compares the learned baseline, infers WebSocket structure, and updates host dossiers.
3. Serializable assessments stay attached to each session for filtering, reports, storage, and capsules.
4. Windows Bypass Radar independently polls established IPv4 TCP rows and the DNS client cache. It never intercepts or blocks those connections.

## Pages

### Timeline

Lists HTTP and WebSocket events with process name, PID, executable path, parent process, publisher, signature result, launch time, and executable SHA-256 when available. Provenance lookup is cached per PID so executable hashing and signature checks are not repeated for every request.

### Baseline

**Learn Normal** records process-to-host relationships plus methods, paths, content types, and WebSocket message types. Once learning is stopped, unseen behavior is attached to new sessions as a deviation. Baselines are stored in `baselines.json` and can be cleared from the page.

### Bypass

On Windows, the page observes established IPv4 TCP connections that are not the local proxy connection and correlates remote addresses with entries found in the DNS client cache. This provides useful evidence of proxy bypass, but it is not a packet capture engine and does not decode payloads, UDP, IPv6, or arbitrary tunneled traffic.

### WebSockets

The protocol tracker recognizes JSON, JSON-RPC, GraphQL, event streams, MessagePack-like payloads, and protobuf-like binary payloads. It extracts message type, correlation identifiers, sequence values, reply relationships, and observed schemas. A compiled protobuf `FileDescriptorSet` can be loaded to test named message decoders against the selected frame. Replay uses a separate connection and does not inherit application cookies or authentication automatically.

### Dossiers

Host dossiers aggregate first and last seen times, processes, PIDs, schemes, paths, statuses, byte counts, warning counts, TLS failures, and bypass observations. Optional public enrichment performs DNS, reverse-DNS, and RDAP lookups for the selected host and stores registry-provided network and registration context in `host-dossiers.json`.

### Capsules

Capsules bundle sessions, rules, the baseline, and host dossiers into one `.whispercapsule` file. Sanitization strips sensitive HTTP headers and bodies and removes raw WebSocket bytes. A passphrase enables AES-256-GCM authenticated encryption with a key derived through PBKDF2-HMAC-SHA256. Capsules are untrusted input and are decoded with size limits.

### Experiments

Record a before window, perform an application change, then record an after window. The report compares endpoint sets, request counts, headers, cookies, JSON field values, and WebSocket message types.

### Rules

Simulates every auto-response and response-rewrite rule against the selected session. Each condition is reported as pass or fail, matched rewrites include an effect preview, and historical hits are counted from captured sessions. The most recently saved rule change can be undone while the app remains open.

## Data Guard

The Data Guard examines outbound proxied HTTP headers and bodies and decoded WebSocket text. **Warn** records findings, **Redact** replaces detected secret values before forwarding, and **Block** returns a local HTTP 451 response or drops the outbound WebSocket frame. Trusted host entries support exact text, `*` wildcards, and `re:` regular expressions.

The guard reduces accidental exfiltration risk; it is not a replacement for endpoint security, data-loss prevention, or a host firewall.
