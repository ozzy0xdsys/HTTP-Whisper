# Rule Format

Rules are stored in `settings.json` under the current user's HTTP Whisper application data directory.

Automatic response example:

```json
{
  "name": "Mock login",
  "enabled": true,
  "method": "POST",
  "host": "api.example.com",
  "path": "/api/login",
  "status_code": 200,
  "content_type": "application/json",
  "body": "{\"success\":true}"
}
```

Response rewrite example:

```json
{
  "host": "api.example.com",
  "find_text": "user123",
  "replace_text": "admin123"
}
```

Automatic-response host matching is case-insensitive and path matching is case-sensitive. An empty automatic-response method matches every method. Host and path fields support `*` wildcards.

Prefix a match value with `re:` to use a regular expression. This notation works in the filter bar, Hidden Hosts list, automatic-response Method, Host, and Path fields, and response-rewrite Host and Find fields. For example:

```text
Method: re:^(GET|POST)$
Host: re:^api\d+\.example\.com$
Path: re:^/users/\d+$
Find: re:"user_id":\s*(\d+)
Replace: "account_id": $1
```

Response rewrites require a host and apply to every textual HTTP response and decoded WebSocket message for matching hosts, without method or path restrictions. Host matching is case-insensitive and supports `*` wildcards. Replace supports `$1` and `${name}` capture references. Find matching is case-sensitive by default; use an inline flag such as `re:(?i)user123` for case-insensitive matching. Values without the `re:` prefix retain their existing wildcard or plain-text behavior.
