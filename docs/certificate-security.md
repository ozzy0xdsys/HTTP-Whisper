# Certificate Security

HTTPS interception uses a local CA generated with `rcgen`. The certificate and private key stay in the current user's application data directory and are never uploaded.

Starting capture is the explicit action that may install the CA in the current-user Windows Root store, configure WinINET, and enable Firefox enterprise-root trust. HTTP Whisper restores proxy and Firefox policy values from the exact pre-capture snapshot when capture stops.

Captured traffic, certificate keys, bodies, settings, and the session database must be treated as sensitive. Do not commit or share generated runtime data.
