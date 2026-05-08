# Changelog

## Phase 3 — Cloud Deployment (May 2026)

### Added
- Cloud-hosted deployment: WebSocket backend on Render, static frontend on Render, MySQL on Aiven, encrypted file storage on Firebase
- MySQL persistence layer (`database.py`) with `DBUtils.PooledDB` connection pooling (8 max / 2 cached)
- Encrypted message persistence to MySQL `messages` table — server stores ciphertext only
- TOFU (Trust On First Use) key fingerprint verification with MITM detection
- Persistent RSA keypair (localStorage as JWK) so users decrypt previously-received messages after re-login
- Bidirectional heartbeat: client pings every 30s, server responds with pong; pre-auth pings allowed
- Typing indicator: server-side relay between users
- Five-layer rate limiting: login (5/5min), registration (3/hour), message (10/5sec), connection-per-IP (10), frame size (64KB)
- Username regex validation, password length bounds (8-128), malformed-JSON rejection
- Auto-reconnect logic on dropped WebSocket connections (5-second retry)
- Client-side file validation: 10MB cap and 24-extension blocklist (.exe, .bat, .dll, etc.)
- Audit logging tables in MySQL: `login_attempts`, `registration_attempts`

### Changed
- Authentication backend migrated from `users.json` (file-based) to Aiven MySQL with bcrypt-hashed passwords
- TLS termination moved to Render's edge — server skips loading local cert when `RENDER` env var is set
- WebSocket URL detection: client uses `wss://localhost:8765` for local development, deployed Render URL otherwise
- All SQL queries use parameterized placeholders (`%s` for MySQL, `?` for SQLite)
- Plaintext message rejection: server refuses any message carrying a `content` field

### Removed
- Legacy file-based user storage (`users.json`)
- Local TLS helper script (`https_helper.py`) — Render's edge TLS replaces it
- Backup zip (`SecureChat-main.zip`) cluttering repo root

### Security
- E2E encryption: RSA-4096-OAEP + AES-GCM-256, all in browser
- Server never sees plaintext or private keys
- Public key directory persisted in MySQL `public_keys` table
- Audit logs sanitized — passwords never logged

## Phase 2 — Local LAN Build (April 2026)

### Added
- Initial WebSocket server on Python with bcrypt password hashing
- RSA-4096 + AES-GCM-256 end-to-end encryption client-side
- Login brute-force throttling
- File-based JSON user store and per-pair message logs
- Self-signed TLS for local-network use
- Emoji picker, typing-indicator scaffold, online-users list

## Phase 1 — Prototype (March 2026)

### Added
- Local-only chat prototype, plaintext over loopback
- Basic HTML UI with username + send box
- Initial project skeleton
