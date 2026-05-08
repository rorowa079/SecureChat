# SecureChat — Phase 3

A cloud-hosted, end-to-end encrypted real-time messaging app. Built for the Capstone Phase 3 deliverable: transitions SecureChat from a LAN-only build to a 24/7 internet-accessible service while preserving strong client-side cryptography.

## Live Demo

- **Frontend (web app):** https://securechat-web-csuf.onrender.com
- **WebSocket backend:** wss://securechat-4jmv.onrender.com
- **Demo video:** [link to your video — YouTube, Drive, etc.]

> If the backend appears slow on the first connection, Render's free tier may be cold-starting. UptimeRobot keeps it warm; subsequent connections are instant.

## What it does

- Real-time encrypted chat between any two registered users
- End-to-end encryption: every message and file is RSA-4096 + AES-GCM-256 encrypted in the browser before transmission
- Server only ever sees ciphertext — never plaintext, never private keys
- Encrypted file sharing via Firebase Storage (with size + type validation)
- Online/offline presence and typing indicators
- TOFU (Trust On First Use) key fingerprint verification with MITM detection
- Persistent keys across login sessions (decryptable message history)

## Architecture

| Layer | Service | Notes |
|---|---|---|
| Frontend | Render Static Site | Serves `index.html` over HTTPS |
| WebSocket Backend | Render Web Service (Python) | Async server, TLS terminated at Render's edge |
| Relational DB | Aiven MySQL | Users, audit logs, public keys, encrypted messages |
| File Storage | Firebase Storage | Encrypted blob uploads only |
| Uptime Monitor | UptimeRobot | Pings backend every 5 min to prevent cold starts |

## Security features

- **End-to-end encryption** — RSA-4096-OAEP for key exchange, AES-GCM-256 for message content. Server cannot decrypt any message.
- **Bcrypt password hashing** — auto-salted, work factor 12 default.
- **TOFU key verification** — peer public-key fingerprints stored client-side and compared on every message; mismatch refuses to send and warns the user.
- **Key persistence** — RSA keypair persisted to localStorage as JWK so users can decrypt previously-received messages after re-login.
- **SQL-injection safe** — every query uses driver-level parameterized statements.
- **Connection pooling** — `DBUtils.PooledDB` with 8 max / 2 cached connections.
- **Rate limiting** — five layers:
  - Login: 5 fails / 5 min per IP and per username (DB-backed)
  - Registration: 3 / hour per IP (DB-backed)
  - Message: 10 / 5 sec per user (in-memory sliding window)
  - Connection: 10 simultaneous WebSockets per IP
  - Frame size: 64 KB hard cap
- **Input validation** — username regex (`[a-zA-Z0-9_-]{1,32}`), password length 8-128, JSON malformed-input rejection.
- **Plaintext rejection** — server hard-rejects any message that includes a `content` field, blocking accidental encryption bypass.
- **File upload validation** — 10 MB size cap; 24 dangerous extensions blocked client-side (`.exe`, `.bat`, `.dll`, etc.).
- **Heartbeat** — bidirectional ping/pong every 30 seconds keeps WebSockets alive.
- **Auto-reconnect** — client retries dropped connections every 5 seconds.

## Wire protocol (summary)

| Direction | Type | Purpose |
|---|---|---|
| C → S | `{action: "register", username, password}` | Create account |
| C → S | `{action: "login", username, password}` | Authenticate |
| C → S | `{type: "upload_key", publicKey}` | Publish RSA public key (SPKI base64) |
| C → S | `{type: "get_key", username}` | Fetch peer's public key |
| C → S | `{type: "message", to, contentType, ciphertext, encryptedKey, iv, ...}` | Send encrypted text or file |
| C → S | `{type: "typing", to}` | Typing indicator |
| C → S | `{type: "ping"}` | Heartbeat |
| S → C | `{status: "success"\|"error", message}` | Response to register/login |
| S → C | `{type: "user_list", users}` | Online users |
| S → C | `{type: "public_key", username, publicKey}` | Key lookup result |
| S → C | `{type: "message", from, ...}` | Forwarded encrypted message |

## Local development

Requires Python 3.11+ and (optionally) a MySQL instance. Without `DB_MODE=mysql`, the server falls back to local SQLite (`securechat.db`) for testing.

```bash
git clone https://github.com/rorowa079/SecureChat.git
cd SecureChat
git checkout phase-3
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# For local-only test (uses SQLite, no SSL cert):
python server.py
```

Then open `index.html` in a browser — it auto-detects localhost and connects to `wss://localhost:8765`.

## Production deployment

The deployed instance runs on:

- **Render Web Service** — backend, with these env vars set:
  - `DB_MODE=mysql`
  - `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB` (from Aiven)
  - `RENDER` is auto-injected; the server uses it to skip loading local self-signed certs since Render terminates TLS at the edge.
- **Render Static Site** — serves `index.html`. Auto-redeploys on push to phase-3.
- **Aiven MySQL** — managed MySQL. CA cert (`ca.pem`) committed for SSL connection.
- **Firebase** — Storage bucket for encrypted file blobs. Web SDK config is public (controlled via Storage Rules).

## File structure

```
SecureChat/
├── index.html          # Frontend (HTML/CSS/JS, single-file)
├── server.py           # WebSocket backend (asyncio + websockets)
├── database.py         # MySQL/SQLite layer with connection pooling
├── ca.pem              # Aiven public CA cert
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── CHANGELOG.md        # Phase-by-phase change log
├── USER_GUIDE.md       # End-user instructions
└── .gitignore
```

## Acknowledgements

Built for [Course Name] Capstone Phase 3, [University Name].

## License

[Whatever you want — MIT, or just "Educational use only"]
