import asyncio
import json
import ssl
import os
import re
import time
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

import websockets

import database  # MySQL-backed user store (with connection pool)


# ── Configuration ──────────────────────────────────────────────────────────

HOST      = "0.0.0.0"
PORT      = int(os.environ.get("PORT", 8765))
CERT_FILE = "certs/cert.pem"
KEY_FILE  = "certs/key.pem"
LOGS_DIR  = "logs"

# Rate-limiting / throttle constants
MAX_ATTEMPTS           = 5      # failed logins or registrations before lockout
LOCKOUT_TIME           = 300    # lockout window (seconds)
MAX_CONNECTIONS_PER_IP = 10     # simultaneous WebSocket connections per IP
MSG_RATE_LIMIT         = 10     # max messages per MSG_RATE_WINDOW seconds
MSG_RATE_WINDOW        = 5      # sliding window size (seconds)
MAX_MSG_BYTES          = 64_000 # 64 KB hard cap per WebSocket frame

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')


# ── Rotating logger ────────────────────────────────────────────────────────

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

logger = logging.getLogger("SecureChat")
logger.setLevel(logging.INFO)
_log_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, "server.log"),
    maxBytes=5 * 1024 * 1024,
    backupCount=5,
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_log_handler)


# ── In-memory state ────────────────────────────────────────────────────────

connected_users   = {}  # username -> websocket
failed_logins     = {}  # username -> [epoch timestamps]
reg_attempts      = {}  # ip       -> [epoch timestamps]
connection_counts = {}  # ip       -> int


def _prune(store: dict, key: str, window: float) -> None:
    if key in store:
        cutoff = time.time() - window
        store[key] = [t for t in store[key] if t > cutoff]


# ── Auth (delegates to MySQL via database module) ──────────────────────────

def authenticate_user(username: str, plain_password: str):
    _prune(failed_logins, username, LOCKOUT_TIME)
    if len(failed_logins.get(username, [])) >= MAX_ATTEMPTS:
        return False, "Account locked due to too many failed attempts. Try again in 5 minutes."

    if database.verify_user(username, plain_password):
        failed_logins.pop(username, None)
        return True, "Login successful"

    failed_logins.setdefault(username, []).append(time.time())
    return False, "Invalid username or password."


# ── Encrypted-message audit log (server stores ONLY ciphertext) ────────────

def log_chat_message(sender: str, receiver: str, encrypted_payload: str) -> None:
    pair = sorted([sender, receiver])
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = os.path.join(LOGS_DIR, f"log_{pair[0]}_{pair[1]}_{date_str}.txt")
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {sender}: {encrypted_payload}\n")


def iso_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ── WebSocket helpers ──────────────────────────────────────────────────────

async def safe_send(ws, payload: dict) -> bool:
    try:
        await ws.send(json.dumps(payload))
        return True
    except Exception:
        return False


async def send_error(ws, message: str) -> None:
    await safe_send(ws, {"type": "error", "message": message})


async def broadcast_user_list() -> None:
    if not connected_users:
        return
    payload = {"type": "user_list", "users": sorted(connected_users.keys())}
    dead = []
    for uname, ws in connected_users.items():
        if not await safe_send(ws, payload):
            dead.append(uname)
    for uname in dead:
        connected_users.pop(uname, None)


# ── Main connection handler ────────────────────────────────────────────────

async def handler(websocket):
    ip = websocket.remote_address[0]

    # 1. Connection-level throttle
    connection_counts[ip] = connection_counts.get(ip, 0) + 1
    if connection_counts[ip] > MAX_CONNECTIONS_PER_IP:
        logger.warning(f"BLOCKED: too many connections from {ip}")
        connection_counts[ip] -= 1
        await websocket.close(1008, "Too many connections from your IP.")
        return

    username = None
    msg_timestamps = []

    try:
        async for raw_message in websocket:

            # 2. Hard size cap
            if len(raw_message) > MAX_MSG_BYTES:
                await send_error(websocket, "Message too large.")
                logger.warning(f"OVERSIZED frame ({len(raw_message)} bytes) from {ip}")
                continue

            try:
                data = json.loads(raw_message)
            except json.JSONDecodeError:
                await send_error(websocket, "Invalid JSON.")
                continue

            msg_type = data.get("type")

            # ── HEARTBEAT (allowed pre-auth so client can keep socket warm) ──
            if msg_type == "ping":
                await safe_send(websocket, {"type": "pong"})
                continue

            # ── REGISTRATION ──────────────────────────────────────────────
            if msg_type == "register":
                req_user = str(data.get("username", "")).strip()
                req_pass = str(data.get("password", ""))

                if not req_user or not req_pass:
                    await send_error(websocket, "Missing credentials.")
                    continue
                if not USERNAME_RE.match(req_user):
                    await send_error(websocket, "Username must be 1–32 characters: letters, numbers, hyphens, underscores only.")
                    continue
                if len(req_pass) < 8:
                    await send_error(websocket, "Password must be at least 8 characters.")
                    continue
                if len(req_pass) > 128:
                    await send_error(websocket, "Password too long.")
                    continue

                _prune(reg_attempts, ip, LOCKOUT_TIME)
                if len(reg_attempts.get(ip, [])) >= MAX_ATTEMPTS:
                    logger.warning(f"BLOCKED: registration flood from {ip}")
                    await send_error(websocket, "Too many registration attempts. Try again in 5 minutes.")
                    continue
                reg_attempts.setdefault(ip, []).append(time.time())

                logger.info(f"Registration attempt for '{req_user}' from {ip}")
                success, msg = database.register_user(req_user, req_pass)
                if success:
                    logger.info(f"Registered new user '{req_user}'")
                    await safe_send(websocket, {"type": "system", "message": msg})
                else:
                    await send_error(websocket, msg)
                continue

            # ── LOGIN ─────────────────────────────────────────────────────
            if msg_type == "login":
                req_user = str(data.get("username", "")).strip()
                req_pass = str(data.get("password", ""))

                if not req_user or not req_pass:
                    await send_error(websocket, "Missing credentials.")
                    continue
                if not USERNAME_RE.match(req_user):
                    await send_error(websocket, "Invalid username format.")
                    continue
                if len(req_pass) > 128:
                    await send_error(websocket, "Input too long.")
                    continue

                logger.info(f"Login attempt for '{req_user}' from {ip}")
                success, auth_msg = authenticate_user(req_user, req_pass)

                if not success:
                    logger.warning(f"FAILED LOGIN: '{req_user}' from {ip}")
                    await send_error(websocket, auth_msg)
                    await safe_send(websocket, {"type": "login_failed"})
                    continue

                # Kick any stale session for this user
                old_ws = connected_users.get(req_user)
                if old_ws and old_ws is not websocket:
                    try:
                        await old_ws.close()
                    except Exception:
                        pass

                username = req_user
                connected_users[username] = websocket
                logger.info(f"SUCCESS: '{username}' authenticated from {ip}")
                await safe_send(websocket, {"type": "login_success", "username": username})
                await broadcast_user_list()
                continue

            # ── Auth required for everything below ────────────────────────
            if not username:
                await send_error(websocket, "You must log in first.")
                continue

            # 3. Post-auth message rate limit (sliding window)
            now = time.time()
            msg_timestamps = [t for t in msg_timestamps if now - t < MSG_RATE_WINDOW]
            if len(msg_timestamps) >= MSG_RATE_LIMIT:
                await send_error(websocket, "Sending too fast. Please slow down.")
                continue
            msg_timestamps.append(now)

            # ── E2EE PUBLIC KEY EXCHANGE ──────────────────────────────────
            if msg_type == "public_key_exchange":
                target = data.get("to")
                target_ws = connected_users.get(target)
                if target_ws:
                    await safe_send(target_ws, {
                        "type": "public_key_exchange",
                        "from": username,
                        "key":  data.get("key"),
                    })
                continue

            # ── E2EE AES KEY EXCHANGE ─────────────────────────────────────
            if msg_type == "aes_key_exchange":
                target = data.get("to")
                target_ws = connected_users.get(target)
                if target_ws:
                    await safe_send(target_ws, {
                        "type":              "aes_key_exchange",
                        "from":              username,
                        "encrypted_aes_key": data.get("encrypted_aes_key"),
                    })
                continue

            # ── TYPING INDICATOR ──────────────────────────────────────────
            if msg_type == "typing":
                target = data.get("to")
                target_ws = connected_users.get(target)
                if target_ws:
                    await safe_send(target_ws, {"type": "typing", "from": username})
                continue

            # ── CHAT & FILE MESSAGES ──────────────────────────────────────
            if msg_type in ("chat", "file"):
                recipient = str(data.get("to", "")).strip()
                payload   = data.get("payload")

                if not payload:
                    await send_error(websocket, "Payload cannot be empty.")
                    continue

                # Server only ever sees ciphertext — we audit-log it as-is
                log_chat_message(username, recipient, payload)

                msg_out = {
                    "type":      msg_type,
                    "from":      username,
                    "to":        recipient,
                    "payload":   payload,
                    "timestamp": iso_now(),
                }

                recipient_ws = connected_users.get(recipient)
                if recipient_ws:
                    await safe_send(recipient_ws, msg_out)
                await safe_send(websocket, msg_out)
                continue

            await send_error(websocket, f"Unknown message type: {msg_type}")

    except websockets.ConnectionClosed:
        pass
    finally:
        connection_counts[ip] = max(0, connection_counts.get(ip, 1) - 1)
        if username and connected_users.get(username) is websocket:
            connected_users.pop(username, None)
            logger.info(f"DISCONNECT: '{username}' has left.")
            await broadcast_user_list()


# ── Entry point ────────────────────────────────────────────────────────────

async def main():
    # Render terminates TLS at the edge; only load self-signed certs locally.
    ssl_context = None
    if not os.environ.get("RENDER"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)

    scheme = "wss" if ssl_context else "ws"
    logger.info(f"SecureChat server starting on {scheme}://{HOST}:{PORT}")
    print(f"SecureChat server running on {scheme}://{HOST}:{PORT}")

    async with websockets.serve(
        handler,
        HOST,
        PORT,
        ssl=ssl_context,
        max_size=MAX_MSG_BYTES,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
