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

import database  # MySQL-backed user store with connection pool


# ── Configuration ──────────────────────────────────────────────────────────

HOST      = "0.0.0.0"
PORT      = int(os.environ.get("PORT", 8765))
CERT_FILE = "certs/cert.pem"
KEY_FILE  = "certs/key.pem"
LOGS_DIR  = "logs"

MAX_CONNECTIONS_PER_IP = 10
MSG_RATE_LIMIT         = 10
MSG_RATE_WINDOW        = 5
MAX_MSG_BYTES          = 64_000

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')


# ── Logger ─────────────────────────────────────────────────────────────────

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

logger = logging.getLogger("SecureChat")
logger.setLevel(logging.INFO)
_log_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, "server.log"),
    maxBytes=5 * 1024 * 1024, backupCount=5,
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_log_handler)


# ── In-memory state ────────────────────────────────────────────────────────

active_clients    = {}   # username -> websocket
connection_counts = {}   # ip -> int


async def safe_send(ws, payload: dict) -> bool:
    try:
        await ws.send(json.dumps(payload))
        return True
    except Exception:
        return False


async def broadcast_user_list() -> None:
    payload = {"type": "user_list", "users": list(active_clients.keys())}
    dead = []
    for uname, ws in list(active_clients.items()):
        if not await safe_send(ws, payload):
            dead.append(uname)
    for uname in dead:
        active_clients.pop(uname, None)


def log_chat_message(sender: str, receiver: str, ciphertext: str) -> None:
    """Audit log of ciphertext only — server never sees plaintext."""
    pair = sorted([sender, receiver])
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = os.path.join(LOGS_DIR, f"log_{pair[0]}_{pair[1]}_{date_str}.txt")
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {sender}: {ciphertext}\n")


# ── Authentication loop ────────────────────────────────────────────────────

async def handle_authentication(websocket):
    """Loops until the client either registers + then logs in, or disconnects."""
    ip = websocket.remote_address[0]

    while True:
        try:
            raw = await websocket.recv()
        except websockets.ConnectionClosed:
            return None

        if len(raw) > MAX_MSG_BYTES:
            await safe_send(websocket, {"status": "error", "message": "Message too large."})
            continue

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            await safe_send(websocket, {"status": "error", "message": "Invalid data format."})
            continue

        # Heartbeat is allowed during auth so the connection stays warm
        if data.get("type") == "ping":
            await safe_send(websocket, {"type": "pong"})
            continue

        action   = data.get("action")
        username = data.get("username")
        password = data.get("password")

        if action not in ("register", "login"):
            await safe_send(websocket, {"status": "error", "message": "Please log in or register."})
            continue

        if not username or not password:
            await safe_send(websocket, {"status": "error", "message": "Missing credentials."})
            continue

        username = str(username).strip()
        password = str(password)

        if not USERNAME_RE.match(username):
            await safe_send(websocket, {"status": "error",
                "message": "Username must be 1–32 chars: letters, numbers, hyphens, underscores."})
            continue

        if len(password) > 128:
            await safe_send(websocket, {"status": "error", "message": "Input too long."})
            continue

        # ── REGISTER ──
        if action == "register":
            if len(password) < 8:
                await safe_send(websocket, {"status": "error",
                    "message": "Password must be at least 8 characters."})
                continue

            if database.is_registration_rate_limited(ip):
                logger.warning(f"BLOCKED: registration flood from {ip}")
                await safe_send(websocket, {"status": "error",
                    "message": "Too many registration attempts. Try again in an hour."})
                continue
            database.record_registration_attempt(ip)

            logger.info(f"Registration attempt for '{username}' from {ip}")
            success, msg = database.register_user(username, password)
            await safe_send(websocket, {
                "status":  "success" if success else "error",
                "message": msg,
            })
            continue

        # ── LOGIN ──
        if database.is_rate_limited(ip, username):
            logger.warning(f"BLOCKED: brute-force from {ip} on '{username}'")
            await safe_send(websocket, {"status": "error",
                "message": "Too many failed attempts. Try again in 5 minutes."})
            return None  # drop the connection

        if database.verify_user(username, password):
            if username in active_clients:
                await safe_send(websocket, {"status": "error", "message": "User already logged in."})
                return None

            active_clients[username] = websocket
            database.clear_failed_logins(ip, username)
            logger.info(f"SUCCESS: '{username}' authenticated from {ip}")
            await safe_send(websocket, {"status": "success", "message": "Authentication successful."})
            return username

        database.record_failed_login(ip, username)
        logger.warning(f"FAILED LOGIN: '{username}' from {ip}")
        await safe_send(websocket, {"status": "error", "message": "Invalid username or password."})


# ── Post-auth chat loop ────────────────────────────────────────────────────

async def chat_loop(websocket, username):
    msg_timestamps = []
    await broadcast_user_list()

    try:
        async for raw in websocket:
            if len(raw) > MAX_MSG_BYTES:
                await safe_send(websocket, {"status": "error", "message": "Message too large."})
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await safe_send(websocket, {"status": "error", "message": "Invalid data format."})
                continue

            msg_type = data.get("type")

            # ── Heartbeat ──
            if msg_type == "ping":
                await safe_send(websocket, {"type": "pong"})
                continue

            # ── Per-user sliding-window message rate limit ──
            now = time.time()
            msg_timestamps = [t for t in msg_timestamps if now - t < MSG_RATE_WINDOW]
            if len(msg_timestamps) >= MSG_RATE_LIMIT:
                await safe_send(websocket, {"status": "error",
                    "message": "Sending too fast — slow down."})
                continue
            msg_timestamps.append(now)

            # ── Public key upload ──
            if msg_type == "upload_key":
                pub = data.get("publicKey")
                if pub:
                    database.store_public_key(username, pub)
                    await safe_send(websocket, {"type": "key_uploaded", "status": "success"})
                    logger.info(f"Public key stored for '{username}'")
                continue

            # ── Public key fetch ──
            if msg_type == "get_key":
                target = data.get("username")
                key = database.get_public_key(target) if target else None
                if key:
                    await safe_send(websocket, {
                        "type": "public_key", "username": target, "publicKey": key,
                    })
                else:
                    await safe_send(websocket, {"status": "error",
                        "message": f"No public key for '{target}'."})
                continue

            # ── Online users list (explicit refresh) ──
            if msg_type == "get_users":
                await safe_send(websocket, {
                    "type": "user_list", "users": list(active_clients.keys()),
                })
                continue

            # ── Typing indicator ──
            if msg_type == "typing":
                to = data.get("to")
                if to and to in active_clients:
                    await safe_send(active_clients[to], {"type": "typing", "from": username})
                continue

            # ── Encrypted message (text or file) ──
            if msg_type == "message":
                # Reject any plaintext attempt
                if data.get("content"):
                    logger.warning(f"SECURITY: '{username}' sent plaintext — rejected.")
                    await safe_send(websocket, {"status": "error",
                        "message": "Unencrypted messages are not permitted."})
                    continue

                to            = data.get("to")
                ciphertext    = data.get("ciphertext")
                encrypted_key = data.get("encryptedKey")
                iv            = data.get("iv")
                content_type  = data.get("contentType", "text")
                file_url      = data.get("fileUrl")
                file_name     = data.get("fileName")

                if not all([to, encrypted_key, iv]):
                    await safe_send(websocket, {"status": "error",
                        "message": "Encrypted message missing required fields."})
                    continue
                if content_type == "text" and not ciphertext:
                    await safe_send(websocket, {"status": "error",
                        "message": "Text message missing ciphertext."})
                    continue
                if content_type == "file" and not (ciphertext or file_url):
                    await safe_send(websocket, {"status": "error",
                        "message": "File message missing payload."})
                    continue

                if to not in active_clients:
                    await safe_send(websocket, {"status": "error",
                        "message": f"User '{to}' is not online."})
                    continue

                # Audit-log ciphertext only (plaintext never reaches the server)
                log_chat_message(username, to, ciphertext or file_url)

                await safe_send(active_clients[to], {
                    "type":         "message",
                    "from":         username,
                    "encryptedKey": encrypted_key,
                    "iv":           iv,
                    "ciphertext":   ciphertext,
                    "fileUrl":      file_url,
                    "contentType":  content_type,
                    "fileName":     file_name,
                })
                continue

            await safe_send(websocket, {"status": "error",
                "message": f"Unknown message type: {msg_type}"})

    except websockets.ConnectionClosed:
        pass
    finally:
        if active_clients.get(username) is websocket:
            active_clients.pop(username, None)
            logger.info(f"DISCONNECT: '{username}' has left.")
            await broadcast_user_list()


# ── Top-level connection handler ───────────────────────────────────────────

async def connection_handler(websocket, path=None):
    ip = websocket.remote_address[0]

    connection_counts[ip] = connection_counts.get(ip, 0) + 1
    if connection_counts[ip] > MAX_CONNECTIONS_PER_IP:
        logger.warning(f"BLOCKED: too many connections from {ip}")
        connection_counts[ip] -= 1
        await websocket.close(1008, "Too many connections from your IP.")
        return

    logger.info(f"New connection from {ip}")
    try:
        username = await handle_authentication(websocket)
        if username:
            await chat_loop(websocket, username)
    finally:
        connection_counts[ip] = max(0, connection_counts.get(ip, 1) - 1)


# ── Entry point ────────────────────────────────────────────────────────────

async def main():
    ssl_context = None
    if not os.environ.get("RENDER"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)

    scheme = "wss" if ssl_context else "ws"
    logger.info(f"SecureChat server starting on {scheme}://{HOST}:{PORT}")
    print(f"SecureChat server running on {scheme}://{HOST}:{PORT}")

    async with websockets.serve(
        connection_handler, HOST, PORT,
        ssl=ssl_context, max_size=MAX_MSG_BYTES,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
