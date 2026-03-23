import asyncio
import json
import ssl
import os
import time
from datetime import datetime
from pathlib import Path
import websockets
import bcrypt

HOST = "0.0.0.0"
PORT = 8765
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"
USERS_FILE = "users.json"
LOGS_DIR = "logs"

# Ensure logs directory exists
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

connected_users = {}

# --- SECURITY: Brute Force Protection ---
failed_logins = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300 # 5 minutes

def load_users():
    path = Path(USERS_FILE)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w', encoding="utf-8") as f:
        json.dump(users, f)

# --- SECURITY: Encrypted Storage (Hashing) ---
def register_user(username, plain_password):
    users = load_users()
    if username in users:
        return False, "Username already exists."
    
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed.decode('utf-8')
    save_users(users)
    return True, "Account created successfully!"

def authenticate_user(username, plain_password):
    current_time = time.time()
    
    # 1. Check Brute-Force
    if username in failed_logins:
        failed_logins[username] = [t for t in failed_logins[username] if current_time - t < LOCKOUT_TIME]
        if len(failed_logins[username]) >= MAX_ATTEMPTS:
            return False, "Account locked due to too many failed attempts. Try again in 5 minutes."

    users = load_users()
    if username not in users:
        return False, "Invalid username or password."

    # 2. Verify Hash
    stored_hash = users[username].encode('utf-8')
    try:
        if bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash):
            if username in failed_logins:
                del failed_logins[username]
            return True, "Login successful"
        else:
            raise ValueError("Invalid password")
    except ValueError:
        if username not in failed_logins:
            failed_logins[username] = []
        failed_logins[username].append(current_time)
        return False, "Invalid username or password."

# --- SECURITY: Session Logging ---
def log_chat_message(sender, receiver, encrypted_payload):
    users = sorted([sender, receiver])
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = os.path.join(LOGS_DIR, f"log_{users[0]}_{users[1]}_{date_str}.txt")
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # We log the raw payload (which is E2EE encrypted gibberish)
    with open(filename, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {sender}: {encrypted_payload}\n")

def iso_now():
    return datetime.utcnow().isoformat() + "Z"

async def safe_send(ws, payload):
    try:
        await ws.send(json.dumps(payload))
        return True
    except Exception:
        return False

async def broadcast_user_list():
    if not connected_users:
        return
    payload = {
        "type": "user_list",
        "users": sorted(list(connected_users.keys()))
    }
    dead_users = []
    for username, ws in connected_users.items():
        if not await safe_send(ws, payload):
            dead_users.append(username)
    for username in dead_users:
        connected_users.pop(username, None)

async def send_error(ws, message):
    await safe_send(ws, {"type": "error", "message": message})

async def handler(websocket):
    username = None
    try:
        async for raw_message in websocket:
            try:
                data = json.loads(raw_message)
            except json.JSONDecodeError:
                await send_error(websocket, "Invalid JSON.")
                continue

            msg_type = data.get("type")

            # --- REGISTRATION ---
            if msg_type == "register":
                req_user = str(data.get("username", "")).strip()
                req_pass = str(data.get("password", ""))
                if not req_user or not req_pass:
                    await send_error(websocket, "Missing credentials.")
                    continue
                
                success, msg = register_user(req_user, req_pass)
                if success:
                    await safe_send(websocket, {"type": "system", "message": msg})
                else:
                    await send_error(websocket, msg)
                continue

            # --- LOGIN ---
            if msg_type == "login":
                req_user = str(data.get("username", "")).strip()
                req_pass = str(data.get("password", ""))

                success, auth_msg = authenticate_user(req_user, req_pass)
                
                if not success:
                    await send_error(websocket, auth_msg)
                    await safe_send(websocket, {"type": "login_failed"})
                    continue

                old_ws = connected_users.get(req_user)
                if old_ws and old_ws != websocket:
                    try: await old_ws.close()
                    except: pass

                username = req_user
                connected_users[username] = websocket

                await safe_send(websocket, {"type": "login_success", "username": username})
                await broadcast_user_list()
                continue

            if not username:
                await send_error(websocket, "You must log in first.")
                continue

            # --- E2EE PUBLIC KEY EXCHANGE ---
            if msg_type == "public_key_exchange":
                target = data.get("to")
                target_ws = connected_users.get(target)
                if target_ws:
                    await safe_send(target_ws, {
                        "type": "public_key_exchange",
                        "from": username,
                        "key": data.get("key")
                    })
                continue
            
            # --- E2EE AES KEY EXCHANGE ---
            if msg_type == "aes_key_exchange":
                target = data.get("to")
                target_ws = connected_users.get(target)
                if target_ws:
                    await safe_send(target_ws, {
                        "type": "aes_key_exchange",
                        "from": username,
                        "encrypted_aes_key": data.get("encrypted_aes_key")
                    })
                continue

            # --- CHAT & FILE MESSAGES ---
            if msg_type in ["chat", "file"]:
                recipient = str(data.get("to", "")).strip()
                payload = data.get("payload") # This is now the E2EE encrypted string
                
                if not payload:
                    await send_error(websocket, "Payload cannot be empty.")
                    continue

                # Log the encrypted traffic securely
                log_chat_message(username, recipient, payload)

                msg_out = {
                    "type": msg_type,
                    "from": username,
                    "to": recipient,
                    "payload": payload,
                    "timestamp": iso_now()
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
        if username and connected_users.get(username) == websocket:
            connected_users.pop(username, None)
            await broadcast_user_list()


async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)

    print(f"SecureChat server running on wss://{HOST}:{PORT}")

    async with websockets.serve(
        handler,
        HOST,
        PORT,
        ssl=ssl_context,
        max_size=10_000_000 # Increased for encrypted file sharing
    ):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
