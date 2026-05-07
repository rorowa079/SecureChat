
import asyncio
import websockets
import json
import ssl
import database  # Imports the DB script we just created

import os
import logging
from logging.handlers import RotatingFileHandler

# --- Setup Secure, Rotating Logging ---
if not os.path.exists('logs'):
    os.makedirs('logs')

logger = logging.getLogger('SecureChat')
logger.setLevel(logging.INFO)

# Keeps 5 backup logs, max 5MB each.
handler = RotatingFileHandler('logs/server.log', maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
# --------------------------------------

# Server Configuration
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8765))   # Render injects PORT automatically
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"

# Dictionary to keep track of authenticated, active connections
# Format: { "username": websocket_object }
active_clients = {}

async def handle_authentication(websocket):
    """Handles the initial login or registration process in a loop."""
    
    # Get the client's IP address securely
    ip_address = websocket.remote_address[0]
    
    while True:
        try:
            message = await websocket.recv()
            data = json.loads(message)
            
            action = data.get("action")
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                await websocket.send(json.dumps({"status": "error", "message": "Missing credentials."}))
                continue 

            if action == "register":
                # SANITIZED LOGGING: Log attempt, NEVER log the password payload
                logger.info(f"Registration attempt for '{username}' from IP {ip_address}")
                success, msg = database.register_user(username, password)
                await websocket.send(json.dumps({"status": "success" if success else "error", "message": msg}))
                
            elif action == "login":
                # 1. CHECK RATE LIMIT FIRST
                if database.is_rate_limited(ip_address, username):
                    logger.warning(f"BLOCKED: Brute-force threshold met for IP: {ip_address}, Target User: {username}")
                    await websocket.send(json.dumps({"status": "error", "message": "Too many failed attempts. Try again in 5 minutes."}))
                    return None # Strictly drop the connection
                
                # 2. VERIFY CREDENTIALS
                if database.verify_user(username, password):
                    if username in active_clients:
                        await websocket.send(json.dumps({"status": "error", "message": "User already logged in."}))
                        return None
                        
                    active_clients[username] = websocket
                    database.clear_failed_logins(ip_address, username) # Clear the strike-count!
                    
                    logger.info(f"SUCCESS: '{username}' authenticated successfully from {ip_address}.")
                    await websocket.send(json.dumps({"status": "success", "message": "Authentication successful."}))
                    return username
                else:
                    # 3. RECORD FAILURE
                    database.record_failed_login(ip_address, username)
                    logger.warning(f"FAILED LOGIN: User '{username}' from IP {ip_address}")
                    await websocket.send(json.dumps({"status": "error", "message": "Invalid username or password."}))
                    
        except json.JSONDecodeError:
            logger.error(f"Malformed JSON received from {ip_address}")
            await websocket.send(json.dumps({"status": "error", "message": "Invalid data format."}))
            return None

async def broadcast_user_list():
    """Push the current online user list to every connected client."""
    msg = json.dumps({"type": "user_list", "users": list(active_clients.keys())})
    for ws in list(active_clients.values()):
        try:
            await ws.send(msg)
        except Exception:
            pass

async def chat_loop(websocket, username):
    await broadcast_user_list()
    try:
        async for raw in websocket:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"status": "error", "message": "Invalid data format."}))
                continue

            msg_type = data.get("type")

            if msg_type == "upload_key":
                pub = data.get("publicKey")
                if pub:
                    database.store_public_key(username, pub)
                    await websocket.send(json.dumps({"type": "key_uploaded", "status": "success"}))
                    logger.info(f"Public key stored for '{username}'")

            elif msg_type == "get_key":
                target = data.get("username")
                key = database.get_public_key(target) if target else None
                if key:
                    await websocket.send(json.dumps({"type": "public_key", "username": target, "publicKey": key}))
                else:
                    await websocket.send(json.dumps({"status": "error", "message": f"No public key for '{target}'."}))

            elif msg_type == "get_users":
                await websocket.send(json.dumps({"type": "user_list", "users": list(active_clients.keys())}))

            elif msg_type == "message":
                # Reject any message that still carries plaintext
                if data.get("content"):
                    logger.warning(f"SECURITY: '{username}' attempted to send unencrypted message. Rejected.")
                    await websocket.send(json.dumps({"status": "error", "message": "Unencrypted messages are not permitted."}))
                    continue

                to = data.get("to")
                ciphertext = data.get("ciphertext")
                encrypted_key = data.get("encryptedKey")
                iv = data.get("iv")

                content_type = data.get("contentType", "text")
                file_url = data.get("fileUrl")

                # text messages carry ciphertext; file messages carry a fileUrl from cloud storage
                if not all([to, encrypted_key, iv]):
                    await websocket.send(json.dumps({"status": "error", "message": "Encrypted message missing required fields."}))
                    continue
                if content_type == "text" and not ciphertext:
                    await websocket.send(json.dumps({"status": "error", "message": "Text message missing ciphertext."}))
                    continue
                if content_type == "file" and not file_url:
                    await websocket.send(json.dumps({"status": "error", "message": "File message missing fileUrl."}))
                    continue

                if to not in active_clients:
                    await websocket.send(json.dumps({"status": "error", "message": f"User '{to}' is not online."}))
                    continue

                await active_clients[to].send(json.dumps({
                    "type": "message",
                    "from": username,
                    "encryptedKey": encrypted_key,
                    "iv": iv,
                    "ciphertext": ciphertext,
                    "fileUrl": file_url,
                    "contentType": content_type,
                    "fileName": data.get("fileName")
                }))
                logger.debug(f"Encrypted message routed from '{username}' to '{to}'")

            elif msg_type == "ping":
                await websocket.send(json.dumps({"type": "pong"}))

            elif msg_type == "typing":
                to = data.get("to")
                if to and to in active_clients:
                    try:
                        await active_clients[to].send(json.dumps({"type": "typing", "from": username}))
                    except Exception:
                        pass

            else:
                await websocket.send(json.dumps({"status": "error", "message": "Unknown message type."}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username in active_clients:
            del active_clients[username]
            logger.info(f"DISCONNECT: '{username}' has left the chat.")
        await broadcast_user_list()

async def connection_handler(websocket, path=None):
    """Entry point for all new WebSocket connections."""
    logger.info(f"New connection initiated from {websocket.remote_address[0]}")

    username = await handle_authentication(websocket)
    if username:
        await chat_loop(websocket, username)

async def main():
    # Render terminates TLS at the edge and forwards plain ws:// internally,
    # so only load local self-signed certs when running outside Render.
    ssl_context = None
    if not os.environ.get("RENDER"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(CERT_FILE, keyfile=KEY_FILE)

    scheme = "wss" if ssl_context else "ws"
    logger.info(f"Starting SecureChat server on {scheme}://{HOST}:{PORT}...")

    async with websockets.serve(connection_handler, HOST, PORT, ssl=ssl_context):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())