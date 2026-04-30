import asyncio
import websockets
import json
import ssl
import database  

HOST = "0.0.0.0"
PORT = 8765
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"

import asyncio
import websockets
import json
import ssl
import database  # Imports the DB script we just created

# Server Configuration
HOST = "0.0.0.0"
PORT = 8765
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"

# Dictionary to keep track of authenticated, active connections
# Format: { "username": websocket_object }
active_clients = {}

async def handle_authentication(websocket):
    """Handles the initial login or registration process."""
    try:
        # Wait for the first message from the client
        message = await websocket.recv()
        data = json.loads(message)
        
        action = data.get("action")
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            await websocket.send(json.dumps({"status": "error", "message": "Missing credentials."}))
            return None

        if action == "register":
            success, msg = database.register_user(username, password)
            await websocket.send(json.dumps({"status": "success" if success else "error", "message": msg}))
            return None # Client should initiate a 'login' action after registering
            
        elif action == "login":
            if database.verify_user(username, password):
                # Ensure user isn't already logged in elsewhere
                if username in active_clients:
                    await websocket.send(json.dumps({"status": "error", "message": "User already logged in."}))
                    return None
                    
                active_clients[username] = websocket
                await websocket.send(json.dumps({"status": "success", "message": "Authentication successful."}))
                print(f"[+] {username} authenticated successfully.")
                return username
            else:
                await websocket.send(json.dumps({"status": "error", "message": "Invalid username or password."}))
                return None
                
    except json.JSONDecodeError:
        await websocket.send(json.dumps({"status": "error", "message": "Invalid data format."}))
        return None

async def chat_loop(websocket, username):
    """Main loop for handling messages once a user is authenticated."""
    try:
        async for message in websocket:
            data = json.loads(message)
            target_user = data.get("to")
            content = data.get("content")
            
            # Simple routing logic
            if target_user in active_clients:
                target_ws = active_clients[target_user]
                await target_ws.send(json.dumps({
                    "from": username,
                    "content": content
                }))
            else:
                await websocket.send(json.dumps({"status": "error", "message": "User offline."}))
                
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        # Cleanup when client disconnects
        if username in active_clients:
            del active_clients[username]
            print(f"[-] {username} disconnected.")

async def connection_handler(websocket, path=None):
    """Entry point for all new WebSocket connections."""
    print(f"New connection from {websocket.remote_address}")
    
    # 1. Authenticate the user
    username = await handle_authentication(websocket)
    
    # 2. If authentication passed, enter the chat loop
    if username:
        await chat_loop(websocket, username)

async def main():
    print(f"Starting secure chat server on wss://{HOST}:{PORT}...")
    
    # Create the SSL context for WSS
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(CERT_FILE, keyfile=KEY_FILE)
    
    # Inject the SSL context into the serve function
    async with websockets.serve(connection_handler, HOST, PORT, ssl=ssl_context):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
