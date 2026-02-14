import asyncio, ssl, json, time
from collections import defaultdict, deque
import websockets

HOST, PORT = "0.0.0.0", 8765
CERT_FILE, KEY_FILE = "certs/cert.pem", "certs/key.pem"
USERS_FILE = "users.json"

MAX_MESSAGE_CHARS = 500
RATE_N, RATE_WINDOW = 8, 5  # 8 messages per 5 seconds

connected = set()
authed = {}  # websocket -> username
msg_times = defaultdict(lambda: deque())

def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

USERS = load_users()

def is_rate_limited(username: str) -> bool:
    now = time.time()
    dq = msg_times[username]
    while dq and dq[0] <= now - RATE_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_N:
        return True
    dq.append(now)
    return False

async def broadcast(obj, exclude=None):
    if not connected:
        return
    data = json.dumps(obj)
    await asyncio.gather(
        *[ws.send(data) for ws in list(connected) if ws != exclude],
        return_exceptions=True
    )

async def handler(ws):
    connected.add(ws)
    try:
        await ws.send(json.dumps({"type":"auth_required","message":"login first"}))

        async for raw in ws:
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send(json.dumps({"type":"error","message":"Send JSON only"}))
                continue

            t = payload.get("type")

            if t == "login":
                u = (payload.get("username") or "").strip()
                p = payload.get("password") or ""
                if u in USERS and USERS[u] == p:
                    authed[ws] = u
                    await ws.send(json.dumps({"type":"auth_ok","username":u}))
                    await broadcast({"type":"system","message":f"{u} joined"})
                else:
                    await ws.send(json.dumps({"type":"auth_error","message":"bad creds"}))

            elif t == "chat":
                u = authed.get(ws)
                if not u:
                    await ws.send(json.dumps({"type":"auth_required","message":"login first"}))
                    continue

                if is_rate_limited(u):
                    await ws.send(json.dumps({"type":"rate_limited","message":"slow down"}))
                    continue

                msg = (payload.get("message") or "").strip()
                if not msg:
                    continue
                if len(msg) > MAX_MESSAGE_CHARS:
                    await ws.send(json.dumps({"type":"error","message":"message too long"}))
                    continue

                await broadcast({"type":"chat","from":u,"message":msg})

            elif t == "file":
                u = authed.get(ws)
                if not u:
                    await ws.send(json.dumps({"type":"auth_required","message":"login first"}))
                    continue

                filename = payload.get("filename")
                data = payload.get("data")  # base64

                if not filename or not data:
                    await ws.send(json.dumps({"type":"error","message":"invalid file"}))
                    continue

                await broadcast({"type":"file","from":u,"filename":filename,"data":data})

            else:
                await ws.send(json.dumps({"type":"error","message":"unknown type"}))

    finally:
        connected.discard(ws)
        u = authed.pop(ws, None)
        if u:
            await broadcast({"type":"system","message":f"{u} left"})

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    print(f"Server on wss://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT, ssl=ctx):
        await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
