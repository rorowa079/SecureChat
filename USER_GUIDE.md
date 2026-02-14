# SecureChat User Guide

## 1. Overview

SecureChat is a WebSocket-based real-time messaging application.
It consists of:

- A WebSocket Server
- A Browser-based Client
- Multiple clients can connect simultaneously and exchange messages in real time.

---

## 2. System Requirements

- Ubuntu 20.04+ (or compatible Linux)
- Python 3.x (if Python backend)
  OR
- Node.js 18+ (if Node backend)
- Modern web browser (Chrome, Firefox, Edge)

---

## 3. Installation

### Step 1 — Clone the Repository

git clone https://github.com/rorowa079/SecureChat.git
cd SecureChat

---

## 4. Running the Server

### If Python:

Install dependencies:

pip install -r requirements.txt

Start server:

python server.py


### If Node.js:

Install dependencies:

npm install

Start server:

npm start


You should see:

"WebSocket server running on port XXXX"

---

## 5. Running the Client

If the client is browser-based:

Option 1 — Open directly:

Open `index.html` in your browser.

Option 2 — If served through backend:

Navigate to:

http://localhost:PORT

---

## 6. How to Use the Application

1. Start the server.
2. Open two browser windows.
   - One normal window
   - One incognito/private window
3. Connect both clients to the server.
4. Type a message in one window.
5. Observe real-time message delivery in the second window.

---

## 7. Two-Client Demonstration Instructions

To simulate multiple users:

1. Open two separate browser windows.
2. Connect both to the same WebSocket server.
3. Send messages between them.
4. Observe message logs on the server terminal.

This demonstrates concurrent WebSocket connections and real-time communication.

---

## 8. Troubleshooting

If you see "Address already in use":
- Stop other server instances.
- Change the port number.

If WebSocket connection fails:
- Ensure the server is running.
- Verify correct port number in client.

---

## 9. Security Notes

- This project is intended for educational use.
- Authentication and encryption mechanisms (if implemented) are basic.
- Not production-ready.
