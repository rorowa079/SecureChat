import os
import time
import bcrypt

# Set DB_MODE=mysql (+ MYSQL_* vars) in production env, leave unset for local SQLite.
DB_MODE = os.environ.get("DB_MODE", "sqlite").lower()
DB_FILE = os.environ.get("DB_FILE", "securechat.db")

MYSQL_HOST     = os.environ.get("MYSQL_HOST",     "localhost")
MYSQL_PORT     = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER     = os.environ.get("MYSQL_USER",     "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DB       = os.environ.get("MYSQL_DB",       "securechat")

# Resolve ca.pem next to this file so the path works regardless of CWD.
CA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca.pem")

# Parameterised-query placeholder differs between drivers.
P = "%s" if DB_MODE == "mysql" else "?"


def get_connection():
    if DB_MODE == "mysql":
        import pymysql
        return pymysql.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASSWORD,
            database=MYSQL_DB, autocommit=False,
            ssl={"ca": CA_PATH}
        )
    import sqlite3
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    c = conn.cursor()

    if DB_MODE == "mysql":
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(191) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

        c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            username VARCHAR(191) NOT NULL,
            timestamp DOUBLE NOT NULL,
            INDEX idx_ip (ip_address),
            INDEX idx_user (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')

        c.execute('''CREATE TABLE IF NOT EXISTS public_keys (
            username VARCHAR(191) PRIMARY KEY,
            public_key MEDIUMTEXT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    else:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT NOT NULL,
            timestamp REAL NOT NULL
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS public_keys (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL
        )''')

    conn.commit()
    conn.close()


def register_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(f'INSERT INTO users (username, password_hash) VALUES ({P}, {P})',
                  (username, hashed.decode('utf-8')))
        conn.commit()
        return True, "Registration successful."
    except Exception as e:
        msg = str(e)
        if "UNIQUE" in msg.upper() or "Duplicate" in msg:
            return False, "Username already exists."
        return False, f"Database error: {e}"
    finally:
        conn.close()


def verify_user(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute(f'SELECT password_hash FROM users WHERE username = {P}', (username,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), row[0].encode('utf-8'))


def is_rate_limited(ip_address, username):
    conn = get_connection()
    c = conn.cursor()
    cutoff = time.time() - 300
    c.execute(f'SELECT COUNT(*) FROM login_attempts WHERE ip_address = {P} AND timestamp > {P}',
              (ip_address, cutoff))
    ip_hits = c.fetchone()[0]
    c.execute(f'SELECT COUNT(*) FROM login_attempts WHERE username = {P} AND timestamp > {P}',
              (username, cutoff))
    user_hits = c.fetchone()[0]
    conn.close()
    return ip_hits >= 5 or user_hits >= 5


def record_failed_login(ip_address, username):
    conn = get_connection()
    c = conn.cursor()
    c.execute(f'INSERT INTO login_attempts (ip_address, username, timestamp) VALUES ({P}, {P}, {P})',
              (ip_address, username, time.time()))
    conn.commit()
    conn.close()


def clear_failed_logins(ip_address, username):
    conn = get_connection()
    c = conn.cursor()
    c.execute(f'DELETE FROM login_attempts WHERE ip_address = {P} OR username = {P}',
              (ip_address, username))
    conn.commit()
    conn.close()


def store_public_key(username, public_key_spki):
    conn = get_connection()
    c = conn.cursor()
    if DB_MODE == "mysql":
        c.execute(
            f'INSERT INTO public_keys (username, public_key) VALUES ({P}, {P}) '
            f'ON DUPLICATE KEY UPDATE public_key = VALUES(public_key)',
            (username, public_key_spki)
        )
    else:
        c.execute(
            f'INSERT INTO public_keys (username, public_key) VALUES ({P}, {P}) '
            f'ON CONFLICT(username) DO UPDATE SET public_key = excluded.public_key',
            (username, public_key_spki)
        )
    conn.commit()
    conn.close()


def get_public_key(username):
    conn = get_connection()
    c = conn.cursor()
    c.execute(f'SELECT public_key FROM public_keys WHERE username = {P}', (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

init_db()
