import os
import time
import bcrypt

# DB_MODE=mysql in production; leave unset (defaults to sqlite) for local dev.
DB_MODE = os.environ.get("DB_MODE", "sqlite").lower()
DB_FILE = os.environ.get("DB_FILE", "securechat.db")

MYSQL_HOST     = os.environ.get("MYSQL_HOST",     "localhost")
MYSQL_PORT     = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER     = os.environ.get("MYSQL_USER",     "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DB       = os.environ.get("MYSQL_DB",       "securechat")

CA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca.pem")

# Parameterised-query placeholder differs between drivers
P = "%s" if DB_MODE == "mysql" else "?"

# ── Connection pool (lazy) ─────────────────────────────────────────────────

_pool = None

def _get_pool():
    """Build the DBUtils connection pool on first use."""
    global _pool
    if _pool is not None:
        return _pool
    from dbutils.pooled_db import PooledDB
    import pymysql
    _pool = PooledDB(
        creator       = pymysql,
        maxconnections= 8,
        mincached     = 2,
        maxcached     = 4,
        blocking      = True,
        ping          = 1,    # auto-reconnect dropped connections
        host          = MYSQL_HOST,
        port          = MYSQL_PORT,
        user          = MYSQL_USER,
        password      = MYSQL_PASSWORD,
        database      = MYSQL_DB,
        ssl           = {"ca": CA_PATH},
        autocommit    = False,
        charset       = "utf8mb4",
    )
    return _pool


def get_connection():
    if DB_MODE == "mysql":
        return _get_pool().connection()
    import sqlite3
    return sqlite3.connect(DB_FILE)


# ── Schema ─────────────────────────────────────────────────────────────────

def init_db():
    conn = get_connection()
    c = conn.cursor()

    if DB_MODE == "mysql":
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            username      VARCHAR(191) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at    DOUBLE NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    else:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    REAL NOT NULL
        )''')

    conn.commit()
    conn.close()


# ── User operations (all queries parameterised — SQL-injection safe) ───────

def register_user(username: str, password: str):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            f'INSERT INTO users (username, password_hash, created_at) VALUES ({P}, {P}, {P})',
            (username, hashed.decode("utf-8"), time.time()),
        )
        conn.commit()
        return True, "Account created successfully!"
    except Exception as e:
        msg = str(e)
        if "UNIQUE" in msg.upper() or "Duplicate" in msg:
            return False, "Username already exists."
        return False, f"Database error: {e}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def verify_user(username: str, password: str) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute(f'SELECT password_hash FROM users WHERE username = {P}', (username,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return False
    stored = row[0]
    if isinstance(stored, bytes):
        stored = stored.decode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))


# Initialise schema at import time so the server fails loudly if DB is bad
init_db()
