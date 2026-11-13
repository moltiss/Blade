import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR.parent / "storage"
DATABASE_PATH = STORAGE_DIR / "blade.db"


def get_connection():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_database():
    """Создаёт таблицы пользователей, сессий и истории зашифрованных сообщений."""
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                device_id TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_id TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id
            ON sessions(user_id);

            CREATE TABLE IF NOT EXISTS encrypted_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                salt TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_messages_user_created
            ON encrypted_messages(user_id, created_at DESC, id DESC);
            """
        )


def check_database():
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name IN ('users', 'sessions', 'encrypted_messages')
            ORDER BY name
            """
        ).fetchall()
    return [row["name"] for row in rows]


if __name__ == "__main__":
    init_database()
    print("База данных Blade инициализирована.")
    print(f"Путь: {DATABASE_PATH}")
    print(f"Таблицы: {', '.join(check_database())}")
