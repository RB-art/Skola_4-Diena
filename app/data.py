"""3. līmenis · Datu līmenis: relāciju datubāze (SQLite) un SQL vaicājumi.

Tikai šis modulis zina par SQL. Pārējie līmeņi izmanto tā funkcijas.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class UserRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def create_user(self, username: str, email: str, password_hash: str, salt: str) -> int:
        """Atgriež jaunā lietotāja ID. Dublikāta gadījumā met sqlite3.IntegrityError."""
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, salt),
            )
            return int(cursor.lastrowid)

    def find_by_username(self, username: str) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

    def create_session(self, token: str, user_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id)
            )

    def find_user_by_session(self, token: str) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT u.id, u.username, u.email, u.created_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token = ?",
                (token,),
            ).fetchone()

    def delete_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
