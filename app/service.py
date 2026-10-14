"""2. līmenis · Biznesa loģika: validācija, paroļu jaukšana, sesijas.

Šis modulis nezina ne par HTTP, ne par SQL.
"""

import hashlib
import hmac
import re
import secrets
import sqlite3
from dataclasses import dataclass

from app.data import UserRepository

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
PBKDF2_ITERATIONS = 200_000


class AuthError(Exception):
    """Kļūda, ko var parādīt lietotājam."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class User:
    id: int
    username: str
    email: str


def _hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    )
    return digest.hex()


class AuthService:
    def __init__(self, repository: UserRepository) -> None:
        self.repository = repository

    def register(self, username: str, email: str, password: str) -> User:
        username = username.strip()
        email = email.strip().lower()

        if not USERNAME_RE.match(username):
            raise AuthError("Lietotājvārdam jābūt 3–32 simboliem: burti, cipari, _ . -")
        if not EMAIL_RE.match(email):
            raise AuthError("Nederīga e-pasta adrese")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise AuthError(f"Parolei jābūt vismaz {MIN_PASSWORD_LENGTH} simbolus garai")

        salt = secrets.token_hex(16)
        try:
            user_id = self.repository.create_user(
                username, email, _hash_password(password, salt), salt
            )
        except sqlite3.IntegrityError:
            raise AuthError("Lietotājvārds vai e-pasts jau ir aizņemts", status_code=409)
        return User(id=user_id, username=username, email=email)

    def login(self, username: str, password: str) -> str:
        """Atgriež sesijas žetonu."""
        row = self.repository.find_by_username(username.strip())
        if row is None or not hmac.compare_digest(
            _hash_password(password, row["salt"]), row["password_hash"]
        ):
            raise AuthError("Nepareizs lietotājvārds vai parole", status_code=401)

        token = secrets.token_urlsafe(32)
        self.repository.create_session(token, row["id"])
        return token

    def current_user(self, token: str) -> User:
        row = self.repository.find_user_by_session(token)
        if row is None:
            raise AuthError("Sesija nav derīga", status_code=401)
        return User(id=row["id"], username=row["username"], email=row["email"])

    def logout(self, token: str) -> None:
        self.repository.delete_session(token)
