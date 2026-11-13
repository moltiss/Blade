
import hashlib
import base64
import json
import os
from pathlib import Path
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from database import get_connection


PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
SESSION_LIFETIME_MINUTES = 30


def current_time():
    """Возвращает текущее время в UTC в формате ISO 8601."""
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    )


def hash_password(password, salt=None):
    """Создаёт PBKDF2-хеш пароля и возвращает хеш с солью."""
    if not isinstance(password, str) or not password:
        raise ValueError("Пароль не должен быть пустым.")

    if salt is None:
        salt_bytes = secrets.token_bytes(SALT_BYTES)
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
        dklen=32
    )

    return password_hash.hex(), salt_bytes.hex()


def verify_password(password, stored_hash, stored_salt):
    """Проверяет пароль, используя сохранённые хеш и соль."""
    try:
        calculated_hash, _ = hash_password(
            password,
            salt=stored_salt
        )
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


# JWT HS256: секрет хранится в storage, не в распространяемом клиенте.
JWT_SECRET_PATH = Path(__file__).resolve().parent.parent / "storage" / "jwt_secret.key"

def _jwt_secret():
    JWT_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(JWT_SECRET_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    secret = JWT_SECRET_PATH.read_bytes()
    if len(secret) < 32:
        raise RuntimeError("JWT secret должен содержать не менее 32 байт")
    return secret

def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _decode64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def _verify_jwt(token):
    try:
        header, payload, signature = token.split(".")
        signed = f"{header}.{payload}".encode("ascii")
        expected = _b64(hmac.new(_jwt_secret(), signed, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        h = json.loads(_decode64(header))
        claims = json.loads(_decode64(payload))
        if h != {"alg": "HS256", "typ": "JWT"}:
            return None
        now = int(datetime.now(timezone.utc).timestamp())
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= now:
            return None
        if not isinstance(claims.get("sub"), str) or not claims["sub"].isdigit():
            return None
        if not isinstance(claims.get("device_id"), str):
            return None
        return claims
    except (ValueError, TypeError, UnicodeError, KeyError, json.JSONDecodeError):
        return None

def create_session(user_id, device_id=None):
    """Создаёт JWT HS256 с 30-минутным сроком и записью для отзыва."""
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(minutes=SESSION_LIFETIME_MINUTES)
    claims = {
        "sub": str(user_id), "device_id": device_id or "",
        "iat": int(created_at.timestamp()),
        "exp": int(expires_at.timestamp()), "jti": secrets.token_hex(16),
    }
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    unsigned = f"{header}.{payload}"
    signature = _b64(hmac.new(_jwt_secret(), unsigned.encode("ascii"), hashlib.sha256).digest())
    token = f"{unsigned}.{signature}"
    with get_connection() as connection:
        connection.execute(
            """INSERT INTO sessions (token,user_id,device_id,created_at,expires_at)
               VALUES (?,?,?,?,?)""",
            (token, user_id, device_id,
             created_at.isoformat(timespec="milliseconds"),
             expires_at.isoformat(timespec="milliseconds"))
        )
    return token

def get_session(token):
    """Проверяет подпись JWT, срок, привязку к устройству и отзыв в БД."""
    claims = _verify_jwt(token) if token else None
    if claims is None:
        return None
    with get_connection() as connection:
        row = connection.execute(
            """SELECT sessions.token,sessions.user_id,sessions.device_id,
                      sessions.created_at,sessions.expires_at,users.login
               FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token=?""", (token,)
        ).fetchone()
        if row is None:
            return None
        if str(row["user_id"]) != claims["sub"] or (row["device_id"] or "") != claims["device_id"]:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            connection.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
        return dict(row)


def delete_session(token):
    """Удаляет сессию, завершая вход пользователя."""
    if not token:
        return False

    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

        return cursor.rowcount > 0
