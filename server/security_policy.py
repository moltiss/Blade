"""Настройки безопасности учётных записей Blade (сервер является источником истины)."""
from datetime import datetime, timedelta, timezone
import re
import sqlite3
from threading import Lock

from logging_config import load_config
from database import get_connection

_config = load_config()
MIN_LENGTH = max(8, min(128, _config.getint('security', 'min_password_length', fallback=10)))
REQUIRE_UPPER = _config.getboolean('security', 'require_uppercase', fallback=True)
REQUIRE_LOWER = _config.getboolean('security', 'require_lowercase', fallback=True)
REQUIRE_DIGIT = _config.getboolean('security', 'require_digit', fallback=True)
REQUIRE_SPECIAL = _config.getboolean('security', 'require_special', fallback=True)
MAX_ATTEMPTS = max(1, min(30, _config.getint('security', 'max_login_attempts', fallback=5)))
LOCK_MINUTES = max(1, min(1440, _config.getint('security', 'lockout_minutes', fallback=15)))
_lock = Lock()

def public_policy():
    return dict(min_password_length=MIN_LENGTH, require_uppercase=REQUIRE_UPPER,
                require_lowercase=REQUIRE_LOWER, require_digit=REQUIRE_DIGIT,
                require_special=REQUIRE_SPECIAL, max_login_attempts=MAX_ATTEMPTS,
                lockout_minutes=LOCK_MINUTES)

def password_error(password):
    if not isinstance(password,str):return 'Некорректный пароль'
    if len(password)<MIN_LENGTH:return f'Пароль должен содержать минимум {MIN_LENGTH} символов'
    if len(password)>1024:return 'Пароль слишком длинный (максимум 1024 символа)'
    if REQUIRE_UPPER and not any(c.isupper() for c in password):return 'Добавьте заглавную букву'
    if REQUIRE_LOWER and not any(c.islower() for c in password):return 'Добавьте строчную букву'
    if REQUIRE_DIGIT and not any(c.isdigit() for c in password):return 'Добавьте цифру'
    if REQUIRE_SPECIAL and not any(not c.isalnum() and not c.isspace() for c in password):return 'Добавьте специальный символ'
    return None

def init_login_limits():
    with get_connection() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS login_limits (
            login TEXT PRIMARY KEY, failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT)""")

def _lock_time(row):
    if not row or not row['locked_until']:return None
    until=datetime.fromisoformat(row['locked_until'])
    if until.tzinfo is None:until=until.replace(tzinfo=timezone.utc)
    return until if until>datetime.now(timezone.utc) else None

def remaining_lock(login):
    with _lock, get_connection() as c:
        row=c.execute('SELECT locked_until FROM login_limits WHERE login=?',(login,)).fetchone()
        until=_lock_time(row)
        return max(1,int((until-datetime.now(timezone.utc)).total_seconds()+0.999)) if until else 0

def record_failed_login(login):
    """Атомарно считает попытки для одного логина (включая несуществующие)."""
    with _lock, get_connection() as c:
        row=c.execute('SELECT failed_attempts,locked_until FROM login_limits WHERE login=?',(login,)).fetchone()
        until=_lock_time(row)
        if until:return max(1,int((until-datetime.now(timezone.utc)).total_seconds()+0.999))
        count=(row['failed_attempts'] if row and not row['locked_until'] else 0)+1
        expiry=(datetime.now(timezone.utc)+timedelta(minutes=LOCK_MINUTES)).isoformat() if count>=MAX_ATTEMPTS else None
        c.execute("""INSERT INTO login_limits(login,failed_attempts,locked_until) VALUES (?,?,?)
          ON CONFLICT(login) DO UPDATE SET failed_attempts=excluded.failed_attempts,
          locked_until=excluded.locked_until""",(login,count,expiry))
        return LOCK_MINUTES*60 if expiry else 0

def reset_failed_logins(login):
    with _lock,get_connection() as c:c.execute('DELETE FROM login_limits WHERE login=?',(login,))
