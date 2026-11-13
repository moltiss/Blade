
import configparser
import json
import logging
import os
import re
import socket
from datetime import datetime, timedelta, timezone
import time
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.ini"


def load_config():
    """Загружает конфигурацию сервера."""
    config = configparser.ConfigParser()

    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Файл конфигурации не найден: {CONFIG_PATH}"
        )

    config.read(CONFIG_PATH, encoding="utf-8")
    return config


def parse_size(value):
    """Преобразует значения наподобие 10MB или 100KB в байты."""
    match = re.fullmatch(
        r"\s*(\d+)\s*(B|KB|MB|GB)?\s*",
        value.upper()
    )

    if not match:
        raise ValueError(
            f"Некорректный размер файла: {value}"
        )

    number = int(match.group(1))
    unit = match.group(2) or "B"

    multipliers = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3,
    }

    return number * multipliers[unit]


def get_host_ip():
    """Получает IP-адрес сетевого интерфейса хоста."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class SecurityJsonFormatter(logging.Formatter):
    """Формирует записи журнала в JSON."""

    def format(self, record):
        event = {
            "event_datetime": datetime.fromtimestamp(
                record.created
            ).astimezone().isoformat(timespec="milliseconds"),
            "source_name": getattr(
                record, "source_name", "Blade Server"
            ),
            "user_account": getattr(
                record, "user_account", "anonymous"
            ),
            "source_ip": getattr(
                record, "source_ip", "unknown"
            ),
            "host_ip": getattr(
                record, "host_ip", "127.0.0.1"
            ),
            "operation_start": getattr(
                record, "operation_start", None
            ),
            "operation_end": getattr(
                record, "operation_end", None
            ),
            "description": record.getMessage(),
            "status": getattr(record, "status", "info"),
            "action": getattr(record, "action", "none"),
            "level": getattr(record, "security_level", "info"),
        }

        return json.dumps(
            event,
            ensure_ascii=False
        )


def setup_logging():
    """Настраивает журналирование согласно config.ini."""
    config = load_config()

    log_settings = config["logging"]

    log_path = Path(log_settings["log_path"])

    if not log_path.is_absolute():
        log_path = BASE_DIR / log_path

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    max_bytes = parse_size(
        log_settings.get("max_file_size", "10MB")
    )

    backup_count = log_settings.getint(
        "backup_count", fallback=5
    )

    log_level = log_settings.get(
        "level", "INFO"
    ).upper()

    if log_level not in logging._nameToLevel:
        raise ValueError(
            f"Некорректный уровень логирования: {log_level}"
        )

    logger = logging.getLogger("blade.security")
    logger.setLevel(logging._nameToLevel[log_level])
    logger.propagate = False

    # Не добавляем обработчики повторно при повторной настройке.
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8"
    )

    handler.setFormatter(SecurityJsonFormatter())
    logger.addHandler(handler)

    cleanup_old_logs(force=True)
    return logger


def log_event(
    logger,
    description,
    *,
    user_account="anonymous",
    source_ip="unknown",
    host_ip=None,
    status="info",
    action="none",
    level="info",
    operation_start=None,
    operation_end=None
):
    """Записывает событие информационной безопасности."""

    if host_ip is None:
        host_ip = get_host_ip()

    if operation_end is None:
        operation_end = datetime.now().astimezone().isoformat(
            timespec="milliseconds"
        )

    logger.info(
        description,
        extra={
            "source_name": "Blade Server",
            "user_account": user_account,
            "source_ip": source_ip,
            "host_ip": host_ip,
            "operation_start": operation_start,
            "operation_end": operation_end,
            "status": status,
            "action": action,
            "security_level": level,
        }
    )


_cleanup_lock = threading.Lock()
_last_cleanup = 0.0


def get_log_path():
    config = load_config()
    path = Path(config.get("logging", "log_path", fallback="logs/blade_server.log"))
    return path if path.is_absolute() else BASE_DIR / path


def cleanup_old_logs(force=False):
    """Remove old rotated log files; never delete the active log file."""
    global _last_cleanup
    config = load_config()
    period = config.get("logging", "cleanup_period", fallback="30d").strip().lower()
    match = re.fullmatch(r"(\d+)d", period)
    if not match:
        raise ValueError("cleanup_period должен быть задан в днях, например 30d")
    now = time.time()
    with _cleanup_lock:
        if not force and now - _last_cleanup < 86400:
            return 0
        active = get_log_path()
        removed = 0
        for candidate in active.parent.glob(active.name + ".*"):
            if not candidate.is_file() or not re.fullmatch(re.escape(active.name) + r"\.\d+", candidate.name):
                continue
            try:
                if now - candidate.stat().st_mtime > int(match.group(1)) * 86400:
                    candidate.unlink()
                    removed += 1
            except OSError:
                pass
        _last_cleanup = now
        return removed


def read_security_events(user_account, limit=200):
    """Read only records belonging to the authenticated user."""
    active = get_log_path()
    config = load_config()
    backups = max(0, config.getint("logging", "backup_count", fallback=5))
    paths = [active.with_name(active.name + f".{i}") for i in range(backups, 0, -1)] + [active]
    events = []
    for path in paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(event, dict) and event.get("user_account") == user_account:
                    events.append(event)
    return events[-limit:][::-1]
