"""Чтение конфигурации клиента Blade из config.ini."""
import configparser
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent / "config.ini"

def load_client_config():
    config = configparser.ConfigParser()
    if not CONFIG_PATH.is_file():
        raise FileNotFoundError(f"Не найден файл конфигурации: {CONFIG_PATH}")
    config.read(CONFIG_PATH, encoding="utf-8")
    for section in ("client", "cryptography"):
        if not config.has_section(section):
            raise ValueError(f"В config.ini отсутствует раздел [{section}]")
    algorithms = config["cryptography"]
    expected = {"encryption": "AES-256-GCM", "hashing": "SHA-256"}
    for key, value in expected.items():
        if algorithms.get(key, "").upper() != value:
            raise ValueError(f"Алгоритм {key}={algorithms.get(key)} не поддерживается")
    return config

CONFIG = load_client_config()
SERVER_URL = CONFIG.get("client", "server_url").rstrip("/")
APP_NAME = CONFIG.get("client", "app_name", fallback="Blade")
APP_VERSION = CONFIG.get("client", "app_version", fallback="1.0.0")
BUILD_DATE = CONFIG.get("client", "build_date", fallback="Не указана")
REQUEST_TIMEOUT = CONFIG.getint("client", "timeout", fallback=10)
STATUS_TIMEOUT = CONFIG.getint("client", "status_timeout", fallback=5)
