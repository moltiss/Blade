"""Fixtures for Blade: real source modules, isolated test state, no running server."""
from contextlib import contextmanager
import importlib
import logging
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "BladeTest9!"
DEVICE = "a" * 64


@contextmanager
def isolated_imports(folder, names):
    # The client and server both have an auth.py; isolate flat import names.
    previous = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    sys.path.insert(0, str(folder))
    try:
        yield
    finally:
        sys.path.remove(str(folder))
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(previous)


@pytest.fixture
def crypto():
    with isolated_imports(ROOT / 'client', ['encryption']):
        yield importlib.import_module('encryption').AESService()


@pytest.fixture
def update_module(tmp_path, monkeypatch):
    with isolated_imports(ROOT / 'client', ['updater', 'settings']):
        # Test update logic independently from local settings/config.ini.
        settings = types.ModuleType('settings')
        settings.APP_VERSION = '1.0.0'
        settings.SERVER_URL = 'http://127.0.0.1:5000'
        settings.REQUEST_TIMEOUT = 5
        sys.modules['settings'] = settings
        updater = importlib.import_module('updater')
        monkeypatch.setattr(updater, 'APP_DATA_DIR', tmp_path / 'appdata')
        monkeypatch.setattr(updater, 'UPDATE_CACHE', tmp_path / 'appdata' / 'updates')
        monkeypatch.setattr(updater, 'AUDIT_PATH', tmp_path / 'appdata' / 'audit.jsonl')
        monkeypatch.setattr(updater, 'PENDING_REPORTS', tmp_path / 'appdata' / 'pending.jsonl')
        yield updater


@pytest.fixture
def api(tmp_path, monkeypatch):
    names = ['app', 'auth', 'database', 'logging_config', 'security_policy', 'update_service']
    with isolated_imports(ROOT / 'server', names):
        config_path = tmp_path / 'config.ini'
        config_path.write_text(f'''[server]
host = 127.0.0.1
port = 5000
debug = false
[logging]
log_path = { (tmp_path / 'security.log').as_posix() }
log_format = JSON
cleanup_period = 30d
max_file_size = 10MB
backup_count = 2
level = INFO
[security]
min_password_length = 10
require_uppercase = true
require_lowercase = true
require_digit = true
require_special = true
max_login_attempts = 5
lockout_minutes = 15
[updates]
release_directory = { (tmp_path / 'releases').as_posix() }
public_key = { (tmp_path / 'update_public.pem').as_posix() }
download_token_ttl_seconds = 300
''', encoding='utf-8')
        db = importlib.import_module('database')
        monkeypatch.setattr(db, 'STORAGE_DIR', tmp_path / 'storage')
        monkeypatch.setattr(db, 'DATABASE_PATH', tmp_path / 'storage' / 'blade.db')
        logs = importlib.import_module('logging_config')
        monkeypatch.setattr(logs, 'CONFIG_PATH', config_path)
        monkeypatch.setattr(logs, 'get_host_ip', lambda: '127.0.0.1')
        auth = importlib.import_module('auth')
        monkeypatch.setattr(auth, 'JWT_SECRET_PATH', tmp_path / 'storage' / 'jwt_secret.key')
        try:
            app_module = importlib.import_module('app')
            app_module.app.config['TESTING'] = True
            with app_module.app.test_client() as client:
                yield client
        finally:
            # Windows does not allow deleting open log files.
            logger = logging.getLogger('blade.security')
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                handler.close()


@pytest.fixture
def account(api):
    credentials = {'login': 'blade_student', 'password': PASSWORD, 'device_id': DEVICE}
    response = api.post('/register', json=credentials)
    assert response.status_code == 201, response.get_json()
    return credentials


@pytest.fixture
def headers(api, account):
    response = api.post('/login', json=account)
    assert response.status_code == 200, response.get_json()
    token = response.get_json()['token']
    assert len(token.split('.')) == 3
    return {'Authorization': 'Bearer ' + token}
