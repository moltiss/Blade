"""Safe smoke test of update routes; no credentials or releases required."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from app import app
from database import get_connection

with app.test_client() as client:
    resp = client.get('/status')
    assert resp.status_code == 200, ('/status', resp.status_code)
    for path in (
        '/updates/check?os=windows&arch=x64&version=1.0.0',
        '/updates/manifest/1.1.0',
        '/updates/download/1.1.0',
        '/updates/sbom/1.1.0.json',
    ):
        resp = client.get(path)
        assert resp.status_code == 401, (path, resp.status_code)
    resp = client.post('/updates/report', json={})
    assert resp.status_code == 401, ('/updates/report', resp.status_code)

with get_connection() as connection:
    tables = {row[0] for row in connection.execute('SELECT name FROM sqlite_master WHERE type="table"')}
    required = {'users', 'sessions', 'encrypted_messages', 'releases',
                'update_audit', 'update_download_tokens'}
    assert required.issubset(tables), required - tables

print('OK: /status, все пять API-маршрутов защищены JWT, таблицы созданы.')
