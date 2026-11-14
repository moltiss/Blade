"""PZ 6 — Issue #7: functional positive tests."""
import base64
import json
from zipfile import ZipFile, ZIP_DEFLATED

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_aes_roundtrip(crypto):
    text, password = 'Сообщение Blade 🔐', 'TestEncryption9!'
    encrypted = crypto.encrypt(text, password)
    assert set(encrypted) == {'salt', 'nonce', 'ciphertext'}
    assert len(base64.b64decode(encrypted['salt'], validate=True)) == 16
    assert len(base64.b64decode(encrypted['nonce'], validate=True)) == 12
    assert len(base64.b64decode(encrypted['ciphertext'], validate=True)) == len(text.encode('utf-8')) + 16
    assert crypto.decrypt(encrypted, password) == text


def test_aes_random_salt_and_nonce(crypto):
    text, password = 'Blade', 'TestEncryption9!'
    first = crypto.encrypt(text, password)
    second = crypto.encrypt(text, password)
    assert first['salt'] != second['salt']
    assert first['nonce'] != second['nonce']
    assert first['ciphertext'] != second['ciphertext']
    assert crypto.decrypt(first, password) == crypto.decrypt(second, password) == text


def test_server_status(api):
    response = api.get('/status')
    assert response.status_code == 200
    assert response.get_json()['success'] is True


def test_register_success(api):
    response = api.post('/register', json={'login': 'new_student', 'password': 'BladeTest9!', 'device_id': 'b' * 64})
    assert response.status_code == 201
    assert response.get_json()['success'] is True


def test_login_success_and_jwt_profile(api, account, headers):
    response = api.get('/me', headers=headers)
    assert response.status_code == 200
    assert response.get_json()['user']['login'] == account['login']


def test_logout_success(api, headers):
    response = api.post('/logout', headers=headers)
    assert response.status_code == 200
    assert response.get_json()['success'] is True
    assert api.get('/me', headers=headers).status_code == 401


def test_encrypted_message_history_and_decryption(api, headers, crypto):
    text, password = 'Тест сохранения истории', 'TestEncryption9!'
    encrypted = crypto.encrypt(text, password)
    response = api.post('/encrypt', headers=headers, json=encrypted)
    assert response.status_code == 201
    message_id = response.get_json()['message_id']
    history = api.get('/messages', headers=headers)
    assert history.status_code == 200
    assert [item['id'] for item in history.get_json()['messages']] == [message_id]
    received = api.get('/decrypt', headers=headers, query_string={'message_id': message_id})
    assert received.status_code == 200
    stored = received.get_json()['data']
    assert all(stored[key] == value for key, value in encrypted.items())
    assert crypto.decrypt(stored, password) == text


def test_security_log_records_login(api, account, headers):
    response = api.get('/security-logs', headers=headers)
    assert response.status_code == 200
    events = response.get_json()['events']
    assert any(e['action'] == 'login' and e['status'] == 'success' and e['user_account'] == account['login'] for e in events)


def test_update_check_without_published_release(api, headers):
    response = api.get('/updates/check', headers=headers,
                       query_string={'os': 'windows', 'arch': 'x64', 'version': '1.0.0'})
    assert response.status_code == 200
    assert response.get_json()['update_available'] is False


def test_valid_signed_update_package(update_module, tmp_path):
    u = update_module
    key = Ed25519PrivateKey.generate()
    public = tmp_path / 'test_public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os_name, arch = u.platform_info()
    version = '1.1.0'
    package = tmp_path / f'Blade-{version}-{os_name}-{arch}.zip'
    # Synthetic fixture pins: test the consistency check, not installed versions.
    deps = {'cryptography': '1.0.0', 'requests': '2.0.0', 'pyside6': '6.0.0'}
    with ZipFile(package, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('requirements.txt', ''.join(f'{name}=={v}\n' for name, v in deps.items()))
        archive.writestr('README.txt', 'Synthetic test package. Never install.')
    sbom = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
                       'metadata': {'component': {'type': 'application', 'name': 'Blade', 'version': version}},
                       'components': [{'type': 'library', 'name': n, 'version': v} for n, v in deps.items()]}).encode('utf-8')
    manifest = {'version': version, 'min_supported': '1.0.0', 'os': os_name, 'arch': arch,
                'package_filename': package.name, 'package_size': package.stat().st_size,
                'package_sha256': u.digest_file(package),
                'sbom': {'format': 'CycloneDX-1.5', 'sha256': u.digest_bytes(sbom)}}
    manifest['signature'] = base64.b64encode(key.sign(u.canonical_manifest_bytes(manifest))).decode('ascii')
    result = u.verify_package(manifest, sbom, package, current_version='1.0.0', public_key_path=public)
    assert result['verified'] is True
    assert result['version'] == version
    assert result['files'] == 2
    assert result['key_dependencies'] == deps
