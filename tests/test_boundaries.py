"""PZ 6 — Issue #9: boundary values on real Blade modules.
All server cases reuse the isolated SQLite/config fixtures from conftest.py.
"""
import base64
import json
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.mark.parametrize('length,expected', [
    (0, 400), (1, 400), (2, 400), (3, 201), (4, 201),
    (63, 201), (64, 201), (65, 400),
])
def test_login_length_boundary(api, length, expected):
    result = api.post('/register', json={
        'login': 'a' * length, 'password': 'BladeTest9!', 'device_id': 'a' * 64,
    })
    assert result.status_code == expected, result.get_json()


@pytest.mark.parametrize('length,expected', [
    (0, 400), (1, 400), (9, 400), (10, 201), (11, 201),
    (1023, 201), (1024, 201), (1025, 400),
])
def test_password_length_boundary(api, length, expected):
    # Fix the test policy rather than relying on a user's local configuration.
    policy = api.get('/auth-policy').get_json()['policy']
    assert policy['min_password_length'] == 10
    password = ('Aa9!' + 'a' * length)[:length]
    result = api.post('/register', json={
        'login': 'boundary_student', 'password': password, 'device_id': 'a' * 64,
    })
    assert result.status_code == expected, result.get_json()


@pytest.mark.parametrize('length,expected', [
    (0, 400), (1, 201), (255, 201), (256, 201), (257, 400),
])
def test_device_id_length_boundary(api, length, expected):
    # The server's current format allows 1..256 characters, even though
    # the actual client sends a 64-character SHA-256 device fingerprint.
    result = api.post('/register', json={
        'login': 'boundary_student', 'password': 'BladeTest9!', 'device_id': 'a' * length,
    })
    assert result.status_code == expected, result.get_json()


@pytest.mark.parametrize('text', ['', 'Я', 'a' * 4096])
def test_aes_text_length_boundary(crypto, text):
    # AESService itself permits empty plaintext; the GUI may reject it.
    password = 'TestEncryption9!'
    encrypted = crypto.encrypt(text, password)
    assert len(base64.b64decode(encrypted['ciphertext'], validate=True)) == len(text.encode('utf-8')) + 16
    assert crypto.decrypt(encrypted, password) == text


@pytest.mark.parametrize('length,valid', [
    (0, False), (1, True), (1_999_999, True), (2_000_000, True), (2_000_001, False),
])
def test_ciphertext_field_length_boundary(api, length, valid):
    # Isolate the existing field-length validator, not a crypto validity test.
    app_module = sys.modules['app']
    result = app_module.validate_encrypted_payload({'salt': 'a', 'nonce': 'b', 'ciphertext': 'c' * length})
    assert (result is None) == valid


@pytest.mark.parametrize('count', [0, 1])
def test_message_history_collection_boundary(api, headers, crypto, count):
    if count:
        result = api.post('/encrypt', headers=headers, json=crypto.encrypt('X', 'TestEncryption9!'))
        assert result.status_code == 201
    response = api.get('/messages', headers=headers)
    assert response.status_code == 200
    assert len(response.get_json()['messages']) == count


def test_login_attempt_limit_boundary(api, account):
    policy = api.get('/auth-policy').get_json()['policy']
    assert policy['max_login_attempts'] == 5
    bad = {**account, 'password': 'WrongPassword9!'}
    for attempt in range(1, 7):
        result = api.post('/login', json=bad)
        assert result.status_code == (401 if attempt < 5 else 429), (attempt, result.get_json())
    result = api.post('/login', json=account)
    assert result.status_code == 429
    assert int(result.headers['Retry-After']) > 0


def freeze_clock(monkeypatch, module, instant):
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz) if tz is not None else instant.replace(tzinfo=None)
    monkeypatch.setattr(module, 'datetime', FrozenDateTime)


@pytest.mark.parametrize('offset,expected', [(-1, 200), (0, 401), (1, 401)])
def test_jwt_expiry_boundary(api, headers, monkeypatch, offset, expected):
    auth = sys.modules['auth']
    token = headers['Authorization'].split()[1]
    encoded = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    assert claims['exp'] - claims['iat'] == 1800
    freeze_clock(monkeypatch, auth, datetime.fromtimestamp(claims['exp'] + offset, timezone.utc))
    assert api.get('/me', headers=headers).status_code == expected


@pytest.mark.parametrize('offset,expected', [(-1, 429), (0, 200), (1, 200)])
def test_lockout_expiry_boundary(api, account, monkeypatch, offset, expected):
    policy = sys.modules['security_policy']
    start = datetime(2026, 12, 31, 23, 55, tzinfo=timezone.utc)
    freeze_clock(monkeypatch, policy, start)
    assert policy.LOCK_MINUTES == 15
    for _ in range(policy.MAX_ATTEMPTS):
        policy.record_failed_login(account['login'])
    expiry = start + timedelta(minutes=policy.LOCK_MINUTES)
    freeze_clock(monkeypatch, policy, expiry + timedelta(seconds=offset))
    assert api.post('/login', json=account).status_code == expected


@pytest.mark.parametrize('before,after', [
    ('2026-06-15T23:59:59+00:00', '2026-06-16T00:00:00+00:00'),
    ('2026-04-30T23:59:59+00:00', '2026-05-01T00:00:00+00:00'),
    ('2024-02-28T23:59:59+00:00', '2024-02-29T00:00:00+00:00'),
    ('2024-02-29T23:59:59+00:00', '2024-03-01T00:00:00+00:00'),
    ('2026-12-31T23:59:59+00:00', '2027-01-01T00:00:00+00:00'),
])
def test_utc_timestamp_transition(api, monkeypatch, before, after):
    auth = sys.modules['auth']
    first = datetime.fromisoformat(before)
    second = first + timedelta(seconds=1)
    assert second == datetime.fromisoformat(after)
    freeze_clock(monkeypatch, auth, first)
    observed_first = datetime.fromisoformat(auth.current_time())
    freeze_clock(monkeypatch, auth, second)
    observed_second = datetime.fromisoformat(auth.current_time())
    assert observed_first == first
    assert observed_second == second
    assert observed_second - observed_first == timedelta(seconds=1)


@pytest.fixture
def manifest_factory(update_module, tmp_path):
    u = update_module
    key = Ed25519PrivateKey.generate()
    public = tmp_path / 'boundary_public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os_name, arch = u.platform_info()
    def make(version='1.1.0', minimum='1.0.0', size=1):
        manifest = {'version': version, 'min_supported': minimum, 'os': os_name, 'arch': arch,
                    'package_filename': f'Blade-{version}-{os_name}-{arch}.zip',
                    'package_size': size, 'package_sha256': 'a' * 64,
                    'sbom': {'format': 'CycloneDX-1.5', 'sha256': 'b' * 64}}
        manifest['signature'] = base64.b64encode(key.sign(u.canonical_manifest_bytes(manifest))).decode('ascii')
        return manifest
    return u, public, make


@pytest.mark.parametrize('version,minimum,valid', [
    ('0.9.9', '0.9.0', False), ('1.0.0', '1.0.0', False),
    ('1.0.1', '0.9.9', True), ('1.1.0', '1.0.0', True),
    ('1.1.0', '1.0.1', False),
])
def test_update_version_boundary(manifest_factory, version, minimum, valid):
    u, public, make = manifest_factory
    manifest = make(version, minimum)
    if valid:
        assert u.verify_manifest(manifest, current_version='1.0.0', public_key_path=public) == manifest
    else:
        with pytest.raises(u.UpdateError):
            u.verify_manifest(manifest, current_version='1.0.0', public_key_path=public)


@pytest.mark.parametrize('case,valid', [('zero', False), ('one', True), ('below_max', True), ('max', True), ('above_max', False)])
def test_update_declared_size_boundary(manifest_factory, case, valid):
    # Test signed metadata only; no 1 GiB file is created or downloaded.
    u, public, make = manifest_factory
    size = {'zero': 0, 'one': 1, 'below_max': u.MAX_PACKAGE_SIZE - 1,
            'max': u.MAX_PACKAGE_SIZE, 'above_max': u.MAX_PACKAGE_SIZE + 1}[case]
    manifest = make(size=size)
    if valid:
        assert u.verify_manifest(manifest, current_version='1.0.0', public_key_path=public) == manifest
    else:
        with pytest.raises(u.UpdateError):
            u.verify_manifest(manifest, current_version='1.0.0', public_key_path=public)
