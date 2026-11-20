"""PZ 6 — Issue #8: functional negative tests, using isolated fixtures."""
import base64
import json
from zipfile import ZipFile, ZIP_DEFLATED

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_aes_wrong_password(crypto):
    payload = crypto.encrypt('Blade test', 'TestEncryption9!')
    with pytest.raises(InvalidTag):
        crypto.decrypt(payload, 'DifferentPassword9!')


@pytest.mark.parametrize('field', ['ciphertext', 'nonce', 'salt'])
def test_aes_modified_payload(crypto, field):
    password = 'TestEncryption9!'
    payload = crypto.encrypt('Blade test', password)
    raw = bytearray(base64.b64decode(payload[field]))
    raw[0] ^= 1
    payload[field] = base64.b64encode(raw).decode('ascii')
    with pytest.raises(InvalidTag):
        crypto.decrypt(payload, password)


@pytest.mark.parametrize('changes', [
    {'login': ''}, {'login': 'invalid login'}, {'login': None},
    {'password': ''}, {'password': 'weak'}, {'password': 123},
    {'device_id': []},
])
def test_register_invalid_input(api, changes):
    data = {'login': 'test_student', 'password': 'BladeTest9!', 'device_id': 'a' * 64}
    data.update(changes)
    response = api.post('/register', json=data)
    assert response.status_code == 400
    assert response.get_json()['success'] is False


def test_register_duplicate_login(api, account):
    response = api.post('/register', json=account)
    assert response.status_code == 409
    assert response.get_json()['success'] is False


def test_login_wrong_password(api, account):
    response = api.post('/login', json={**account, 'password': 'WrongPassword9!'})
    assert response.status_code == 401
    assert 'token' not in response.get_json()


def test_login_unknown_device(api, account):
    response = api.post('/login', json={**account, 'device_id': 'b' * 64})
    assert response.status_code == 403
    assert 'token' not in response.get_json()


@pytest.mark.parametrize('route', ['/me', '/messages', '/decrypt', '/security-logs'])
def test_protected_endpoint_without_token(api, route):
    assert api.get(route).status_code == 401


def test_jwt_tampered_signature(api, headers):
    token = headers['Authorization'].split()[1]
    head, body, sig = token.split('.')
    bad_sig = ('A' if sig[0] != 'A' else 'B') + sig[1:]
    assert api.get('/me', headers={'Authorization': f'Bearer {head}.{body}.{bad_sig}'}).status_code == 401


@pytest.mark.parametrize('payload', [{}, {'salt': 'a', 'nonce': 'b'},
    {'salt': '', 'nonce': 'b', 'ciphertext': 'c'},
    {'salt': 123, 'nonce': 'b', 'ciphertext': 'c'}])
def test_encrypt_rejects_invalid_payload(api, headers, payload):
    response = api.post('/encrypt', headers=headers, json=payload)
    assert response.status_code == 400
    assert response.get_json()['success'] is False
    assert api.get('/messages', headers=headers).get_json()['messages'] == []


def test_message_access_isolation(api, headers, crypto):
    encrypted = crypto.encrypt('Private message', 'TestEncryption9!')
    result = api.post('/encrypt', headers=headers, json=encrypted)
    assert result.status_code == 201
    message_id = result.get_json()['message_id']
    other = {'login': 'other_student', 'password': 'BladeTest9!', 'device_id': 'b' * 64}
    assert api.post('/register', json=other).status_code == 201
    login = api.post('/login', json=other)
    assert login.status_code == 200
    other_headers = {'Authorization': 'Bearer ' + login.get_json()['token']}
    response = api.get('/decrypt', headers=other_headers, query_string={'message_id': message_id})
    assert response.status_code == 404
    assert 'data' not in response.get_json()
    assert api.get('/messages', headers=other_headers).get_json()['messages'] == []


@pytest.fixture
def signed_package(update_module, tmp_path):
    u = update_module
    key = Ed25519PrivateKey.generate()
    public = tmp_path / 'test_public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os_name, arch = u.platform_info()
    version = '1.1.0'
    package = tmp_path / f'Blade-{version}-{os_name}-{arch}.zip'
    deps = {'cryptography': '1.0.0', 'requests': '2.0.0', 'pyside6': '6.0.0'}
    with ZipFile(package, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('requirements.txt', ''.join(f'{n}=={v}\n' for n,v in deps.items()))
        archive.writestr('README.txt', 'Synthetic test package. Never install.')
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
           'metadata': {'component': {'type': 'application', 'name': 'Blade', 'version': version}},
           'components': [{'type': 'library', 'name': n, 'version': v} for n,v in deps.items()]}
    sbom = json.dumps(bom).encode('utf-8')
    manifest = {'version': version, 'min_supported': '1.0.0', 'os': os_name, 'arch': arch,
                'package_filename': package.name, 'package_size': package.stat().st_size,
                'package_sha256': u.digest_file(package),
                'sbom': {'format': 'CycloneDX-1.5', 'sha256': u.digest_bytes(sbom)}}
    def sign():
        manifest['signature'] = base64.b64encode(key.sign(u.canonical_manifest_bytes(manifest))).decode('ascii')
    sign()
    assert u.verify_package(manifest, sbom, package, current_version='1.0.0', public_key_path=public)['verified']
    return u, manifest, sbom, package, public, sign


def test_update_tampered_manifest(signed_package):
    u, manifest, sbom, package, public, _ = signed_package
    manifest['min_supported'] = '0.9.0'
    with pytest.raises(u.UpdateError, match='Ed25519'):
        u.verify_package(manifest, sbom, package, current_version='1.0.0', public_key_path=public)


def test_update_tampered_zip(signed_package):
    u, manifest, sbom, package, public, _ = signed_package
    data = bytearray(package.read_bytes())
    data[0] ^= 1
    package.write_bytes(data)
    with pytest.raises(u.UpdateError, match='SHA-256'):
        u.verify_package(manifest, sbom, package, current_version='1.0.0', public_key_path=public)


def test_update_tampered_sbom(signed_package):
    u, manifest, sbom, package, public, _ = signed_package
    with pytest.raises(u.UpdateError, match='SHA-256') as exc:
        u.verify_package(manifest, sbom+b' ', package, current_version='1.0.0', public_key_path=public)
    assert exc.value.status == 'sbom_mismatch'


def test_update_signed_but_inconsistent_dependencies(signed_package):
    u, manifest, sbom, package, public, sign = signed_package
    bom = json.loads(sbom)
    bom['components'][0]['version'] = '9.9.9'
    modified = json.dumps(bom).encode('utf-8')
    manifest['sbom']['sha256'] = u.digest_bytes(modified)
    sign()
    with pytest.raises(u.UpdateError) as exc:
        u.verify_package(manifest, modified, package, current_version='1.0.0', public_key_path=public)
    assert exc.value.status == 'sbom_mismatch'


def test_update_incompatible_minimum_version(signed_package):
    u, manifest, sbom, package, public, sign = signed_package
    manifest['min_supported'] = '1.0.1'
    sign()
    with pytest.raises(u.UpdateError, match='несовместимо'):
        u.verify_package(manifest, sbom, package, current_version='1.0.0', public_key_path=public)
