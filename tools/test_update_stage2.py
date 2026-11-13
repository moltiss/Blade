"""Read-only PZ4 stage 2 tests. No real account, database, or server required."""
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CLIENT_DIR = Path(__file__).resolve().parent.parent / 'client'
sys.path.insert(0, str(CLIENT_DIR))
from updater import (UpdateCore, UpdateError, verify_package, verify_manifest,
                     canonical_manifest_bytes, digest_bytes, platform_info)


def generate(folder, version='1.0.1'):
    folder = Path(folder)
    key = Ed25519PrivateKey.generate()
    key_path = folder / 'update_public.pem'
    key_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    os_name, cpu = platform_info()
    filename = f'Blade-{version}-{os_name}-{cpu}.zip'
    package = folder / filename
    pinned = {'cryptography': '50.0.1', 'requests': '2.32.5', 'pyside6': '6.10.0'}
    with ZipFile(package, 'w', ZIP_DEFLATED) as z:
        z.writestr('requirements.txt', ''.join(f'{n}=={v}\n' for n, v in pinned.items()))
        z.writestr('README.txt', 'TEST DATA - NEVER INSTALL\n')
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
           'metadata': {'component': {'type': 'application', 'name': 'Blade', 'version': version}},
           'components': [{'type': 'library', 'name': n, 'version': v} for n, v in pinned.items()]}
    bom_bytes = json.dumps(bom).encode()
    (folder / 'sbom.json').write_bytes(bom_bytes)
    manifest = {'version': version, 'min_supported': '1.0.0',
                'os': os_name, 'arch': cpu, 'package_filename': filename,
                'package_size': package.stat().st_size,
                'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                'sbom': {'format': 'CycloneDX-1.5', 'sha256': digest_bytes(bom_bytes)}}
    manifest['signature'] = base64.b64encode(key.sign(canonical_manifest_bytes(manifest))).decode()
    (folder / 'manifest.json').write_text(json.dumps(manifest))
    return key_path, manifest, bom_bytes, package


def assert_rejected(operation, message):
    try:
        operation()
    except UpdateError as exc:
        print('  OK — отклонено:', message, '|', exc)
        return
    raise AssertionError('Не обнаружена ошибка: ' + message)


def main():
    with tempfile.TemporaryDirectory() as folder:
        public, manifest, bom, package = generate(folder)
        valid = verify_package(manifest, bom, package,
                               public_key_path=public, current_version='1.0.0')
        assert valid['verified'] and valid['files'] == 2
        print('  OK — корректная подпись, SHA-256 ZIP, SBOM и версии зависимостей')
        core = UpdateCore(public_key_path=public, current_version='1.0.0')
        offline = core.prepare_offline(Path(folder) / 'manifest.json')
        assert offline['verified']
        print('  OK — проверка офлайн-пакета')
        forged = dict(manifest, version='99.0.0')
        assert_rejected(lambda: verify_manifest(forged, public_key_path=public),
                        'подмена манифеста')
        wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        other_path = Path(folder) / 'other.pem'
        other_path.write_bytes(wrong_key)
        assert_rejected(lambda: verify_manifest(manifest, public_key_path=other_path),
                        'чужой ключ')
        assert_rejected(lambda: verify_package(manifest, bom + b' ', package, public_key_path=public),
                        'изменённый SBOM')
        assert_rejected(lambda: verify_package(manifest, bom, package, current_version='1.0.1', public_key_path=public),
                        'нет новой версии')
        original = package.read_bytes()
        package.write_bytes(original + b'TAMPER')
        assert_rejected(lambda: verify_package(manifest, bom, package, public_key_path=public),
                        'изменённый ZIP')
        package.write_bytes(original)
        bad_sbom = json.loads(bom)
        bad_sbom['components'][0]['version'] = '0.0.1'
        bad_raw = json.dumps(bad_sbom).encode()
        from updater import validate_sbom
        assert_rejected(lambda: validate_sbom(bad_raw, package, '1.0.1'),
                        'несовпадение зависимостей SBOM')
        # Network simulation uses exactly the endpoint layout of server stage 1.
        import updater
        updater.APP_DATA_DIR = Path(folder) / 'appdata'
        updater.UPDATE_CACHE = updater.APP_DATA_DIR / 'updates'
        updater.AUDIT_PATH = updater.APP_DATA_DIR / 'audit.jsonl'

        class FakeResponse:
            def __init__(self, value, code=200):
                self.content = value
                self.status_code = code
            def iter_content(self, chunk_size=1024):
                for pos in range(0, len(self.content), chunk_size):
                    yield self.content[pos:pos+chunk_size]
            def close(self):
                pass

        class FakeSession:
            def __init__(self):
                self.reports = []
                self.downloads = 0
            def get(self, url, headers=None, params=None, **kwargs):
                assert headers['Authorization'] == 'Bearer jwt-test'
                if url.endswith('/updates/check'):
                    assert params['version'] == '1.0.0'
                    return FakeResponse(json.dumps({
                        'update_available': True, 'version': '1.0.1',
                        'min_supported': '1.0.0', 'download_token': 'once-xyz',
                    }).encode())
                if url.endswith('/updates/manifest/1.0.1'):
                    return FakeResponse(json.dumps(manifest).encode())
                if url.endswith('/updates/sbom/1.0.1.json'):
                    return FakeResponse(bom)
                if url.endswith('/updates/download/1.0.1'):
                    assert headers['X-Download-Token'] == 'once-xyz'
                    self.downloads += 1
                    assert self.downloads == 1
                    return FakeResponse(package.read_bytes())
                raise AssertionError('Unexpected URL: ' + url)
            def post(self, url, json=None, **kwargs):
                assert url.endswith('/updates/report')
                self.reports.append(json)
                return FakeResponse(b'{}')

        mock = FakeSession()
        online = UpdateCore(server_url='http://127.0.0.1:5000',
                            public_key_path=public, current_version='1.0.0', session=mock)
        online_result = online.prepare_online('jwt-test')
        assert online_result['verified']
        assert Path(online_result['package']).exists()
        assert mock.reports[-1]['status'] == 'verified'
        print('  OK — онлайн API: check, manifest, SBOM, one-time download token, verified audit')
        print('OK: все проверки этапа 2 пройдены')

if __name__ == '__main__':
    main()
