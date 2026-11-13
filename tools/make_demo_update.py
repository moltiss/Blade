"""Developer-only example release for PZ4 stage-2 verification.

DEMO ZIP intentionally does not contain an EXE and MUST NOT be installed.
Uses exactly the same signature rules as the stage-1 publisher.
"""
import argparse
import base64
import hashlib
import importlib.metadata
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha(data):
    return hashlib.sha256(data).hexdigest()


def payload(data):
    return json.dumps({k: v for k, v in data.items() if k != 'signature'},
                      sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description='Создать безопасный учебный пакет Blade без exe')
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--version', default='1.0.1')
    parser.add_argument('--min-supported', default='1.0.0')
    args = parser.parse_args()
    if not args.version.replace('.', '').isdigit() or len(args.version.split('.')) != 3:
        parser.error('Версия должна быть Major.Minor.Patch')
    key = serialization.load_pem_private_key(args.private.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        parser.error('Требуется закрытый Ed25519 ключ')

    folder = args.out.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    version = args.version
    filename = f'Blade-{version}-windows-x64.zip'
    zip_path = folder / filename
    names = ('cryptography', 'requests', 'PySide6')
    locked = {}
    for name in names:
        try:
            locked[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            parser.error(f'Установи библиотеку в среду сборки: {name}')
    requirements = ''.join(f'{name}=={v}\n' for name, v in locked.items())
    with ZipFile(zip_path, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('README.txt', 'DEMO ONLY. This ZIP is NOT an installable Blade release.\n')
        archive.writestr('requirements.txt', requirements)
    sbom = {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': 'Blade', 'version': version}},
        'components': [
            {'type': 'library', 'name': name, 'version': v,
             'purl': f'pkg:pypi/{name.lower()}@{v}'}
            for name, v in locked.items()
        ],
    }
    sbom_raw = (json.dumps(sbom, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    (folder / 'sbom.json').write_bytes(sbom_raw)
    zip_raw = zip_path.read_bytes()
    manifest = {
        'version': version, 'min_supported': args.min_supported,
        'release_date': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'),
        'os': 'windows', 'arch': 'x64',
        'package_url': f'/updates/download/{version}',
        'package_filename': filename,
        'package_size': len(zip_raw), 'package_sha256': sha(zip_raw),
        'sbom': {'format': 'CycloneDX-1.5',
                 'url': f'/updates/sbom/{version}.json', 'sha256': sha(sbom_raw)},
        'critical': False,
    }
    manifest['signature'] = base64.b64encode(key.sign(payload(manifest))).decode('ascii')
    (folder / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Демо-пакет для ПРОВЕРКИ создан в:', folder)
    print('Этот ZIP не содержит EXE и НЕ предназначен для установки.')
    print('Для офлайн-режима выбери:', folder / 'manifest.json')


if __name__ == '__main__':
    main()
