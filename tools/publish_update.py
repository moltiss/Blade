"""Developer-only offline publisher: ZIP + CycloneDX SBOM -> signed release.

Run from the `tools` directory. Never expose this tool as a public REST endpoint.
"""
import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "server"
sys.path.insert(0, str(SERVER))
from database import get_connection
from update_service import (RELEASE_ROOT, PUBLIC_KEY_PATH, init_update_tables,
                            parse_version, manifest_payload, sha256, verify_manifest,
                            OS_VALUES, ARCH_VALUES)


def publish(args):
    version = args.version
    parse_version(version)
    parse_version(args.min_supported)
    if parse_version(args.min_supported) > parse_version(version):
        raise ValueError("min_supported не может быть выше версии релиза")
    if args.os not in OS_VALUES or args.arch not in ARCH_VALUES:
        raise ValueError("Неподдерживаемые os/arch")
    package = args.package.resolve(strict=True)
    sbom_path = args.sbom.resolve(strict=True)
    private_path = args.private.resolve(strict=True)
    if private_path.is_relative_to(HERE.parent.resolve()):
        raise ValueError("Приватный ключ обновлений должен лежать вне проекта")
    if not package.is_file() or not sbom_path.is_file():
        raise ValueError("Пакет и SBOM должны быть файлами")
    # Only publish actual ZIP archives with no path traversal or links.
    try:
        with ZipFile(package) as archive:
            items = archive.infolist()
            if not items or len(items) > 20000:
                raise ValueError("ZIP пуст или слишком много файлов")
            for item in items:
                name = item.filename.replace('\\', '/')
                parts = name.split('/')
                if name.startswith('/') or any(p in ('', '.', '..') for p in parts if p != parts[-1]) or '..' in parts or ':' in name:
                    raise ValueError(f"Небезопасный путь ZIP: {name}")
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError(f"Символьная ссылка в ZIP запрещена: {name}")
    except BadZipFile as exc:
        raise ValueError("Неверный ZIP-пакет") from exc
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    if (sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5" or
            not isinstance(sbom.get("components", []), list)):
        raise ValueError("Ожидается SBOM CycloneDX-1.5")
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Ожидается закрытый ключ Ed25519")
    if not PUBLIC_KEY_PATH.is_file():
        raise ValueError(f"Сначала создайте открытый ключ: {PUBLIC_KEY_PATH}")
    expected_public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
    if PUBLIC_KEY_PATH.read_bytes() != expected_public:
        raise ValueError("Закрытый ключ не соответствует доверенному открытому ключу сервера")

    filename = f"Blade-{version}-{args.os}-{args.arch}.zip"
    manifest = {
        "version": version, "min_supported": args.min_supported,
        "release_date": datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z'),
        "os": args.os, "arch": args.arch,
        "package_url": f"/updates/download/{version}",
        "package_filename": filename,
        "package_size": package.stat().st_size,
        "package_sha256": sha256(package),
        "sbom": {"format": "CycloneDX-1.5",
                 "url": f"/updates/sbom/{version}.json", "sha256": sha256(sbom_path)},
        "critical": bool(args.critical),
    }
    manifest["signature"] = base64.b64encode(key.sign(manifest_payload(manifest))).decode("ascii")
    verify_manifest(manifest)
    RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
    target_dir = RELEASE_ROOT / version
    if target_dir.exists():
        raise ValueError(f"Релиз {version} уже существует; перезапись запрещена")
    with get_connection() as connection:
        if connection.execute("SELECT 1 FROM releases WHERE version=?", (version,)).fetchone():
            raise ValueError("Версия уже есть в БД")
    with tempfile.TemporaryDirectory(prefix='.staging-', dir=RELEASE_ROOT) as temp:
        staging = Path(temp) / 'release'
        staging.mkdir()
        shutil.copyfile(package, staging / filename)
        shutil.copyfile(sbom_path, staging / 'sbom.json')
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        # All files are verified before publishing.
        if sha256(staging / filename) != manifest['package_sha256'] or sha256(staging / 'sbom.json') != manifest['sbom']['sha256']:
            raise ValueError("Ошибка копирования файлов релиза")
        os.replace(staging, target_dir)
    try:
        init_update_tables()
        with get_connection() as connection:
            connection.execute("""INSERT INTO releases
                (version,os,arch,min_supported,critical,package_path,package_sha256,
                 manifest_path,sbom_path,signature,created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (version, args.os, args.arch, args.min_supported, int(bool(args.critical)),
                 f"{version}/{filename}", manifest['package_sha256'],
                 f"{version}/manifest.json", f"{version}/sbom.json",
                 manifest['signature'], manifest['release_date']))
    except BaseException:
        shutil.rmtree(target_dir)
        raise
    print(f"Релиз {version} опубликован: {target_dir}")
    print("SHA-256 ZIP:", manifest['package_sha256'])
    print("Ed25519 подпись манифеста проверена")


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Публикация подписанного релиза Blade')
    p.add_argument('--version', required=True)
    p.add_argument('--min-supported', required=True)
    p.add_argument('--os', default='windows', choices=sorted(OS_VALUES))
    p.add_argument('--arch', default='x64', choices=sorted(ARCH_VALUES))
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--sbom', type=Path, required=True)
    p.add_argument('--private', type=Path, required=True)
    p.add_argument('--critical', action='store_true')
    try:
        publish(p.parse_args())
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as e:
        p.error(str(e))
