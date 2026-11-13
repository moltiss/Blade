"""Windows-only build: signed Blade --onedir + external BladeUpdater + SBOM.

Run in a dedicated Windows venv, using keys stored outside PreEncryption.
Creates an installation bootstrap and an Ed25519-signed update package.
Never ships private keys or the user's SQLite database, JWT secret or logs.
"""
import argparse
import base64
import configparser
import hashlib
import importlib.metadata as md
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / 'client'
TOOLS = ROOT / 'tools'
DEP_NAMES = ['cryptography', 'requests', 'PySide6', 'PySide6-Addons',
             'PySide6-Essentials', 'shiboken6', 'certifi',
             'charset-normalizer', 'idna', 'urllib3', 'cffi', 'pycparser']


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def sha_file(path):
    dig = hashlib.sha256()
    with Path(path).open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            dig.update(part)
    return dig.hexdigest()


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def payload(manifest):
    return json.dumps({k:v for k,v in manifest.items() if k != 'signature'},
                      sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def build(args):
    if sys.platform != 'win32':
        raise SystemExit('Blade.exe надо собирать непосредственно в Windows (PyInstaller не кросс-компилятор)')
    import re
    if not re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)', args.version):
        raise SystemExit('Укажите версию Major.Minor.Patch')
    ecdsa = args.ecdsa_key.resolve()
    ed = args.ed25519_key.resolve(strict=True)
    if ecdsa.is_relative_to(ROOT.resolve()) or ed.is_relative_to(ROOT.resolve()):
        raise SystemExit('Закрытые ключи должны храниться ВНЕ проекта')
    private = serialization.load_pem_private_key(ed.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise SystemExit('Ключ обновлений должен быть Ed25519')
    if public_bytes(private) != (CLIENT / 'update_public.pem').read_bytes():
        raise SystemExit('Ed25519 закрытый ключ не соответствует встроенному доверенному ключу')

    from importlib.util import find_spec
    if find_spec('PyInstaller') is None:
        raise SystemExit('Установите pyinstaller: py -m pip install pyinstaller')

    locked = {}
    for name in DEP_NAMES:
        try:
            locked[name] = md.version(name)
        except md.PackageNotFoundError:
            if name in ('cryptography', 'requests', 'PySide6'):
                raise SystemExit(f'Не установлена библиотека: {name}')
    req = ''.join(f'{k}=={v}\n' for k,v in sorted(locked.items(),key=lambda p:p[0].lower()))
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': 'Blade', 'version': args.version}},
            'components': [{'type':'library','name':k,'version':v,
                            'purl':f'pkg:pypi/{k.lower()}@{v}'} for k,v in locked.items()]}
    # For more extensive SBOMs, also export `cyclonedx-py environment` from this venv.
    sbom_raw = (json.dumps(sbom,ensure_ascii=False,indent=2)+'\n').encode('utf-8')

    build_root = ROOT / 'build' / ('v' + args.version)
    release = ROOT / 'release' / args.version
    if release.exists():
        raise SystemExit(f'Папка {release} существует — сборка не перезаписывается')
    build_root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='blade-src-', dir=build_root) as tmp:
        src = Path(tmp)
        for item in CLIENT.iterdir():
            if item.is_file() and item.suffix in ('.py','.ini','.json','.sig','.pem'):
                shutil.copy2(item,src / item.name)
        cfg = configparser.ConfigParser()
        cfg.read(src / 'config.ini', encoding='utf-8')
        cfg['client']['app_version'] = args.version
        cfg['client']['build_date'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        with (src / 'config.ini').open('w',encoding='utf-8') as f:
            cfg.write(f)
        subprocess.run([sys.executable, str(TOOLS / 'sign_release.py'),
                        '--client',str(src),'--key',str(ecdsa)] +
                       (['--init-key'] if args.init_ecdsa_key else []),check=True)
        dist = build_root / 'dist'
        work = build_root / 'work'
        spec = build_root / 'spec'
        data_files = ['config.ini','integrity_manifest.json','integrity_manifest.sig',
                      'developer_public.pem','update_public.pem',
                      'main.py','auth.py','encryption.py','settings.py','integrity.py',
                      'updater.py','update_ui.py','install_core.py']
        app_cmd = [sys.executable,'-m','PyInstaller','--noconfirm','--clean',
                   '--onedir','--windowed','--name','Blade',
                   '--distpath',str(dist),'--workpath',str(work/'app'),
                   '--specpath',str(spec), '--paths',str(src)]
        for name in data_files:
            app_cmd += ['--add-data',str(src / name) + os.pathsep + '.']
        app_cmd += [str(src / 'main.py')]
        subprocess.run(app_cmd,check=True)

        helper_cmd = [sys.executable,'-m','PyInstaller','--noconfirm','--clean',
                      '--onefile','--console','--name','BladeUpdater',
                      '--distpath',str(dist),'--workpath',str(work/'helper'),
                      '--specpath',str(spec), '--paths',str(src)]
        for name in ('config.ini','update_public.pem'):
            helper_cmd += ['--add-data', str(src / name) + os.pathsep + '.']
        helper_cmd += [str(TOOLS / 'installer_helper.py')]
        subprocess.run(helper_cmd, check=True)
        app_dir = dist / 'Blade'
        helper_exe = dist / 'BladeUpdater.exe'
        if not (app_dir / 'Blade.exe').is_file() or not helper_exe.is_file():
            raise SystemExit('Не создан Blade.exe или BladeUpdater.exe')
        release.mkdir(parents=True)
        package_name = f'Blade-{args.version}-windows-x64.zip'
        package = release / package_name
        with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for item in sorted(app_dir.rglob('*')):
                if item.is_file():
                    archive.write(item,item.relative_to(app_dir).as_posix())
            archive.writestr('requirements.txt',req)
        (release/'sbom.json').write_bytes(sbom_raw)
        manifest = {'version':args.version,'min_supported':args.min_supported,
                    'release_date':datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'),
                    'os':'windows','arch':'x64',
                    'package_url':f'/updates/download/{args.version}',
                    'package_filename':package_name,
                    'package_size':package.stat().st_size,
                    'package_sha256':sha_file(package),
                    'sbom':{'format':'CycloneDX-1.5','url':f'/updates/sbom/{args.version}.json',
                            'sha256':sha(sbom_raw)},'critical':False}
        manifest['signature'] = base64.b64encode(private.sign(payload(manifest))).decode('ascii')
        (release/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        bootstrap = release / 'first_install'
        shutil.copytree(app_dir, bootstrap / 'app')
        shutil.copy2(helper_exe, bootstrap / 'BladeUpdater.exe')
        print('ГОТОВО:',release)
        print('ПЕРВИЧНАЯ УСТАНОВКА:',bootstrap)
        print('SIGNED OFFLINE:',release/'manifest.json')
        print('Не копируйте tools, ключи, server, storage и исходники в папку установки!')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Собрать подписанный релиз Blade для Windows x64')
    p.add_argument('--version',required=True)
    p.add_argument('--min-supported',default='1.0.0')
    p.add_argument('--ecdsa-key',type=Path,required=True)
    p.add_argument('--ed25519-key',type=Path,required=True)
    p.add_argument('--init-ecdsa-key',action='store_true')
    build(p.parse_args())
