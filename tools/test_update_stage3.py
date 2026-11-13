"""Safe filesystem tests: work ONLY in fresh TemporaryDirectory, never in user's Blade."""
import base64
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'client'))
import updater
from updater import canonical_manifest_bytes, platform_info, verify_package, UpdateError
from install_core import apply_update, recover_interrupted


def fixtures(parent, version='1.1.0', minimum='1.0.0'):
    private = Ed25519PrivateKey.generate()
    public = parent / 'public.pem'
    public.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    system, arch = platform_info()
    filename = f'Blade-{version}-{system}-{arch}.zip'
    package = parent / filename
    libs = {'cryptography':'50.0.1','requests':'2.32.5','pyside6':'6.10.0'}
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('Blade.exe',b'NEW EXECUTABLE TEST')
        z.writestr('_internal/info.txt',b'v1.1.0')
        z.writestr('requirements.txt',''.join(f'{k}=={v}\n' for k,v in libs.items()))
    sbom = {'bomFormat':'CycloneDX','specVersion':'1.5',
            'metadata':{'component':{'type':'application','name':'Blade','version':version}},
            'components':[{'type':'library','name':k,'version':v} for k,v in libs.items()]}
    sbom_raw = json.dumps(sbom).encode()
    manifest = {'version':version,'min_supported':minimum,'os':system,'arch':arch,
                'package_filename':filename,'package_size':package.stat().st_size,
                'package_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),
                'sbom':{'format':'CycloneDX-1.5','sha256':hashlib.sha256(sbom_raw).hexdigest()}}
    manifest['signature'] = base64.b64encode(private.sign(canonical_manifest_bytes(manifest))).decode()
    return public, package, manifest, sbom_raw


def root_for(parent):
    root = parent / 'installed'
    (root / 'app' / '_internal').mkdir(parents=True)
    (root / 'app' / 'Blade.exe').write_bytes(b'OLD EXECUTABLE')
    (root / 'app' / '_internal' / 'info.txt').write_bytes(b'v1.0.0')
    return root


def rejected(fn, what):
    try:
        fn()
    except UpdateError as exc:
        print('OK denied:', what, '|', str(exc)[:90])
        return
    raise AssertionError('MUST reject: '+what)


def run():
    with tempfile.TemporaryDirectory(prefix='blade-stage3-test-') as d:
        home = Path(d)
        updater.AUDIT_PATH = home / 'audit.jsonl'
        key, pkg, manifest, sbom = fixtures(home)
        root = root_for(home)
        result=apply_update(root,pkg,manifest,sbom,old_version='1.0.0',
                            trusted_public_key=key,launch_check=lambda exe,t: True)
        assert result['status']=='installed'
        assert (root/'app'/'Blade.exe').read_bytes()==b'NEW EXECUTABLE TEST'
        assert not (root/'backup').exists() and not (root/'staging').exists()
        print('OK: installed and cleaned backup')
        shutil_root=root
        import shutil
        shutil.rmtree(shutil_root)
        root = root_for(home)
        rejected(lambda:apply_update(root,pkg,manifest,sbom,old_version='1.0.0',
                    trusted_public_key=key,launch_check=lambda exe,t: False),'startup failed; rollback')
        assert (root/'app'/'Blade.exe').read_bytes()==b'OLD EXECUTABLE'
        assert not (root/'backup').exists() and not (root/'staging').exists()
        print('OK: automatic rollback restored old app')
        changed=dict(manifest,version='2.0.0')
        rejected(lambda:apply_update(root,pkg,changed,sbom,old_version='1.0.0',
                    trusted_public_key=key,launch_check=lambda exe,t: True),'tampered manifest')
        assert (root/'app'/'Blade.exe').read_bytes()==b'OLD EXECUTABLE'
        old_bytes=pkg.read_bytes()
        pkg.write_bytes(old_bytes+b'X')
        rejected(lambda:apply_update(root,pkg,manifest,sbom,old_version='1.0.0',
                    trusted_public_key=key,launch_check=lambda exe,t: True),'tampered ZIP')
        pkg.write_bytes(old_bytes)
        rejected(lambda:apply_update(root,pkg,manifest,sbom+b' ',old_version='1.0.0',
                    trusted_public_key=key,launch_check=lambda exe,t: True),'tampered SBOM')
        shutil.rmtree(root/'app')
        (root/'backup').mkdir()
        (root/'backup'/'Blade.exe').write_bytes(b'OLD EXECUTABLE')
        assert recover_interrupted(root)
        assert (root/'app'/'Blade.exe').read_bytes()==b'OLD EXECUTABLE'
        print('OK: crash-gap restore from backup')
        audit=(home/'audit.jsonl').read_text(encoding='utf-8')
        assert '"installed"' in audit and '"rolled_back"' in audit
        print('OK: audit records installed and rolled_back')
    print('PASS: Stage 3 installer filesystem tests completed')

if __name__=='__main__': run()
