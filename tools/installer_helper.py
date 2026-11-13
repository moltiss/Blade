"""External Windows updater, packaged as BladeUpdater.exe via PyInstaller.

This executable stays OUTSIDE app/ so Blade.exe can be replaced while closed.
It re-verifies signed release materials with its embedded Ed25519 public key.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Source-mode support for tests; PyInstaller bundles client modules via --paths.
if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'client'))
from install_core import apply_update, recover_interrupted
from updater import UpdateError, TRUSTED_UPDATE_KEY, APP_DATA_DIR, queue_installed_report


def wait_for_parent(pid, timeout=45):
    if pid <= 0:
        return
    if os.name == 'nt':
        # On Windows, os.kill(pid, 0) can terminate the process: NEVER use it.
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            # Process may already be gone; replacement will still retry on locked files.
            return
        try:
            result = kernel.WaitForSingleObject(handle, int(timeout * 1000))
            if result != 0:  # WAIT_OBJECT_0 = 0
                raise UpdateError('Blade не завершился: установка отменена')
        finally:
            kernel.CloseHandle(handle)
    else:
        until = time.monotonic() + timeout
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                pass
            if time.monotonic() >= until:
                raise UpdateError('Blade не завершился: установка отменена')
            time.sleep(0.2)


def startup_check(exe, timeout):
    health_dir = APP_DATA_DIR / 'health'
    health_dir.mkdir(parents=True, exist_ok=True)
    import secrets
    marker = health_dir / (secrets.token_hex(16) + '.ready')
    nonce = secrets.token_hex(16)
    try:
        proc = subprocess.Popen([str(exe), '--update-health-check', str(marker), nonce],
                                cwd=str(exe.parent), close_fds=True)
    except OSError:
        return False
    healthy = False
    try:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if proc.poll() is not None:
                return False
            if marker.is_file():
                try:
                    body = json.loads(marker.read_text(encoding='utf-8'))
                    if body.get('nonce') == nonce and body.get('status') == 'ready' and proc.poll() is None:
                        healthy = True
                        return True
                except (ValueError, OSError):
                    pass
            time.sleep(0.3)
        return False
    finally:
        marker.unlink(missing_ok=True)
        if proc.poll() is not None:
            pass
        elif not healthy:
            proc.terminate()
            try: proc.wait(timeout=8)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=8)


def main():
    parser = argparse.ArgumentParser(description='Blade — доверенный внешний установщик')
    parser.add_argument('--install-root', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--sbom', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--from-version', required=True)
    parser.add_argument('--parent-pid', type=int, default=0)
    parser.add_argument('--source', choices=('online', 'offline'), default='offline')
    args = parser.parse_args()
    try:
        wait_for_parent(args.parent_pid)
        if recover_interrupted(args.install_root):
            print('Предыдущий прерванный swap восстановлен; повторите установку')
            return 2
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        sbom = args.sbom.read_bytes()
        result = apply_update(args.install_root, args.package, manifest, sbom,
                              old_version=args.from_version,
                              trusted_public_key=TRUSTED_UPDATE_KEY,
                              launch_check=startup_check)
        if args.source == 'online':
            queue_installed_report(args.from_version, result['version'])
        print('Установлено:', result['version'])
        return 0
    except (UpdateError, OSError, ValueError, json.JSONDecodeError) as exc:
        print('Ошибка обновления:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
