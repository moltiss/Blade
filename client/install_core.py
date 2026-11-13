"""Blade release replacement engine. Run ONLY in an independent updater process.

The signed package is verified AGAIN immediately before touching the installation.
`app` and `backup` are siblings on the same volume for atomic directory renames.
No credentials, private signing keys or application database are touched.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from updater import (UpdateError, verify_package, validate_zip_package,
                     MAX_ARCHIVE_UNPACKED, write_local_audit)


def _audit(status, old_version, new_version, detail):
    write_local_audit(status, old_version, new_version, detail)


def _no_symlink(path: Path):
    if path.is_symlink():
        raise UpdateError(f"Запрещена символическая ссылка: {path}")


def _archive_layout(package: Path):
    """Only full PyInstaller --onedir Windows releases may be installed."""
    with zipfile.ZipFile(package) as z:
        names = set(z.namelist())
        if "Blade.exe" not in names or not any(n.startswith("_internal/") and not n.endswith("/") for n in names):
            raise UpdateError("В ZIP нет Blade.exe и _internal/: это проверочный, не установочный пакет")
        if "requirements.txt" not in names:
            raise UpdateError("Не хватает requirements.txt в установочном пакете")


def _extract_safe(package: Path, stage: Path):
    """Explicit extraction with limits and no path traversal or link traversal."""
    validate_zip_package(package)
    written = 0
    with zipfile.ZipFile(package) as archive:
        for entry in archive.infolist():
            rel = entry.filename.rstrip("/")
            target = stage.joinpath(*rel.split("/"))
            if not target.resolve().is_relative_to(stage.resolve()):
                raise UpdateError("ZIP содержит выход за границы staging")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # Stage is created empty by the installer, and no existing links are followed.
            with archive.open(entry) as src, target.open("xb") as dest:
                while True:
                    block = src.read(1024 * 1024)
                    if not block:
                        break
                    written += len(block)
                    if written > MAX_ARCHIVE_UNPACKED:
                        raise UpdateError("Распакованный ZIP слишком большой")
                    dest.write(block)
    _archive_layout(package)
    if not (stage / "Blade.exe").is_file():
        raise UpdateError("После распаковки Blade.exe отсутствует")



# Windows may keep handles open briefly after the GUI process has exited.
# Retry only sharing/lock errors; never suppress a lasting access failure.
def _replace_with_retry(source: Path, destination: Path, *, wait_seconds=45.0):
    deadline = time.monotonic() + wait_seconds
    attempts = 0
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            # ERROR_SHARING_VIOLATION=32, ERROR_LOCK_VIOLATION=33,
            # ERROR_ACCESS_DENIED=5 (sometimes transient during process exit).
            transient = os.name == "nt" and getattr(exc, "winerror", None) in (5, 32, 33)
            if not transient:
                raise
            attempts += 1
            if time.monotonic() >= deadline:
                raise UpdateError(
                    f"Windows удерживает {source} (WinError {exc.winerror}). "
                    f"Не удалось переименовать за {wait_seconds:g} с; "
                    f"попыток: {attempts}. Закройте все экземпляры Blade "
                    f"и проверьте блокирующие процессы."
                ) from exc
            time.sleep(0.3)


def recover_interrupted(root):
    """Restore the previous app if the process died between the two renames."""
    root = Path(root).resolve()
    app, backup = root / "app", root / "backup"
    if backup.exists() and not app.exists():
        _no_symlink(backup)
        _replace_with_retry(backup, app)
        return True
    return False


def apply_update(root, package, manifest, sbom, *, old_version,
                 trusted_public_key, launch_check, timeout=45):
    """Apply verified release. `launch_check(exe, timeout)` must report readiness.

    `launch_check` belongs to the separate helper; it must terminate the failed
    new process before reporting False (needed on Windows to unlock EXE files).
    """
    root = Path(root).resolve(strict=True)
    app, backup, stage = root / "app", root / "backup", root / "staging"
    lock = root / ".blade-update.lock"
    if not root.is_dir() or not app.is_dir() or not (app / "Blade.exe").is_file():
        raise UpdateError("Обновления разрешены только для установленного Blade.exe в папке app")
    for obj in (root, app, root / "BladeUpdater.exe"):
        _no_symlink(obj)
    if stage.exists() or backup.exists():
        # Never destroy possible recovery data from a previous interrupted update.
        raise UpdateError("Найдены staging/ или backup/: сначала проверьте состояние предыдущего обновления")
    try:
        fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(str(os.getpid()))
    except FileExistsError as exc:
        raise UpdateError("Другой установщик уже выполняется (или остался .blade-update.lock)") from exc

    swapped = False
    incoming = False
    new_version = manifest.get("version") if isinstance(manifest, dict) else None
    try:
        if not isinstance(sbom, (bytes, bytearray)):
            raise UpdateError("Некорректные данные SBOM")
        # Check signed metadata on the exact package that will be extracted.
        verify_package(manifest, sbom, package, current_version=old_version,
                       public_key_path=trusted_public_key)
        _archive_layout(Path(package))
        # staging and app must live on the same filesystem.
        stage.mkdir(mode=0o700)
        _extract_safe(Path(package), stage)
        # Recheck hash and signature, mitigating changed source ZIP during extract.
        verify_package(manifest, sbom, package, current_version=old_version,
                       public_key_path=trusted_public_key)
        _audit("verified", old_version, new_version, "installer: payload verified")

        # First rename is atomic, then second is atomic (recovery handles crash gap).
        _replace_with_retry(app, backup)
        swapped = True
        try:
            _replace_with_retry(stage, app)
            incoming = True
        except BaseException:
            if backup.exists() and not app.exists():
                _replace_with_retry(backup, app)
            swapped = False
            raise

        if not launch_check(app / "Blade.exe", timeout):
            raise UpdateError("Новая версия не прошла проверку запуска: выполняется откат")

        # Once readiness is confirmed, never roll back just because cleanup fails.
        swapped = False
        try:
            shutil.rmtree(backup)
            cleanup_note = "startup health check OK"
        except OSError as cleanup_error:
            # Keep original backup for manual cleanup; no data is destroyed.
            cleanup_note = f"startup OK; backup retained: {cleanup_error}"
        _audit("installed", old_version, new_version, cleanup_note)
        return {"status": "installed", "version": new_version}
    except BaseException as original:
        if swapped:
            try:
                if app.exists():
                    failed_dir = root / (".failed-" + secrets.token_hex(5))
                    _replace_with_retry(app, failed_dir)
                    _replace_with_retry(backup, app)
                    shutil.rmtree(failed_dir, ignore_errors=True)
                elif backup.exists():
                    _replace_with_retry(backup, app)
                _audit("rolled_back", old_version, new_version, str(original))
            except Exception as rollback_exc:
                _audit("failed", old_version, new_version,
                       f"ОТКАТ НЕ ЗАВЕРШЁН: {rollback_exc}; исходная ошибка: {original}")
                raise UpdateError("Ошибка отката: вручную восстановите app из backup; данные не удаляйте") from rollback_exc
        else:
            _audit("failed", old_version, new_version, str(original))
        if isinstance(original, UpdateError):
            raise
        raise UpdateError(f"Установка прервана: {original}") from original
    finally:
        # Do not remove recovery evidence if an operation after swap failed.
        if not swapped and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        try:
            lock.unlink(missing_ok=True)
        except OSError:
            pass
