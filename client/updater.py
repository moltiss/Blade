"""Blade PZ4 stage 2: authenticated online/offline update verification.

No file installation occurs here. All release data is untrusted until verified
against the built-in Ed25519 key and SHA-256. No private keys are used here.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from settings import SERVER_URL, REQUEST_TIMEOUT, APP_VERSION

CLIENT_DIR = Path(__file__).resolve().parent
TRUSTED_UPDATE_KEY = CLIENT_DIR / "update_public.pem"
APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".cache")) / "Blade"
UPDATE_CACHE = APP_DATA_DIR / "updates"
AUDIT_PATH = APP_DATA_DIR / "update_audit.jsonl"
PENDING_REPORTS = APP_DATA_DIR / "pending_update_reports.jsonl"
MAX_PACKAGE_SIZE = 1024 * 1024 * 1024  # 1 GiB
MAX_SBOM_SIZE = 8 * 1024 * 1024         # 8 MiB
MAX_ARCHIVE_FILES = 20000
MAX_ARCHIVE_UNPACKED = 2 * 1024 * 1024 * 1024
VERSION_RE = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
HASH_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
PKG_FILENAME_RE = re.compile(r"Blade-(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)-(?:windows|linux|macos)-(?:x86|x64|arm64)\.zip\Z")
KEY_DEPENDENCIES = frozenset(("cryptography", "requests", "pyside6"))


class UpdateError(Exception):
    def __init__(self, message, *, status="failed", auth_expired=False):
        super().__init__(message)
        self.status = status
        self.auth_expired = auth_expired


def version_tuple(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise UpdateError("Неверный формат версии (нужно Major.Minor.Patch)")
    return tuple(map(int, value.split(".")))


def platform_info():
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
    cpu = platform.machine().lower()
    cpu_name = {"amd64": "x64", "x86_64": "x64", "i386": "x86", "i686": "x86",
                "x86": "x86", "arm64": "arm64", "aarch64": "arm64"}.get(cpu)
    if not os_name or not cpu_name:
        raise UpdateError(f"Неподдерживаемая платформа: {platform.system()} / {cpu}")
    return os_name, cpu_name


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical_manifest_bytes(manifest):
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def verify_manifest(manifest, *, current_version=APP_VERSION,
                    public_key_path=TRUSTED_UPDATE_KEY):
    """Fail closed: validate Ed25519 signature BEFORE trusting any manifest values."""
    if not isinstance(manifest, dict):
        raise UpdateError("Манифест не является JSON-объектом")
    try:
        signature_text = manifest["signature"]
        if not isinstance(signature_text, str):
            raise ValueError("Тип подписи")
        signature = base64.b64decode(signature_text, validate=True)
        public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("Неверный алгоритм ключа обновлений")
        public.verify(signature, canonical_manifest_bytes(manifest))
    except (KeyError, ValueError, OSError, InvalidSignature, TypeError) as exc:
        raise UpdateError("Подпись Ed25519 недействительна или нет доверенного ключа") from exc

    version = manifest.get("version")
    min_supported = manifest.get("min_supported")
    version_tuple(version)
    version_tuple(min_supported)
    if version_tuple(version) <= version_tuple(current_version):
        raise UpdateError("Версия пакета не новее установленного Blade")
    if version_tuple(min_supported) > version_tuple(current_version):
        raise UpdateError("Обновление несовместимо: требуется ручная установка с нуля")
    os_name, cpu = platform_info()
    if manifest.get("os") != os_name or manifest.get("arch") != cpu:
        raise UpdateError("Обновление предназначено для другой ОС или архитектуры")
    filename = manifest.get("package_filename")
    if not isinstance(filename, str) or not PKG_FILENAME_RE.fullmatch(filename):
        raise UpdateError("Небезопасное или некорректное имя пакета")
    if filename != f"Blade-{version}-{os_name}-{cpu}.zip":
        raise UpdateError("Имя ZIP не соответствует версии и платформе")
    size = manifest.get("package_size")
    if type(size) is not int or not (0 < size <= MAX_PACKAGE_SIZE):
        raise UpdateError("Размер ZIP отсутствует или превышает допустимый предел")
    if not isinstance(manifest.get("package_sha256"), str) or not HASH_RE.fullmatch(manifest["package_sha256"]):
        raise UpdateError("Неправильный SHA-256 ZIP-пакета")
    sbom = manifest.get("sbom")
    if (not isinstance(sbom, dict) or sbom.get("format") != "CycloneDX-1.5" or
        not isinstance(sbom.get("sha256"), str) or not HASH_RE.fullmatch(sbom["sha256"])):
        raise UpdateError("Неверный формат или SHA-256 SBOM")
    # Не выполняем переход по URL из недоверенного манифеста: адреса задаёт клиент.
    return manifest


def _normalize_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_sbom(sbom_data, package, version):
    """Verify signed-hash SBOM structure and key dep composition against ZIP's lock file.

    requirements.txt with exact pins for the key runtime libraries must ship at
    ZIP root. Thus metadata describes dependencies of the delivered archive,
    not just libraries installed on this machine.
    """
    if len(sbom_data) > MAX_SBOM_SIZE:
        raise UpdateError("SBOM слишком большой", status="sbom_mismatch")
    try:
        sbom = json.loads(sbom_data)
    except (ValueError, UnicodeError) as exc:
        raise UpdateError("SBOM не является корректным JSON", status="sbom_mismatch") from exc
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise UpdateError("SBOM должен быть CycloneDX версии 1.5", status="sbom_mismatch")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        raise UpdateError("В SBOM отсутствуют сведения о приложении", status="sbom_mismatch")
    component_meta = metadata.get("component")
    if not isinstance(component_meta, dict) or component_meta.get("version") != version:
        raise UpdateError("Версия приложения в SBOM не совпадает с релизом", status="sbom_mismatch")
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) > 20000:
        raise UpdateError("SBOM не содержит корректный список библиотек", status="sbom_mismatch")
    library_versions = {}
    for component in components:
        if not isinstance(component, dict):
            raise UpdateError("Повреждённые компоненты SBOM", status="sbom_mismatch")
        name, release = component.get("name"), component.get("version")
        if component.get("type") != "library" or not isinstance(name, str) or not isinstance(release, str):
            continue
        norm = _normalize_name(name)
        if norm in library_versions and library_versions[norm] != release:
            raise UpdateError(f"Противоречивые версии в SBOM: {name}", status="sbom_mismatch")
        library_versions[norm] = release

    try:
        with zipfile.ZipFile(package) as bundle:
            requirement_names = bundle.namelist()
            if "requirements.txt" not in requirement_names:
                raise UpdateError("В пакете нет requirements.txt с зафиксированными версиями", status="sbom_mismatch")
            info = bundle.getinfo("requirements.txt")
            if info.file_size > 1024 * 1024:
                raise UpdateError("requirements.txt слишком большой", status="sbom_mismatch")
            lines = bundle.read("requirements.txt").decode("utf-8-sig").splitlines()
    except (OSError, zipfile.BadZipFile, UnicodeError) as exc:
        raise UpdateError("Нельзя прочитать зависимости из ZIP", status="sbom_mismatch") from exc
    pinned = {}
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
        if not m:
            raise UpdateError("В requirements.txt зависимости должны иметь точные версии ==", status="sbom_mismatch")
        name = _normalize_name(m.group(1))
        if name in pinned and pinned[name] != m.group(2):
            raise UpdateError(f"Конфликт версий в requirements.txt: {name}", status="sbom_mismatch")
        pinned[name] = m.group(2)
    for dep in KEY_DEPENDENCIES:
        if dep not in pinned or dep not in library_versions:
            raise UpdateError(f"Не указана ключевая зависимость: {dep}", status="sbom_mismatch")
    for name, release in pinned.items():
        if library_versions.get(name) != release:
            raise UpdateError(f"Несовпадение SBOM и requirements.txt: {name}", status="sbom_mismatch")
    return {"components": len(library_versions), "key_dependencies":
            {dep: pinned[dep] for dep in sorted(KEY_DEPENDENCIES)}}


def validate_zip_package(package):
    """Metadata-only safe-archive inspection. We do NOT extract at stage 2."""
    try:
        with zipfile.ZipFile(package) as bundle:
            infos = bundle.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_FILES:
                raise UpdateError("ZIP пуст или содержит слишком много файлов")
            total_unpacked = 0
            seen = set()
            for entry in infos:
                name = entry.filename
                normalized = name.rstrip("/")
                parts = normalized.split("/")
                if (not normalized or name.startswith(("/", "\\")) or "\\" in name or
                    any(part in ("", ".", "..") for part in parts) or ":" in name or
                    name.startswith("__MACOSX/")):
                    raise UpdateError("В ZIP содержится небезопасный путь")
                if normalized.lower() in seen:
                    raise UpdateError("В ZIP повторяется имя файла")
                seen.add(normalized.lower())
                mode = (entry.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise UpdateError("Символические ссылки в ZIP запрещены")
                if entry.file_size > 0 and (entry.compress_size == 0 or
                        entry.file_size / max(entry.compress_size, 1) > 1500):
                    raise UpdateError("Слишком высокое сжатие ZIP — возможная ZIP-бомба")
                if entry.flag_bits & 0x1:
                    raise UpdateError("Зашифрованные ZIP-записи не поддерживаются")
                total_unpacked += entry.file_size
                if total_unpacked > MAX_ARCHIVE_UNPACKED:
                    raise UpdateError("Слишком большой распакованный пакет")
            # Sanity check local file headers + CRC without writing files to disk.
            bad = bundle.testzip()
            if bad is not None:
                raise UpdateError(f"CRC-ошибка файла в ZIP: {bad}")
            return len(infos)
    except (OSError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise UpdateError("Неверный или повреждённый ZIP-пакет") from exc


def verify_package(manifest, sbom_data, package, *, current_version=APP_VERSION, public_key_path=TRUSTED_UPDATE_KEY):
    verify_manifest(manifest, current_version=current_version, public_key_path=public_key_path)
    path = Path(package)
    if not path.is_file() or path.is_symlink():
        raise UpdateError("ZIP-пакет отсутствует либо является ссылкой")
    if path.stat().st_size != manifest["package_size"]:
        raise UpdateError("Размер ZIP-пакета не совпадает с манифестом")
    actual_hash = digest_file(path)
    if not hmac.compare_digest(actual_hash.lower(), manifest["package_sha256"].lower()):
        raise UpdateError("Ошибка SHA-256: ZIP-пакет изменён")
    if not hmac.compare_digest(digest_bytes(sbom_data).lower(), manifest["sbom"]["sha256"].lower()):
        raise UpdateError("Ошибка SHA-256: SBOM изменён", status="sbom_mismatch")
    count = validate_zip_package(path)
    dep_info = validate_sbom(sbom_data, path, manifest["version"])
    return {"version": manifest["version"], "min_supported": manifest["min_supported"],
            "package": str(path), "size": path.stat().st_size, "files": count,
            "sbom_components": dep_info["components"], "key_dependencies": dep_info["key_dependencies"],
            "verified": True, "installation_available": False}


def write_local_audit(status, from_version, to_version=None, detail=""):
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                 "status": status, "from_version": from_version,
                 "to_version": to_version, "detail": str(detail)[:300]}
        with AUDIT_PATH.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # Audit log must not mask the original verification error.


def _safe_json(data, what):
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise UpdateError(f"Некорректный JSON: {what}") from exc
    if not isinstance(result, dict):
        raise UpdateError(f"Ожидается JSON-объект: {what}")
    return result


class UpdateCore:
    def __init__(self, server_url=SERVER_URL, public_key_path=TRUSTED_UPDATE_KEY,
                 current_version=APP_VERSION, timeout=REQUEST_TIMEOUT, session=None):
        self.server_url = server_url.rstrip("/")
        self.public_key_path = Path(public_key_path)
        self.current_version = current_version
        self.timeout = max(3, min(120, int(timeout)))
        self.http = session if session is not None else requests.Session()

    def _get(self, path, token, *, headers=None, stream=False, params=None):
        request_headers = {"Authorization": f"Bearer {token}"}
        if headers:
            request_headers.update(headers)
        response = self.http.get(self.server_url + path, headers=request_headers, params=params,
                                 timeout=self.timeout, stream=stream, allow_redirects=False)
        if response.status_code == 401:
            response.close()
            raise UpdateError("Сессия истекла: войдите в Blade повторно", auth_expired=True)
        if not 200 <= response.status_code < 300:
            code = response.status_code
            response.close()
            raise UpdateError(f"Сервер отклонил запрос обновления (HTTP {code})")
        return response

    def _read_limited(self, response, limit):
        buf = bytearray()
        try:
            for block in response.iter_content(chunk_size=64 * 1024):
                if block:
                    buf.extend(block)
                    if len(buf) > limit:
                        raise UpdateError("Ответ сервера превышает допустимый размер")
            return bytes(buf)
        finally:
            response.close()

    def check_online(self, token):
        if not token:
            raise UpdateError("Для проверки обновлений требуется авторизация", auth_expired=True)
        os_name, cpu = platform_info()
        req = self._get("/updates/check", token, stream=True,
                        params={"os": os_name, "arch": cpu, "version": self.current_version})
        data = _safe_json(self._read_limited(req, 256 * 1024), "ответ проверки обновлений")
        if data.get("update_available"):
            newer = data.get("version")
            version_tuple(newer)
            if version_tuple(newer) <= version_tuple(self.current_version):
                raise UpdateError("Сервер прислал устаревшую версию")
            minimum = data.get("min_supported")
            version_tuple(minimum)
            data["manual_install_required"] = version_tuple(minimum) > version_tuple(self.current_version)
        return data

    def _report(self, token, status, new_version, detail=""):
        if not token:
            return
        try:
            response = self.http.post(self.server_url + "/updates/report",
                           headers={"Authorization": f"Bearer {token}"},
                           json={"from_version": self.current_version,
                                 "to_version": new_version, "status": status, "detail": detail[:300]},
                           timeout=self.timeout, allow_redirects=False)
            response.close()
        except requests.RequestException:
            pass  # The local result is authoritative; server audit is best effort.

    def prepare_online(self, token, progress=None):
        target = None
        temp_file = None
        try:
            if progress: progress("Проверяю наличие совместимого обновления…")
            state = self.check_online(token)
            if not state.get("update_available"):
                raise UpdateError("Новых версий пока нет")
            target = state["version"]
            if state.get("manual_install_required"):
                raise UpdateError("min_supported выше установленной версии: автообновление запрещено")
            code = state.get("download_token")
            if not isinstance(code, str) or not code:
                raise UpdateError("Сервер не выдал токен скачивания")
            if progress: progress("Загружаю подписанный манифест…")
            response = self._get(f"/updates/manifest/{target}", token, stream=True)
            manifest = _safe_json(self._read_limited(response, 256 * 1024), "манифест")
            verify_manifest(manifest, current_version=self.current_version,
                            public_key_path=self.public_key_path)
            if manifest["version"] != target:
                raise UpdateError("Сервер выдал манифест другой версии")
            if progress: progress("Проверяю SBOM…")
            response = self._get(f"/updates/sbom/{target}.json", token, stream=True)
            sbom = self._read_limited(response, MAX_SBOM_SIZE)
            if not hmac.compare_digest(digest_bytes(sbom).lower(), manifest["sbom"]["sha256"].lower()):
                raise UpdateError("SBOM не совпадает с манифестом", status="sbom_mismatch")
            if progress: progress("Скачиваю ZIP-пакет…")
            UPDATE_CACHE.mkdir(parents=True, exist_ok=True)
            fd, temp_file = tempfile.mkstemp(prefix=".blade-download-", suffix=".part", dir=UPDATE_CACHE)
            total = 0
            hashed = hashlib.sha256()
            with os.fdopen(fd, "wb") as target_file:
                response = self._get(f"/updates/download/{target}", token,
                                     headers={"X-Download-Token": code}, stream=True)
                try:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            total += len(chunk)
                            if total > manifest["package_size"] or total > MAX_PACKAGE_SIZE:
                                raise UpdateError("Пакет больше заявленного размера")
                            hashed.update(chunk)
                            target_file.write(chunk)
                finally:
                    response.close()
            if total != manifest["package_size"] or not hmac.compare_digest(hashed.hexdigest(), manifest["package_sha256"].lower()):
                raise UpdateError("Полученный ZIP не совпадает с SHA-256 манифеста")
            if progress: progress("Проверяю файлы ZIP и состав зависимостей…")
            result = verify_package(manifest, sbom, temp_file,
                                    current_version=self.current_version,
                                    public_key_path=self.public_key_path)
            final = UPDATE_CACHE / manifest["package_filename"]
            os.replace(temp_file, final)
            temp_file = None
            # The standalone installer will verify these artifacts AGAIN.
            meta = UPDATE_CACHE / ("release-" + target)
            meta.mkdir(parents=True, exist_ok=True)
            manifest_file = meta / "manifest.json"
            sbom_file = meta / "sbom.json"
            for dest, payload in ((manifest_file, json.dumps(manifest, ensure_ascii=False).encode("utf-8")),
                                  (sbom_file, sbom)):
                fd, partial = tempfile.mkstemp(prefix=".meta-", dir=meta)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                os.replace(partial, dest)
            result["package"] = str(final)
            result["source"] = "online"
            result["manifest_path"] = str(manifest_file)
            result["sbom_path"] = str(sbom_file)
            self._report(token, "verified", target)
            write_local_audit("verified", self.current_version, target, "online")
            return result
        except (requests.RequestException, OSError, ValueError, UpdateError, zipfile.BadZipFile) as exc:
            err = exc if isinstance(exc, UpdateError) else UpdateError(f"Ошибка проверки онлайн-обновления: {exc}")
            if target:
                self._report(token, err.status, target, str(err))
            write_local_audit(err.status, self.current_version, target, str(err))
            raise err
        finally:
            if temp_file:
                try: Path(temp_file).unlink(missing_ok=True)
                except OSError: pass

    def prepare_offline(self, manifest_file, progress=None):
        version = None
        try:
            path = Path(manifest_file).resolve(strict=True)
            if not path.is_file() or path.name != "manifest.json" or path.stat().st_size > 256 * 1024:
                raise UpdateError("Выберите файл manifest.json (до 256 КБ)")
            if progress: progress("Проверяю подпись Ed25519…")
            manifest = _safe_json(path.read_bytes(), "манифест")
            version = manifest.get("version") if isinstance(manifest.get("version"), str) else None
            verify_manifest(manifest, current_version=self.current_version,
                            public_key_path=self.public_key_path)
            parent = path.parent
            package = parent / manifest["package_filename"]
            sbom_path = parent / "sbom.json"
            if package.is_symlink() or sbom_path.is_symlink() or not sbom_path.is_file() or sbom_path.stat().st_size > MAX_SBOM_SIZE:
                raise UpdateError("Отсутствует или небезопасен sbom.json")
            if progress: progress("Проверяю SHA-256 ZIP, SBOM и зависимости…")
            result = verify_package(manifest, sbom_path.read_bytes(), package,
                                    current_version=self.current_version,
                                    public_key_path=self.public_key_path)
            result["source"] = "offline"
            result["manifest_path"] = str(path)
            result["sbom_path"] = str(sbom_path)
            write_local_audit("verified", self.current_version, version, "offline")
            return result
        except (OSError, ValueError, UpdateError, zipfile.BadZipFile) as exc:
            err = exc if isinstance(exc, UpdateError) else UpdateError(f"Ошибка проверки офлайн-обновления: {exc}")
            write_local_audit(err.status, self.current_version, version, str(err))
            raise err


def queue_installed_report(from_version, to_version):
    """No JWT is stored by the helper; report is sent after next login."""
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        with PENDING_REPORTS.open("a", encoding="utf-8") as dest:
            dest.write(json.dumps({"from_version": from_version, "to_version": to_version,
                                   "status": "installed", "detail": "external installer; health check OK"}) + "\n")
    except OSError:
        pass


def flush_installed_reports(token, server_url=SERVER_URL):
    """Best-effort HTTP reporting of previously installed online updates."""
    if not token or not PENDING_REPORTS.is_file():
        return
    try:
        lines = PENDING_REPORTS.read_text(encoding="utf-8").splitlines()
        remaining = []
        for line in lines[:100]:
            try:
                body = json.loads(line)
                if (not isinstance(body, dict) or body.get("status") != "installed" or
                    not isinstance(body.get("from_version"), str) or
                    not isinstance(body.get("to_version"), str)):
                    remaining.append(line)
                    continue
                with requests.post(server_url.rstrip("/") + "/updates/report",
                                   headers={"Authorization": f"Bearer {token}"},
                                   json=body, timeout=REQUEST_TIMEOUT, allow_redirects=False) as resp:
                    if resp.status_code != 201:
                        remaining.append(line)
            except (requests.RequestException, ValueError, TypeError):
                remaining.append(line)
        remaining.extend(lines[100:])
        partial = PENDING_REPORTS.with_suffix(".tmp")
        partial.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
        os.replace(partial, PENDING_REPORTS)
    except OSError:
        pass
