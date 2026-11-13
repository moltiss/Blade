"""Blade PZ4: authenticated release API, one-time download capabilities and audit.

This module does NOT install updates. Client-side verification and installation follow
in the next project stage. Never store a private signing key here.
"""
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Blueprint, current_app, jsonify, request, send_file

from auth import get_session
from database import get_connection
from logging_config import load_config

updates_bp = Blueprint("updates", __name__)
BASE_DIR = Path(__file__).resolve().parent
CONFIG = load_config()
RELEASE_ROOT = BASE_DIR / CONFIG.get("updates", "release_directory", fallback="releases")
PUBLIC_KEY_PATH = BASE_DIR / CONFIG.get("updates", "public_key", fallback="update_public.pem")
TOKEN_TTL = max(60, min(3600, CONFIG.getint("updates", "download_token_ttl_seconds", fallback=300)))
VERSION_PATTERN = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
OS_VALUES = {"windows", "linux", "macos"}
ARCH_VALUES = {"x64", "arm64", "x86"}
REPORT_STATUSES = {"downloaded", "verified", "installed", "failed", "rolled_back", "sbom_mismatch"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_version(value):
    if not isinstance(value, str) or not VERSION_PATTERN.fullmatch(value):
        raise ValueError("Версия должна иметь формат Major.Minor.Patch")
    return tuple(map(int, value.split(".")))


def init_update_tables():
    """Idempotent migrations: no changes to existing auth or encrypted data tables."""
    with get_connection() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS releases (
                id INTEGER PRIMARY KEY,
                version TEXT UNIQUE NOT NULL,
                os TEXT NOT NULL,
                arch TEXT NOT NULL,
                min_supported TEXT NOT NULL,
                critical INTEGER NOT NULL DEFAULT 0,
                package_path TEXT NOT NULL,
                package_sha256 TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                sbom_path TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS update_audit (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                device_id TEXT,
                from_version TEXT,
                to_version TEXT,
                status TEXT NOT NULL,
                ip TEXT,
                ts TEXT NOT NULL,
                detail TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_update_audit_user_ts
            ON update_audit(user_id, ts DESC);
            CREATE TABLE IF NOT EXISTS update_download_tokens (
                token_hash TEXT PRIMARY KEY,
                jwt_hash TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                version TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_download_tokens_expiry
            ON update_download_tokens(expires_at);
        """)


def error(message, status):
    return jsonify({"success": False, "error": message}), status


def authenticate():
    parts = request.headers.get("Authorization", "").split()
    token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None
    session = get_session(token) if token else None
    if not session:
        return None, None, error("Требуется действующий JWT", 401)
    return session, token, None


def audit(session, status, from_version=None, to_version=None, detail=None):
    with get_connection() as db:
        db.execute("""INSERT INTO update_audit
            (user_id,device_id,from_version,to_version,status,ip,ts,detail)
            VALUES (?,?,?,?,?,?,?,?)""",
            (session["user_id"], session["device_id"] or "", from_version,
             to_version, status, request.remote_addr, now(), detail))


def safe_release_path(relative):
    """DB values must resolve strictly beneath the release directory."""
    if not isinstance(relative, str) or "\\" in relative:
        raise ValueError("Недопустимое расположение релиза")
    root = RELEASE_ROOT.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
        raise ValueError("Файл релиза отсутствует или небезопасен")
    return path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_payload(manifest):
    """Signature covers all fields except `signature`, as canonical UTF-8 JSON."""
    clean = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(clean, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def verify_manifest(manifest):
    signature = base64.b64decode(manifest["signature"], validate=True)
    public = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Неверный тип доверенного ключа обновлений")
    public.verify(signature, manifest_payload(manifest))


def find_release(version):
    with get_connection() as db:
        return db.execute("SELECT * FROM releases WHERE version=?", (version,)).fetchone()


def validated_manifest(release):
    p = safe_release_path(release["manifest_path"])
    manifest = json.loads(p.read_text(encoding="utf-8"))
    verify_manifest(manifest)
    if (manifest.get("version") != release["version"] or
            manifest.get("signature") != release["signature"] or
            manifest.get("package_sha256") != release["package_sha256"]):
        raise ValueError("Манифест не соответствует реестру релизов")
    return manifest


def create_download_token(session, jwt, version):
    token = secrets.token_urlsafe(32)
    jwt_hash = hashlib.sha256(jwt.encode("utf-8")).hexdigest()
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TTL)).isoformat(timespec="milliseconds")
    with get_connection() as db:
        db.execute("""INSERT INTO update_download_tokens
            (token_hash,jwt_hash,user_id,device_id,version,expires_at)
            VALUES (?,?,?,?,?,?)""",
            (token_hash, jwt_hash, session["user_id"],
             session["device_id"] or "", version, expires))
        db.execute("DELETE FROM update_download_tokens WHERE expires_at < ?",
                   (datetime.now(timezone.utc).isoformat(),))
    return token


@updates_bp.get("/updates/check")
def check_update():
    session, jwt, auth_error = authenticate()
    if auth_error:
        return auth_error
    client_os = request.args.get("os", "").lower()
    arch = request.args.get("arch", "").lower()
    current = request.args.get("version", "")
    try:
        current_tuple = parse_version(current)
    except ValueError as exc:
        return error(str(exc), 400)
    if client_os not in OS_VALUES or arch not in ARCH_VALUES:
        return error("Поддерживаются os=windows/linux/macos и arch=x64/arm64/x86", 400)
    with get_connection() as db:
        releases = db.execute("SELECT version,min_supported,critical FROM releases WHERE os=? AND arch=?",
                              (client_os, arch)).fetchall()
    newer = [r for r in releases if parse_version(r["version"]) > current_tuple]
    if not newer:
        return jsonify({"success": True, "update_available": False, "current_version": current})
    release = max(newer, key=lambda r: parse_version(r["version"]))
    compatible = parse_version(release["min_supported"]) <= current_tuple
    result = {"success": True, "update_available": True,
              "version": release["version"], "min_supported": release["min_supported"],
              "critical": bool(release["critical"]), "manual_install_required": not compatible,
              "manifest_url": f"/updates/manifest/{release['version']}"}
    if compatible:
        result["download_url"] = f"/updates/download/{release['version']}"
        result["sbom_url"] = f"/updates/sbom/{release['version']}.json"
        result["download_token"] = create_download_token(session, jwt, release["version"])
        result["download_token_ttl_seconds"] = TOKEN_TTL
    return jsonify(result)


@updates_bp.get("/updates/manifest/<version>")
def get_manifest(version):
    session, _, auth_error = authenticate()
    if auth_error:
        return auth_error
    try:
        parse_version(version)
        row = find_release(version)
        if row is None:
            return error("Релиз не найден", 404)
        return jsonify(validated_manifest(row))
    except (ValueError, OSError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
        current_app.logger.exception("Ошибка проверки манифеста обновления")
        audit(session, "failed", to_version=version, detail="manifest_invalid")
        return error("Подпись или состав манифеста обновления недействительны", 503)


@updates_bp.get("/updates/sbom/<version>.json")
def get_sbom(version):
    session, _, auth_error = authenticate()
    if auth_error:
        return auth_error
    try:
        parse_version(version)
        row = find_release(version)
        if row is None:
            return error("Релиз не найден", 404)
        manifest = validated_manifest(row)
        path = safe_release_path(row["sbom_path"])
        if sha256(path) != manifest["sbom"]["sha256"]:
            audit(session, "sbom_mismatch", to_version=version, detail="server_sbom_hash_mismatch")
            return error("Контрольная сумма SBOM не совпадает", 503)
        return send_file(path, mimetype="application/json")
    except (ValueError, OSError, KeyError, InvalidSignature, json.JSONDecodeError):
        current_app.logger.exception("Не удалось отдать SBOM")
        audit(session, "failed", to_version=version, detail="sbom_unavailable")
        return error("SBOM недоступен или повреждён", 503)


@updates_bp.get("/updates/download/<version>")
def download(version):
    session, jwt, auth_error = authenticate()
    if auth_error:
        return auth_error
    supplied = request.headers.get("X-Download-Token", "")
    if not supplied or len(supplied) > 256:
        return error("Требуется одноразовый X-Download-Token", 403)
    try:
        parse_version(version)
        row = find_release(version)
        if row is None:
            return error("Релиз не найден", 404)
        manifest = validated_manifest(row)
        path = safe_release_path(row["package_path"])
        if sha256(path) != manifest["package_sha256"] or path.stat().st_size != manifest["package_size"]:
            audit(session, "failed", to_version=version, detail="server_package_hash_mismatch")
            return error("Пакет повреждён на сервере", 503)
        with get_connection() as db:
            cursor = db.execute("""UPDATE update_download_tokens SET used_at=?
                WHERE token_hash=? AND jwt_hash=? AND user_id=? AND device_id=?
                  AND version=? AND used_at IS NULL AND expires_at > ?""",
                (now(), hashlib.sha256(supplied.encode("utf-8")).hexdigest(),
                 hashlib.sha256(jwt.encode("utf-8")).hexdigest(), session["user_id"],
                 session["device_id"] or "", version, now()))
            valid = cursor.rowcount == 1
        if not valid:
            audit(session, "failed", to_version=version, detail="invalid_download_token")
            return error("Токен скачивания использован, истёк или не принадлежит сессии", 403)
        audit(session, "downloaded", to_version=version)
        response = send_file(path, as_attachment=True, download_name=path.name,
                             mimetype="application/zip", conditional=False)
        response.headers["Cache-Control"] = "no-store"
        return response
    except (ValueError, OSError, KeyError, InvalidSignature, json.JSONDecodeError):
        current_app.logger.exception("Ошибка скачивания релиза")
        audit(session, "failed", to_version=version, detail="download_unavailable")
        return error("Пакет обновления недоступен", 503)


@updates_bp.post("/updates/report")
def report_update():
    session, _, auth_error = authenticate()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Требуется JSON-объект", 400)
    status, old, new = data.get("status"), data.get("from_version"), data.get("to_version")
    if status not in REPORT_STATUSES:
        return error("Неизвестный статус обновления", 400)
    try:
        parse_version(old)
        parse_version(new)
    except ValueError as exc:
        return error(str(exc), 400)
    detail = data.get("detail", "")
    if not isinstance(detail, str) or len(detail) > 500:
        return error("Слишком длинное описание", 400)
    audit(session, status, from_version=old, to_version=new, detail=detail)
    return jsonify({"success": True, "message": "Результат обновления сохранён"}), 201
