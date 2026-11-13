"""Проверка подписи манифеста и SHA-256 файлов Blade (без доверия к локальным эталонам без подписи)."""
import base64
import hashlib
import json
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE = Path(__file__).resolve().parent


def verify_installation():
    manifest_file = BASE / "integrity_manifest.json"
    signature_file = BASE / "integrity_manifest.sig"
    public_key_file = BASE / "developer_public.pem"
    report = {"ok": False, "message": "", "files": []}
    try:
        manifest_bytes = manifest_file.read_bytes()
        signature = base64.b64decode(signature_file.read_text(encoding="ascii").strip(), validate=True)
        public_key = serialization.load_pem_public_key(public_key_file.read_bytes())
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Ожидается открытый ключ ECDSA P-256")
        public_key.verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
        manifest = json.loads(manifest_bytes)
        if manifest.get("algorithm") != "SHA-256" or not isinstance(manifest.get("files"), dict):
            raise ValueError("Неверный формат манифеста")
        files = manifest["files"]
        if not files:
            raise ValueError("Манифест не содержит файлов")
        all_ok = True
        for rel, expected in files.items():
            path = (BASE / rel).resolve()
            if not path.is_relative_to(BASE) or not path.is_file() or path.is_symlink():
                actual, status = "—", "НЕТ ФАЙЛА / НЕДОПУСТИМЫЙ ПУТЬ"
            else:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                status = "OK" if actual == expected else "ИЗМЕНЁН"
            all_ok = all_ok and status == "OK"
            report["files"].append({"path": rel, "status": status, "actual_hash": actual})
        report["ok"] = all_ok
        report["message"] = "Подпись действительна; все файлы совпадают с эталоном" if all_ok else "Подпись действительна, но найдены изменённые или отсутствующие файлы"
    except InvalidSignature:
        report["message"] = "ОШИБКА: недействительная цифровая подпись манифеста"
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report["message"] = f"Проверка невозможна: {exc}"
    return report
