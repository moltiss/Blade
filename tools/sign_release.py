"""Запускать ТОЛЬКО разработчику из папки tools; ключ хранить вне распространяемой программы."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

parser = argparse.ArgumentParser()
parser.add_argument("--client", required=True, type=Path)
parser.add_argument("--key", required=True, type=Path, help="Путь к приватному ключу ВНЕ каталога клиента")
parser.add_argument("--init-key", action="store_true", help="Однократная генерация ключа (не перезаписывает существующий)")
args = parser.parse_args()
client = args.client.resolve()
key_path = args.key.resolve()
if key_path.is_relative_to(client):
    raise SystemExit("ОШИБКА: приватный ключ нельзя хранить в каталоге клиента")
if args.init_key:
    if key_path.exists():
        raise SystemExit("Ключ уже существует, перезапись запрещена")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private = ec.generate_private_key(ec.SECP256R1())
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
else:
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
        raise SystemExit("Требуется приватный ключ ECDSA P-256")
files = ["main.py", "auth.py", "encryption.py", "settings.py", "integrity.py", "config.ini",
         "updater.py", "update_ui.py", "install_core.py", "update_public.pem"]
for rel in files:
    if not (client / rel).is_file():
        raise SystemExit(f"Отсутствует обязательный файл: {rel}")
manifest = {"algorithm": "SHA-256", "files": {rel: hashlib.sha256((client / rel).read_bytes()).hexdigest() for rel in files}}
manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
(client / "integrity_manifest.json").write_bytes(manifest_bytes)
signature = private.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))
(client / "integrity_manifest.sig").write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
(client / "developer_public.pem").write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
print("Подписан манифест:", client / "integrity_manifest.json")
print("Приватный ключ храните в секрете:", key_path)
