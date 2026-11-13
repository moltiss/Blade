"""One-time creation of Ed25519 signing keys for Blade update manifests.

Keep the private key OUTSIDE D:/PreEncryption and any distributable ZIP.
"""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

parser = argparse.ArgumentParser(description="Генерация ключей Ed25519 обновлений Blade")
parser.add_argument("--private", required=True, type=Path, help="Путь вне проекта, например D:\\BladeSigningKeys\\updates_private.pem")
parser.add_argument("--public", required=True, type=Path, help="Путь к server\\update_public.pem")
args = parser.parse_args()
private_path, public_path = args.private.resolve(), args.public.resolve()
if private_path == public_path or private_path.is_relative_to(public_path.parent.parent):
    raise SystemExit("Закрытый ключ должен храниться вне каталога проекта")
if private_path.exists() or public_path.exists():
    raise SystemExit("Ключи уже существуют; автоматическая перезапись запрещена")
private_path.parent.mkdir(parents=True, exist_ok=True)
public_path.parent.mkdir(parents=True, exist_ok=True)
private = Ed25519PrivateKey.generate()
private_bytes = private.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
public_bytes = private.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
# Exclusive create so an existing key can never be overwritten.
with private_path.open('xb') as file:
    file.write(private_bytes)
try:
    private_path.chmod(0o600)
except OSError:
    pass
try:
    with public_path.open('xb') as file:
        file.write(public_bytes)
except BaseException:
    private_path.unlink(missing_ok=True)
    raise
print(f"Открытый ключ: {public_path}")
print(f"Закрытый ключ (не распространять): {private_path}")
