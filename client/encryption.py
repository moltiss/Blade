import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESService:

    def _generate_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000
        )

        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, text: str, password: str) -> dict:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        key = self._generate_key(password, salt)

        aes = AESGCM(key)

        ciphertext = aes.encrypt(
            nonce,
            text.encode("utf-8"),
            None
        )

        return {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }

    def decrypt(self, encrypted_data: dict, password: str) -> str:
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        key = self._generate_key(password, salt)

        aes = AESGCM(key)

        decrypted = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return decrypted.decode("utf-8")