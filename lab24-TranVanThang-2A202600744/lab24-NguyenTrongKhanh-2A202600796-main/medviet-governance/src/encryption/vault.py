# src/encryption/vault.py
import os
import base64
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SimpleVault:
    """
    Mô phỏng envelope encryption pattern (thay thế AWS KMS cho local dev).
    
    Architecture:
        Master Key (KEK) → encrypts → Data Key (DEK) → encrypts → Data
    """

    def __init__(self, master_key_path: str = ".vault_key"):
        self.master_key_path = master_key_path
        self.kek = self._load_or_create_kek()

    def _load_or_create_kek(self) -> bytes:
        """
        Load KEK từ file nếu tồn tại,
              ngược lại generate 32-byte random key và lưu vào file.
        QUAN TRỌNG: Trong production, KEK phải lưu trong HSM/KMS, không phải file.
        """
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, "rb") as f:
                kek = base64.b64decode(f.read(), validate=True)
            if len(kek) != 32:
                raise ValueError("The KEK must be a 32-byte AES-256 key")
            return kek
        else:
            kek = os.urandom(32)  # 256-bit key
            with open(self.master_key_path, "wb") as f:
                f.write(base64.b64encode(kek))
            try:
                os.chmod(self.master_key_path, 0o600)
            except OSError:
                # Windows ACLs do not implement POSIX permission bits.
                pass
            return kek

    def generate_dek(self) -> tuple[bytes, bytes]:
        """
        Generate một Data Encryption Key (DEK) mới.
        Trả về (plaintext_dek, encrypted_dek).
        Dùng AESGCM để encrypt DEK bằng KEK.
        """
        plaintext_dek = os.urandom(32)

        # Encrypt DEK bằng KEK
        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        encrypted_dek = nonce + aesgcm.encrypt(nonce, plaintext_dek, None)

        return plaintext_dek, encrypted_dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        """
        Decrypt encrypted DEK bằng KEK.
        Trả về plaintext DEK.
        """
        if len(encrypted_dek) < 29:  # nonce (12) + GCM tag (16) + data
            raise ValueError("Invalid encrypted DEK payload")
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_data(self, plaintext: str) -> dict:
        """
        Implement envelope encryption.
        1. Generate DEK mới
        2. Encrypt data bằng plaintext DEK
        3. Xóa plaintext DEK khỏi memory
        4. Trả về dict chứa encrypted_dek và ciphertext (base64 encoded)
        
        Return format:
        {
            "encrypted_dek": "<base64>",
            "ciphertext": "<base64>",
            "algorithm": "AES-256-GCM"
        }
        """
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")

        plaintext_dek, encrypted_dek = self.generate_dek()

        # Encrypt data bằng plaintext_dek
        aesgcm = AESGCM(plaintext_dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Xóa plaintext DEK
        del plaintext_dek

        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode(),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_data(self, encrypted_payload: dict) -> str:
        """
        Decrypt data từ envelope encryption payload.
        1. Decrypt DEK bằng KEK
        2. Decrypt data bằng DEK
        3. Trả về plaintext string
        """
        if encrypted_payload.get("algorithm") != "AES-256-GCM":
            raise ValueError("Unsupported or missing encryption algorithm")
        encrypted_dek = base64.b64decode(
            encrypted_payload["encrypted_dek"], validate=True
        )
        ciphertext_with_nonce = base64.b64decode(
            encrypted_payload["ciphertext"], validate=True
        )
        if len(ciphertext_with_nonce) < 29:
            raise ValueError("Invalid ciphertext payload")

        # Decrypt the envelope key before decrypting the data.
        plaintext_dek = self.decrypt_dek(encrypted_dek)
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]

        aesgcm = AESGCM(plaintext_dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        del plaintext_dek

        return plaintext.decode()

    def encrypt_column(self, df, column: str) -> pd.DataFrame:
        """
        Encrypt một cột trong DataFrame.
        Thay thế giá trị gốc bằng JSON string của encrypted payload.
        """
        import json

        if column not in df.columns:
            raise KeyError(f"Column not found: {column}")
        df = df.copy()
        df[column] = df[column].apply(
            lambda x: json.dumps(self.encrypt_data(str(x)))
        )
        return df
