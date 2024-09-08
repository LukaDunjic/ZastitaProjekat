from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import datetime


class PrivateKeyRing:
    def __init__(self):
        self.keys = []

    def generate_key(self, key_size, name, email, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Šifrovanje privatnog ključa pomoću lozinke
        encrypted_private_key = self._encrypt_private_key(private_key, password)

        # Generisanje KeyID
        key_id = self._generate_key_id(public_key)

        # Dodavanje ključa u prsten
        self.add_key(key_id, public_key, encrypted_private_key, name, email)

        # Spremanje ključa u fajl
        self.save_private_key_to_file(private_key, f'{key_id}_private.pem', password)
        return {
            "KeyID": key_id,
            "Size": key_size,
            "Name": name,
            "Email": email,
            "PublicKey": public_key
        }

    def add_key(self, key_id, public_key, encrypted_private_key, name, email):
        timestamp = datetime.datetime.now().timestamp()
        key = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Public key": public_key,
            "Encrypted private key": encrypted_private_key,
            "Name": name,
            "UserID": email
        }
        self.keys.append(key)

    def _encrypt_private_key(self, private_key, password):
        password_bytes = password.encode()
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password_bytes)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key)
        )
        return base64.b64encode(pem).decode('utf-8')

    def _generate_key_id(self, public_key):
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_pem[:10]).decode('utf-8')

    def save_private_key_to_file(self, private_key, filename, password):
        password_bytes = password.encode()
        with open(filename, 'wb') as key_file:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
            )
            key_file.write(pem)

    def load_private_key_from_file(self, filename, password):
        with open(filename, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
        return private_key

    def load_private_keys_from_files(self):
        # Učitaj sve privatne ključeve iz fajlova
        private_key_files = [f for f in os.listdir() if f.startswith("private_") and f.endswith(".pem")]
        for filename in private_key_files:
            with open(filename, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # Lozinka se može tražiti ako je neophodno
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                key_id = self._generate_key_id(public_key)
                self.add_key(key_id, public_key, "Encrypted", "Unknown", "Unknown")
