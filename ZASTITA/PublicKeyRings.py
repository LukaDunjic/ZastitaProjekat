import base64
import datetime
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class PublicKeyRing:
    def __init__(self, keys=None):
        if keys is None:
            keys = []
        self.keys = keys

    def add_key(self, key_id, public_key, name, email):
        timestamp = datetime.datetime.now().timestamp()
        key = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Public key": public_key,
            "Name": name,
            "UserID": email
        }
        self.keys.append(key)

    def load_public_key(self, filename):
        with open(filename, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key

    def save_public_key_to_file(self, public_key, filename):
        with open(filename, 'wb') as key_file:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_file.write(pem)

    def load_public_keys_from_files(self):
        # Učitaj sve javne ključeve iz fajlova
        public_key_files = [f for f in os.listdir() if f.startswith("public_") and f.endswith(".pem")]
        for filename in public_key_files:
            with open(filename, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
                key_id = base64.b64encode(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )[:10]).decode('utf-8')
                self.add_key(key_id, public_key, "Unknown", "Unknown")
