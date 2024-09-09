import base64
import datetime
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class PublicKeyRing:
    def __init__(self, keys=None):
        if keys is None:
            keys = []
        self.keys = keys

    def add_key(self, key_id, public_key, name, email, timestamp):
        key = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Public key": public_key,
            "Name": name,
            "Email": email
        }
        self.keys.append(key)

    def save_public_key_to_file(self, public_key, filename):
        with open(filename, 'wb') as key_file:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_file.write(pem)

    def load_public_key_from_pem(self, filename):
        with open(filename, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            key_id = base64.b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )[:-8]).decode('utf-8')

        return public_key

    def load_public_keys_from_files(self):
        # Učitaj sve JSON fajlove koji sadrže privatne ključeve i metapodatke
        key_files = [f for f in os.listdir() if f.endswith(".json")]

        for filename in key_files:
            # Pročitaj podatke iz JSON fajla
            with open(filename, 'r') as file:
                key_data = json.load(file)

            # Učitaj public key i ostale podatke
            public_key = self.load_public_key_from_pem(f"public_{key_data['KeyID']}.pem")
            key_id = key_data["KeyID"]
            name = key_data.get("Name", "Unknown")
            email = key_data.get("Email", "Unknown")
            timestamp = key_data.get("Timestamp", datetime.datetime.now().timestamp())

            # Dodaj ključ sa stvarnim podacima
            self.add_key(key_id, public_key, name, email, timestamp)
