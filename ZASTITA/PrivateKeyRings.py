import json

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
        timestamp = datetime.datetime.now().timestamp()
        self.add_key(key_id, public_key, encrypted_private_key, name, email, timestamp)

        # Spremanje ključa u fajl
        self.save_private_key_to_file(private_key, f'{key_id}_private.pem', password)

        # generisanje json fajla
        self.save_keys_to_file()

        return {
            "KeyID": key_id,
            "Size": key_size,
            "Name": name,
            "Email": email,
            "PublicKey": public_key
        }

    def add_key(self, key_id, public_key, encrypted_private_key, name, email, timestamp):
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
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(public_pem)
        hashed_key = hasher.finalize()
        return hashed_key[-8:].hex()

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

    def load_private_keys_from_files(self, password):
        # Učitaj sve JSON fajlove koji sadrže privatne ključeve i metapodatke
        key_files = [f for f in os.listdir() if f.endswith(".json")]

        for filename in key_files:
            # Pročitaj podatke iz JSON fajla
            with open(filename, 'r') as file:
                key_data = json.load(file)

            # Dekodiraj privatni ključ iz base64 stringa
            private_key_bytes = base64.b64decode(key_data["EncryptedPrivateKey"])
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=password.encode(),  # Ako je privatni ključ šifrovan, ovde možeš tražiti lozinku
                backend=default_backend()
            )

            # Učitaj public key i ostale podatke
            public_key_bytes = base64.b64decode(key_data["PublicKey"])
            public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
            key_id = key_data["KeyID"]
            name = key_data.get("Name", "Unknown")
            email = key_data.get("Email", "Unknown")
            encrypted_private_key = key_data.get("EncryptedPrivateKey", "Unknown")
            timestamp = key_data.get("Timestamp", datetime.datetime.now().timestamp())

            # Dodaj ključ sa stvarnim podacima
            self.add_key(key_id, public_key, encrypted_private_key, name, email, timestamp=timestamp)

    # def load_private_keys_from_files(self):
    #     # Učitaj sve privatne ključeve iz fajlova
    #     private_key_files = [f for f in os.listdir() if f.startswith("private_") and f.endswith(".pem")]
    #     timestamp = datetime.datetime.now().timestamp()
    #     for filename in private_key_files:
    #         with open(filename, 'rb') as key_file:
    #             private_key = serialization.load_pem_private_key(
    #                 key_file.read(),
    #                 password=None,  # Lozinka se može tražiti ako je neophodno
    #                 backend=default_backend()
    #             )
    #             public_key = private_key.public_key()
    #             key_id = self._generate_key_id(public_key)
    #             # self.add_key(key_id, public_key, "Encrypted", "Unknown", "Unknown", timestamp=timestamp)

    def save_keys_to_file(self):
        for key in self.keys:
            # Kreiraj JSON strukturu sa svim relevantnim podacima
            key_data = {
                "Timestamp": key["Timestamp"],
                "KeyID": key["KeyID"],
                "Name": key["Name"],
                "Email": key["UserID"],  # Email je u UserID polju
                "PublicKey": base64.b64encode(key["Public key"].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8'),
                "EncryptedPrivateKey": key["Encrypted private key"]  # Enkriptovani privatni ključ
            }

            # Sačuvaj sve podatke u jednom JSON fajlu
            json_filename = f"key_{key['KeyID']}.json"
            with open(json_filename, 'w') as json_file:
                json.dump(key_data, json_file, indent=4)

    # def save_keys_to_file(self, filename):
    #     # Pripremi podatke za čuvanje
    #     data = []
    #     for key in self.keys:
    #         key_data = {
    #             "Timestamp": key["Timestamp"],
    #             "KeyID": key["KeyID"],
    #             "Name": key["Name"],
    #             "Email": key["UserID"],
    #             "PublicKey": base64.b64encode(key["Public key"].public_bytes(
    #                 encoding=serialization.Encoding.PEM,
    #                 format=serialization.PublicFormat.SubjectPublicKeyInfo
    #             )).decode('utf-8'),
    #             "EncryptedPrivateKey": key["Encrypted private key"]
    #         }
    #         data.append(key_data)
    #
    #     # Sačuvaj podatke u JSON fajl
    #     with open(filename, 'w') as f:
    #         json.dump(data, f, indent=4)

    def load_keys_from_file(self, filename):
        # Učitaj podatke iz JSON fajla
        with open(filename, 'r') as f:
            data = json.load(f)

        # Dodaj ključeve u prsten
        for key_data in data:
            public_key_pem = base64.b64decode(key_data["PublicKey"])
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            self.add_key(
                key_data["Timestamp"],
                key_data["KeyID"],
                public_key,
                key_data["EncryptedPrivateKey"],
                key_data["Name"],
                key_data["Email"]
            )