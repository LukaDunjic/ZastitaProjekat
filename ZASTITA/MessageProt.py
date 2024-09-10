import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import zlib


class MessageProcessor:

    def __init__(self, private_key_ring, public_key_ring):
        self.private_key_ring = private_key_ring
        self.public_key_ring = public_key_ring

    # Slanje

    def encrypt_message(self, message, public_key, algorithm='AES128'):
        """Enkripcija poruke pomoću javnog ključa i simetričnog algoritma"""

        # Simetrični ključ - u zavisnosti od algoritma
        if algorithm == 'AES128':
            session_key = os.urandom(16)  # 128-bitni ključ za AES
            cipher = Cipher(algorithms.AES(session_key), modes.CFB(os.urandom(16)), backend=default_backend())
        elif algorithm == 'TripleDES':
            session_key = os.urandom(24)  # 192-bitni ključ za TripleDES
            cipher = Cipher(algorithms.TripleDES(session_key), modes.CFB(os.urandom(8)), backend=default_backend())
        # Dodaj opcije za Cast5 i IDEA

        # Šifrovanje poruke simetričnim ključem
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        # Šifrovanje simetričnog ključa pomoću javnog ključa
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        return encrypted_message, encrypted_session_key

    def sign_message(self, message, private_key):
        """Digitalno potpisivanje poruke koristeći privatni ključ i SHA-1"""
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA1()
        )
        return signature

    def compress_and_encode(self, message):
        """Kompresovanje i radix-64 (Base64) konverzija poruke"""
        compressed_message = zlib.compress(message)
        encoded_message = base64.b64encode(compressed_message)
        return encoded_message

    def save_message_to_file(self, file_path, encrypted_message, encrypted_key, signature, public_key_info):
        """Čuvanje poruke u fajl sa svim potrebnim informacijama"""
        data = {
            "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "public_key_info": public_key_info
        }

        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)

    # Prijem

    def process_received_message(self, file_path, user_name, password):
        """Obrada primljene poruke - dekripcija i verifikacija potpisa"""
        with open(file_path, 'r') as file:
            message_data = json.load(file)

        encrypted_message = base64.b64decode(message_data["encrypted_message"])
        encrypted_key = base64.b64decode(message_data["encrypted_key"])
        signature = base64.b64decode(message_data["signature"])
        public_key_info = message_data["public_key_info"]

        # Nađi privatni ključ pomoću imena i lozinke
        private_key = self.private_key_ring.load_private_key_from_file(user_name, password)

        session_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        algorithm = self.detect_algorithm(len(session_key))
        cipher = Cipher(algorithm(session_key), modes.CFB(os.urandom(16)), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

        public_key = self.public_key_ring.load_public_key_from_pem(public_key_info)
        try:
            public_key.verify(
                signature,
                decrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
        except Exception as e:
            raise Exception(f"Signature verification failed: {e}")

        return decrypted_message

    def detect_algorithm(self, key_length):
        """Pomoćna funkcija za izbor algoritma na osnovu dužine ključa"""
        if key_length == 16:
            return algorithms.AES
        elif key_length == 24:
            return algorithms.TripleDES
