import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import zlib
from tkinter import Tk, filedialog


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
            cipher = Cipher(algorithms.AES(session_key), modes.CFB(session_key), backend=default_backend())
        elif algorithm == 'TripleDES':
            session_key = os.urandom(24)  # 192-bitni ključ za TripleDES
            cipher = Cipher(algorithms.TripleDES(session_key), modes.CFB(session_key[:8]), backend=default_backend())
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
        return compressed_message

    def save_message_to_file(self, file_path, encrypted_message, encrypted_session_key, signature, sender_key_id, receiver_key_id, algorithm):
        """Čuvanje poruke u fajl sa svim potrebnim informacijama"""
        data = {
            "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "sender_key_id": sender_key_id,
            "receiver_key_id": receiver_key_id,
            "algorithm": algorithm
        }

        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)

    # Prijem

    def decompress_and_decode(self, compressed_encoded_message):
        decompressed_data = zlib.decompress(compressed_encoded_message)
        return decompressed_data

    def process_received_message(self, file_path, name, password):
        """Obrada primljene poruke - dekripcija i verifikacija potpisa"""
        with open(file_path, 'r') as file:
            message_data = json.load(file)

        compressed_encoded_message = base64.b64decode(message_data["encrypted_message"])#.decode('utf-8')     # ovo je ustvari compressed_encoded_message
        encrypted_session_key = base64.b64decode(message_data["encrypted_session_key"])
        signature = base64.b64decode(message_data["signature"])
        sender_key_id = message_data["sender_key_id"]
        receiver_key_id = message_data["receiver_key_id"]
        algorithm = message_data["algorithm"]

        encrypted_message = self.decompress_and_decode(compressed_encoded_message)

        # Nađi privatni ključ pomoću imena i lozinke
        private_key = self.private_key_ring.load_private_key_from_file(f"{name}_{receiver_key_id}_private.pem", password)      # ovim kljucem doijamo session key

        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        bytes_num = 16
        if algorithm == "TripleDES":
            bytes_num = 8

        algorithm = self.detect_algorithm(algorithm)
        cipher = Cipher(algorithm(session_key), modes.CFB(session_key[:bytes_num]), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()     # dodao encode()

        public_key = self.public_key_ring.load_public_key_from_pem(f"public_{sender_key_id}.pem")   # ovim kljucem dekriptujemo signature

        print(decrypted_message.decode('utf-8').strip())

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

        self.save_decrypted_message_to_file(message=decrypted_message.decode('utf-8').strip(), name=name)

        return decrypted_message

    def detect_algorithm(self, algorithm):
        """Pomoćna funkcija za izbor algoritma na osnovu dužine ključa"""
        if algorithm == "AES128":
            return algorithms.AES
        elif algorithm == "TripleDES":
            return algorithms.TripleDES

    def save_decrypted_message_to_file(self, message, name):
        data = {
            "message": message,
            "name": name
        }

        # Kreiranje Tkinter prozora za fajl eksplorer
        root = Tk()
        root.withdraw()  # Skrivanje glavnog prozora

        # Otvaranje fajl dijaloga za biranje destinacije i imena fajla
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Choose where to save the file"
        )

        # Ako je fajl izabran (korisnik nije odustao)
        if file_path:
            # Zapisivanje podataka u JSON fajl
            with open(file_path, 'w') as json_file:
                json.dump(data, json_file, indent=4)
            print(f"File saved successfully at {file_path}")
        else:
            print("No file was selected.")