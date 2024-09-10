import ast
import json
import re
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

from MessageProt import MessageProcessor
from PrivateKeyRings import PrivateKeyRing
from PublicKeyRings import PublicKeyRing

message_processor = MessageProcessor()
private_key_ring = PrivateKeyRing()
public_key_ring = PublicKeyRing()


class KeyGenerationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PGP Key Management")

        # Private and Public Key Rings instance
        self.private_key_ring = PrivateKeyRing()
        self.public_key_ring = PublicKeyRing()

        # Labels and entry fields for user input
        self.label_name = tk.Label(root, text="Name:")
        self.label_name.grid(row=0, column=0, padx=10, pady=5)

        self.entry_name = tk.Entry(root)
        self.entry_name.grid(row=0, column=1, padx=10, pady=5)

        self.label_email = tk.Label(root, text="Email:")
        self.label_email.grid(row=1, column=0, padx=10, pady=5)

        self.entry_email = tk.Entry(root)
        self.entry_email.grid(row=1, column=1, padx=10, pady=5)

        self.label_key_size = tk.Label(root, text="Key Size (1024 or 2048):")
        self.label_key_size.grid(row=2, column=0, padx=10, pady=5)

        self.entry_key_size = tk.Entry(root)
        self.entry_key_size.grid(row=2, column=1, padx=10, pady=5)

        self.label_password = tk.Label(root, text="Password:")
        self.label_password.grid(row=3, column=0, padx=10, pady=5)

        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.grid(row=3, column=1, padx=10, pady=5)

        # Generate key button
        self.button_generate = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.button_generate.grid(row=4, column=1, padx=10, pady=10)

        # Load existing keys button (can be clicked only once)
        self.button_load_keys = tk.Button(root, text="Show Keys", command=self.load_keys)
        self.button_load_keys.grid(row=5, column=1, padx=10, pady=10)

        # Frames for Private and Public keys
        self.private_frame = tk.Frame(root)
        self.private_frame.grid(row=6, column=0, padx=10, pady=10)

        self.public_frame = tk.Frame(root)
        self.public_frame.grid(row=6, column=1, padx=10, pady=10)

        # Private key label and listbox
        self.label_private = tk.Label(self.private_frame, text="Private Keys:")
        self.label_private.pack()

        self.private_key_list = tk.Listbox(self.private_frame, height=10, width=50)
        self.private_key_list.pack()

        # Public key label and listbox
        self.label_public = tk.Label(self.public_frame, text="Public Keys:")
        self.label_public.pack()

        self.public_key_list = tk.Listbox(self.public_frame, height=10, width=50)
        self.public_key_list.pack()

        # Disable "Show Keys" after one click
        self.show_keys_clicked = False

    def generate_key(self):
        name = self.entry_name.get()
        email = self.entry_email.get()
        key_size = int(self.entry_key_size.get())
        password = self.entry_password.get()

        # Validacija unosa
        if not name or not email or key_size not in [1024, 2048] or not password:
            messagebox.showerror("Input Error", "Please fill in all fields correctly.")
            return

        # Generisanje ključeva (privatni i javni)
        key_info = self.private_key_ring.generate_key(key_size, name, email, password)

        # Spremanje javnog ključa u fajl
        self.public_key_ring.save_public_key_to_file(key_info['Public key'], f'public_{key_info["KeyID"]}.pem')

        # Prikaz privatnih i javnih ključeva u odvojenim tabelama
        # self.private_key_list.insert(tk.END, f"Private KeyID: {key_info['KeyID']}, Name: {key_info['Name']}, Email: {key_info['Email']}, "
        #                                      f"EncryptedPrivateKey: {key_info['Encrypted private key']}, Timestamp: {key_info['Timestamp']}")
        # self.public_key_list.insert(tk.END, f"Public KeyID: {key_info['KeyID']}, Name: {key_info['Name']}, Email: {key_info['Email']}, "
        #                                    f"Public key: {key_info['Public key']}, Timestamp: {key_info['Timestamp']}")
        self.load_keys()

    def load_keys(self):
        # Onemogući ponovno klikanje dugmeta
        # if self.show_keys_clicked:
        #     return

        # Očisti postojeći prikaz u tabelama
        self.private_key_list.delete(0, tk.END)
        self.public_key_list.delete(0, tk.END)

        # Učitaj privatne ključeve iz fajlova i dodaj ih u tabelu
        print(self.entry_name.get())
        self.private_key_ring.load_private_keys_from_files(self.entry_name.get(), self.entry_password.get())
        for key in self.private_key_ring.keys:
            self.private_key_list.insert(
                tk.END,
                f"Private KeyID: {key['KeyID']}, Name: {key['Name']}, Email: {key['Email']}, EncryptedPrivateKey: {key['Encrypted private key']}, Timestamp: {key['Timestamp']}"
            )

        # Učitaj javne ključeve iz fajlova i dodaj ih u tabelu
        self.public_key_ring.load_public_keys_from_files()
        for key in self.public_key_ring.keys:
            self.public_key_list.insert(
                tk.END,
                f"Public KeyID: {key['KeyID']}, Name: {key['Name']}, Email: {key['Email']}, Public key: {key['Public key']}, Timestamp: {key['Timestamp']}"
            )

        # Onemogući ponovno klikanje dugmeta
        # self.button_load_keys.config(state=tk.DISABLED)
        # self.show_keys_clicked = True


def send_message_screen():
    message_window = tk.Toplevel()
    message_window.title("Send Message")

    label_message = tk.Label(message_window, text="Enter Message:")
    label_message.grid(row=0, column=0, padx=10, pady=5)

    entry_message = tk.Text(message_window, height=10, width=50)
    entry_message.grid(row=1, column=0, padx=10, pady=5)

    label_algorithm = tk.Label(message_window, text="Encryption Algorithm:")
    label_algorithm.grid(row=2, column=0, padx=10, pady=5)

    algorithm_choice = tk.StringVar()
    algorithm_menu = tk.OptionMenu(message_window, algorithm_choice, "AES128", "TripleDES")
    algorithm_menu.grid(row=3, column=0, padx=10, pady=5)

    message_window = tk.Tk()
    message_window.title("Key Selection")


    # Polje za unos name-a
    label_name = tk.Label(message_window, text="Name:")
    label_name.grid(row=0, column=0, padx=10, pady=5)

    entry_name = tk.Entry(message_window)
    entry_name.grid(row=0, column=1, padx=10, pady=5)

    # Polje za unos password-a
    label_password = tk.Label(message_window, text="Password:")
    label_password.grid(row=1, column=0, padx=10, pady=5)

    entry_password = tk.Entry(message_window, show="*")
    entry_password.grid(row=1, column=1, padx=10, pady=5)

    def load_keys():
        name = entry_name.get()
        password = entry_password.get()

        # Dobavljanje privatnih i javnih ključeva na osnovu unetih podataka
        private_keys = get_private_keys(name, password)
        public_keys = get_public_keys()

        # Ažuriranje padajućih listi stvarnim ključevima
        private_key_menu["menu"].delete(0, "end")
        for key in private_keys:
            private_key_menu["menu"].add_command(label=key, command=lambda value=key: private_key_choice.set(value))

        public_key_menu["menu"].delete(0, "end")
        for key in public_keys:
            public_key_menu["menu"].add_command(label=key, command=lambda value=key: public_key_choice.set(value))


    # Dugme za učitavanje ključeva
    load_button = tk.Button(message_window, text="Load Keys", command=load_keys)
    load_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    # Dropdown za privatne ključeve
    label_private_key = tk.Label(message_window, text="Select Private Key:")
    label_private_key.grid(row=4, column=0, padx=10, pady=5)

    private_key_choice = tk.StringVar()
    private_key_menu = tk.OptionMenu(message_window, private_key_choice, "")
    private_key_menu.grid(row=5, column=0, padx=10, pady=5)

    # Dropdown za javne ključeve
    label_public_key = tk.Label(message_window, text="Select Public Key:")
    label_public_key.grid(row=6, column=0, padx=10, pady=5)

    public_key_choice = tk.StringVar()
    public_key_menu = tk.OptionMenu(message_window, public_key_choice, "")
    public_key_menu.grid(row=7, column=0, padx=10, pady=5)

    send_button = tk.Button(
        message_window, text="Send Message",
        command=lambda: process_message(
            entry_message.get("1.0", tk.END),
            entry_password.get(),
            algorithm_choice.get(),
            private_key_choice.get(),
            public_key_choice.get()
        )
    )
    send_button.grid(row=8, column=0, padx=10, pady=5)


def process_message(message, password, algorithm, private_key_name, public_key_name):
    keyIdPattern = "'KeyID':\\s*'([^']+)'"
    namePattern = "'Name':\\s*'([^']+)'"

    # Pronađi podudaranja
    privateKeyIdMatch = re.search(keyIdPattern, private_key_name)
    nameMatch = re.search(namePattern, private_key_name)
    publicKeyIdMatch = re.search(keyIdPattern, public_key_name)

    # Izvuci rezultate
    private_key_id = privateKeyIdMatch.group(1) if privateKeyIdMatch else ''
    name = nameMatch.group(1) if nameMatch else ''
    public_key_id = publicKeyIdMatch.group(1) if publicKeyIdMatch else ''

    # Simulacija preuzimanja ključeva
    private_key = get_private_key(name=name, key_id=private_key_id, password=password)
    public_key = get_public_key(key_id=public_key_id)

    processor = MessageProcessor()

    # 1. Digitalno potpisivanje poruke
    signature = processor.sign_message(message.encode(), private_key)

    # 2. Spajanje poruke i potpisa (u skladu sa šemom)
    combined_message = message.encode() + signature  # Dodavanje potpisa originalnoj poruci

    # 3. Enkripcija kombinovane poruke pomoću sesijskog ključa
    encrypted_message, encrypted_key = processor.encrypt_message(combined_message.decode('utf-8'), public_key, algorithm)

    # 4. Kompresija i kodiranje enkriptovane poruke
    compressed_encoded_message = processor.compress_and_encode(encrypted_message)

    # 5. Čuvanje poruke u fajl (sa enkriptovanim ključem i potpisom)
    filename = "sent_message.json"
    processor.save_message_to_file(
        filename,
        compressed_encoded_message,
        encrypted_key,
        signature,
        public_key_name
    )

    # Informacija korisniku
    messagebox.showinfo("Message Sent", f"Message successfully sent and saved to {filename}")



# dohvata 1 kljuc na osnovu name-a i key_id-a
def get_private_key(name, key_id, password):
    private_key = private_key_ring.load_private_key_from_file(filename=f"{name}_{key_id}_private.pem", password=password)
    return private_key


def get_public_key(key_id):
    public_key = public_key_ring.load_public_key_from_pem(f"public_{key_id}.pem")
    return public_key


# metode za gui
def get_private_keys(name, password):
    private_key_ring.load_private_keys_from_files(name, password)
    return private_key_ring.keys


def get_public_keys():
    public_key_ring.load_public_keys_from_files()
    return public_key_ring.keys


# Funkcija za početni ekran sa dva dugmeta
def main_screen():
    root = tk.Tk()
    root.title("PGP Main Screen")

    key_button = tk.Button(root, text="Generisanje/Prikaz Ključeva", command=lambda: open_key_management(root))
    key_button.grid(row=0, column=0, padx=20, pady=20)

    message_button = tk.Button(root, text="Slanje Poruke", command=send_message_screen)
    message_button.grid(row=1, column=0, padx=20, pady=20)

    root.mainloop()


# Funkcija za otvaranje prozora za generisanje/prikaz ključeva
def open_key_management(parent_root):
    key_window = tk.Toplevel(parent_root)
    key_app = KeyGenerationApp(key_window)


if __name__ == "__main__":
    main_screen()
    # root = tk.Tk()
    # app = KeyGenerationApp(root)
    # root.mainloop()
