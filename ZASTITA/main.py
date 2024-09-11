import base64
import json
import os
import re
import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import datetime
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization

from MessageProt import MessageProcessor
from PrivateKeyRings import PrivateKeyRing
from PublicKeyRings import PublicKeyRing


private_key_ring = PrivateKeyRing()
public_key_ring = PublicKeyRing()
message_processor = MessageProcessor(private_key_ring, public_key_ring)


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

        self.load_keys()

    def load_keys(self):
        # Očisti postojeći prikaz u tabelama
        self.private_key_list.delete(0, tk.END)
        self.public_key_list.delete(0, tk.END)

        # Učitaj privatne ključeve iz fajlova i dodaj ih u tabelu
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


# Sifrovanje
def send_message_screen():
    message_window = tk.Toplevel()
    message_window.title("Send Message")

    # Korišćenje LabelFrame za lepši izgled
    frame_message = tk.LabelFrame(message_window, text="Enter Message", padx=10, pady=10)
    frame_message.grid(row=0, column=0, padx=20, pady=20)

    # Unos poruke sa skrol-barom
    entry_message = tk.Text(frame_message, height=10, width=50, wrap="word")
    entry_message.pack()

    # Korišćenje LabelFrame za enkripciju
    frame_options = tk.LabelFrame(message_window, text="Message Options", padx=10, pady=10)
    frame_options.grid(row=1, column=0, padx=20, pady=10)

    # Algoritam enkripcije
    label_algorithm = tk.Label(frame_options, text="Encryption Algorithm:")
    label_algorithm.grid(row=0, column=0, padx=10, pady=5)

    algorithm_choice = tk.StringVar(value="AES128")  # Default value
    algorithm_menu = tk.OptionMenu(frame_options, algorithm_choice, "AES128", "TripleDES")
    algorithm_menu.grid(row=0, column=1, padx=10, pady=5)

    # Polje za unos name-a
    label_name = tk.Label(frame_options, text="Name:")
    label_name.grid(row=1, column=0, padx=10, pady=5)

    entry_name = tk.Entry(frame_options)
    entry_name.grid(row=1, column=1, padx=10, pady=5)

    # Polje za unos password-a
    label_password = tk.Label(frame_options, text="Password:")
    label_password.grid(row=2, column=0, padx=10, pady=5)

    entry_password = tk.Entry(frame_options, show="*")
    entry_password.grid(row=2, column=1, padx=10, pady=5)

    # Internal variables to store selected keys
    selected_private_key = None
    selected_public_key = None

    def load_keys():
        name = entry_name.get()
        password = entry_password.get()

        # Dobavljanje privatnih i javnih ključeva na osnovu unetih podataka
        private_keys = get_private_keys(name, password)
        public_keys = get_public_keys()

        # Ažuriranje padajućih listi stvarnim ključevima (samo KeyID i Email prikaz)
        private_key_menu["menu"].delete(0, "end")
        for key in private_keys:
            display_text = f"{key['KeyID']} - {key['Email']}"
            private_key_menu["menu"].add_command(
                label=display_text,
                command=lambda key_data=key: select_private_key(key_data)
            )

        public_key_menu["menu"].delete(0, "end")
        for key in public_keys:
            display_text = f"{key['KeyID']} - {key['Email']}"
            public_key_menu["menu"].add_command(
                label=display_text,
                command=lambda key_data=key: select_public_key(key_data)
            )

    def select_private_key(key_data):
        nonlocal selected_private_key
        selected_private_key = key_data  # Save the entire key data internally
        private_key_choice.set("Private Key Selected")  # Display neutral message

    def select_public_key(key_data):
        nonlocal selected_public_key
        selected_public_key = key_data  # Save the entire key data internally
        public_key_choice.set("Public Key Selected")  # Display neutral message

    # Dugme za učitavanje ključeva
    load_button = tk.Button(frame_options, text="Load Keys", command=load_keys)
    load_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Dropdown za privatne ključeve (bez prikaza samog ključa)
    label_private_key = tk.Label(frame_options, text="Select Private Key:")
    label_private_key.grid(row=4, column=0, padx=10, pady=5)

    private_key_choice = tk.StringVar()
    private_key_menu = tk.OptionMenu(frame_options, private_key_choice, "")
    private_key_menu.grid(row=4, column=1, padx=10, pady=5)

    # Dropdown za javne ključeve (bez prikaza samog ključa)
    label_public_key = tk.Label(frame_options, text="Select Public Key:")
    label_public_key.grid(row=5, column=0, padx=10, pady=5)

    public_key_choice = tk.StringVar()
    public_key_menu = tk.OptionMenu(frame_options, public_key_choice, "")
    public_key_menu.grid(row=5, column=1, padx=10, pady=5)

    # Checkbutton za enkripciju
    encryption_var = tk.BooleanVar()
    check_encryption = tk.Checkbutton(frame_options, text="Encryption", variable=encryption_var)
    check_encryption.grid(row=6, column=0, padx=10, pady=5)

    # Checkbutton za kompresiju
    compression_var = tk.BooleanVar()
    check_compression = tk.Checkbutton(frame_options, text="Compression", variable=compression_var)
    check_compression.grid(row=6, column=1, padx=10, pady=5)

    # Checkbutton za enkripciju
    signing_var = tk.BooleanVar()
    check_signing = tk.Checkbutton(frame_options, text="Sign", variable=signing_var)
    check_signing.grid(row=7, column=0, padx=10, pady=5)

    # Checkbutton za kompresiju
    radix64_var = tk.BooleanVar()
    check_radix64 = tk.Checkbutton(frame_options, text="Radix-64", variable=radix64_var)
    check_radix64.grid(row=7, column=1, padx=10, pady=5)

    # Dugme za slanje poruke
    send_button = tk.Button(
        frame_options, text="Send Message",
        command=lambda: process_message(
            entry_message.get("1.0", tk.END),
            entry_password.get(),
            algorithm_choice.get(),
            selected_private_key,
            selected_public_key,
            encryption_var.get(),
            signing_var.get(),
            compression_var.get(),
            radix64_var.get()
        )
    )
    send_button.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

# Implement the rest of the message processing logic accordingly


def process_message(message, password, algorithm, private_key_data, public_key_data, encryption_bool, signing_bool, compression_bool, radix64_bool):
    # keyIdPattern = "'KeyID':\\s*'([^']+)'"
    # namePattern = "'Name':\\s*'([^']+)'"
    #
    # # Pronađi podudaranja
    # privateKeyIdMatch = re.search(keyIdPattern, private_key_name)
    # publicKeyIdMatch = re.search(keyIdPattern, public_key_name)
    # senderNameMatch = re.search(namePattern, private_key_name)
    # receiverNameMatch = re.search(namePattern, public_key_name)
    #
    # # Izvuci rezultate
    # private_key_id = privateKeyIdMatch.group(1) if privateKeyIdMatch else ''
    # public_key_id = publicKeyIdMatch.group(1) if publicKeyIdMatch else ''
    # sender_name = senderNameMatch.group(1) if senderNameMatch else ''
    # receiver_name = receiverNameMatch.group(1) if receiverNameMatch else ''

    private_key_id = private_key_data['KeyID']
    public_key_id = public_key_data['KeyID']
    sender_name = private_key_data['Name']
    receiver_name = public_key_data['Name']

    # Simulacija preuzimanja ključeva
    private_key = get_private_key(name=sender_name, key_id=private_key_id, password=password)
    public_key = get_public_key(key_id=public_key_id)

    # Simulacija preuzimanja ključeva
    private_key = get_private_key(name=sender_name, key_id=private_key_id, password=password)
    public_key = get_public_key(key_id=public_key_id)

    processor = MessageProcessor(private_key_ring, public_key_ring)

    # 1. Digitalno potpisivanje poruke
    signature = ""
    if signing_bool == 1:
        signature = processor.sign_message(message.encode(), private_key)

    # 2. Spajanje poruke i potpisa (u skladu sa šemom)
    combined_message = message.encode()# + signature        # fali key_id (id privatnog kljuca koji se koristi za hash) !!!

    # 3. Enkripcija kombinovane poruke pomoću sesijskog ključa
    encrypted_message = combined_message
    encrypted_session_key = ""
    if encryption_bool == 1:
        encrypted_message, encrypted_session_key = processor.encrypt_message(combined_message, public_key, algorithm)

    # encrypted_message + encrypted_session_key + key_id (id javnog kljuca kojim se sifruje session id)

    # 4. Kompresija i kodiranje enkriptovane poruke
    compressed_encoded_message = encrypted_message
    if compression_bool == 1:
        compressed_encoded_message = processor.compress_and_encode(encrypted_message)

    # 5. Čuvanje poruke u fajl (sa enkriptovanim ključem i potpisom)
    message_id = datetime.datetime.now().timestamp()
    directory = receiver_name

    if not os.path.exists(directory):
        os.makedirs(directory)

    filename = f"{sender_name}_{message_id}.json"
    file_path = os.path.join(directory, filename)

    processor.save_message_to_file(
        file_path,
        compressed_encoded_message,
        encrypted_session_key,
        signature,
        private_key_id,
        public_key_id,
        algorithm,
        encryption_bool,
        signing_bool,
        compression_bool,
        radix64_bool
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


# Desifrovanje

def receive_message_screen():
    receive_window = tk.Toplevel()
    receive_window.title("Receive Message")

    label_name = tk.Label(receive_window, text="Enter Your Name:")
    label_name.grid(row=0, column=0, padx=10, pady=5)

    entry_name = tk.Entry(receive_window)
    entry_name.grid(row=0, column=1, padx=10, pady=5)

    label_password = tk.Label(receive_window, text="Enter Password:")
    label_password.grid(row=1, column=0, padx=10, pady=5)

    entry_password = tk.Entry(receive_window, show="*")
    entry_password.grid(row=1, column=1, padx=10, pady=5)

    button_select_file = tk.Button(receive_window, text="Select Message File",
                                   command=lambda: process_receiving_message(entry_name.get(), entry_password.get()))
    button_select_file.grid(row=2, column=1, padx=10, pady=10)


def process_receiving_message(name, password):
    if not name:
        messagebox.showerror("Input Error", "Please enter your name.")
        return

    # Nađi fajlove u direktorijumu sa korisničkim imenom
    user_directory = f"./{name}"
    if not os.path.exists(user_directory):
        messagebox.showerror("Error", f"No messages found for user: {name}")
        return

    # Prikaži dijalog za izbor fajla iz korisničkog direktorijuma
    file_path = filedialog.askopenfilename(initialdir=user_directory, filetypes=[("JSON files", "*.json")])
    if not file_path:
        return

    try:
        decrypted_message = message_processor.process_received_message(file_path, name, password)
        messagebox.showinfo("Success", f"Message decrypted successfully: {decrypted_message.decode()}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Funkcija za cuvanje dekriptovane poruke
def save_decrypted_message(message, window):
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if save_path:
        with open(save_path, 'w') as f:
            f.write(message.decode())
        messagebox.showinfo("Saved", f"Message saved to {save_path}")


# Importovanje samo javnog kljuca
def import_public_key_screen():
    """Otvara prozor za unos imena, emaila i biranje javnog ključa"""
    import_window = tk.Toplevel()
    import_window.title("Uvezi javni ključ")

    # Labela i unos za ime
    label_name = tk.Label(import_window, text="Name:")
    label_name.grid(row=0, column=0, padx=10, pady=5)

    entry_name = tk.Entry(import_window)
    entry_name.grid(row=0, column=1, padx=10, pady=5)

    # Labela i unos za email
    label_email = tk.Label(import_window, text="Email:")
    label_email.grid(row=1, column=0, padx=10, pady=5)

    entry_email = tk.Entry(import_window)
    entry_email.grid(row=1, column=1, padx=10, pady=5)

    # Dugme za biranje fajla
    def choose_file():
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                # Obrada ključa
                process_imported_public_key(file_path, entry_name.get(), entry_email.get())
                messagebox.showinfo("Success", "Public key successfully imported!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import public key: {str(e)}")

    button_choose_file = tk.Button(import_window, text="Izaberi fajl", command=choose_file)
    button_choose_file.grid(row=2, column=0, columnspan=2, padx=10, pady=10)


def process_imported_public_key(file_path, name, email):
    """Funkcija za obradu uvezenog javnog ključa"""
    # Učitaj javni ključ iz fajla
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Generiši KeyID na osnovu javnog ključa
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Hash za KeyID
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(public_pem)
    hashed_key = hasher.finalize()
    key_id = hashed_key[-8:].hex()

    # Sačuvaj javni ključ u fajl
    public_key_file_name = f'public_{key_id}.pem'
    with open(public_key_file_name, 'wb') as key_file:
        key_file.write(public_pem)

    timestamp = datetime.datetime.now().timestamp()
    save_in_json(timestamp, key_id, name, email, public_key, "")

    # Dodaj ključ u PublicKeyRing
    public_key_ring.add_key(key_id, public_key, name, email, timestamp)


# Importovanje para kljuceva

def import_key_pair_screen():
    """Otvara prozor za unos podataka i uvoz para ključeva"""
    import_window = tk.Toplevel()
    import_window.title("Uvezi par ključeva")

    # Unos za name
    label_name = tk.Label(import_window, text="Name:")
    label_name.grid(row=0, column=0, padx=10, pady=5)

    entry_name = tk.Entry(import_window)
    entry_name.grid(row=0, column=1, padx=10, pady=5)

    # Unos za email
    label_email = tk.Label(import_window, text="Email:")
    label_email.grid(row=1, column=0, padx=10, pady=5)

    entry_email = tk.Entry(import_window)
    entry_email.grid(row=1, column=1, padx=10, pady=5)

    # Unos za password
    label_password = tk.Label(import_window, text="Password:")
    label_password.grid(row=2, column=0, padx=10, pady=5)

    entry_password = tk.Entry(import_window, show="*")
    entry_password.grid(row=2, column=1, padx=10, pady=5)

    # Dugme za uvoz ključeva
    def choose_keys():
        # Izaberi privatni ključ
        private_key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not private_key_path:
            messagebox.showerror("Error", "Private key not selected")
            return

        # Izaberi javni ključ
        public_key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not public_key_path:
            messagebox.showerror("Error", "Public key not selected")
            return

        # Obradi uvoženi par ključeva
        try:
            process_imported_key_pair(private_key_path, public_key_path, entry_name.get(), entry_email.get(),
                                      entry_password.get())
            messagebox.showinfo("Success", "Key pair successfully imported!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import key pair: {str(e)}")

    button_import_pair = tk.Button(import_window, text="Uvezi par", command=choose_keys)
    button_import_pair.grid(row=3, column=0, columnspan=2, padx=10, pady=10)


def process_imported_key_pair(private_key_path, public_key_path, name, email, password):
    """Funkcija za obradu i uvoz privatnog i javnog ključa"""
    # Učitaj i dekriptuj privatni ključ pomoću lozinke
    with open(private_key_path, 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=password.encode(),
            backend=default_backend()
        )

    # Učitaj javni ključ
    with open(public_key_path, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # Generiši KeyID na osnovu javnog ključa
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Hash za KeyID
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(public_pem)
    hashed_key = hasher.finalize()
    key_id = hashed_key[-8:].hex()

    # Sačuvaj privatni ključ
    private_key_ring.save_private_key_to_file(private_key, f'{name}_{key_id}_private.pem', password)

    # Sačuvaj javni ključ
    public_key_ring.save_public_key_to_file(public_key, f'public_{key_id}.pem')

    # Dodaj ključeve u prstenove
    timestamp = datetime.datetime.now().timestamp()
    private_key_ring.add_key(key_id, public_key, "Encrypted private key", name, email, timestamp)
    public_key_ring.add_key(key_id, public_key, name, email, timestamp)

    save_in_json(timestamp, key_id, name, email, public_key, "")


def save_in_json(timestamp, key_id, name, email, public_key, encrypted_private_key):
    key_data = {
        "Timestamp": timestamp,
        "KeyID": key_id,
        "Name": name,
        "Email": email,
        "PublicKey": base64.b64encode(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8'),
        "EncryptedPrivateKey": encrypted_private_key
    }

    # Sačuvaj sve podatke u jednom JSON fajlu
    json_filename = f"{name}_key_{key_id}_info.json"
    with open(json_filename, 'w') as json_file:
        json.dump(key_data, json_file, indent=4)


# Funkcija za početni ekran sa dva dugmeta
def main_screen():
    root = tk.Tk()
    root.title("PGP Main Screen")

    key_button = tk.Button(root, text="Generisanje/Prikaz Ključeva", command=lambda: open_key_management(root))
    key_button.grid(row=0, column=0, padx=20, pady=20)

    message_button = tk.Button(root, text="Slanje Poruke", command=send_message_screen)
    message_button.grid(row=1, column=0, padx=20, pady=20)

    receive_button = tk.Button(root, text="Prijem Poruke", command=receive_message_screen)
    receive_button.grid(row=2, column=0, padx=20, pady=20)

    import_public_key_button = tk.Button(root, text="Uvezi javni ključ", command=import_public_key_screen)
    import_public_key_button.grid(row=3, column=0, padx=20, pady=20)

    # Dugme za uvoz para ključeva (privatni i javni)
    import_key_pair_button = tk.Button(root, text="Uvezi par ključeva", command=import_key_pair_screen)
    import_key_pair_button.grid(row=4, column=0, padx=20, pady=20)

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
