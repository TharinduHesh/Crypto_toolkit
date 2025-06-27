import os
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import hashlib
import itertools
import string
import time
from PIL import Image, ImageTk
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

class CryptographicToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("Comprehensive Cryptographic Toolkit")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10), padding=5)
        self.style.configure("Header.TLabel", font=("Helvetica", 14, "bold"))
        
        self.encrypted_data = None
        self.iv = None
        self.aes_key = None
        self.signature = None
        self.alice_private_key = None
        self.alice_public_key = None
        self.bob_private_key = None
        self.bob_public_key = None
        
        self.create_notebook()
        
    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.create_secure_messaging_tab()
        self.create_file_encryption_tab()
        self.create_hash_cracker_tab()
        self.create_digital_signature_tab()
        self.create_steganography_tab()

    def create_secure_messaging_tab(self):
        messaging_frame = ttk.Frame(self.notebook)
        self.notebook.add(messaging_frame, text="Secure Messaging")
        
        # Base64 Tools Section
        ttk.Label(messaging_frame, text="Base64 Tools", font=("Helvetica", 12, "bold")).pack(pady=(10,5))
        
        base64_frame = ttk.Frame(messaging_frame)
        base64_frame.pack(pady=5, fill=tk.X)
        
        ttk.Label(base64_frame, text="Text:").pack(side=tk.LEFT)
        self.base64_text_entry = ttk.Entry(base64_frame, width=50)
        self.base64_text_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        base64_button_frame = ttk.Frame(messaging_frame)
        base64_button_frame.pack(pady=5)
        
        ttk.Button(base64_button_frame, text="Encode Base64", 
                  command=lambda: self.base64_encode_text(self.base64_text_entry.get())).pack(side=tk.LEFT, padx=5)
        ttk.Button(base64_button_frame, text="Decode Base64", 
                  command=lambda: self.base64_decode_text(self.base64_text_entry.get())).pack(side=tk.LEFT, padx=5)
        
        # Secure Messaging Section
        ttk.Label(messaging_frame, text="Secure Messaging", font=("Helvetica", 12, "bold")).pack(pady=(10,5))
        
        ttk.Label(messaging_frame, text="Enter Message:").pack()
        self.message_entry = ttk.Entry(messaging_frame, width=60)
        self.message_entry.pack(pady=5)
        
        ttk.Label(messaging_frame, text="Encrypted Message (Base64):").pack()
        self.base64_entry = ttk.Entry(messaging_frame, width=60)
        self.base64_entry.pack(pady=5)
        
        button_frame = ttk.Frame(messaging_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_message_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_message_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_messaging).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(messaging_frame, text="Result:").pack(pady=(10,0))
        self.messaging_result = tk.Text(messaging_frame, height=15, width=80, font=("Courier", 9))
        self.messaging_result.pack(pady=5, fill=tk.BOTH, expand=True)
        
        scrollbar1 = ttk.Scrollbar(messaging_frame, orient="vertical", command=self.messaging_result.yview)
        self.messaging_result.configure(yscrollcommand=scrollbar1.set)
    
    def base64_encode_text(self, text):
        try:
            if not text:
                messagebox.showerror("Error", "Please enter text to encode")
                return
            
            encoded = base64.b64encode(text.encode()).decode()
            self.messaging_result.delete(1.0, tk.END)
            self.messaging_result.insert(tk.END, "=== Base64 Encoding ===\n")
            self.messaging_result.insert(tk.END, f"Original text: {text}\n")
            self.messaging_result.insert(tk.END, f"Base64 encoded: {encoded}\n")
            self.base64_text_entry.delete(0, tk.END)
            self.base64_text_entry.insert(0, encoded)
            
        except Exception as e:
            messagebox.showerror("Error", f"Base64 encoding failed: {str(e)}")
    
    def base64_decode_text(self, text):
        try:
            if not text:
                messagebox.showerror("Error", "Please enter Base64 text to decode")
                return
            
            decoded = base64.b64decode(text.encode()).decode()
            self.messaging_result.delete(1.0, tk.END)
            self.messaging_result.insert(tk.END, "=== Base64 Decoding ===\n")
            self.messaging_result.insert(tk.END, f"Base64 text: {text}\n")
            self.messaging_result.insert(tk.END, f"Decoded text: {decoded}\n")
            self.base64_text_entry.delete(0, tk.END)
            self.base64_text_entry.insert(0, decoded)
            
        except Exception as e:
            messagebox.showerror("Error", f"Base64 decoding failed: {str(e)}")
    
    def create_file_encryption_tab(self):
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="File Encryption")
        
        ttk.Label(file_frame, text="File Encryption/Decryption Tool", style="Header.TLabel").pack(pady=10)
        
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(file_select_frame, text="Selected File:").pack(anchor=tk.W)
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=60)
        self.file_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.RIGHT, padx=(5,0))
        
        password_frame = ttk.Frame(file_frame)
        password_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(password_frame, text="Password:").pack(anchor=tk.W)
        self.file_password = ttk.Entry(password_frame, show="*", width=30)
        self.file_password.pack(anchor=tk.W)
        
        algo_frame = ttk.Frame(file_frame)
        algo_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(algo_frame, text="Algorithm:").pack(anchor=tk.W)
        self.encryption_algo = ttk.Combobox(algo_frame, values=["AES-256", "AES-128"], state="readonly")
        self.encryption_algo.set("AES-256")
        self.encryption_algo.pack(anchor=tk.W)
        
        file_button_frame = ttk.Frame(file_frame)
        file_button_frame.pack(pady=10)
        
        ttk.Button(file_button_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_button_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(file_frame, text="Status:").pack(pady=(10,0))
        self.file_result = tk.Text(file_frame, height=10, width=80, font=("Courier", 9))
        self.file_result.pack(pady=5, fill=tk.BOTH, expand=True, padx=20)
    
    def create_hash_cracker_tab(self):
        hash_frame = ttk.Frame(self.notebook)
        self.notebook.add(hash_frame, text="Hash Cracker")
        
        ttk.Label(hash_frame, text="Hash Cracker Tool", style="Header.TLabel").pack(pady=10)
        
        hash_input_frame = ttk.Frame(hash_frame)
        hash_input_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(hash_input_frame, text="Hash to Crack:").pack(anchor=tk.W)
        self.hash_entry = ttk.Entry(hash_input_frame, width=80)
        self.hash_entry.pack(fill=tk.X, pady=5)
        
        hash_type_frame = ttk.Frame(hash_frame)
        hash_type_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(hash_type_frame, text="Hash Type:").pack(anchor=tk.W)
        self.hash_type = ttk.Combobox(hash_type_frame, values=["MD5", "SHA1", "SHA256"], state="readonly")
        self.hash_type.set("MD5")
        self.hash_type.pack(anchor=tk.W)
        
        hash_button_frame = ttk.Frame(hash_frame)
        hash_button_frame.pack(pady=10)
        
        ttk.Button(hash_button_frame, text="Start Cracking", command=self.start_hash_cracking).pack(side=tk.LEFT, padx=5)
        ttk.Button(hash_button_frame, text="Stop", command=self.stop_hash_cracking).pack(side=tk.LEFT, padx=5)
        ttk.Button(hash_button_frame, text="Generate Test Hash", command=self.generate_test_hash).pack(side=tk.LEFT, padx=5)
        
        self.hash_progress = ttk.Progressbar(hash_frame, mode='indeterminate')
        self.hash_progress.pack(pady=5, fill=tk.X, padx=20)
        
        ttk.Label(hash_frame, text="Results:").pack(pady=(10,0))
        self.hash_result = tk.Text(hash_frame, height=8, width=80, font=("Courier", 9))
        self.hash_result.pack(pady=5, fill=tk.BOTH, expand=True, padx=20)
        
        self.cracking_active = False
    
    def create_digital_signature_tab(self):
        sig_frame = ttk.Frame(self.notebook)
        self.notebook.add(sig_frame, text="Digital Signatures")
        
        ttk.Label(sig_frame, text="Digital Signature Tool", style="Header.TLabel").pack(pady=10)
        
        key_frame = ttk.Frame(sig_frame)
        key_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Button(key_frame, text="Generate Key Pair", command=self.generate_signature_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Load Private Key", command=self.load_private_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Load Public Key", command=self.load_public_key).pack(side=tk.LEFT, padx=5)
        
        msg_frame = ttk.Frame(sig_frame)
        msg_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=20)
        
        ttk.Label(msg_frame, text="Message to Sign/Verify:").pack(anchor=tk.W)
        self.signature_message = tk.Text(msg_frame, height=5, width=80, font=("Courier", 9))
        self.signature_message.pack(fill=tk.BOTH, expand=True, pady=5)
        
        sig_input_frame = ttk.Frame(sig_frame)
        sig_input_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(sig_input_frame, text="Signature (Base64):").pack(anchor=tk.W)
        self.signature_entry = ttk.Entry(sig_input_frame, width=80)
        self.signature_entry.pack(fill=tk.X, pady=5)
        
        sig_button_frame = ttk.Frame(sig_frame)
        sig_button_frame.pack(pady=10)
        
        ttk.Button(sig_button_frame, text="Sign Message", command=self.sign_message_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_button_frame, text="Verify Signature", command=self.verify_signature_gui).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(sig_frame, text="Results:").pack(pady=(10,0))
        self.signature_result = tk.Text(sig_frame, height=6, width=80, font=("Courier", 9))
        self.signature_result.pack(pady=5, fill=tk.BOTH, expand=True, padx=20)
        
        self.private_key = None
        self.public_key = None
    
    def create_steganography_tab(self):
        steg_frame = ttk.Frame(self.notebook)
        self.notebook.add(steg_frame, text="Steganography")
        
        ttk.Label(steg_frame, text="Steganography Tool", style="Header.TLabel").pack(pady=10)
        
        img_frame = ttk.Frame(steg_frame)
        img_frame.pack(pady=10, fill=tk.X, padx=20)
        
        ttk.Label(img_frame, text="Cover Image:").pack(anchor=tk.W)
        self.image_path_var = tk.StringVar()
        img_entry_frame = ttk.Frame(img_frame)
        img_entry_frame.pack(fill=tk.X)
        self.image_path_entry = ttk.Entry(img_entry_frame, textvariable=self.image_path_var, width=60)
        self.image_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(img_entry_frame, text="Browse", command=self.browse_image).pack(side=tk.RIGHT, padx=(5,0))
        
        secret_frame = ttk.Frame(steg_frame)
        secret_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=20)
        
        ttk.Label(secret_frame, text="Secret Message:").pack(anchor=tk.W)
        self.secret_message = tk.Text(secret_frame, height=4, width=80, font=("Courier", 9))
        self.secret_message.pack(fill=tk.BOTH, expand=True, pady=5)
        
        steg_button_frame = ttk.Frame(steg_frame)
        steg_button_frame.pack(pady=10)
        
        ttk.Button(steg_button_frame, text="Hide Message", command=self.hide_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(steg_button_frame, text="Extract Message", command=self.extract_message).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(steg_frame, text="Results:").pack(pady=(10,0))
        self.steg_result = tk.Text(steg_frame, height=6, width=80, font=("Courier", 9))
        self.steg_result.pack(pady=5, fill=tk.BOTH, expand=True, padx=20)
    
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_public_key(self, public_key_bytes):
        return serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
    
    def encrypt_aes_key(self, aes_key, public_key):
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_aes_key(self, encrypted_aes_key, private_key):
        return private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def encrypt_message(self, message, aes_key):
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag
        return iv, ciphertext + tag
    
    def decrypt_message(self, iv, encrypted_message, aes_key):
        if len(encrypted_message) < 16:
            raise ValueError("Encrypted message too short to contain tag")
        tag = encrypted_message[-16:]
        ciphertext = encrypted_message[:-16]
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def sign_message(self, message, private_key):
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify_signature(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def encrypt_message_gui(self):
        try:
            self.messaging_result.delete(1.0, tk.END)
            self.messaging_result.insert(tk.END, "Generating RSA key pairs...\n")
            self.root.update()
            
            self.alice_private_key, self.alice_public_key = self.generate_rsa_keys()
            self.bob_private_key, self.bob_public_key = self.generate_rsa_keys()
            
            alice_public_key_bytes = self.serialize_public_key(self.alice_public_key)
            bob_public_key_bytes = self.serialize_public_key(self.bob_public_key)
            
            alice_received_bob_public_key = self.deserialize_public_key(bob_public_key_bytes)
            
            message = self.message_entry.get().strip().encode()
            if not message:
                messagebox.showerror("Error", "Please enter a message")
                return
            
            self.messaging_result.insert(tk.END, f"Original message: {message.decode()}\n\n")
            
            self.messaging_result.insert(tk.END, "Alice signing message...\n")
            self.signature = self.sign_message(message, self.alice_private_key)
            
            self.messaging_result.insert(tk.END, "Generating AES key and encrypting...\n")
            self.aes_key = os.urandom(32)
            encrypted_aes_key = self.encrypt_aes_key(self.aes_key, alice_received_bob_public_key)
            
            self.iv, self.encrypted_data = self.encrypt_message(message, self.aes_key)
            
            self.messaging_result.insert(tk.END, "Message encrypted successfully!\n")
            base64_encoded = base64.b64encode(self.encrypted_data).decode()
            self.messaging_result.insert(tk.END, f"Encrypted message (Base64): {base64_encoded[:50]}...\n")
            self.base64_entry.delete(0, tk.END)
            self.base64_entry.insert(0, base64_encoded)
            self.messaging_result.insert(tk.END, "Click 'Decrypt' to verify and decrypt the message\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message_gui(self):
        try:
            self.messaging_result.delete(1.0, tk.END)
            self.messaging_result.insert(tk.END, "Decrypting message...\n")
            
            base64_input = self.base64_entry.get().strip()
            if not base64_input:
                messagebox.showerror("Error", "Please enter a Base64 encoded message")
                return
            
            encrypted_data = base64.b64decode(base64_input)
            if len(encrypted_data) < 16:
                messagebox.showerror("Error", "Invalid Base64 encoded message: too short to contain tag")
                return

            # Check if keys and IV are available
            if not all([self.iv, self.aes_key, self.bob_private_key]):
                messagebox.showerror("Error", "Please encrypt a message first to set up keys and IV")
                return
            
            # Decrypt using the stored IV and AES key
            decrypted_aes_key = self.decrypt_aes_key(self.encrypt_aes_key(self.aes_key, self.bob_public_key), self.bob_private_key)
            decrypted_message = self.decrypt_message(self.iv, encrypted_data, decrypted_aes_key)
            
            self.messaging_result.insert(tk.END, "Decryption successful!\n")
            self.messaging_result.insert(tk.END, f"\n=== RESULTS ===\n")
            self.messaging_result.insert(tk.END, f"Decrypted Message: {decrypted_message.decode()}\n")
            self.messaging_result.insert(tk.END, f"Encryption: AES-256-GCM\n")
            self.messaging_result.insert(tk.END, f"Key Exchange: RSA-2048\n")
            
            # Optional signature verification if original message is available
            message = self.message_entry.get().strip().encode()
            if message:
                bob_received_alice_public_key = self.deserialize_public_key(self.serialize_public_key(self.alice_public_key))
                self.messaging_result.insert(tk.END, "Verifying signature...\n")
                if self.verify_signature(message, self.signature, bob_received_alice_public_key):
                    self.messaging_result.insert(tk.END, "✓ Signature verified - message is authentic\n")
                else:
                    self.messaging_result.insert(tk.END, "✗ Signature verification failed!\n")
                self.messaging_result.insert(tk.END, f"Signature Status: {'✓ VERIFIED' if self.verify_signature(message, self.signature, bob_received_alice_public_key) else '✗ INVALID'}\n")
            else:
                self.messaging_result.insert(tk.END, "Note: Original message not available for signature verification.\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def clear_messaging(self):
        self.message_entry.delete(0, tk.END)
        self.base64_entry.delete(0, tk.END)
        self.messaging_result.delete(1.0, tk.END)
        self.encrypted_data = None
        self.iv = None
        self.aes_key = None
        self.signature = None
        self.alice_private_key = None
        self.alice_public_key = None
        self.bob_private_key = None
        self.bob_public_key = None
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
    
    def derive_key_from_password(self, password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)[:32]
    
    def encrypt_file(self):
        file_path = self.file_path_var.get()
        password = self.file_password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password")
            return
        
        try:
            self.file_result.delete(1.0, tk.END)
            self.file_result.insert(tk.END, "Starting file encryption...\n")
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            salt = os.urandom(16)
            key = self.derive_key_from_password(password, salt)
            
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            
            encrypted_file_path = file_path + ".encrypted"
            with open(encrypted_file_path, 'wb') as f:
                f.write(salt + iv + encryptor.tag + ciphertext)
            
            self.file_result.insert(tk.END, f"File encrypted successfully!\n")
            self.file_result.insert(tk.END, f"Encrypted file: {encrypted_file_path}\n")
            self.file_result.insert(tk.END, f"Algorithm: {self.encryption_algo.get()}\n")
            self.file_result.insert(tk.END, f"Original size: {len(file_data)} bytes\n")
            self.file_result.insert(tk.END, f"Encrypted size: {os.path.getsize(encrypted_file_path)} bytes\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_file(self):
        file_path = self.file_path_var.get()
        password = self.file_password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password")
            return
        
        try:
            self.file_result.delete(1.0, tk.END)
            self.file_result.insert(tk.END, "Starting file decryption...\n")
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]
            
            key = self.derive_key_from_password(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            if file_path.endswith('.encrypted'):
                decrypted_file_path = file_path[:-10]
            else:
                decrypted_file_path = file_path + ".decrypted"
            
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.file_result.insert(tk.END, f"File decrypted successfully!\n")
            self.file_result.insert(tk.END, f"Decrypted file: {decrypted_file_path}\n")
            self.file_result.insert(tk.END, f"Decrypted size: {len(decrypted_data)} bytes\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def hash_function(self, text, hash_type):
        text_bytes = text.encode('utf-8')
        if hash_type == "MD5":
            return hashlib.md5(text_bytes).hexdigest()
        elif hash_type == "SHA1":
            return hashlib.sha1(text_bytes).hexdigest()
        elif hash_type == "SHA256":
            return hashlib.sha256(text_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def brute_force_attack(self, target_hash, hash_type):
        self.hash_result.insert(tk.END, "Starting brute force attack with dynamic length...\n")
        
        chars = string.ascii_lowercase + string.digits + string.ascii_uppercase + string.punctuation
        length = 1
        
        while self.cracking_active:
            self.hash_result.insert(tk.END, f"Trying length {length}...\n")
            self.root.update()
            
            count = 0
            for password in itertools.product(chars, repeat=length):
                if not self.cracking_active:
                    break
                
                password_str = ''.join(password)
                count += 1
                
                if count % 1000 == 0:
                    self.hash_result.insert(tk.END, f"Tested {count} combinations for length {length}...\n")
                    self.root.update()
                
                if self.hash_function(password_str, hash_type).lower() == target_hash.lower():
                    return password_str
            
            length += 1
            if length > 16:  # Optional safety limit to prevent infinite loops
                break
        
        return None
    
    def start_hash_cracking(self):
        target_hash = self.hash_entry.get().strip()
        if not target_hash:
            messagebox.showerror("Error", "Please enter a hash to crack")
            return
        
        self.cracking_active = True
        self.hash_progress.start()
        self.hash_result.delete(1.0, tk.END)
        
        hash_type = self.hash_type.get()
        
        self.hash_result.insert(tk.END, f"Target hash: {target_hash}\n")
        self.hash_result.insert(tk.END, f"Hash type: {hash_type}\n")
        self.hash_result.insert(tk.END, f"Attack method: Brute Force with Dynamic Length\n\n")
        
        def crack_thread():
            try:
                start_time = time.time()
                result = self.brute_force_attack(target_hash, hash_type)
                
                end_time = time.time()
                elapsed = end_time - start_time
                
                if result and self.cracking_active:
                    self.hash_result.insert(tk.END, f"\n=== SUCCESS ===\n")
                    self.hash_result.insert(tk.END, f"Password found: {result}\n")
                    self.hash_result.insert(tk.END, f"Time elapsed: {elapsed:.2f} seconds\n")
                    messagebox.showinfo("Success", f"Password found: {result}")
                elif self.cracking_active:
                    self.hash_result.insert(tk.END, f"\n=== FAILED ===\n")
                    self.hash_result.insert(tk.END, f"Password not found (tried up to length 16)\n")
                    self.hash_result.insert(tk.END, f"Time elapsed: {elapsed:.2f} seconds\n")
                else:
                    self.hash_result.insert(tk.END, f"\n=== STOPPED ===\n")
                
                self.cracking_active = False
                self.hash_progress.stop()
                
            except Exception as e:
                self.hash_result.insert(tk.END, f"Error: {str(e)}\n")
                self.cracking_active = False
                self.hash_progress.stop()
        
        threading.Thread(target=crack_thread, daemon=True).start()
    
    def stop_hash_cracking(self):
        self.cracking_active = False
        self.hash_progress.stop()
        self.hash_result.insert(tk.END, "Stopping attack...\n")
    
    def generate_test_hash(self):
        test_password = "hello123"
        hash_type = self.hash_type.get()
        test_hash = self.hash_function(test_password, hash_type)
        
        self.hash_entry.delete(0, tk.END)
        self.hash_entry.insert(0, test_hash)
        
        self.hash_result.delete(1.0, tk.END)
        self.hash_result.insert(tk.END, f"Generated test hash for password '{test_password}':\n")
        self.hash_result.insert(tk.END, f"{hash_type}: {test_hash}\n")
        self.hash_result.insert(tk.END, f"Try cracking this hash!\n")
    
    def generate_signature_keys(self):
        try:
            self.signature_result.delete(1.0, tk.END)
            self.signature_result.insert(tk.END, "Generating RSA key pair...\n")
            
            self.private_key, self.public_key = self.generate_rsa_keys()
            
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.serialize_public_key(self.public_key)
            
            with open("private_key.pem", "wb") as f:
                f.write(private_pem)
            
            with open("public_key.pem", "wb") as f:
                f.write(public_pem)
            
            self.signature_result.insert(tk.END, "Key pair generated successfully!\n")
            self.signature_result.insert(tk.END, "Private key saved to: private_key.pem\n")
            self.signature_result.insert(tk.END, "Public key saved to: public_key.pem\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def load_private_key(self):
        filename = filedialog.askopenfilename(
            title="Select private key file",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                self.signature_result.delete(1.0, tk.END)
                self.signature_result.insert(tk.END, f"Private key loaded from: {filename}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {str(e)}")
    
    def load_public_key(self):
        filename = filedialog.askopenfilename(
            title="Select public key file",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "rb") as f:
                    self.public_key = self.deserialize_public_key(f.read())
                self.signature_result.delete(1.0, tk.END)
                self.signature_result.insert(tk.END, f"Public key loaded from: {filename}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {str(e)}")
    
    def sign_message_gui(self):
        if not self.private_key:
            messagebox.showerror("Error", "Please generate or load a private key first")
            return
        
        message = self.signature_message.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to sign")
            return
        
        try:
            signature = self.sign_message(message.encode(), self.private_key)
            signature_b64 = base64.b64encode(signature).decode()
            
            self.signature_entry.delete(0, tk.END)
            self.signature_entry.insert(0, signature_b64)
            
            self.signature_result.delete(1.0, tk.END)
            self.signature_result.insert(tk.END, "Message signed successfully!\n")
            self.signature_result.insert(tk.END, f"Message: {message}\n")
            self.signature_result.insert(tk.END, f"Signature (Base64): {signature_b64[:50]}...\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {str(e)}")
    
    def verify_signature_gui(self):
        if not self.public_key:
            messagebox.showerror("Error", "Please generate or load a public key first")
            return
        
        message = self.signature_message.get("1.0", tk.END).strip()
        signature_b64 = self.signature_entry.get().strip()
        
        if not message or not signature_b64:
            messagebox.showerror("Error", "Please enter both message and signature")
            return
        
        try:
            signature = base64.b64decode(signature_b64)
            is_valid = self.verify_signature(message.encode(), signature, self.public_key)
            
            self.signature_result.delete(1.0, tk.END)
            self.signature_result.insert(tk.END, f"Signature verification: {'✓ VALID' if is_valid else '✗ INVALID'}\n")
            self.signature_result.insert(tk.END, f"Message: {message}\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
    
    def browse_image(self):
        filename = filedialog.askopenfilename(
            title="Select cover image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"), ("All files", "*.*")]
        )
        if filename:
            self.image_path_var.set(filename)
    
    def hide_message(self):
        image_path = self.image_path_var.get()
        secret_msg = self.secret_message.get("1.0", tk.END).strip()
        
        if not image_path or not secret_msg:
            messagebox.showerror("Error", "Please select an image and enter a secret message")
            return
        
        try:
            self.steg_result.delete(1.0, tk.END)
            self.steg_result.insert(tk.END, "Hiding message in image...\n")
            
            img = Image.open(image_path)
            img = img.convert('RGB')
            
            secret_msg += "===END==="
            binary_msg = ''.join(format(ord(char), '08b') for char in secret_msg)
            
            pixels = list(img.getdata())
            
            if len(binary_msg) > len(pixels) * 3:
                messagebox.showerror("Error", "Message too large for this image")
                return
            
            new_pixels = []
            msg_index = 0
            
            for pixel in pixels:
                if msg_index < len(binary_msg):
                    r, g, b = pixel
                    
                    if msg_index < len(binary_msg):
                        r = (r & 0xFE) | int(binary_msg[msg_index])
                        msg_index += 1
                    
                    if msg_index < len(binary_msg):
                        g = (g & 0xFE) | int(binary_msg[msg_index])
                        msg_index += 1
                    
                    if msg_index < len(binary_msg):
                        b = (b & 0xFE) | int(binary_msg[msg_index])
                        msg_index += 1
                    
                    new_pixels.append((r, g, b))
                else:
                    new_pixels.append(pixel)
            
            stego_img = Image.new('RGB', img.size)
            stego_img.putdata(new_pixels)
            
            output_path = image_path.rsplit('.', 1)[0] + "_stego.png"
            stego_img.save(output_path, "PNG")
            
            self.steg_result.insert(tk.END, f"Message hidden successfully!\n")
            self.steg_result.insert(tk.END, f"Stego image saved to: {output_path}\n")
            self.steg_result.insert(tk.END, f"Message length: {len(secret_msg)} characters\n")
            self.steg_result.insert(tk.END, f"Binary length: {len(binary_msg)} bits\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Steganography failed: {str(e)}")
    
    def extract_message(self):
        image_path = self.image_path_var.get()
        
        if not image_path:
            messagebox.showerror("Error", "Please select a stego image")
            return
        
        try:
            self.steg_result.delete(1.0, tk.END)
            self.steg_result.insert(tk.END, "Extracting message from image...\n")
            
            img = Image.open(image_path)
            img = img.convert('RGB')
            
            pixels = list(img.getdata())
            
            binary_msg = ""
            
            for pixel in pixels:
                r, g, b = pixel
                binary_msg += str(r & 1)
                binary_msg += str(g & 1)
                binary_msg += str(b & 1)
            
            message = ""
            for i in range(0, len(binary_msg), 8):
                byte = binary_msg[i:i+8]
                if len(byte) == 8:
                    char = chr(int(byte, 2))
                    message += char
                    
                    if message.endswith("===END==="):
                        message = message[:-9]
                        break
            
            self.secret_message.delete("1.0", tk.END)
            self.secret_message.insert("1.0", message)
            
            self.steg_result.insert(tk.END, f"Message extracted successfully!\n")
            self.steg_result.insert(tk.END, f"Extracted message: {message[:50]}{'...' if len(message) > 50 else ''}\n")
            self.steg_result.insert(tk.END, f"Message length: {len(message)} characters\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Message extraction failed: {str(e)}")

def main():
    root = tk.Tk()
    app = CryptographicToolkit(root)
    root.mainloop()

if __name__ == "__main__":
    main()