# Crypto_toolkit
A GUI-based Cryptographic Toolkit built with Python and Tkinter. It supports secure messaging with AES and RSA, file encryption, hash cracking, digital signatures, and image-based steganography. Designed for cybersecurity learning, it combines real-world cryptographic techniques into one app.


# 🛡️ Cryptographic Toolkit

A comprehensive, GUI-based cryptographic toolkit built with **Python** and **Tkinter**, combining secure communication, file encryption, hash cracking, digital signatures, and steganography into a single educational application.

---

## 🚀 Features

### 1. 🔐 Secure Messaging
- Encrypt/decrypt messages using **AES-GCM** for confidentiality.
- RSA-based **key exchange** and **digital signatures** for authenticity.
- Base64 encoding/decoding for clean data transfer.

### 2. 📂 File Encryption
- Encrypt and decrypt any file using **AES-256** or **AES-128**.
- Password-based key derivation using PBKDF2 with SHA-256.
- Securely handles files with IV, salt, and GCM tags.

### 3. 🔍 Hash Cracker
- Crack **MD5**, **SHA1**, or **SHA256** hashes.
- Implements a **brute-force attack** with dynamic password length.
- Live status updates and multithreaded processing for UI responsiveness.

### 4. ✍️ Digital Signatures
- Generate **RSA key pairs** (2048-bit).
- Sign and verify messages using **PSS padding** and **SHA-256**.
- Keys saved as PEM files (`private_key.pem`, `public_key.pem`).

### 5. 🖼️ Steganography
- **Hide text messages** inside image files using LSB encoding.
- Extract messages from stego images.
- Works with `.png`, `.jpg`, `.bmp`, etc.

---

## 🧱 Built With
- Python 3.x
- Tkinter (GUI)
- cryptography
- Pillow (PIL)
- hashlib, itertools, base64, threading

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/crypto-toolkit.git
   cd crypto-toolkit
