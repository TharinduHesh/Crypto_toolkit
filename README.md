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

## 💡 How It Works

### Secure Messaging:
1. Generate RSA key pairs for Alice & Bob.
2. Alice signs the message and encrypts it with AES-256.
3. AES key is encrypted using Bob's RSA public key.
4. Bob decrypts AES key, decrypts message, and verifies signature.

### File Encryption:
1. User selects file and password.
2. AES key is derived from password using PBKDF2.
3. File encrypted with AES-GCM and saved with salt+IV+tag.

### Hash Cracking:
1. User enters target hash and algorithm.
2. Toolkit generates combinations and hashes them.
3. Compares with target hash until match is found.

### Digital Signatures:
1. RSA key pair is generated or loaded.
2. User signs a message and gets Base64 signature.
3. Signature is verified using the public key.

### Steganography:
1. User selects an image and enters a secret message.
2. Message is encoded into image LSB and saved.
3. Can extract hidden messages from stego images.

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

   Install dependencies:


pip install cryptography pillow
Run the application:

  ```bash
python crypto_toolkit.py



## 🧠 Use Cases
Learn cryptography with real examples

Encrypt and decrypt messages or files

Understand brute-force attacks on hash functions

Practice digital signatures

Explore steganography in images


📄 License
MIT License – Free to use for learning, testing, and ethical purposes.

🙋‍♂️ Author
Tharindu H Ranasinghe
Cyber Security Undergraduate
📧 ranasingheheshan8@gmail.com
🔗 www.linkedin.com/in/tharindu-ranasinghe-b75b01285



---











