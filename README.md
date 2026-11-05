# StegoCrypt — Secure File Sharing System

A student major-project prototype using Flask, SQLite, AES-256-GCM encryption, Scrypt key derivation, and RGB least-significant-bit (LSB) image steganography.

## Features
- Register and log in with hashed account passwords
- Encrypt any file into an authenticated AES-GCM envelope
- Embed the encrypted bytes in a carrier image and download a PNG
- Extract and decrypt the original file using the same password
- SQLite encoding history for the signed-in user
- Responsive HTML/CSS interface

## Requirements
- Python 3.10 or newer
- Internet is not required for Python packages after installation; the Google Fonts import in CSS is optional.

## Run on Windows
1. Extract this folder.
2. Open Command Prompt in the `stegocrypt` folder.
3. Create a virtual environment:
   ```bat
   python -m venv venv
   venv\Scripts\activate
   ```
4. Install packages:
   ```bat
   pip install -r requirements.txt
   ```
5. Start the application:
   ```bat
   python app.py
   ```
6. Open `http://127.0.0.1:5000` in your browser.
7. Register, log in, then use **Encode** or **Decode**.

## Suggested demonstration
1. Register a new account and sign in.
2. On Encode, choose a small document and a sufficiently large image, then enter a password of at least 8 characters.
3. Save the downloaded `stegocrypt_*.png` without editing or recompressing it.
4. Open Decode, upload that PNG, and enter the same password. The recovered file downloads.
5. Try a wrong password to demonstrate authenticated decryption failure.

## Important limitations and security notes
- This is an educational prototype, not a production-ready file-sharing service. It does not provide end-to-end user-to-user sharing links or access control for recipients yet; the encoded PNG is the shareable artifact, and the recipient needs the password and this app's Decode page.
- LSB steganography is not a substitute for encryption. Do not edit, resize, or recompress encoded images; this can destroy the hidden data.
- Use a large carrier image. Embedding adds a 4-byte length header and cryptographic metadata, so the image must have enough RGB pixel capacity.
- The Flask development server is enabled for local testing only. Before deployment, disable debug mode, configure a stable secret key through `STEGOCRYPT_SECRET_KEY`, add CSRF protection and rate limiting, enforce stricter upload validation, and deploy behind HTTPS using a production WSGI server.
- The 25 MB limit applies to the whole request, not just the secret file.
- The history records filenames and generated image names, not encryption passwords or secret-file contents.
