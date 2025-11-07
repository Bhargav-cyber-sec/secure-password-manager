# 🔒 SecureVault: A Zero-Knowledge Password Manager

SecureVault is a web-based password manager built with Python (Flask) and vanilla JavaScript. It demonstrates a **"zero-knowledge"** security model where the server *never* sees a user's unencrypted passwords. All encryption and decryption happen client-side using a key derived from the user's master password.

This project was built as a portfolio piece to demonstrate secure coding practices, full-stack development, and authentication (including MFA).



---

## Key Features

* **Zero-Knowledge Architecture:** The server only stores an encrypted blob of data. The master password never leaves the client.
* **Client-Side Encryption:** Uses **PBKDF2** (with a unique, per-user salt) to derive a strong encryption key from the master password.
* **Strong Encryption:** Vaults are encrypted and decrypted in the browser using **AES-256**.
* **Secure Authentication:** User login passwords are hashed using **bcrypt** on the server.
* **Multi-Factor Authentication:** Supports Time-based One-Time Passwords (**TOTP**) for an extra layer of security (compatible with Google Authenticator, Authy, etc.).

---

## How the Security Model Works

The "zero-knowledge" model is the core of this project.

1.  **Registration:**
    * You provide a `username` and `master_password`.
    * The server hashes the `master_password` with **bcrypt** and stores this hash for login.
    * The server *also* generates a **unique random salt** for you (`pbkdf2_salt`) and stores it. This salt is *only* for vault encryption, not for login.

2.  **Login:**
    * You enter your `master_password`.
    * The server checks it against the `bcrypt` hash.
    * If you have MFA, you're asked for a TOTP code.

3.  **Data Fetching (The "Zero-Knowledge" Part):**
    * After a successful login, the server sends two things to your browser:
        1.  Your encrypted `vault_blob` (which the server can't read).
        2.  Your unique `pbkdf2_salt`.

4.  **Client-Side Decryption:**
    * The JavaScript in your browser takes your `master_password` (from memory) and the `pbkdf2_salt` (from the server).
    * It runs them through **PBKDF2** to re-create your unique encryption key.
    * It then uses this key to decrypt the `vault_blob` with **AES** right in your browser.

5.  **Saving:**
    * The process is reversed. The JavaScript on your client encrypts your vault data with the derived key and sends *only the encrypted blob* to the server.

**The Result:** The server never has access to your plaintext master password (only a bcrypt hash), your encryption key, or your unencrypted vault data.

---

## Technology Stack

### Backend
* **Python 3**
* **Flask:** A lightweight web framework for the API.
* **SQLite:** A simple file-based database.
* **bcrypt:** For securely hashing user login passwords.
* **pyotp:** For generating and verifying MFA (TOTP) codes.

### Frontend
* **HTML5**
* **CSS3:** For modern, clean styling.
* **Vanilla JavaScript:** For all client-side logic, including UI and crypto.
* **CryptoJS:** Used for client-side AES encryption and PBKDF2 key derivation.
* **qrcode.js:** For generating the MFA setup QR code.

---

## How to Run This Project

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
    cd YOUR_REPO_NAME
    ```

2.  **Create a virtual environment (Recommended):**
    ```bash
    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install Flask bcrypt pyotp
    ```

4.  **Run the application:**
    ```bash
    python app.py
    ```
    The server will initialize the `users.db` file automatically.

5.  **Open in your browser:**
    Navigate to `http://127.0.0.1:5001/`

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.