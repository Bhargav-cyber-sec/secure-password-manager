# app.py
from flask import Flask, request, jsonify, render_template
import bcrypt
import pyotp
import base64
import os
import sqlite3

# --- Configuration ---
app = Flask(__name__)
DATABASE = 'users.db'

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            pbkdf2_salt TEXT NOT NULL,
            mfa_secret TEXT,
            vault_blob TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Utility Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

# --- Routes ---

@app.route('/')
def index():
    # Serves the main HTML page from the 'templates' folder
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # 1. Hash the master password for login (bcrypt)
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # 2. Create a unique salt for vault encryption (PBKDF2)
    # This is the CRITICAL FIX
    pbkdf2_salt = os.urandom(16).hex() 
    
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, pbkdf2_salt) VALUES (?, ?, ?)", 
            (username, hashed_password.decode('utf-8'), pbkdf2_salt)
        )
        conn.commit()
        return jsonify({"status": "User registered successfully."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists."}), 409
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    # Fetch all data needed for login and decryption
    user = conn.execute(
        "SELECT password_hash, mfa_secret, pbkdf2_salt FROM users WHERE username = ?", 
        (username,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # Verify password
    try:
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            if user['mfa_secret']:
                # User has MFA. Don't send salt yet.
                return jsonify({"mfa_required": True, "status": "MFA required"}), 200
            else:
                # Login successful, no MFA. Send the salt for decryption.
                return jsonify({
                    "mfa_required": False, 
                    "pbkdf2_salt": user['pbkdf2_salt'], 
                    "status": "Login successful"
                }), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except ValueError:
        return jsonify({"error": "Invalid credentials (hash error)"}), 401


@app.route('/mfa-enroll', methods=['POST'])
def mfa_enroll():
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({"error": "Username required"}), 400

    new_secret = base64.b32encode(os.urandom(10)).decode('utf-8').replace('=', '')
    totp_uri = pyotp.totp.TOTP(new_secret).provisioning_uri(
        name=username,
        issuer_name="SecureVault (Demo)"
    )

    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET mfa_secret = ? WHERE username = ?", 
            (new_secret, username)
        )
        conn.commit()
    except Exception as e:
        print(f"DATABASE ERROR during MFA enrollment: {e}")
        return jsonify({"error": "Database error during MFA setup."}), 500
    finally:
        conn.close()

    return jsonify({"qr_uri": totp_uri}), 200

@app.route('/mfa-verify', methods=['POST'])
def mfa_verify():
    data = request.json
    username = data.get('username')
    totp_code = data.get('totp_code')

    conn = get_db_connection()
    # Fetch secret AND salt
    user = conn.execute(
        "SELECT mfa_secret, pbkdf2_salt FROM users WHERE username = ?", 
        (username,)
    ).fetchone()
    conn.close()

    if not user or not user['mfa_secret']:
        return jsonify({"error": "MFA not enabled or user not found."}), 400

    totp = pyotp.TOTP(user['mfa_secret'])
    if totp.verify(totp_code):
        # MFA verified. Send the salt for decryption.
        return jsonify({
            "verified": True, 
            "status": "MFA verified",
            "pbkdf2_salt": user['pbkdf2_salt'] # <-- Send salt
        }), 200
    else:
        return jsonify({"error": "Invalid MFA code."}), 401

@app.route('/vault', methods=['GET'])
def load_vault():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Username required"}), 400
        
    conn = get_db_connection()
    user = conn.execute("SELECT vault_blob FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user:
        return jsonify({"vault_blob": user['vault_blob']}), 200
    
    return jsonify({"error": "User not found"}), 404

@app.route('/vault', methods=['POST'])
def save_vault():
    data = request.json
    username = data.get('username')
    vault_blob = data.get('vault_blob') 

    if not username or vault_blob is None:
        return jsonify({"error": "Username and vault data required"}), 400

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET vault_blob = ? WHERE username = ?", 
        (vault_blob, username)
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "Vault saved successfully"}), 200

if __name__ == '__main__':
    # Runs on port 5001, serving both the API and the frontend
    app.run(debug=True, port=5001)