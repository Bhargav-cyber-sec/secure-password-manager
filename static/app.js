// static/app.js
document.addEventListener('DOMContentLoaded', () => {

    // --- State Management ---
    // Storing these in global vars is for demo purposes.
    let currentUser = null;
    let masterPassword = null; // The login password, held in memory
    let pbkdf2Salt = null; // The user-specific salt, sent from server
    
    // API_URL is no longer needed; we use relative paths (e.g., /login)
    // const API_URL = 'http://127.0.0.1:5001'; 

    // --- Safe Element Getter ---
    function getEl(id) {
        return document.getElementById(id);
    }

    // --- UI Elements ---
    const registerArea = getEl('register-area');
    const loginArea = getEl('login-area');
    const mfaLoginArea = getEl('mfa-login-area');
    const mfaEnrollArea = getEl('mfa-enroll-area');
    const vaultArea = getEl('vault-area');
    const messageArea = getEl('message-area');
    const vaultContent = getEl('vault-content');

    // --- UI Helpers ---

    let messageTimer;
    function showMessage(msg, isError = false) {
        if (!messageArea) {
            if (isError) console.error(msg); else console.info(msg);
            return;
        }

        // Clear any existing timer
        if (messageTimer) clearTimeout(messageTimer);

        messageArea.textContent = msg;
        messageArea.className = isError ? 'message-toast error' : 'message-toast success';
        messageArea.style.display = 'block';

        // Hide message after 3 seconds
        messageTimer = setTimeout(() => {
            messageArea.style.display = 'none';
        }, 3000);
    }

    function showView(view) {
        [registerArea, loginArea, mfaLoginArea, mfaEnrollArea, vaultArea].forEach(v => {
            if (v) v.style.display = 'none';
        });
        if (view) view.style.display = 'block';
    }

    // --- Crypto Helper Functions (The "Zero-Knowledge" Core) ---

    /**
     * CRITICAL FIX: Derive the encryption key using the user's
     * unique salt. This salt is provided by the server upon
     * successful login.
     */
    function deriveKey(password, salt) {
        if (typeof CryptoJS === 'undefined') throw new Error('CryptoJS not available');
        if (!salt) throw new Error("Encryption salt is missing! Cannot derive key.");

        const pbkdf2Salt = CryptoJS.enc.Hex.parse(salt);
        const iterations = 100000; // Standard iteration count
        const keySize = 256 / 32;
        
        return CryptoJS.PBKDF2(password, pbkdf2Salt, {
            keySize: keySize,
            iterations: iterations
        });
    }

    function encryptVault(data, key) {
        if (typeof CryptoJS === 'undefined') throw new Error('CryptoJS not available');
        const keyString = key.toString(CryptoJS.enc.Hex);
        const encrypted = CryptoJS.AES.encrypt(data, keyString);
        return encrypted.toString();
    }

    function decryptVault(encryptedBlob, key) {
        if (typeof CryptoJS === 'undefined') throw new Error('CryptoJS not available');
        try {
            const keyString = key.toString(CryptoJS.enc.Hex);
            const decrypted = CryptoJS.AES.decrypt(encryptedBlob, keyString);
            const out = decrypted.toString(CryptoJS.enc.Utf8);
            // If the output is empty string, it means decryption failed (wrong key)
            return out || null; 
        } catch (e) {
            console.error("Decryption failed. Bad password or corrupted blob?", e);
            return null;
        }
    }

    // --- Core Logic ---

    // Toggle links
    getEl('link-to-register')?.addEventListener('click', (e) => { e.preventDefault(); showView(registerArea); });
    getEl('link-to-login')?.addEventListener('click', (e) => { e.preventDefault(); showView(loginArea); });

    /**
     * 1. Register User
     */
    getEl('btn-register')?.addEventListener('click', async () => {
        const username = getEl('reg-username')?.value.trim();
        const password = getEl('reg-password')?.value;
        if (!username || !password) { showMessage("Username and password required.", true); return; }
        
        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (response.ok) {
                showMessage(data.status || 'Registered.');
                showView(loginArea);
            } else {
                showMessage(data.error || 'Registration failed', true);
            }
        } catch (err) {
            showMessage('Server error during registration.', true);
        }
    });

    /**
     * 2. Login - Step 1 (Password)
     */
    getEl('btn-login')?.addEventListener('click', async () => {
        const username = getEl('login-username')?.value.trim();
        const password = getEl('login-password')?.value;

        if (!username || !password) { showMessage("Please enter username and password.", true); return; }

        // Store credentials TEMPORARILY
        currentUser = username;
        masterPassword = password; 

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();

            if (response.ok) {
                if (data.mfa_required) {
                    showView(mfaLoginArea);
                } else {
                    // Login success! Store the salt.
                    pbkdf2Salt = data.pbkdf2_salt; 
                    showMessage('Login successful!');
                    await loadVault();
                }
            } else {
                showMessage(data.error || "Invalid credentials", true);
                logout(false); // Clear credentials
            }
        } catch (err) {
            showMessage('Server error during login.', true);
            logout(false); // Clear credentials
        }
    });

    /**
     * 3. Login - Step 2 (MFA Code)
     */
    getEl('btn-mfa-login')?.addEventListener('click', async () => {
        const totp_code = getEl('mfa-code')?.value;
        if (!totp_code) { showMessage('Enter MFA code.', true); return; }

        try {
            const response = await fetch('/mfa-verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser, totp_code })
            });
            const data = await response.json();
            if (response.ok && data.verified) {
                // MFA success! Store the salt.
                pbkdf2Salt = data.pbkdf2_salt; 
                showMessage('MFA verified! Logging in...');
                await loadVault();
            } else {
                showMessage(data.error || "Invalid MFA code.", true);
                logout(false); // CRITICAL: Clear credentials on MFA failure
                showView(loginArea); 
            }
        } catch (err) {
            showMessage('Server error during MFA verification.', true);
        }
    });

    /**
     * 4. Load the Encrypted Vault (Zero-Knowledge)
     */
    async function loadVault() {
        if (!currentUser || !masterPassword || !pbkdf2Salt) {
            showMessage('Error: Not logged in or salt is missing.', true);
            logout();
            return;
        }
        
        showView(vaultArea);
        try {
            const response = await fetch(`/vault?username=${encodeURIComponent(currentUser)}`);
            const data = await response.json();
            const encryptedBlob = data.vault_blob;
            
            if (encryptedBlob) {
                // Decrypt using the key derived from password AND unique salt
                const encryptionKey = deriveKey(masterPassword, pbkdf2Salt);
                const decryptedData = decryptVault(encryptedBlob, encryptionKey);
                
                if (decryptedData === null) {
                    // This is the user's "wrong password" check
                    showMessage("Decryption failed! Did you enter the correct master password?", true);
                    logout(); // Log out if password was wrong
                    return;
                }
                
                if (vaultContent) vaultContent.value = decryptedData;
            } else {
                // Vault is empty (e.g., new user)
                if (vaultContent) vaultContent.value = '';
                showMessage('Your vault is empty. Add some data!', false);
            }
        } catch (err) {
            showMessage('Error loading vault.', true);
        }
    }

    /**
     * 5. Save the Encrypted Vault (Zero-Knowledge)
     */
    getEl('btn-save-vault')?.addEventListener('click', async () => {
        if (!currentUser || !masterPassword || !pbkdf2Salt) {
            showMessage("Not logged in or salt is missing.", true); 
            return; 
        }
        const vaultData = vaultContent?.value || '';
        
        try {
            // Encrypt using the key derived from password AND unique salt
            const encryptionKey = deriveKey(masterPassword, pbkdf2Salt);
            const encryptedBlob = encryptVault(vaultData, encryptionKey);
            
            const response = await fetch('/vault', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser, vault_blob: encryptedBlob })
            });
            
            const data = await response.json();
            if (response.ok) {
                showMessage('Vault saved successfully!');
            } else {
                showMessage(data.error || 'Error saving vault.', true);
            }
        } catch (err) {
            showMessage('Server error while saving vault.', true);
        }
    });

    /**
     * 6. Start MFA Enrollment
     */
    getEl('btn-setup-mfa')?.addEventListener('click', async () => {
        try {
            const response = await fetch('/mfa-enroll', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser })
            });
            
            const data = await response.json();
            if (response.ok) {
                const qrContainer = getEl('qr-code');
                if (!qrContainer) { showMessage('QR container missing.', true); return; }

                showView(mfaEnrollArea);
                qrContainer.innerHTML = ''; // Clear old QR code
                
                if (typeof QRCode === 'undefined') {
                    qrContainer.innerHTML = 'Error: QRCode.js library not loaded.';
                    showMessage('QR library not loaded.', true);
                } else {
                    new QRCode(qrContainer, {
                        text: data.qr_uri || '',
                        width: 200,
                        height: 200,
                        colorDark: "#000000",
                        colorLight: "#ffffff",
                        correctLevel: QRCode.CorrectLevel.H
                    });
                }
            } else {
                showMessage(data.error || 'Error setting up MFA.', true);
            }
        } catch (err) {
            showMessage('Server error during MFA setup.', true);
        }
    });

    getEl('btn-mfa-done')?.addEventListener('click', () => {
        showView(vaultArea);
        showMessage("MFA enabled. Please log out and back in to test it.");
    });
    
    /**
     * 7. Logout
     */
    getEl('btn-logout')?.addEventListener('click', () => logout(true));
    
    function logout(showMessageOnSuccess = true) {
        // CRITICAL: Clear all sensitive in-memory data
        currentUser = null;
        masterPassword = null;
        pbkdf2Salt = null; 

        // Clear UI fields
        if (vaultContent) vaultContent.value = '';
        if (getEl('login-username')) getEl('login-username').value = '';
        if (getEl('login-password')) getEl('login-password').value = '';
        if (getEl('mfa-code')) getEl('mfa-code').value = '';
        
        if (showMessageOnSuccess) showMessage('Logged out.');
        showView(loginArea);
    }

    // Initial view
    if (loginArea) showView(loginArea);
    else showMessage('Login area not found; check your HTML IDs.', true);
});