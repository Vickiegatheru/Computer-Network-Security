import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Security Parameters (In production, these should be hidden)
K = b'1234567890123456' # 16-byte AES-128 Key
S = b'secret_salt_123'  # Shared Secret 'S' for Authenticated Hashing

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # --- STEP 1: DATA SALTING ---
    salted = m_bytes + S
    steps.append({
        'label': '1. SALTED DATA (M || S)',
        'data': salted.hex(),
        'tech': f"The message '{message}' is merged with salt '{S.decode()}'. This ensures that even if an attacker intercepted the message, they cannot reproduce the hash without knowing the secret salt 'S'."
    })
    
    # --- STEP 2: FULL SHA-256 HASH GENERATION ---
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({
        'label': '2. SHA-256 AUTHENTICATION TAG',
        'data': h_obj.hexdigest(),
        'tech': f"A unique 64-character (256-bit) digital fingerprint is created. SHA-256 is 'collision-resistant', meaning no two different messages can produce this exact hash."
    })
    
    # --- STEP 3: ENCAPSULATION ---
    payload = m_bytes + h_digest
    steps.append({
        'label': '3. ENCAPSULATED PAYLOAD [M || H]',
        'data': payload.hex(),
        'tech': f"Following Method (d), the message and hash are bound together. The first {len(m_bytes)} bytes are your data; the final 32 bytes are the integrity seal."
    })
    
    # --- STEP 4: AES-128-CBC ENCRYPTION ---
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    steps.append({
        'label': '4. AES-128-CBC CIPHERTEXT',
        'data': f"IV: {iv.hex()} | CT: {ct.hex()}",
        'tech': f"The random IV ({iv.hex()[:8]}...) ensures that if you encrypt '{message}' twice, the results will look completely different, preventing pattern analysis."
    })
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt).finalize()
        
        m, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m + S).digest()
        
        steps = [
            {'label': 'EXTRACTED HASH', 'data': h_received.hex(), 'tech': 'This tag was extracted from the decrypted envelope.'},
            {'label': 'CALCULATED HASH', 'data': h_calc.hex(), 'tech': 'This was generated locally from the decrypted message and secret salt S.'}
        ]
        return m.decode(), (h_received == h_calc), steps
    except:
        return "ERROR", False, [{'label': 'CRITICAL', 'data': 'FAIL', 'tech': 'Package corrupted or invalid format.'}]