import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Secret Keys
K = b'1234567890123456' # 16-byte AES Key
S = b'secret_salt_123'  # Secret 'S'

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # 1. H(M || S)
    h = hashlib.sha256(m_bytes + S).digest()
    steps.append(f"Hashed message with secret S: {h.hex()[:20]}...")
    
    # 2. [M || H]
    payload = m_bytes + h
    steps.append("Concatenated Message and Hash.")
    
    # 3. E(K, Payload)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    steps.append(f"Encrypted entire package with Key K (AES-CBC).")
    
    final_b64 = base64.b64encode(iv + ct).decode()
    return final_b64, steps

def decrypt_m4(b64_data):
    steps = []
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        steps.append("Decoded Base64 and extracted IV.")
        
        # 1. D(K, ct)
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        steps.append("Decryption successful.")
        
        # 2. Split
        m, h_rec = pt[:-32], pt[-32:]
        steps.append(f"Extracted Hash: {h_rec.hex()[:20]}...")
        
        # 3. Re-Verify H(M || S)
        h_calc = hashlib.sha256(m + S).digest()
        if h_rec == h_calc:
            steps.append("Verification: Hashes MATCH. Message is authentic.")
            return m.decode(), True, steps
        
        steps.append("Verification: Hashes DO NOT match! Tamper detected.")
        return "ALERT: DATA TAMPERED", False, steps
    except Exception as e:
        return f"Error: {str(e)}", False, ["Process failed at decryption step."]