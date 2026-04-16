import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Secrets
K = b'1234567890123456' # 16-byte AES Key
S = b'secret_salt_123'  # Shared Secret 'S'

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # STEP 1: Append Salt
    salted = m_bytes + S
    steps.append(f"SALTED: '{message}' + '{S.decode()}'")
    
    # STEP 2: Generate Hash
    h = hashlib.sha256(salted).digest()
    steps.append(f"HASH: {h.hex()[:32]}...")
    
    # STEP 3: Concatenate [M || H]
    payload = m_bytes + h
    steps.append(f"PAYLOAD: [Msg] + [32-byte Hash Tag]")
    
    # STEP 4: Encrypt
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    steps.append(f"CIPHER: AES-CBC encrypted with IV {iv.hex()[:8]}...")
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    steps = []
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        steps.append(f"IV EXTRACTED: {iv.hex()}")
        
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        steps.append("DECRYPTED: AES layer removed.")
        
        m, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m + S).digest()
        
        steps.append(f"RECV HASH: {h_received.hex()[:24]}...")
        steps.append(f"CALC HASH: {h_calc.hex()[:24]}...")
        
        if h_received == h_calc:
            steps.append("VERIFIED: Hashes Match. Data is authentic.")
            return m.decode(), True, steps
        
        steps.append("FAILED: Hash Mismatch! Tampering detected.")
        return "ALERT: TAMPERED", False, steps
    except:
        return "ERROR: CORRUPT DATA", False, ["Process failed: Invalid Ciphertext format."]