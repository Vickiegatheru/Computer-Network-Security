import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Secret Keys
K = b'1234567890123456' # 16-byte AES Key
S = b'secret_salt_123'  # Shared Salt 'S'

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # 1. Salt
    salted = m_bytes + S
    steps.append({'label': '1. SALTING', 'data': salted.hex(), 'tech': 'M + S concatenated.'})
    
    # 2. Hash (The Seal)
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({'label': '2. SHA-256 HASH', 'data': h_obj.hexdigest(), 'tech': 'Full 256-bit integrity tag.'})
    
    # 3. Binding [M || H]
    payload = m_bytes + h_digest
    steps.append({'label': '3. BINDING', 'data': payload.hex(), 'tech': 'Message and Hash bound together.'})
    
    # 4. Encryption
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    try:
        data = base64.b64decode(b64_data.strip())
        iv, ct = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        
        # Method (d) Separation
        m_bytes, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m_bytes + S).digest()
        
        # Prepare data for comparison UI
        steps = [
            {'label': 'RECEIVED HASH (From Package)', 'data': h_received.hex()},
            {'label': 'CALCULATED HASH (From Message)', 'data': h_calc.hex()}
        ]
        
        return m_bytes.decode(), (h_received == h_calc), steps
    except Exception as e:
        return "ERROR", False, [{'label': 'CRITICAL FAILURE', 'data': str(e)}]