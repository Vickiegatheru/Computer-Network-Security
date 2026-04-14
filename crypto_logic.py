import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants for Method 4
K = b'1234567890123456' # 16-byte Key
S = b'secret_salt_123'  # Shared Secret

def encrypt_m4(message):
    m_bytes = message.encode()
    # 1. H(M || S)
    h = hashlib.sha256(m_bytes + S).digest()
    # 2. [M || H(M || S)]
    payload = m_bytes + h
    # 3. E(K, [...])
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_m4(b64_data):
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        # Split Message and Hash
        m, h_rec = pt[:-32], pt[-32:]
        # Verify
        if h_rec == hashlib.sha256(m + S).digest():
            return m.decode(), True
        return "TAMPERED!", False
    except:
        return "Invalid Data!", False