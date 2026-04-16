import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Security Parameters
K = b'1234567890123456' # AES-128 Key
S = b'secret_salt_123'  # Secret Salt 'S'

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # --- STEP 1: DATA SALTING ---
    salted = m_bytes + S
    steps.append({
        'label': 'SALTED DATA',
        'data': salted.hex(),
        'tech': f"The plaintext '{message}' is concatenated with the shared secret 'S'. In memory, this creates a new byte-array: {m_bytes.hex()} + {S.hex()}. This prevents pre-computation (Rainbow Table) attacks."
    })
    
    # --- STEP 2: SHA-256 HASHING ---
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({
        'label': 'SHA-256 FULL HASH',
        'data': h_obj.hexdigest(),
        'tech': f"The compression function processes the {len(salted)} bytes through 64 rounds of Bitwise XORs and Rotations. The result is a fixed 256-bit unique 'digital fingerprint' that proves the data hasn't been touched."
    })
    
    # --- STEP 3: ENCAPSULATION ---
    payload = m_bytes + h_digest
    steps.append({
        'label': 'ENCAPSULATED PAYLOAD',
        'data': payload.hex(),
        'tech': f"Following Method (d), we bind the message and hash together. The first {len(m_bytes)} bytes are your data; the final 32 bytes are the integrity tag. Total package size: {len(payload)} bytes."
    })
    
    # --- STEP 4: AES-128-CBC ENCRYPTION ---
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    steps.append({
        'label': 'AES-CBC CIPHERTEXT',
        'data': f"IV: {iv.hex()} | CT: {ct.hex()}",
        'tech': f"Confidentiality layer: Each 16-byte block is XORed with the previous ciphertext block. The IV ({iv.hex()[:8]}...) ensures that even if you send '{message}' again, the ciphertext will look completely different."
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
            {'label': 'RECOVERED HASH', 'data': h_received.hex(), 'tech': 'This 32-byte tag was extracted from the decrypted AES envelope.'},
            {'label': 'COMPUTED HASH', 'data': h_calc.hex(), 'tech': 'This was generated locally from the decrypted message and secret salt S.'}
        ]
        return m.decode(), (h_received == h_calc), steps
    except:
        return "ERROR", False, []