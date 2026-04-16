import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

K = b'1234567890123456' # AES-128 Key
S = b'secret_salt_123'  # Authentication Secret

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # STEP 1: SALTING
    salted = m_bytes + S
    steps.append({
        'title': '1. DATA SALTING (M || S)',
        'data': salted.hex(),
        'desc': f"The message '{message}' ({len(m_bytes)} bytes) is merged with secret salt '{S.decode()}'. This ensures that even if an attacker knows the plaintext, they cannot recreate the hash without the secret key 'S'."
    })
    
    # STEP 2: HASHING
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({
        'title': '2. SHA-256 MAC GENERATION',
        'data': h_obj.hexdigest(),
        'desc': f"A 256-bit unique 'digital fingerprint' is generated. SHA-256 uses 64 rounds of logical operations to ensure that changing even one bit in '{message}' results in a completely different 64-character hex string."
    })
    
    # STEP 3: ENCAPSULATION
    payload = m_bytes + h_digest
    steps.append({
        'title': '3. PAYLOAD BINDING [M || H]',
        'data': payload.hex(),
        'desc': f"The original message and the 32-byte hash are glued together. Total payload: {len(payload)} bytes. This creates the 'Authenticated Package' required for Method (d)."
    })
    
    # STEP 4: ENCRYPTION
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    steps.append({
        'title': '4. AES-128-CBC ENCRYPTION',
        'data': f"IV: {iv.hex()} | Ciphertext: {ct.hex()[:40]}...",
        'desc': f"The entire package is wrapped in an AES envelope. CBC mode XORs each block with the previous one. Using random IV {iv.hex()[:8]} ensures that the same message encrypted twice looks totally different."
    })
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    steps = []
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
            {'title': 'EXTRACTED HASH', 'data': h_received.hex(), 'desc': 'The 32-byte hash recovered from the decrypted envelope.'},
            {'title': 'CALCULATED HASH', 'data': h_calc.hex(), 'desc': 'The hash re-computed locally using the decrypted message and the secret salt.'}
        ]
        
        return m.decode(), (h_received == h_calc), steps
    except:
        return "ERROR", False, [{'title': 'CRITICAL', 'data': 'FAIL', 'desc': 'Package corrupted or invalid.'}]