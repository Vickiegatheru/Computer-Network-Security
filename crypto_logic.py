import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Keys (Must be identical on both ends)
K = b'1234567890123456' # 16-byte AES Symmetric Key
S = b'secret_salt_123'  # Shared Secret 'S' for Authenticated Hashing

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # STEP 1: SALT CONCATENATION (M + S)
    salted = m_bytes + S
    steps.append({
        'label': '1. DATA SALTING (M || S)',
        'data': salted.hex(),
        'tech': f"The message '{message}' is combined with salt '{S.decode()}'. This ensures the hash is unique to this protocol."
    })
    
    # STEP 2: SHA-256 HASH GENERATION
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({
        'label': '2. SHA-256 AUTHENTICATION TAG',
        'data': h_obj.hexdigest(),
        'tech': "A 256-bit unique digital fingerprint is created. Changing 1 bit in the input flips ~128 bits here (Avalanche Effect)."
    })
    
    # STEP 3: ENCAPSULATION [M || H]
    payload = m_bytes + h_digest
    steps.append({
        'label': '3. ENCAPSULATED PAYLOAD [M || H]',
        'data': payload.hex(),
        'tech': f"Following Method (d), we bind the message and hash. Payload: {len(m_bytes)}B message + 32B hash."
    })
    
    # STEP 4: AES-128-CBC ENCRYPTION
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    steps.append({
        'label': '4. AES-128-CBC CIPHERTEXT',
        'data': f"IV: {iv.hex()} | CT: {ct.hex()}",
        'tech': "The package is encrypted. CBC mode ensures identical plaintexts result in different ciphertexts via the random IV."
    })
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    steps = []
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        
        m_bytes, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m_bytes + S).digest()
        
        steps = [
            {'label': 'EXTRACTED HASH', 'data': h_received.hex(), 'tech': 'The 32-byte tag recovered from the decrypted envelope.'},
            {'label': 'CALCULATED HASH', 'data': h_calc.hex(), 'tech': 'Re-computed locally using the decrypted message and secret salt S.'}
        ]
        
        return m_bytes.decode(), (h_received == h_calc), steps
    except Exception as e:
        return "ERROR", False, [{'label': 'CRITICAL', 'data': 'FAIL', 'tech': 'Invalid Package or Tampered Ciphertext.'}]