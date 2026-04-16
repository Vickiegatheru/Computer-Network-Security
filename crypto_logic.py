import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

K = b'1234567890123456' # AES-128 Symmetric Key
S = b'secret_salt_123'  # Shared Secret 'S'

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # STEP 1: SALTING
    salted = m_bytes + S
    steps.append({
        'label': '1. DATA SALTING (M || S)',
        'data': salted.hex(),
        'tech': f"Technical: We perform a byte-level concatenation of the message '{message}' and the secret salt '{S.decode()}'. This ensures 'Keyed Hashing', where an attacker cannot reproduce the integrity tag even if they know the original message, because they lack the secret salt 'S'."
    })
    
    # STEP 2: SHA-256 HASH GENERATION
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({
        'label': '2. SHA-256 MAC GENERATION',
        'data': h_obj.hexdigest(),
        'tech': "Technical: The salted message is processed through 64 rounds of compression. Using SHA-256 ensures 'Collision Resistance' (no two messages yield the same hash) and the 'Avalanche Effect' (changing one bit of input flips roughly 50% of the output bits), providing a unique digital fingerprint."
    })
    
    # STEP 3: ENCAPSULATION
    payload = m_bytes + h_digest
    steps.append({
        'label': '3. BINDING [MESSAGE || HASH]',
        'data': payload.hex(),
        'tech': f"Technical: We bind the {len(m_bytes)}-byte message and the 32-byte hash into a single continuous payload. This follows the Method (d) architecture where the integrity proof is physically attached to the data it protects before encryption begins."
    })
    
    # STEP 4: AES-128-CBC ENCRYPTION
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    steps.append({
        'label': '4. AES-128-CBC ENCRYPTION',
        'data': f"IV: {iv.hex()} | CT: {ct.hex()[:64]}...",
        'tech': f"Technical: The payload is encrypted using the Advanced Encryption Standard (AES). CBC mode XORs each block with the previous one, and the random IV ({iv.hex()[:8]}) ensures 'Semantic Security'—identical messages will look completely different every time they are encrypted."
    })
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    try:
        data = base64.b64decode(b64_data.strip())
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt).finalize()
        
        m, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m + S).digest()
        
        steps = [
            {'label': 'RECOVERED HASH (FROM PACKAGE)', 'data': h_received.hex(), 'tech': 'This is the original hash that was hidden inside the AES envelope.'},
            {'label': 'CALCULATED HASH (FROM MESSAGE)', 'data': h_calc.hex(), 'tech': 'This was generated locally from the decrypted message to check for tampering.'}
        ]
        return m.decode(), (h_received == h_calc), steps
    except:
        return "ERROR", False, [{'label': 'CRITICAL', 'data': 'FAIL', 'tech': 'Package corrupted or invalid.'}]