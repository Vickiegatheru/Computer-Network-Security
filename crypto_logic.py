import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Security Parameters
K = b'1234567890123456' # AES-128 Key
S = b'secret_salt_123'  # Shared Secret 'S'

def encrypt_m4(message, tamper=False):
    steps = []
    m_bytes = message.encode()
    
    # 1. SALTING (M || S)
    salted = m_bytes + S
    steps.append({
        'title': '1. DATA SALTING (M || S)',
        'data': salted.hex(),
        'desc': f"The message '{message}' is concatenated with secret salt '{S.decode()}'. This binds the identity (Salt) to the data (M) before hashing."
    })
    
    # 2. SHA-256 HASH GENERATION
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    
    # TAMPERED HASH (if tamper mode is enabled)
    if tamper:
        h_digest_display = h_digest[:-4] + b'\x00\x00\x00\x00'  # Corrupt last 4 bytes
        steps.append({
            'title': '2. SHA-256 MAC GENERATION',
            'data': h_obj.hexdigest(),
            'desc': "A 256-bit unique digital fingerprint is created. SHA-256 is used here for its high collision resistance and avalanche effect properties."
        })
        steps.append({
            'title': '⚠️ HASH TAMPERING (SIMULATED ATTACK)',
            'data': h_digest_display.hex(),
            'desc': f"WARNING: The hash has been intentionally corrupted! Original: {h_digest.hex()[:16]}... | Tampered: {h_digest_display.hex()[:16]}... This simulates an attacker modifying the MAC tag."
        })
        h_digest = h_digest_display
    else:
        steps.append({
            'title': '2. SHA-256 MAC GENERATION',
            'data': h_obj.hexdigest(),
            'desc': "A 256-bit unique digital fingerprint is created. SHA-256 is used here for its high collision resistance and avalanche effect properties."
        })
    
    # 3. ENCAPSULATION [M || H]
    payload = m_bytes + h_digest
    steps.append({
        'title': '3. PAYLOAD BINDING [M || H]',
        'data': payload.hex(),
        'desc': f"Following Method (d), we bind the {len(m_bytes)}B message and the 32B hash tag into a single payload for encryption."
    })
    
    # 4. AES-128-CBC ENCRYPTION
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    
    steps.append({
        'title': '4. AES-128-CBC ENCRYPTION',
        'data': f"IV: {iv.hex()} | CT: {ct.hex()[:48]}...",
        'desc': f"The package is hidden using AES. Random IV {iv.hex()[:8]} ensures identical messages result in totally unique ciphertexts."
    })
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    try:
        data = base64.b64decode(b64_data.strip())
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt) + unpadder.finalize()
        
        m, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m + S).digest()
        
        is_valid = h_received == h_calc
        
        steps = [
            {'title': 'RECEIVED HASH (from ciphertext)', 'data': h_received.hex(), 'desc': 'The 32-byte integrity tag extracted from the decrypted envelope.'},
            {'title': 'CALCULATED HASH (recomputed)', 'data': h_calc.hex(), 'desc': 'The hash re-computed from the decrypted message and secret salt S.'},
            {
                'title': 'HASH COMPARISON & VERIFICATION',
                'data': 'MATCH ✅' if is_valid else 'MISMATCH ❌',
                'desc': (
                    'Both hashes are identical! The message has not been tampered with during transmission. '
                    'MAC verification passed: authenticity and integrity are confirmed.' if is_valid
                    else 'The hashes do NOT match! This indicates the message was corrupted, tampered with, or decrypted with wrong key/salt. '
                    'The package is COMPROMISED and cannot be trusted.'
                )
            }
        ]
        return m.decode(), is_valid, steps
    except Exception as e:
        return f"ERROR: {str(e)}", False, [
            {'title': 'RECEIVED HASH', 'data': 'N/A', 'desc': 'Could not extract hash - decryption failed.'},
            {'title': 'CALCULATED HASH', 'data': 'N/A', 'desc': 'Could not compute hash - decryption failed.'},
            {
                'title': 'HASH COMPARISON & VERIFICATION',
                'data': 'ERROR ❌',
                'desc': f'Package corrupted or invalid ciphertext: {str(e)}'
            }
        ]