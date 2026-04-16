import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

K = b'1234567890123456' # AES-128 Key
S = b'secret_salt_123'  # Authentication Secret

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # 1. Salting
    salted = m_bytes + S
    steps.append({'label': 'SALTED DATA', 'data': salted.hex(), 'tech': 'Concatenated message with secret salt.'})
    
    # 2. Hashing
    h_obj = hashlib.sha256(salted)
    h_digest = h_obj.digest()
    steps.append({'label': 'SHA-256 HASH', 'data': h_obj.hexdigest(), 'tech': 'Generated 32-byte integrity tag.'})
    
    # 3. Encapsulation
    payload = m_bytes + h_digest
    
    # 4. Encryption
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    
    steps.append({'label': 'FINAL PAYLOAD', 'data': (iv + ct).hex(), 'tech': 'Encrypted using AES-CBC with random IV.'})
    
    return base64.b64encode(iv + ct).decode(), steps

def decrypt_m4(b64_data):
    steps = []
    try:
        # Clean the input string (remove spaces/newlines)
        b64_data = b64_data.strip()
        data = base64.b64decode(b64_data)
        
        if len(data) < 48: # Min length: 16(IV) + 32(Hash) + Message
            raise ValueError("Data too short")

        iv, ct = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt_padded = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        
        m, h_received = pt[:-32], pt[-32:]
        h_calc = hashlib.sha256(m + S).digest()
        
        steps = [
            {'label': 'DECRYPTED HASH', 'data': h_received.hex(), 'tech': 'Extracted from envelope.'},
            {'label': 'RE-COMPUTED HASH', 'data': h_calc.hex(), 'tech': 'Calculated from decrypted message.'}
        ]
        
        return m.decode(), (h_received == h_calc), steps
    except Exception as e:
        # This will show specifically what went wrong in your UI logs
        return "DECRYPTION FAILED", False, [{'label': 'ERROR', 'data': 'FAIL', 'tech': f'Technical Error: {str(e)}'}]