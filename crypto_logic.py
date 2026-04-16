import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Shared Secrets (In a real app, these would be environment variables)
K = b'1234567890123456' # 16-byte AES Key
S = b'secret_salt_123'  # Shared Secret 'S' for Hashing

def encrypt_m4(message):
    steps = []
    m_bytes = message.encode()
    
    # 1. H(M || S) - Creating the HMAC-like signature
    h = hashlib.sha256(m_bytes + S).digest()
    steps.append(f"HASH GENERATED: SHA256(M + S) = {h.hex()[:16]}...")
    
    # 2. [M || H] - Binding identity to data
    payload = m_bytes + h
    steps.append("BINDING: Message and Hash concatenated into single payload.")
    
    # 3. E(K, Payload) - Encrypting everything
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    steps.append("ENCRYPTION: AES-128-CBC applied to [Message + Hash].")
    
    final_b64 = base64.b64encode(iv + ct).decode()
    return final_b64, steps

def decrypt_m4(b64_data):
    steps = []
    try:
        data = base64.b64decode(b64_data)
        iv, ct = data[:16], data[16:]
        steps.append("DECODING: Base64 components extracted.")
        
        # 1. D(K, ct) - Reveal M and H
        cipher = Cipher(algorithms.AES(K), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt_padded = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()
        steps.append("DECRYPTION: AES layer stripped. Payload revealed.")
        
        # 2. Split Message and Hash (SHA256 is 32 bytes)
        m, h_received = pt[:-32], pt[-32:]
        
        # 3. Re-Verify H(M || S)
        h_calculated = hashlib.sha256(m + S).digest()
        steps.append(f"VERIFYING: Recalculated Hash vs Received Hash...")
        
        if h_received == h_calculated:
            steps.append("SUCCESS: Hashes match. Integrity and Authenticity confirmed.")
            return m.decode(), True, steps
        
        steps.append("CRITICAL FAILURE: Hash mismatch! Data was altered.")
        return "ALERT: TAMPERED DATA", False, steps
    except Exception as e:
        return "ERROR: INVALID CIPHERTEXT", False, ["Decryption failed: Package corrupted."]