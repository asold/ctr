import struct
from typing import Tuple
from .utils import generate_random_bytes, aes_encrypt_block, xor_bytes

# Keep track of used nonces (optional for homework)
_USED_NONCES = set()

def keygen() -> bytes:
    """Generate a random AES-128 key (16 bytes)."""
    return generate_random_bytes(16)

def generate_nonce() -> bytes:
    """Generate a random 16-byte nonce, ensuring uniqueness."""
    while True:
        nonce = generate_random_bytes(16)
        if nonce not in _USED_NONCES:
            _USED_NONCES.add(nonce)
            return nonce

def _counter_block(nonce: bytes, counter: int) -> bytes:
    """Construct a counter block: nonce[0:8] || counter (64-bit big-endian)."""
    assert len(nonce) == 16
    prefix = nonce[:8]   # use first 8 bytes of nonce
    ctr_bytes = struct.pack(">Q", counter)  # 64-bit counter
    return prefix + ctr_bytes

def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-128 in CTR mode.
    Returns (nonce, ciphertext)."""
    nonce = generate_nonce()
    ciphertext = b""
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    for counter, block in enumerate(blocks):
        keystream = aes_encrypt_block(key, _counter_block(nonce, counter))
        ciphertext += xor_bytes(block, keystream[:len(block)])

    return nonce, ciphertext

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 in CTR mode."""
    plaintext = b""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    for counter, block in enumerate(blocks):
        keystream = aes_encrypt_block(key, _counter_block(nonce, counter))
        plaintext += xor_bytes(block, keystream[:len(block)])

    return plaintext

if __name__ == "__main__":
    # Simple test
    key = keygen()
    message = b"Hello, World! This is a test message for AES-CTR mode."
    nonce, ciphertext = encrypt(key, message)
    decrypted = decrypt(key, nonce, ciphertext)
    assert decrypted == message
    print("Encryption and decryption successful.")
