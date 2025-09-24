import os
from Crypto.Cipher import AES

def generate_random_bytes(n: int) -> bytes:
    """Generate n random bytes using a secure RNG."""
    return os.urandom(n)

def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128 in ECB mode."""
    assert len(key) == 16, "AES-128 key must be 16 bytes"
    assert len(block) == 16, "Block must be 16 bytes"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))
