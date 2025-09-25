import os
from Crypto.Cipher import AES

def generate_random_bytes(n: int) -> bytes:
    return os.urandom(n) ## produces n random bytes

def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    assert len(key) == 16, "AES-128 key must be 16 bytes"
    assert len(block) == 16, "Block must be 16 bytes"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b)) ## does a byte pair xor. 
