import struct
from typing import Tuple
from .utils import generate_random_bytes, aes_encrypt_block, xor_bytes

# Keep track of used nonces (optional for homework)
_USED_NONCES = set()

def keygen() -> bytes:
    return generate_random_bytes(16)

def generate_nonce() -> bytes:
    while True:
        nonce = generate_random_bytes(16) ## random 16 bytes. 
        if nonce not in _USED_NONCES:
            _USED_NONCES.add(nonce)
            return nonce

def _counter_block(nonce: bytes, counter: int) -> bytes:
    assert len(nonce) == 16
    prefix = nonce[:8]   # use first 8 bytes of nonce
    ctr_bytes = struct.pack(">Q", counter)  # converts the counter int into 8 bytes
    ## >Q means big endian unsigned long long
    return prefix + ctr_bytes

def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    nonce = generate_nonce()
    ciphertext = b""
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)] ## splits plaintext into 16 byte blocks.

    for counter, block in enumerate(blocks):
        keystream = aes_encrypt_block(key, _counter_block(nonce, counter))## uses the key to encrypt the counter block.
        ## outputs 16 bytes keystream block
        ciphertext += xor_bytes(block, keystream[:len(block)]) ## if block is shorter than 16 bytes, then we take the first x bytes from the key

    return nonce, ciphertext

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    plaintext = b""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)] ## split the cipher into block os 16 bytes

    for counter, block in enumerate(blocks):
        keystream = aes_encrypt_block(key, _counter_block(nonce, counter))## creates the same sequence of aes inputs
        ## gives the same keystream as during encryption
        plaintext += xor_bytes(block, keystream[:len(block)])## xoring the encrypted blocks with the keystream produces cyphertext blocks

    return plaintext

if __name__ == "__main__":
    # Simple test
    key = keygen()
    message = b"Hello, World! This is a test message for AES-CTR mode."
    nonce, ciphertext = encrypt(key, message)
    decrypted = decrypt(key, nonce, ciphertext)
    assert decrypted == message
    print("Encryption and decryption successful.")
