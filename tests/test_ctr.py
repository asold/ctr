import pytest
from src import ctr

def test_encrypt_decrypt_roundtrip():
    key = ctr.keygen()
    message = b"This is a test message."
    
    nonce, ciphertext = ctr.encrypt(key, message)
    decrypted = ctr.decrypt(key, nonce, ciphertext)
    
    assert decrypted == message, "Decryption failed to recover original message"

def test_different_nonce_produces_different_ciphertext():
    key = ctr.keygen()
    message = b"Same message each time"
    
    nonce1, ciphertext1 = ctr.encrypt(key, message)
    nonce2, ciphertext2 = ctr.encrypt(key, message)
    
    # Nonce must be unique
    assert nonce1 != nonce2, "Nonces should be unique"
    assert ciphertext1 != ciphertext2, "Ciphertexts should differ with different nonces"
