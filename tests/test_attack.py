import pytest
from src import ctr

def test_ctr_malleability_attack():
    key = ctr.keygen()
    message = b"We attack now!"
    
    nonce, ciphertext = ctr.encrypt(key, message)
    
    # attacker flips the first byte
    modified_ciphertext = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    
    modified_plaintext = ctr.decrypt(key, nonce, modified_ciphertext)
    
    # Check that only first byte is flipped
    expected_first_byte = bytes([message[0] ^ 0x01])
    assert modified_plaintext[0:1] == expected_first_byte, "First byte not flipped as expected"
    assert modified_plaintext[1:] == message[1:], "Other bytes should remain unchanged"
