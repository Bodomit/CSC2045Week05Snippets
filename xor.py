#!/usr/bin/env python
# -*- coding: utf-8 -*-

import array

# Encrypt Functions - XORs the PlainText and Key
def encrypt(plaintext, key):
    # Encrypted result stored here.
    encrypted_bytes = bytearray()

    # Loop through all the bytes in the plaintext.
    for i, plaintext_byte in enumerate(list(plaintext)):

        # Get the correct byte from the key.
        key_byte = key[i % len(key)]

        # Encrypt the plaintext byte using XOR (^)
        encrypted_byte = bytes([plaintext_byte ^  key_byte])

        # Store the encrypted byte.
        encrypted_bytes.extend(encrypted_byte)
    
    return bytes(encrypted_bytes)

key = b"Super secret key"
plaintext = b"Some super secret information we want to hide."
encrypted_text = encrypt(plaintext, key)
recovered_text = encrypt(encrypted_text, key)

print("Key: ", key)
print("PlainText: ", plaintext)
print("EncryptedText: ", encrypted_text)
print("RecoveredText: ", recovered_text)
