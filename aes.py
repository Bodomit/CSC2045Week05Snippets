#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES-256 ("Military-Grade Encryption") Example
key = get_random_bytes(32) 
plaintext = b"Some super secret information we want to hide."

# Encrypt.
encrypt_cipher = AES.new(key, AES.MODE_EAX)
encrypted_text, tag = encrypt_cipher.encrypt_and_digest(plaintext)

# Decrypt.
decrypt_cipher = AES.new(key, AES.MODE_EAX, nonce=encrypt_cipher.nonce)
recovered_text = decrypt_cipher.decrypt_and_verify(encrypted_text, tag)

# Print results.
print("Key: ", key)
print("Plaintext: ", plaintext)
print("Encrypted Text: ", encrypted_text)
print("Recovered Text: ", recovered_text)
