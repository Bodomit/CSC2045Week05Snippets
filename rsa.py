#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Get the public and private keys.
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

###############################################
########### On the sender's machine ###########
###############################################

data = b'Super secret data.'

# Get Session Key
session_key = get_random_bytes(16)

# Encrypt the session key with the public key.
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the session key.
cipher_aes = AES.new(session_key, AES.MODE_EAX)
nonce = cipher_aes.nonce
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

###############################################
######### On the recipient's machine ##########
###############################################

# Decrypt the session key with the private key.
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

print(data)