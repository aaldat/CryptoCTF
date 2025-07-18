# Read and understand the code. You'll easily find a way to forge the target cookie.
# nc 130.192.5.212 6521 

from Crypto.Cipher import ChaCha20

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

import base64
import json
from pwn import *

#Inserisco il token ottenuto dal server
token = "O011C90tMhuFVMZc.c7EqPvj8Of8w9A4xZ5+GMofqJfQ="

# Step 1: Parse token
b64nonce, b64ciphertext = token.split('.')
nonce = base64.b64decode(b64nonce)
ciphertext = base64.b64decode(b64ciphertext)

# Step 2: Known plaintext (what you typed as your username)
known_plain = json.dumps({
    "username": "aaaa"
}).encode()

# Step 3: Recover keystream
keystream = xor(ciphertext, known_plain)

# Step 4: Craft forged JSON
forged_plain = json.dumps({"admin": True}).encode()
forged_ct = xor(forged_plain, keystream[:len(forged_plain)])

# Step 5: Rebuild forged token
forged_token = f"{b64nonce}.{base64.b64encode(forged_ct).decode()}"
print("Forged admin token:")
print(forged_token)


