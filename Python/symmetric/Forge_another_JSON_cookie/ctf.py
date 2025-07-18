# ...it's more or less the same but with more errors to manage!
# nc 130.192.5.212 6551 

from pwn import *
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import json

HOST = "130.192.5.212"
PORT = 6551

BLOCK_SIZE = 16


def extract_token(tok: str) -> str:
    prefix = "This is your token: "
    start = tok.find(prefix)
    if start == -1:
        raise ValueError("Token not found")
    start += len(prefix)
    end = tok.find("\n", start)
    return tok[start:end].strip()


if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    server_gen.recv(1024)
    usr = 'AA               "AAAAAAAAA                     ":               true,              A' + '\n'
    server_gen.send(usr)
    token = (server_gen.recv(1024)).decode()
    print(token)
    token = extract_token(token)
    token = base64.b64decode(token)
    print(len(token))
    cookie = token[:16] + token[96:112] + token[80:96] + token[32:48] + token[64:80] + token[112:128] 
    msg = b'flag\n'
    server_gen.send(msg)
    print(server_gen.recv(1024).decode())
    cookie = base64.b64encode(cookie)+b'\n'
    server_gen.send(cookie)
    print(server_gen.recv(4096).decode())





