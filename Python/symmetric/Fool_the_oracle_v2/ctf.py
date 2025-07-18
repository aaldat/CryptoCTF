# fool this new one...
# nc 130.192.5.212 6542 

from pwn import *
import string
from Crypto.Cipher import AES
import os

HOST = "130.192.5.212"
PORT = 6542 

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
context.log_level = 'error'

SECRET_LEN = 48
secret = ""

if __name__ == '__main__':
    prefix = b'Here is the'

    BLOCK_SIZE = AES.block_size


    for i in range(1,SECRET_LEN):
        pad = "A"*(AES.block_size*3-i)
        for letter in string.printable:

            server_gen = remote(HOST, PORT)
            server_gen.recv(1024).decode()
            server_gen.send(b"enc\n")
            server_gen.recv(1024).decode()
            msg = str(prefix.decode())+pad+secret+letter+pad
            server_gen.send((str(msg.encode().hex())+'\n').encode())
            ciphertext = server_gen.recv(4096).strip().splitlines()[0].decode()
            ciphertext2 = bytes.fromhex(ciphertext)
            ciphertext3 = ciphertext2[16:]

            server_gen.close()

            if ciphertext3[32:48] == ciphertext3[80:96]:
                print("Found new character = "+letter)
                secret+=letter
                print(secret)
                break

    print("Secret discovered = "+secret)

        