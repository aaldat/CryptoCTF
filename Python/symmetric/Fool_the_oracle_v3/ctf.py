# ...even more complex now...
# nc 130.192.5.212 6543 

from pwn import *
import string
from Crypto.Cipher import AES
import os

HOST = "130.192.5.212"
PORT = 6543 

BLOCK_SIZE = AES.block_size

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
context.log_level = 'error'

SECRET_LEN = 48
secret = ""

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    server_gen.recv(1024).decode()
    found=0

    for j in range(1, 16): 

        for i in range(1,SECRET_LEN):
            pad_end = "A"*(AES.block_size*3-i)
            pad_start = pad_end + "A"*j
            for letter in string.printable:
                
                server_gen.send(b"enc\n")
                server_gen.recv(1024).decode()
                msg = pad_start+secret+letter+pad_end
                print("Sending: "+str(msg.encode().hex()))
                server_gen.send((str(msg.encode().hex())+'\n').encode())
                ciphertext = server_gen.recvuntil(b'\n').decode()
                server_gen.recv(4096)
                ciphertext2 = bytes.fromhex(str(ciphertext))
                ciphertext3 = ciphertext2[16:]

                if ciphertext3[32:48] == ciphertext3[80:96]:
                    found=1
                    print("Found new character = "+letter)
                    secret+=letter
                    print(secret)
                    break
            if found==0:
                break
        if found==1:
            server_gen.close()

    print("Secret discovered = "+secret)

        