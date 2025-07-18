# Needless to say, you need the proper authorization cookie to get the flag
# nc 130.192.5.212 6552 

from math import ceil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6552

if __name__ == '__main__':

    server_gen = remote(HOST, PORT)
    server_gen.recv(4096)

    crafted_user = b'A'*7 + pad(b'true', AES.block_size) + b'A'*9 + b'\n' #username=AAAAAAA true-padding AAAAAAAAA&admin=  false-padding
    print(crafted_user)                                                        
    server_gen.send(crafted_user)
    printout2 = server_gen.recv(1024)
    crafted_cookie = long_to_bytes(int(str(printout2.decode())))
    final = crafted_cookie[:48] + crafted_cookie[16:32]
    final = bytes_to_long(final)
    server_gen.send(b"flag\n")
    print(server_gen.recv(1024).decode())
    server_gen.send((str(final)+"\n").encode())
    print(server_gen.recv(1024).decode())
    print(server_gen.recv(1024).decode())
    server_gen.close()

