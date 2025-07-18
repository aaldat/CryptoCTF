# ...even harder with this one...
# nc 130.192.5.212 6544 

from pwn import *
import string
from Crypto.Cipher import AES
import os

HOST = "130.192.5.212"
PORT = 6544 

BLOCK_SIZE = AES.block_size

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
context.log_level = 'error'

SECRET_LEN = 46
secret = b""

#   1234AAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAl    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAA5    67890flag
#   -----------------    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAl    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAA56    7890flag
#

#   1AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA
#   12AAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA
#   123AAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA
#   1234AAAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA
#   12345AAAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA
#   123456AAAAAAAAAAA    AAAAAAAAAAAAAAAA    AAAAAAAAAAAAAAAA

def detect_padding_len(server):
    # Trovo la lunghezza di padding1 osservando il cambio nei blocchi
    for i in range(1, 16):
        server_gen.send(b'enc\n')
        server_gen.recv(1024).decode()
        payload = b'A' * (32+i)
        server_gen.send((str(payload.hex())+'\n').encode())
        ciphertext = server_gen.recvuntil(b'\n').decode()
        server_gen.recv(4096)
        ciphertext2 = bytes.fromhex(str(ciphertext))
        ciphertext3 = ciphertext2[16:]
        if (ciphertext3[0:16] == ciphertext3[16:32]):
            print("La lunghezza di padding1 e' :"+str(16-i))
            return (16-i)

        
    print("Failed to detect padding1_len")
    return None

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    server_gen.recvuntil(b'> ')

    pad1_len = detect_padding_len(server_gen)
    print(f"Detected padding1_len = {pad1_len}")
    found=0
    pad2_len = 10 - pad1_len

    for i in range(1,SECRET_LEN+pad2_len+1):
        pad_end = b"A"*(AES.block_size*4-i)
        pad_start = pad_end + b"A"*(AES.block_size - pad1_len)
        if(i<pad2_len+1): #indovino i byte di padding2
            for letter in range(1, 256):
                letter = bytes([letter])
                server_gen.send(b"enc\n")
                server_gen.recv(1024).decode()
                msg = pad_start+secret+letter+pad_end
                print("Sending: "+str(msg.hex()))
                server_gen.send((str(msg.hex())+'\n').encode())
                ciphertext = server_gen.recvuntil(b'\n').decode()
                server_gen.recv(4096)

                ciphertext2 = bytes.fromhex(str(ciphertext))
                if ciphertext2[64:80] == ciphertext2[128:144]:
                    found=1
                    print("Found new character = "+letter.hex())
                    secret+=letter
                    print(secret.hex())
                    break
        else: #indovino le lettere del flag
            for letter in string.printable:
                server_gen.send(b"enc\n")
                server_gen.recv(1024).decode()
                msg = pad_start+secret+letter.encode()+pad_end
                print("Sending: "+str(msg.hex()))
                server_gen.send((str(msg.hex())+'\n').encode())
                ciphertext = server_gen.recvuntil(b'\n').decode()
                server_gen.recv(4096)

                ciphertext2 = bytes.fromhex(str(ciphertext))
                if ciphertext2[64:80] == ciphertext2[128:144]:
                    found=1
                    print("Found new character = "+letter)
                    secret+=letter.encode()
                    print(secret.hex())
                    break
    if found==1:
        server_gen.close()

    secret = secret[pad2_len:]
    print("Secret discovered = "+secret.decode())


        