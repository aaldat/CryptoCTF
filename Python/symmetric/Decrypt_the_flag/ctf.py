# As I don't have enough fantasy, I'm just reusing the same text as other challenges... ...read the challenge code and find the flag!
# nc 130.192.5.212 6561 

from pwn import *
import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

HOST = "130.192.5.212"
PORT = 6561

#Nonce è sempre lo stesso perché metto random.seed con un valore preciso, e nonce è sempre 12*8, quindi sempre lo stesso
#Mettendo un seed in random.seed sto inizializzando il PRNG

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    server_gen.recv(4096)
    seed = "1508"
    server_gen.send((str(seed)+"\n").encode())
    server_gen.recv(1024)
    flag = server_gen.recv(1024).strip().splitlines()[0].decode()
    flag = bytes.fromhex(flag)
    server_gen.send(("y\n").encode())
    server_gen.recv(1024)
    print("Flag: "+str(flag))
    print("Len Flag: "+str(len(flag)))
    msg = "A"*len(flag)
    print(msg)
    server_gen.send((msg+"\n").encode())
    ciph = server_gen.recv(1024).strip().splitlines()[0].decode()
    # print(ciph)
    ciph = bytes.fromhex(ciph)
    server_gen.close()
    # for i in range(len(flag)):
    #     flag_plain[i] = flag[i] ^ ciph[i]
    flag_plain = xor(flag, msg, ciph)
    print(flag_plain.decode())
