# I'm reusing the already reused message... ......read the challenge code and find the flag!
# nc 130.192.5.212 6562 

from pwn import *
import os

os.environ['PWNLIB_NOTERM'] = 'True' 
os.environ['PWNLIB_SILENT'] = 'True'

HOST = "130.192.5.212"
PORT = 6562

#Nonce è sempre lo stesso perché metto random.seed con un valore preciso, e nonce è sempre 12*8, quindi sempre lo stesso
#Mettendo un seed in random.seed sto inizializzando il PRNG
#random.seed(int(time())) -> Ogni volta che chiami encrypt(), se sei nello stesso secondo, ottieni 
# lo stesso nonce → stessa chiave stream (se il messaggio ha la stessa lunghezza).

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    server_gen.recv(4096)
    server_gen.send(("f\n").encode())
    flag = server_gen.recv(1024).strip().splitlines()[0].decode()
    print(flag)
    flag = bytes.fromhex(flag)
    server_gen.send(("y\n").encode())
    server_gen.recv(1024)
    print("Flag: "+str(flag))
    print("Len Flag: "+str(len(flag)))
    msg = "A"*len(flag)
    # print(msg)
    server_gen.send((msg+"\n").encode())
    ciph = server_gen.recv(1024).strip().splitlines()[0].decode()
    print(ciph)
    ciph = bytes.fromhex(ciph) #trovato velocemente, qualche volta va qualche volta no, ma solo questione di velocita'
    server_gen.close()
    # flag XOR msg XOR ciph = flag XOR AAA... XOR (AAA... XOR keystream) = flag XOR keystream = plaintext
    flag_plain = xor(flag, msg, ciph)
    print(flag_plain.decode())
