#nc 130.192.5.212 6645

#Solution: LSB Oracle

HOST = "130.192.5.212"
PORT = 6647

import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from Crypto.Util.number import long_to_bytes, GCD, inverse, bytes_to_long
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from pwn import remote
import decimal

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

if __name__ == '__main__':
    server_gen = remote(HOST, PORT) #tutto in un'unica sessione
    
    n = int(server_gen.recv(2048))
    ciphertext = int(server_gen.recv(2048))
    e = 65537

    decimal.getcontext().prec = n.bit_length()
    lower_bound = decimal.Decimal(0) #inizio intervallo
    upper_bound = decimal.Decimal(n) #fine intervallo
    m = ciphertext

    for i in range(n.bit_length()):
        # mando (2m)^e
        # se 2m < n => LSB è 0 => m < n/2
        # se 2m > n => LSB è 1  => m >= n/2
        m = (pow(2, e, n) * m) % n
        # print(str(m))
        server_gen.sendline(str(m).encode())
        bit = int(server_gen.recv(1024))
        # print(bit)
        
        if bit == 1:
            lower_bound = (lower_bound+upper_bound) / 2
        else:
            upper_bound = (lower_bound+upper_bound) / 2
        #ad ogni iterazione dimezzo lo spazio di ricerca, fino ad arrivare a m
        print("Iteration #"+str(i))
        # print_bounds(lower_bound, upper_bound)

    server_gen.close()
    # print_bounds(lower_bound, upper_bound)
    flag = (long_to_bytes(int(upper_bound)).decode())
    print(flag)