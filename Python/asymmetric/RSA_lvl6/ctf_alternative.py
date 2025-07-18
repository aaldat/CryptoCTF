# access the server and get the flag
# nc 130.192.5.212 6646 

HOST = "130.192.5.212"
PORT = 6646

#come RSA_lvl5 ma senza n
#RSA multiplicative property attack

from Crypto.Util.number import long_to_bytes, GCD, inverse
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from pwn import remote

if __name__ == '__main__':
    e = 65537

    server_gen = remote(HOST, PORT)
    ciph = int(server_gen.recv(1024).decode()) # ciph = m^e mod n

    r = 2
    #richiedo l'encryption di 2
    msg = "e "+str(r)+"\n"
    server_gen.send(msg.encode())
    enc2 = int(server_gen.recv(1024).decode()) # enc2 = 2^e mod n

    r = 3
    #richiedo l'encryption di 3
    msg = "e "+str(r)+"\n"
    server_gen.send(msg.encode())
    enc3 = int(server_gen.recv(1024).decode()) # enc3 = 3^e mod n

    # 2^e - 2^e mod n = k*n
    # 3^e - 3^e mod n = k'*n
    # gcd(k, k') = 1 perché k e k' coprimi
    # gcd(k*n, k'*n) = n*gcd(k, k') = n
    # gcd(2^e - 2^e mod n, 3^e - 3^e mod n) => n
    n = GCD(pow(2,e) - enc2, pow(3,e) - enc3) #trovo n

    #da qui uguale a RSA_lvl5
    ciph_p = (ciph*enc2) % n
    # print(ciph_p)
    msg = "d "+str(ciph_p)+"\n"
    server_gen.send(msg.encode())
    m_per_r = int(server_gen.recv(1024).decode()) # m_per_r = m*r = m*2
    r_inv = inverse(2, n) #calcolo l'inverso di 2 mod n
    
    m = (m_per_r * r_inv) % n
    flag = long_to_bytes(m)
    print(flag.decode(errors="ignore"))
    server_gen.close()