# You have the code, access the server and get the flag!
# nc 130.192.5.212 6645 

HOST = "130.192.5.212"
PORT = 6645

#RSA multiplicative property attack

from Crypto.Util.number import long_to_bytes, inverse
from sympy.ntheory.modular import crt
from pwn import remote

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    n = server_gen.recv(1024).decode()
    c = server_gen.recv(1024).decode()
    print(n)
    print(c)
    e = 65537
    s = 2 # scelgo un moltiplicatore s = 2
    s_e = pow(s, e, int(n))
    # c' = c * s^e mod n = (m^e * s^e) mod n = (m*s)^e mod n
    c_prime = (int(c) * s_e) % int(n)
    # chiedo la decryption di c_prime
    mess = "d " + str(c_prime) + "\n"
    print(mess)
    server_gen.send(mess.encode())
    m_prime = server_gen.recv(1024).decode()
    server_gen.close()
    print(m_prime)
    # m' = (m*s) mod n => m = (m*s*s^-1) mod n
    s_inv = inverse(s, int(n))
    m = (int(m_prime) * s_inv) % int(n)
    flag = long_to_bytes(m)
    print(f"Recovered flag: {flag.decode(errors="ignore")}")
    
    