# Here is my super-strong RSA implementation, because it's 1600 bits strong it should be unbreakable... at least I think so!


import gmpy2
from Crypto.Util.number import long_to_bytes, GCD, inverse

if __name__ == '__main__':
    #Fattorizzo n con YAFU
    n = 770071954467068028952709005868206184906970777429465364126693
    ciph = 388435672474892257936058543724812684332943095105091384265939

    #trovo p e q da yafu
    p = 866961515596671343895614356197
    q = 888242373638787482012535770369
    np = p*q
    # print(n==np) #True
    e = 3
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    m = pow(ciph, d, n)
    flag = long_to_bytes(m)
    # print(flag.hex())
    print(flag.decode(errors='ignore'))