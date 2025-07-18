# The attached file contains the code and the output. Use them to get the flag...

from Crypto.Util.number import long_to_bytes, inverse

n = 176278749487742942508568320862050211633
e = 65537
c = 46228309104141229075992607107041922411

#Ho trovato p e q su factorDB
p = 12271643243945501447
q = 14364722473065221639

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())