# To get your flag, forge a payload that decrypts to a fixed value...
# nc 130.192.5.212 6523 

import socket
import binascii

def xor_bytes(*args):
    from functools import reduce
    return bytes([reduce(lambda x, y: x ^ y, values) for values in zip(*args)])

if __name__ == '__main__':
    X = b"A" * 16
    print(binascii.hexlify(X))
    leak = b"mynamesuperadmin"
    IV_X = binascii.unhexlify("5ee6b96201eaafd1285e5f812f6fb857")
    C_X = binascii.unhexlify("d07442fc95e41e93659394264cb1e78b")
    C_X_2 = binascii.hexlify(C_X)
    IV_fake = xor_bytes(X, IV_X, leak)
    IV_fake_2 = binascii.hexlify(IV_fake)
    print(IV_fake_2.decode())
