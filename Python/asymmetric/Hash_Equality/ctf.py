# Find a string that is both the same and different than another string!
# nc 130.192.5.212 6631 

from Crypto.Hash import MD4, MD5
from hashlib import md5
import hashlib
from binascii import unhexlify, hexlify
from pwn import remote
import struct

HOST = "130.192.5.212"
PORT = 6631

PADDING = b"\x80" + 63 * b"\0"

def md4(data: bytes) -> str:
    h = MD4.new()
    h.update(data)
    return h.hexdigest()

if __name__ == '__main__':


    #Ho trovato due stringhe diverse che hanno lo stesso hash MD4 ma hash MD5 diversi
    # le ho prese da cryptopals/challenges/md4_collisions.py
    # m1 = b'f20c993c2a297fc670abd04494afe2f18bf11dc35e70947d25955d98ce219c5892982d31adf3bb135b71604b340d7e838692bef83bae4dd2b619bbc3244b4488'
    # m2 = b'f20c993c2a297f4670abd0d494afe2f18bf11dc35e70947d25955d98ce219c5892982d31adf3bb135b71604b340d7e838692bff83bae4dd2b619bbc3244b4488'
    m1 = b'a6af943ce36f0cf4adcb12bef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9b0d384d06ef3118bbc643ae6384'
    m2 = b'a6af943ce36f0c74adcb122ef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9a0d384d06ef3118bbc643ae6384'

    server_gen = remote(HOST, PORT)
    print(server_gen.recv(1024))
    server_gen.sendline(m1)
    print(server_gen.recv(1024))
    server_gen.sendline(m2)
    print(server_gen.recv(1024).decode())

    server_gen.close()