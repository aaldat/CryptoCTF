# This is a long message encrypted a line at the time...
# (Remember, flag format is CRYPTO25{<uuid4>})


from binascii import unhexlify
import numpy
from string import *
import operator


CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
} # ',' \

with open("./hacker-manifesto.enc") as f:
    lines = f.readlines()

ciphertexts = [bytes.fromhex(lines[i]) for i in range(len(lines))]
print(ciphertexts)

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print("Longest: "+str(len(longest_c)))
shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print("Shortest: "+str(len(shortest_c)))

#########################################
#guess the first byte: native approach - count the ascii chars
counters = numpy.zeros(256, dtype=int)

for guessed_byte in range(256):
    for c in ciphertexts:
        if chr(c[0] ^ guessed_byte) in ascii_letters:
            counters[guessed_byte] += 1

max_matches = max(counters)
print(max_matches)

match_list = [(int(counters[i]), i) for i in range(256)]
# print(match_list)
ordered_match_list = sorted(match_list, reverse=True)
# print(ordered_match_list)

candidates = []
for pair in ordered_match_list:
    if pair[0] < max_matches * .95:
        break
    candidates.append(pair)

print(candidates)

################################################################################
#approach with stats

candidates_list = []

for byte_to_guess in range(min_len):
    freqs = numpy.zeros(256,dtype=float)

    for guessed_byte in range(256):
        for c in ciphertexts:
            if byte_to_guess >= len(c):
                continue
            if chr(c[byte_to_guess] ^ guessed_byte) in printable:
                freqs[guessed_byte] += CHARACTER_FREQ.get(chr(c[byte_to_guess] ^ guessed_byte).lower(),0)

    max_matches = max(freqs)

    match_list = [(freqs[i], i) for i in range(256)]
    
    ordered_match_list = sorted(match_list, reverse=True)
    
    candidates_list.append(ordered_match_list)

print(candidates_list)


keystream = bytearray()
for x in candidates_list:
    keystream += x[0][1].to_bytes(1,byteorder='big')

print(keystream)

from Crypto.Util.strxor import strxor

dec_plain = b'This is our CTF now... The world of the electron and the switch; the'
# print(len(keystream))
keystream[0] = 251
for i in range(len(dec_plain)):
    c  = dec_plain[i]
    c = bytes([c])
    dec = keystream[i] ^ ciphertexts[0][i]
    mask = dec ^ ord(c)
    keystream[i] = keystream[i] ^ mask

dec0 = keystream[5] ^ ciphertexts[0][5]
dec = keystream[28] ^ ciphertexts[3][28]
dec2 = keystream[20] ^ ciphertexts[6][20]
dec3 = keystream[17] ^ ciphertexts[7][17]
dec4 = keystream[34] ^ ciphertexts[1][34]
dec5 = keystream[37] ^ ciphertexts[4][37]
dec6 = keystream[16] ^ ciphertexts[2][16]
dec7 = keystream[38] ^ ciphertexts[4][38]
dec8 = keystream[40] ^ ciphertexts[0][40]
dec9 = keystream[63] ^ ciphertexts[3][63]


mask0 = dec0 ^ ord('i')
keystream[5] = keystream[5] ^ mask0
mask = dec ^ ord('Y')
keystream[28] = keystream[28] ^ mask
mask2 = dec2 ^ ord('u')
keystream[20] = keystream[20] ^ mask2
mask3 = dec3 ^ ord('o')
keystream[17] = keystream[17] ^ mask3
mask4 = dec4 ^ ord(' ')
keystream[34] = keystream[34] ^ mask4
mask5 = dec5 ^ ord('r')
keystream[37] = keystream[37] ^ mask5
mask6 = dec6 ^ ord('c')
keystream[16] = keystream[16] ^ mask6
mask7 = dec7 ^ ord(',')
keystream[38] = keystream[38] ^ mask7
mask8 = dec8 ^ ord('e')
keystream[40] = keystream[40] ^ mask8
mask9 = dec9 ^ ord(' ')
keystream[63] = keystream[63] ^ mask9

for c in ciphertexts:
    l = min(len(keystream), len(c))
    print(strxor(c[:l], keystream[:l]))



