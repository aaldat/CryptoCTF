# this file has not been encrypted one line at the time... maybe...


from binascii import unhexlify
import numpy
from string import *
import operator

#Stesso keystream per ogni blocco

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
} # ',' \


KEYSTREAM_SIZE = 1000

with open("./file.enc", "rb") as f:
    ciphertext = f.read()

# Dividi il ciphertext in blocchi da 1000 byte come nel server
ciphertexts = [ciphertext[i:i+KEYSTREAM_SIZE] for i in range(0, len(ciphertext), KEYSTREAM_SIZE)]


longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print("Longest: "+str(max_len))
print("Shortest: "+str(min_len))

#########################################
#guess the first byte: native approach - count the ascii chars
counters = numpy.zeros(256, dtype=int)

#Provo ogni possibile byte b da 0 a 255 e vedo se c[0]^b è un carattere alfabetico (conteggio) -> buon candidato
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

#seleziono i candidati migliori, che si ripetono di più
candidates = []
for pair in ordered_match_list:
    if pair[0] < max_matches * .95:
        break
    candidates.append(pair)

print(candidates)

################################################################################
#approach with stats

candidates_list = []

#Per ogni posizione del keystream provo tutti i 256 valori possibili
#Per ciascun valore valuto quanto possibile in base alla frequenza
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
    
    candidates_list.append(ordered_match_list)  #lista ordinata di candidati per ogni posizione del keystream

# print(candidates_list)

#prendo il migliore candidato per ciascun byte e costruisco il keystream
keystream = bytearray()
for x in candidates_list:
    keystream += x[0][1].to_bytes(1,byteorder='big')

print(keystream)

from Crypto.Util.strxor import strxor

# dec_plain = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'

#XOR tra ogni blocco cifrato e keystream => plaintext
for c in ciphertexts:
    l = min(len(keystream), len(c))
    print(strxor(c[:l], keystream[:l]))

#Ho fatto copia-incolla dell'output in word e ho cercato CRYPTO25{



