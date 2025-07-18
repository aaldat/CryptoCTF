# Guess the mode. Now you need to reason about how modes work. Ask a second encryption to confirm your hypothesis...
# nc 130.192.5.212 6532 

from pwn import *
from Crypto.Cipher import AES
    

if __name__ == "__main__":
    io = remote("130.192.5.212", 6532)
    for i in range(128):
        io.recvuntil(b"Challenge")
        
        # Send same input twice: all-zero 32 bytes
        input_hex = "00" * 32
        io.sendlineafter(b"Input: ", input_hex.encode())
        ct1 = bytes.fromhex(io.recvline().decode().strip().split()[-1])

        io.sendlineafter(b"Input: ", input_hex.encode())
        ct2 = bytes.fromhex(io.recvline().decode().strip().split()[-1])

        # ECB reuses key & data → identical ciphertext
        if ct1 == ct2:
            guess = "ECB"
        else:
            guess = "CBC"

        io.sendlineafter(b"What mode did I use? (ECB, CBC)\n", guess.encode())
        response = io.recvline().decode()
        print(f"Round {i}: Guessed {guess} -> {response.strip()}")

        if "Wrong" in response:
            print("Failed")
            break

    try:
        while True:
            print(io.recvline(timeout=1).decode(), end="")
    except:
        pass
