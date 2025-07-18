# Read the code. If you really understood it, you can correctly guess the mode. If you do it with a probability higher than 2^128 you'll get the flag.
# nc 130.192.5.212 6531 

from pwn import remote
from Crypto.Cipher import AES

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def make_input(otp):
    B = b"A" * 16
    block1 = bytes([B[i] ^ otp[i] for i in range(16)])
    block2 = bytes([B[i] ^ otp[i + 16] for i in range(16)])
    return block1 + block2

def detect_mode(ciphertext):
    block1 = ciphertext[:16]
    block2 = ciphertext[16:32]
    if block1 == block2:
        return "ECB"
    else:
        return "CBC"
    

if __name__ == "__main__":

    io = remote("130.192.5.212", 6531)

    for i in range(128):
        print(io.recvuntil(b"The otp I'm using: ").decode(), end="")
        otp_hex = io.recvline().strip().decode() #prendo il valore dell'otp in esadecimale
        otp = bytes.fromhex(otp_hex) #lo trasformo in binario

        crafted_input = make_input(otp) #crafto il valore da mettere in input
        io.sendlineafter(b"Input: ", crafted_input.hex().encode())

        io.recvuntil(b"Output: ")
        ciphertext_hex = io.recvline().strip().decode()
        ciphertext = bytes.fromhex(ciphertext_hex)

        guess = detect_mode(ciphertext)
        io.sendlineafter(b"What mode did I use? (ECB, CBC)\n", guess.encode())

        response = io.recvline().decode()
        print(f"Round {i}: Guessed {guess} -> {response.strip()}")
        if "Wrong" in response:
            print("Failed :(")
            break

    # Try to get the flag if all 128 rounds passed
    try:
        print(io.recvline(timeout=2).decode())
    except:
        pass
