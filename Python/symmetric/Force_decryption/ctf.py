# To get your flag, forge a payload that decrypts to a fixed value...
# nc 130.192.5.212 6523 

import socket
import binascii

def xor_bytes(*args):
    from functools import reduce
    return bytes([reduce(lambda x, y: x ^ y, values) for values in zip(*args)])

def interact_with_server():
    HOST = '130.192.5.212'
    PORT = 6523
    leak = b"mynamesuperadmin"
    X = b"A" * 16

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        menu = s.recv(4096)  # Receive the initial menu
        # Encrypt the chosen plaintext
        answer = "enc\n"
        s.send(answer.encode()) #> enc
        domanda = s.recv(4096+1024)  # Prompt for input
        X_pln = binascii.hexlify(X)
        s.sendall(X_pln + b'\n') #> plaintext
        response = s.recv(4096)
        IV_X = binascii.unhexlify(response.split(b'IV: ')[1][:32])
        C_X = binascii.unhexlify(response.split(b'Encrypted: ')[1][:32])
        IV_X_2 = binascii.hexlify(IV_X)
        C_X_2 = binascii.hexlify(C_X)

        # Compute the forged IV
        IV_fake = xor_bytes(X, IV_X, leak)
        IV_fake_2 = binascii.hexlify(IV_fake)

        # Decrypt with the forged IV
        answer = "dec\n" #> dec
        s.send(answer.encode())
        answer2 = s.recv(4096+1024) 
        print(answer2.decode())
        s.sendall(C_X_2 + b'\n') #> ciphertext
        s.recv(4096) 
        s.send(IV_fake_2 + b'\n') #> fake_IV
        flag_response = s.recv(4096).decode()
        s.close()

if __name__ == '__main__':
    interact_with_server()
