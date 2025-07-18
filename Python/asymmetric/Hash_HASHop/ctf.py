# Here at HA-SHop, we accept only coupons as payment. Do you have one to get the flag?
# nc 130.192.5.212 6630 

import subprocess
from binascii import unhexlify, hexlify
from pwn import remote

HOST = "130.192.5.212"
PORT = 6630

#Length extension attack con Hashpump => calcolo un nuovo hash valido come se fossi il server

if __name__ == '__main__':
    server_gen = remote(HOST, PORT)
    print(server_gen.recv(4096).decode())
    msg = b'1'
    name = "AAAAAAA"
    server_gen.sendline(msg)
    print(server_gen.recv(4096).decode())
    server_gen.sendline(name.encode())
    server_gen.recvuntil(b'Coupon: ')
    coupon = server_gen.recvline().strip().decode()
    server_gen.recvuntil(b'MAC:     ')
    macadd = server_gen.recvline().strip().decode()

    
    original_message = b"username=AAAAAAA&value=10"
    original_mac = macadd
    data_to_add = b"&value=1000"

    # Runno un subprocess di hashpump e prendo l'output
    result = subprocess.run([
        "hashpump",
        "-s", original_mac,
        "-d", original_message.decode(),
        "-a", data_to_add.decode(),
        "-k", "16"
    ], capture_output=True, text=True)

    escaped_string = result.stdout.split('\n')[3].strip()
    print(escaped_string)
    new_message = bytes(escaped_string, "utf-8").decode('unicode_escape').encode('latin1')
        #^^^ => interpreto gli escape come caratteri binari e li converto in bytes
        #latin1 => mappa ogni carattere Unicode da 0 a 255 direttamente nel byte corrispondente
    new_mac = result.stdout.split('\n')[2].strip().split(': ')[1]

    print(f"Coupon: {new_message}")

    #encode new message as hex for the server
    new_coupon = hexlify(new_message).decode()
    print(hexlify(original_message))
    print(hexlify(new_message))

    print(f"Coupon: {new_coupon}")
    print(f"MAC:    {new_mac}")

    print(server_gen.recv(4096).decode())
    msg = b'2'
    server_gen.sendline(msg)
    print(server_gen.recv(4096).decode())
    server_gen.sendline(new_coupon.encode())
    print(server_gen.recv(4096).decode())
    server_gen.sendline(new_mac.encode())
    
    print(server_gen.recv(4096).decode())
    print(server_gen.recv(4096).decode())
    server_gen.close()