from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json
import base64

key = get_random_bytes(32)
cipher = AES.new(key=key, mode=AES.MODE_ECB)


def extract_token(tok: str) -> str:
    prefix = "This is your token: "
    start = tok.find(prefix)
    if start == -1:
        raise ValueError("Token not found")
    start += len(prefix)
    end = tok.find("\n", start)
    return tok[start:end].strip()


def get_user_token(name):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    token = json.dumps({
        "username": name,
        "admin": False
    })
    print(token.encode())
    enc_token = cipher.encrypt(pad(token.encode(), AES.block_size))
    return f"{base64.b64encode(enc_token).decode()}"


def check_user_token(token):
    
    dec_token = unpad(cipher.decrypt(base64.b64decode(token)), AES.block_size)
    print(dec_token)

    user = json.loads(dec_token)

    if user.get("admin", False) == True:
        return True
    else:
        return False


def get_flag():
    token = input("What is your token?\n> ").strip()
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)


if __name__ == "__main__":
    # name = input("Hi, please tell me your name!\n> ").strip()
    # usr = b'A'*2 + pad(b'AAA', AES.block_size)+ b'", "admin": true' + b'A'*11 + b'\n'
    # usr = b"A"*15 + b" true" + b'\n'
    # name = usr.decode().strip()
    name = b'AA               "AAAAAAAAA                     ":               true,              A'
    # name = "A"*2 +  
    # print(name)
    token = get_user_token(name.decode())
    print("This is your token: " + token)
    token = base64.b64decode(token)
    print(len(token))
    blocks = [token[i:i+16] for i in range(0, len(token), 16)]

    print(blocks)
    for i, block in enumerate(blocks):
        try:
            decrypted = cipher.decrypt(block)
            unpadded = unpad(decrypted, AES.block_size)
            text = unpadded.decode()
        except:
            try:
                text = cipher.decrypt(block).decode()
            except:
                text = "(binary data)"

        print(f"Block {i}: {block.hex()}")
        print(f"        → {repr(text)}\n")

    cookie = token[:16] + token[96:112] + token[80:96] + token[32:48] + token[64:80] + token[112:128] 
    print(len(cookie))
    blocks = [cookie[i:i+16] for i in range(0, len(cookie), 16)]
    print(blocks)
    for i, block in enumerate(blocks):
        try:
            decrypted = cipher.decrypt(block)
            unpadded = unpad(decrypted, AES.block_size)
            text = unpadded.decode('utf-8', errors='replace')
        except:
            try:
                text = cipher.decrypt(block).decode('utf-8', errors='replace')
            except:
                text = "(binary data)"

        print(f"Block {i}: {block.hex()}")
        print(f"        → {repr(text)}\n")

    if check_user_token((base64.b64encode(cookie)+b'\n').decode().strip()):
        print("You are admin!")
        print(f"This is your flag!\n")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)
    
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            get_flag()