from pwn import *
from codecs import encode, decode
from colorama import Fore, Style
import colorama

colorama.init()

port = int(input("picoCTF port: "))

r = remote("2018shell.picoctf.com", port)
r.sendlineafter("Please choose: ", "i")
r.recvuntil("Files:\n")
flag_name = decode(r.recvline(), "ascii").strip()

print(f"{Style.RESET_ALL}\nFlag file name:{Fore.GREEN}{Style.BRIGHT}", flag_name)
print()

# Edit flag file name to not contain "_" character.
new_name = flag_name[:4] + "X" + flag_name[5:-4]

# Encrypt an empty file with the new name to get the share code.
r.sendlineafter("Please choose: ", "n")
r.sendlineafter("Name of file? ", new_name)
r.sendlineafter("Data? ", "")
r.recvuntil("Share code:\n")
# Get the share code as a byte array.
share_code = decode(r.recvline(), "base64")

# cipher[i] = enc(ctr[i], key) xor plain[i] ---> enc(ctr[i], key) = cipher[i] xor plain[i]
# xor is a bitwise operation ---> get only the first byte of 2nd iteration of counter and 2nd block of ciphertext and plaintext
cipher = share_code[4]
plain = ord(new_name[4])
enc_ctr = cipher ^ plain

# Since ctr and key are fixed through the entire session, we can use enc_ctr to decipher "_" character.
plain = ord("_")
cipher = enc_ctr ^ plain

# Change 5th byte of share code.
share_code = share_code[:4] + bytes([cipher]) + share_code[5:]
base64_share_code = decode(encode(share_code, "base64"), "ascii").replace("\n","")
print(f"{Style.RESET_ALL}Share code:{Fore.BLUE}{Style.BRIGHT}", base64_share_code)

# Decrypt using the share code in base64.
r.sendlineafter("Please choose: ", "e")
r.sendlineafter("Share code? ", base64_share_code)
while b"Data: " in r.recvline():
	flag = decode(r.recvline(), "ascii").strip()
	print(f"{Style.RESET_ALL}\nFlag:{Fore.GREEN}{Style.BRIGHT}", flag)
	break
