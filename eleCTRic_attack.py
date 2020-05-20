from pwn import *
from codecs import encode, decode
from colorama import Fore, Style
import colorama

colorama.init()

port = int(input("picoCTF port: "))
print()

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

stop = False
# Loop through all possible values for the 5th byte of the share code
# (i.e. the byte corresponding to "_" in the original flag file name).
for i in range(256):
	if not stop:
		# Change 5th byte of share code.
		share_code = share_code[:4] + bytes([i]) + share_code[5:]
		base64_share_code = decode(encode(share_code, "base64"), "ascii").replace("\n","")
		print(f"{Style.RESET_ALL}Test share code:{Fore.BLUE}{Style.BRIGHT}", base64_share_code)

		# Try decryption using the share code in base64.
		r.sendlineafter("Please choose: ", "e")
		r.sendlineafter("Share code? ", base64_share_code)
		while True:
			line = r.recvline()
			if b"Could not find file" in line:
				break
			elif b"Data: " in line:	# Share code corresponds to a saved file: flag or our empty file?
				flag = decode(r.recvline(), "ascii").strip()
				if flag == "":
					break
				else:
					print(f"{Style.RESET_ALL}\nFlag:{Fore.GREEN}{Style.BRIGHT}", flag)
					stop = True
					break