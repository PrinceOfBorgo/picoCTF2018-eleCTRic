# picoCTF2018 - eleCTRic
## Text
> You came across a custom server that Dr Xernon's company eleCTRic Ltd uses. It seems to be storing some encrypted files. Can you get us the flag? Connect with nc 2018shell.picoctf.com 61333. [Source](https://github.com/PrinceOfBorgo/picoCTF2018-eleCTRic/blob/master/eleCTRic.py).

Port may be different.

## Hints
> I have repeated myself many many many times- do not repeat yourself.

> Do I need to say it in different words? You mustn't repeat thyself.

## Problem description
Connecting to the server we can see a menu. Entering `i` we obtain a list of files, in particular, a single `.txt` file named `flag_` followed by some random hex digits. Entering `n` we are asked to insert a name file and some data to encrypt and we receive a share code used for decrypt that file. Entering `e` we are asked to pass a share code: if it correspond to a previously encrypted file, its decrypted content will be printed to screen. It is pretty obvious that we have to find the share code for `flag_[...].txt` file in order to decrypt it and get the flag.

Analyzing the provided source code we can see that the share code generated during the encryption of a file is its encrypted name. In order to get our desired share code we could think to simply encrypt a new file with the same name of the one containing the flag. Unfortunately this cannot be done for two reasons:
1. using a file name of an existing file will overwrite the original content (bye bye flag);
2. the flag name contains an underscore that is considered a disallowed character so the program will stop us before printing the share code.

The encryption used is AES with [CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) with blocks of 32 bits, the ciphertext is converted to Base64 encoding.

![](https://upload.wikimedia.org/wikipedia/commons/3/3f/Ctr_encryption.png)

In CTR mode the plaintext is divided in blocks of fixed length. The encryption of each block doesn't depend on other blocks but only on its position inside the plaintext: the `n`th plaintext block is XORed with the `n`th encrypted counter. The counter can be seen as a block of random bytes which is incremented by 1 each time a block is encrypted.

We can notice that the cipher is initialized at the start of the program (in `main()`) so key and counter remain always the same for the entire session.
Since the ciphertext blocks are generated independently of the others and XORing is a bitwise operation, encrypting similar plaintexts with the same key and the same initial counter will give use similar ciphertexts: if `p1` is a plaintext with ciphertext `c1` and `p2` is a plaintext equal to `p1` except for a single byte, then its ciphertext `c2` will differ from `c1` only in that byte.

Now we che think to a solution: we can encrypt files with names equal to the flag file but replacing `_` with an allowed character. This will give us a share code that, decoded from Base64, will differ from the desired share code only in the fifth byte (the one corresponding to `_`).

##Solution
I proposed two solutions.

The first one is quite slow since it performs several decryptions passing share codes obtained by brute-forcing the fifth byte of a sample share code obtained encrypting an empty file with name equal to the flag file but replacing `_` with an allowed character. Decryptions will always fail until we get to the flag file or to our encrypted file (recognizable by the fact that it is empty). We get to the flag in at most 256 attempts.

The second solution is way faster since we can find the share code directly from the ASCII code of `_`.
Let's call `cipher[i]` and `plain[i]` the `i`th block of ciphertext and plaintext respectively and `enc_ctr[i]` the encrypted counter at `i`th step, we have that `cipher[i] = enc_ctr[i] xor plain[i]` and hence `enc_ctr[i] = cipher[i] xor plain[i]`. Since XOR is a bitwise operation, we find the value of `enc_ctr[i]` byte corresponding to the position of `_` (fifth byte) and then we use it to put the encrypted underscore into the initial share code. Let's see an example:  
`flag_dbe2caedf81debbf4faa` is the flag name, `flagXdbe2caedf81debbf4faa` is the new name obtained replacing `_` with `X` (ASCII code: `0x58`). The difference is in the fifth byte. Suppose that the fifth byte of the share code is `0x26`.  
If `enc_ctr` is the byte of the encrypted counter that modifies the fifth byte, then `0x26 = enc_ctr xor 'X' = enc_ctr xor 0x58` from which `enc_ctr = 0x26 xor 0x58 = 0x7e`. Now, since ASCII code for `_` is `0x5f`, we find the encrypted byte `cipher = enc_ctr xor 0x5f = 0x7e xor 0x5f = 0x21`.  
Finally we can simply replace the fifth byte of the share code with `0x21` and, after converting to Base64, it will decrypt the flag file.

## Usage
Simply run `bruteforce.py` or `fast.py` as a python script and insert port to which to connect:
```
$ python bruteforce.py
picoCTF port: 61333
[+] Opening connection to 2018shell.picoctf.com on port 61333: Done

Flag file name: flag_a0c60ed1a62753905e62.txt

Test share code: R/mckwB97UXQw4xEI/zJ9xagzs1QKbgQ1N2dWGY=
Test share code: R/mckwF97UXQw4xEI/zJ9xagzs1QKbgQ1N2dWGY=
...
...
Test share code: R/mckz597UXQw4xEI/zJ9xagzs1QKbgQ1N2dWGY=
Test share code: R/mckz997UXQw4xEI/zJ9xagzs1QKbgQ1N2dWGY=

Flag: picoCTF{alw4ys_4lways_Always_check_int3grity_6c094576}
```

```
$ python fast.py
picoCTF port: 61333
[+] Opening connection to 2018shell.picoctf.com on port 61333: Done

Flag file name: flag_dbe2caedf81debbf4faa.txt

Share code: jVdFAOGF7Fz2gcWvecZHl49eRgXY1ehYpczQsmk=

Flag: picoCTF{alw4ys_4lways_Always_check_int3grity_6c094576}          
```
