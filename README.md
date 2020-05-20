# picoCTF2018 - eleCTRic
## Text
> You came across a custom server that Dr Xernon's company eleCTRic Ltd uses. It seems to be storing some encrypted files. Can you get us the flag? Connect with nc 2018shell.picoctf.com 61333. [Source](https://github.com/PrinceOfBorgo/picoCTF2018-eleCTRic/blob/master/eleCTRic.py).

Port may be different.

## Hints
> I have repeated myself many many many times- do not repeat yourself.
> Do I need to say it in different words? You mustn't repeat thyself.

## Solution
TODO (see script comments)

## Usage
Simply run `eleCTRic_attack.py` as a python script and insert port to which to connect:
```
$ python SpyFi_attack.py
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
