from pwn import *
index = 1
cmp = 2
shellcode = b'\x80\x7F' + p8(index) + p8(cmp) + b'\x7F\xFA'
shellcode2 = b'\x80\x3F' + p8(cmp) + b'\x7F\xFB'
print(shellcode)
print(shellcode2)