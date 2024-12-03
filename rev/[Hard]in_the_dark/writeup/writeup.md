1. open chall in ida

2. in move_right() function (or any other) there is variable 'MAP'

3. after inspecting the 'MAP' (right click -> array -> turn off 'Use dup construnct') we can see (or in gdb 'x/100x (int*)&MAP'):

```
.rodata:0000000000002040 MAP             db 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0
.rodata:0000000000002040                                         ; DATA XREF: gravity+3F↑o
.rodata:0000000000002040                                         ; move_right+2E↑o ...
.rodata:0000000000002052                 db 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 2, 2, 2, 2
.rodata:0000000000002064                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
.rodata:0000000000002076                 db 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0
.rodata:0000000000002088                 db 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:000000000000209A                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0
.rodata:00000000000020AC                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1
.rodata:00000000000020BE                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1
.rodata:00000000000020D0                 db 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0
.rodata:00000000000020E2                 db 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0
.rodata:00000000000020F4                 db 1, 1, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
.rodata:0000000000002106                 db 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:0000000000002118                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 9
.rodata:000000000000212A                 db 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 2, 0, 0, 1, 1, 1
.rodata:000000000000213C                 db 1, 1, 1, 1, 1, 0, 0, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 0
.rodata:000000000000214E                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
.rodata:0000000000002160                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0
```
also in 
```
.rodata:0000000000002020 MAX_X           db  1Eh
.rodata:0000000000002024 MAX_Y           db  0Ah
```
MAX_X = 30 and MAX_Y = 10 we got map size 30x10
```
.data:0000000000004010 p_y             dd 7                    ; DATA XREF: gravity:loc_126F↑r
.data:0000000000004014 g_x             dd 0Bh                  ; DATA XREF: goblin_move+8↑r
.data:0000000000004018 g_y             dd 7                    ; DATA XREF: goblin_move+18↑r
.data:000000000000401C g_dir           dd 1                    ; DATA XREF: goblin_move+50↑r
```
also from gdb:
```
pwndbg> x/d (int*)&p_x
0x555555558024 <p_x>:   0
pwndbg> x/d (int*)&p_y
0x555555558010 <p_y>:   7
pwndbg> x/d (int*)&g_x
0x555555558014 <g_x>:   11
pwndbg> x/d (int*)&g_y
0x555555558018 <g_y>:   7
pwndbg> x/d (int*)&g_dir
0x55555555801c <g_dir>: 1
```
so starting position of player is (0, 7) and goblin (11, 7) with direction 1 (right - direction is just added to x when moving)

3. from this data we can construct the map with python script:

```python
from PIL import Image
def draw_map(map, p_x, p_y, g_x, g_y):
    for i in map:
        print(i)
    colors = {
        0: (255, 255, 255),  # white
        1: (0, 0, 0),        # black
        2: (255, 0, 0),      # red
        9: (255,255,0)       #yellow
    }
    img = Image.new('RGB', (MAX_X, MAX_Y), color='white')
    pixels = img.load()
    for y in range(MAX_Y):
        for x in range(MAX_X):
            if y < len(map) and x < len(map[y]):
                if x == p_x and y == p_y:
                    pixels[x, y] = (0, 0, 255)  # blue
                elif x == g_x and y == g_y:
                    pixels[x, y] = (0, 255, 0) # green
                else:
                    pixels[x, y] = colors.get(map[y][x], (255, 255, 255))
    img = img.resize((MAX_X * 10, MAX_Y * 10), Image.NEAREST)
    img.save('map.png')
    img.show()

ida_dump = '''.rodata:0000000000002040 MAP             db 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0
.rodata:0000000000002040                                         ; DATA XREF: gravity+3F↑o
.rodata:0000000000002040                                         ; move_right+2E↑o ...
.rodata:0000000000002052                 db 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 2, 2, 2, 2
.rodata:0000000000002064                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
.rodata:0000000000002076                 db 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0
.rodata:0000000000002088                 db 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:000000000000209A                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0
.rodata:00000000000020AC                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1
.rodata:00000000000020BE                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1
.rodata:00000000000020D0                 db 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0
.rodata:00000000000020E2                 db 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0
.rodata:00000000000020F4                 db 1, 1, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
.rodata:0000000000002106                 db 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:0000000000002118                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 9
.rodata:000000000000212A                 db 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 2, 0, 0, 1, 1, 1
.rodata:000000000000213C                 db 1, 1, 1, 1, 1, 0, 0, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 0
.rodata:000000000000214E                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
.rodata:0000000000002160                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0
'''
tmp = []
MAX_X = 30
MAX_Y = 10
p_x =0
p_y = 7
g_x = 11
g_y = 7
for line in ida_dump.split('\n'):
    if 'db' in line:
        for i in line.split('db ')[1].split(', '):
            tmp.append(int(i))
map = []
for i in range(0, len(tmp), MAX_X):
    map.append(tmp[i:i+MAX_X])
map.pop() # remove last null bytes

draw_map(map, p_x, p_y, g_x, g_y)


```

![map.png](start.png)

black - walls, red - lava, green - goblin, yellow - flag (from touching_lava(),goblin_move() and on_flag functions)

4. after inspecting move_right(), move_left(), jump_left(), jump_right() (from decode_moves()) we can see what moves are allowed:

'a' - move_left() - one step left

'd' - move_right() - one step right

'wa' - jump_left() - two vertical-up steps left

'wd' - jump_right() - two vertical-up steps right

also we have only 43 moves (chars) to use

other functions:

- gravity() - after each move player is moved down if possible
- touching_lava() - if player is on lava (red) loose
- on_flag() - if player is on flag (green) win and print flag from hashed input xored with secret key
- goblin_move() - goblin moves in his direction if encounters player he kills him, if encounters hollow space he changes direction

5. we need to simulate possible moves and how goblin's position changes:


```python
from PIL import Image
def draw_map(map, p_x, p_y, g_x, g_y,filename='map.png'):
    #for i in map:
    #    print(i)
    colors = {
        0: (255, 255, 255),  # white
        1: (0, 0, 0),        # black
        2: (255, 0, 0),      # red
        9: (255,255,0)       #yellow
    }
    img = Image.new('RGB', (MAX_X, MAX_Y), color='white')
    pixels = img.load()
    for y in range(MAX_Y):
        for x in range(MAX_X):
            if y < len(map) and x < len(map[y]):
                if x == p_x and y == p_y:
                    pixels[x, y] = (0, 0, 255)  # blue
                elif x == g_x and y == g_y:
                    pixels[x, y] = (0, 255, 0) # green
                else:
                    pixels[x, y] = colors.get(map[y][x], (255, 255, 255))
    img = img.resize((MAX_X * 10, MAX_Y * 10), Image.NEAREST)
    img.save(filename)
    #img.show()
def goblin_move(map,g_x,g_y,g_dir):
    if map[g_y+1][g_x+g_dir] == 0:
        g_dir *= -1
        g_x += g_dir
    else:
        g_x += g_dir
    return g_x, g_y, g_dir
def gravity(map, p_x, p_y):
    while(p_y < MAX_Y and map[p_y+1][p_x] == 0):
        p_y += 1
    return p_x, p_y
def move_right(map, p_x, p_y):
    return p_x + 1, p_y
def move_left(map, p_x, p_y):
    return p_x - 1, p_y
def jump_right(map, p_x, p_y):
    return p_x + 2, p_y - 2
def jump_left(map, p_x, p_y):
    return p_x - 2, p_y - 2
def decode_moves(moves, map, p_x, p_y, g_x, g_y,g_dir):
    i = 0
    while i < len(moves): 
        if moves[i] == 'd':
            p_x,p_y = move_right(map, p_x, p_y)
        elif moves[i] == 'a':
            p_x,p_y = move_left(map, p_x, p_y)
        elif moves[i] == 'w':
            if moves[i+1] == 'd':
                p_x,p_y = jump_right(map, p_x, p_y)
            elif moves[i+1] == 'a':
                p_x,p_y = jump_left(map, p_x, p_y)
            i += 1
        i += 1
        p_x, p_y = gravity(map, p_x, p_y)
        g_x,g_y,g_dir = goblin_move(map,g_x,g_y,g_dir)
    return p_x, p_y, g_x, g_y, g_dir
ida_dump = '''.rodata:0000000000002040 MAP             db 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0
.rodata:0000000000002040                                         ; DATA XREF: gravity+3F↑o
.rodata:0000000000002040                                         ; move_right+2E↑o ...
.rodata:0000000000002052                 db 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 2, 2, 2, 2
.rodata:0000000000002064                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
.rodata:0000000000002076                 db 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0
.rodata:0000000000002088                 db 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:000000000000209A                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0
.rodata:00000000000020AC                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1
.rodata:00000000000020BE                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1
.rodata:00000000000020D0                 db 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0
.rodata:00000000000020E2                 db 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0
.rodata:00000000000020F4                 db 1, 1, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
.rodata:0000000000002106                 db 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
.rodata:0000000000002118                 db 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 9
.rodata:000000000000212A                 db 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 2, 0, 0, 1, 1, 1
.rodata:000000000000213C                 db 1, 1, 1, 1, 1, 0, 0, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 0
.rodata:000000000000214E                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
.rodata:0000000000002160                 db 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0
'''
tmp = []
MAX_X = 30
MAX_Y = 10
p_x =0
p_y = 7
g_x = 11
g_y = 7
g_dir = 1
for line in ida_dump.split('\n'):
    if 'db' in line:
        for i in line.split('db ')[1].split(', '):
            tmp.append(int(i))
map = []
for i in range(0, len(tmp), MAX_X):
    map.append(tmp[i:i+MAX_X])
map.pop() # remove last null bytes

draw_map(map, p_x, p_y, g_x, g_y,filename='start.png')

moves1 = 'dwdwaawddddwddd'
p_x, p_y, g_x, g_y, g_dir = decode_moves(moves1, map, p_x, p_y, g_x, g_y,g_dir)
draw_map(map, p_x, p_y, g_x, g_y, filename='before_goblin.png')
moves2 = 'wd'
p_x, p_y, g_x, g_y, g_dir = decode_moves(moves2, map, p_x, p_y, g_x, g_y,g_dir)
draw_map(map, p_x, p_y, g_x, g_y, filename='after_goblin.png')
moves3 = 'dddddwdwawddddddwdwddaaaaa'
p_x, p_y, g_x, g_y, g_dir = decode_moves(moves3, map, p_x, p_y, g_x, g_y,g_dir)
draw_map(map, p_x, p_y, g_x, g_y, filename='final.png')

print(moves1+moves2+moves3)
```

output:

```
dwdwaawddddwdddwddddddwdwawddddddwdwddaaaaa
```

Stages:

starting position

![start.png](start.png)

before possible death from goblin - we need to jump over him

![before_goblin.png](before_goblin.png)

after avoiding gobiln

![after_goblin.png](after_goblin.png)

flag reached

![final.png](final.png)


```
 ██▓ ███▄    █    ▄▄▄█████▓ ██░ ██ ▓█████    ▓█████▄  ▄▄▄       ██▀███   ██ ▄█▀
▓██▒ ██ ▀█   █    ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀    ▒██▀ ██▌▒████▄    ▓██ ▒ ██▒ ██▄█▒ 
▒██▒▓██  ▀█ ██▒   ▒ ▓██░ ▒░▒██▀▀██░▒███      ░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒▓███▄░ 
░██░▓██▒  ▐▌██▒   ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄    ░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  ▓██ █▄ 
░██░▒██░   ▓██░     ▒██▒ ░ ░▓█▒░██▓░▒████▒   ░▒████▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒ █▄
░▓  ░ ▒░   ▒ ▒      ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░    ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒ ▒▒ ▓▒
 ▒ ░░ ░░   ░ ▒░       ░     ▒ ░▒░ ░ ░ ░  ░    ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░▒ ▒░
 ▒ ░   ░   ░ ░      ░       ░  ░░ ░   ░       ░ ░  ░   ░   ▒     ░░   ░ ░ ░░ ░ 
 ░           ░              ░  ░  ░   ░  ░      ░          ░  ░   ░     ░  ░   
                                              ░
Fellow mage lost in the darkness, he needs your guidance to find the flag as fast as possible and survive... 
dwdwaawddddwdddwddddddwdwawddddddwdwddaaaaa
Thank you for helping poor mage, in return you can see what he found.
zeroday{goblin_also_cant_see_in_the_dark}
```
