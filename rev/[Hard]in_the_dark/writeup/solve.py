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