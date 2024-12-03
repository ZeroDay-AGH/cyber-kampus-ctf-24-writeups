from pwn import *

HOST = 'localhost'
PORT = 1337
io = remote(HOST,PORT)

# MOTD
for _ in range(22):
    l = io.recvline().decode().rstrip()
    print(l)

CN = [340649031679478708871356501710247209854526956821188127472136012686397651, 17226095350814884309562782709503476832333815043778073233750461, 2857918787712346525006109491322802855472993589681966310076027177885154155603141]
factors = [
    [10360877555851, 134691408226051, 424795979789851, 549126510460051, 1046448633140851],
    [2118459439, 7767684607, 19066134943, 31776891571, 38838423031, 44487648199],
    [261791962759, 3926879441371, 6719327044123, 33596635220611, 43195673855071, 285091447443463]
]

i = 0
resp = b''
while True:
    resp = io.recvline()
    if b'The spell is complete' in resp:
        io.close()
        break

    if b'Summon the ancient number' in resp:
        number = CN[i]
        io.sendline(str(number).encode())

    resp = io.recv(7)
    if resp == b'The anc' or resp == b'The ech' or resp == b'The mag':
        io.recvuntil(b'.\n')
        sleep(0.1)
        continue

    if resp == b'Speak t':
        log.info(f'Prime {i+1} accepted')
        f_list = factors[i]
        f = ' '.join(list(map(str,f_list)))
        io.sendline(f.encode())
        resp = io.recvline()
        i += 1

flag = resp.split()[-1]
log.success(flag.decode())
io.close()

