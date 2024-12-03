from pwn import *

# import sys
# import requests
from hashpumpy import hashpump
from time import sleep

import HashTools
from os import urandom

def forge(secret_length,original_data,append_data,signature):
    magic = HashTools.new("sha1")
    new_data, new_sig = magic.extension(
        secret_length=secret_length, original_data=original_data,
        append_data=append_data, signature=signature
    )
    return new_data, new_sig

HOST = 'localhost'
PORT = 1337
io = remote(HOST,PORT)

# MOTD
for _ in range(22):
    l = io.recvline().decode().rstrip()
    print(l)

# Message - signature
io.recvuntil(b'The ancient seal reads: ')
original_sig = io.recvline().strip().decode()
log.info(f'Original signature: {original_sig}') 

# Message - abracadabra
io.recvuntil(b'Your incantation must weave the sacred word: ')
original_data = io.recvline().strip()
log.info(f'Original spell: {original_data}') 

# Message - But beware, only unique enchantments hold true power!
l = io.recvline() 

# Receive the data and forge the signature, changing the secret length
data_to_add = b'abracadabra'
l = 1
resp = b''
while b'The enchantment is complete!' not in resp:
    forged_data, forged_sig = forge(l,original_data,data_to_add,original_sig)
    x = io.recvuntil(b'Whisper your spell into the enchanted tome (hex): ')
    io.sendline(forged_data.hex().encode())
    io.recvuntil(b'Seal your magic with a sacred rune: ')
    io.sendline(forged_sig.encode())
    resp = io.recvline()
    l += 1

print(resp.split()[-1].decode())


