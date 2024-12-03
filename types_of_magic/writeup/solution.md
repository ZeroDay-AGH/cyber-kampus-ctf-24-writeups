The file is actually a `.zip` file, not a `.txt` one. To get the flag following commands must be executed:

```
mv flag.txt flag.zip
unzip flag.zip

mv flag flag.gz
gunzip -d flag.gz

mv flag flag.ar
ar -x flar.ar

mv flag flag.tar
tar -xf flag.tar

mv flag flag.bz2
bzip2 -d flag.bz2

mv flag flag.lzma
lzma -d flag.lzma

mv flag flag.lz4
lz4 -d flag.lz4

mv flag flag.lzo
lzop -d flag.lzo
```

Otrzymujemy plik `flag`. Należy zmienić jego rozszerzenie na `.png` oraz należy zedytować nagłówek, tak aby wyświetlił zdjęcie:

- 11 byte: `FF -> 00`
- `IDHR -> IHDR`
- `IDED -> IDAT`

Flag: `zeroday{th3r3_are_m4ny_typ3s_0f_magic}`
