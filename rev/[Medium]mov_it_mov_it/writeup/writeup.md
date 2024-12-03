https://www.youtube.com/watch?v=jLPYnw17GTY

1. Run chall in gdb

2. Set breakpoint on puts (b *puts) (other breakpoints probably also work, puts is visible in the debugger)

3. Stack:

```
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ eax esp 0x85f626c (stack+2096572) —▸ 0x804b9d0 (main+9972) ◂— mov dword ptr [0x804d370], eax
01:0004│         0x85f6270 (stack+2096576) —▸ 0x804d1e0 ◂— imul esp, dword ptr [eax], 0x746e6163 /* 0x61632069; "i cant't move it move it :(\n" */
02:0008│         0x85f6274 (stack+2096580) ◂— 0x7d /* '}' */
03:000c│         0x85f6278 (stack+2096584) ◂— 1
04:0010│         0x85f627c (stack+2096588) ◂— 0x61 /* 'a' */
05:0014│         0x85f6280 (stack+2096592) ◂— 0
```

last char of flag is at 0x85f6274

4.  rwatch *(int *) 0x85f6274

5. read values from watchpoint and convert to char

6. profit

zeroday{l00king_4t_m0ving_ch4rs_m4k3s_r0cks_flight_4way}

7. solve script:

```python
#use:
#gdb -x solve.py
#podac jako flage cokolwiek
import pwndbg
import pwndbg.commands
import gdb
file = './chall'
address = 0x85f6274
values = []
# function to print flag chars
def print_value(event):
    value = gdb.parse_and_eval(f'*(int *) {address}')
    print(f'Value at address {hex(address)} changed to: {value}')
    values.append(chr(value))
    print(''.join(values))
    gdb.execute("c")

# add watchpoint
gdb.execute(f'rwatch *(int *) {address}')
# add function to event
gdb.events.stop.connect(print_value)
# gdb commands
gdb.execute(f'file ./{file}')
gdb.execute('run')
gdb.execute('c')
gdb.execute('c')
