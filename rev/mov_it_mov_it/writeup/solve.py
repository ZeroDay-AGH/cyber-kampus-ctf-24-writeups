# use:
# gdb -x solve.py
# podac jako flage cokolwiek
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

