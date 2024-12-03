we can seperate the code into parts:
```ASM
PUSH 0;
PUSH 6;
PUSH 102;
PUSH 108;
PUSH 97;
PUSH 103;
PUSH 58;
PUSH 32;
SYSCALL;
```
prints `flag: `
```ASM
PUSH 244;
PUSH 100;
PUSH 224;
PUSH 108;
PUSH 192;
PUSH 92;
PUSH 230;
PUSH 116;
PUSH 202;
PUSH 43;
PUSH 210;
PUSH 105;
PUSH 178;
PUSH 101;
PUSH 162;
PUSH 13;
PUSH 37;
PUSH 78;
PUSH 182;
PUSH 78;
PUSH 166;
PUSH 84;
PUSH 154;
PUSH 72;
PUSH 168;
PUSH 72;
PUSH 168;
PUSH 76;
PUSH 178;
PUSH 68;
PUSH 146;
PUSH 70;
PUSH 166;
PUSH 92;
PUSH 0;
PUSH 34;
``` 
this part of the code is a flag chars before decryption.
```ASM
MOV A 0;  // index
POP B;    // take the flag char into B
CMP B 13; // if flag char == 13...
JNZ 50;
MOV B 33; // ...replace it with 33
CMP B 37; // if flag char == 37...
JNZ 53;   
MOV B 172; // ...replace it with 172
MOV C A;  // C = index
CMP C 0;  // (loop2 start)if index == 0
JZ 60;   //go to DIV B 2
CMP C 1; // if index == 1
JZ 61;  //go to ADD B A
SUB C 2; // index -= 2
JMP 54; //loop2
DIV B 2; //happens if index == 0
ADD B A; // index is added to flag char
PUSH B; // add the flag char to the stack
CMP A 33; // if index == 33
JZ 67;    //break
ADD A 1;
JMP 46;
SYSCALL; //print flag
END 
```
this is loop that iterates over the len of flag (34) and adds index of char to the char itself.
then if index is divisible by 2, it divides the char by 2.

solve script:
```python
n = [244,100,224,108,192,92,230,116,202,43,210,105,178,101,162,13,37,78,182,78,166,84,154,72,168,72,168,76,178,68,146,70,166,92]
n[n.index(13)] = 33
n[n.index(37)] = 172
flag = [ chr((n[i]//2)+i) if i%2==0 else chr(n[i]+i) for i in range(len(n))]
print(''.join(flag))
```

output:
```
zeroday{m4ster_0f_magic_languages}
```

also i wrote interpreter for FIFO-ASM, you can run your challenge with it :)

you can find it as [interpreter.py](/fifology/writeup/interpreter.py) run with:
```
python3 interpreter.py --file program.fo
```

or

```
python3 interpreter.py --debug --file program.fo
```

```python
import argparse
def parse_reg(input):
    if input == 'A':
        return 0, True
    if input == 'B':
        return 1, True
    if input == 'C':
        return 2, True
    return int(input), False
debug = False
parser = argparse.ArgumentParser()
parser.add_argument('--file', help='file to interpret')
parser.add_argument('--debug', help='debug mode', action='store_true')
args = parser.parse_args()
#if --debug is present
if args.debug:
    debug = True
if args.file:
    with open(args.file,'r') as f:
        code = f.read()
        code = code.split(';\n')
else:
    code = input()
    code = code.split(';')
queue = []
reg = [0]*3 #A B C
flag = 0 #zero flag
fd = None #file descriptor
instruction = 0
debug_outputs =[]
while instruction < len(code):
    line  = code[instruction].strip()
    single = False
    if ' ' not in line:
        mne = line
        single = True
    else:
        mne = line.split(' ')[0]
    if debug:
        print('queue: ',queue[:3],'...',queue[:3],'reg',reg,'flag', flag, 'i', instruction, code[instruction])
    if mne == 'PUSH':
        op,is_reg = parse_reg(line.split(' ')[1])
        if is_reg:
            queue.append(reg[op])
        else:
            queue.append(op)
    elif mne == 'POP':
        if single:
            queue.pop(0)
        else:
            op,is_reg = parse_reg(line.split(' ')[1])
            if is_reg:
                reg[op] = queue.pop(0)
            else:
                reg[op] = queue.pop(0)
    elif mne == 'GET':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] = queue[reg[op2]]
        elif is_reg1:
            reg[op1] = queue[op2]
    elif mne == 'MOV':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] = reg[op2]
        elif is_reg1:
            reg[op1] = op2
    elif mne =='ADD':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] += reg[op2]
        elif is_reg1:
            reg[op1] += op2
    elif mne == 'SUB':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] -= reg[op2]
        elif is_reg1:
            reg[op1] -= op2
    elif mne == 'MUL':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] *= reg[op2]
        elif is_reg1:
            reg[op1] *= op2
    elif mne == 'DIV':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] //= reg[op2]
        elif is_reg1:
            reg[op1] //= op2
    elif mne == 'XOR':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            reg[op1] ^= reg[op2]
        elif is_reg1:
            reg[op1] ^= op2
    elif mne == 'CMP':
        op1,is_reg1 = parse_reg(line.split(' ')[1])
        op2,is_reg2 = parse_reg(line.split(' ')[2])
        if is_reg1 and is_reg2:
            if reg[op1] == reg[op2]:
                flag = 0
            elif reg[op1] > reg[op2]: #first operand is greater
                flag = 1 
            elif reg[op1] < reg[op2]: #second operand is greater
                flag = 2
        elif is_reg1:
            if reg[op1] == op2:
                flag = 0
            elif reg[op1] > op2:
                flag = 1
            elif reg[op1] < op2:
                flag = 2
    elif mne == 'JMP':
        op,is_reg = parse_reg(line.split(' ')[1])
        if is_reg:
            instruction = reg[op]-1
        else:
            instruction = op-1
    elif mne == 'JZ':
        op,is_reg = parse_reg(line.split(' ')[1])
        if flag == 0:
            if is_reg:
                instruction = reg[op]-1
            else:
                instruction = op-1
    elif mne == 'JNZ':
        op,is_reg = parse_reg(line.split(' ')[1])
        if flag != 0:
            if is_reg:
                instruction = reg[op]-1
            else:
                instruction = op-1
    elif mne == 'SYSCALL': # 0 print, 1 openfile, 2 readfile, 3 close file, 4 input from stdin, 
        if single:
            id = queue.pop(0)
            if id == 0: # print
                # queue: id,buf_len,buf
                buf_len = queue.pop(0)
                buf = []
                for i in range(buf_len):
                    buf.append(chr(queue.pop(0)))
                print(''.join(buf))
                debug_outputs.append(''.join(buf))
            elif id == 1: #openfile
                filename_len = queue.pop(0)
                filename = []
                for i in range(filename_len):
                    filename.append(chr(queue.pop(0)))
                fd = open(''.join(filename),'r')
            elif id == 2:
                with fd as f:
                    content = f.read()
                    queue.append(len(content))
                    for char in content:
                        queue.append(ord(char))
            elif id == 3:
                fd.close()
                fd = None
            elif id == 4:
                content = input()
                queue.append(len(content))
                for char in content:
                    queue.append(ord(char))


    elif mne == 'END':
        print('Exited Successfully')
        if debug:
            print(queue)
            print(reg)
            print('all outputs:\n-----------------------------------\n','\n'.join(debug_outputs))
        break
    instruction += 1

        
'''
Hello World (just prints Hello World)
PUSH 0;PUSH 11;PUSH 72;PUSH 101;PUSH 108;PUSH 108;PUSH 111;PUSH 32;PUSH 119;PUSH 111;PUSH 114;PUSH 108;PUSH 100;SYSCALL;END

Prints numbers in loop
MOV A 5; CMP A 0;JZ 11;MOV B A;ADD B 47;PUSH 0;PUSH 1;PUSH B;SYSCALL;SUB A 1;JMP 1;END

Reads filename from user and prints the content of the file
PUSH 4;PUSH 1;SYSCALL;SYSCALL;PUSH 2;PUSH 0;SYSCALL;SYSCALL;END

'''
```
