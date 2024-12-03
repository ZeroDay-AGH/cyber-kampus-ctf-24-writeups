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
