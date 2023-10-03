- shellcode_bin_mips: fail
- another: success
# Deploy
## Test shellcode
   
        python ./shellcode_\<type\>.py

        nc -nv \<localhost\> \<port\>

## Debug shellcode

       python ./shellcode_\<type\>.py
 
       => Starting local process '/tmp/pwn-asm-xxxxxx/step3-elf': pid xxx

        qemu-mips -g 1234 /tmp/pwn-asm-xxxxxx/step3-elf

        gdb-mutiarch
               set architecture mips
               target remote host:post
               layout asm (to view source)

## Exploit
- Set up emulator firmware
- Because aslr's emulator firmware is on while the real device is off, so the base libc address must be cútomize in exploit_bind code.
- Depending on the implementation, we can customize the shellcode in the exploit code.
