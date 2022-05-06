#!/usr/bin/env python3
from metaGadget import metaGadetGenerator
from preprocessor import preprocessor

class sentenceGenerator:
    def __init__(self, intermediate : metaGadetGenerator, pre : preprocessor) -> None:
        self.intermediate = intermediate
        self.pre = pre

    def PRE_ASSIGNMENT(self, addr, value):
        self.intermediate.write_what_where(addr, value)


    # 32 bit
    # TODO: Refactor
    def ADDITION (self, lvar_name, rvar_name):
        l_addr, r_addr = self.pre.variable_address(lvar_name), self.pre.variable_address(rvar_name)

        # Prepare lvar and rvar
        self.intermediate.read_toRAX(l_addr)
        self.intermediate.write_what_where_RAX(self.pre.LVAR)
        self.intermediate.read_toRAX(r_addr)
        self.intermediate.write_what_where_RAX(self.pre.RVAR)

        # Do addition 
        self.intermediate.read_toRAX(self.pre.LVAR)
        self.intermediate.exchange_eax_ebx()
        self.intermediate.read_toRAX(self.pre.RVAR)
        self.intermediate.add_eax_to_ebx()
        self.intermediate.exchange_eax_ebx()

        # Write to result variable and lvar
        self.intermediate.write_what_where_RAX(self.pre.MATH_RES)
        self.intermediate.write_what_where_RAX(l_addr)


    def MOVE_PTR(self, dir):
        # Read to RAX variables ptr
        self.intermediate.read_toRAX(self.pre.VAR_PTR)

        # Do move
        if dir:
            self.intermediate.add_rax_8()
        else:
            self.intermediate.sub_rax_n(8)

        self.intermediate.ex_write_what_where(rsi_where=self.pre.VAR_PTR)

    # 32 Bit
    # Side-Effect: Changes rbx
    def ADD_PTR(self, positive):
        # Read to RAX variables ptr
        self.intermediate.read_toRAX(self.pre.VAR_PTR)

        # Dereference
        self.intermediate.follow_rax_rax()

        # Do math
        if positive:
            self.intermediate.add_rax_2()
            self.intermediate.sub_rax_1()
        else:
            self.intermediate.sub_rax_1()

        # RAX holds answer, save in temp1
        self.intermediate.ex_write_what_where(rsi_where=self.pre.TEMP2)

        # Move ptr to rsi for write
        self.intermediate.read_toRAX(self.pre.VAR_PTR)
        self.intermediate.mov_rsi_rax(self.pre)
        self.intermediate.read_toRAX(self.pre.TEMP2)
        self.intermediate.ex_write_what_where()

    def RETURN_TO_MAIN(self):
            self.intermediate.goto_main()
