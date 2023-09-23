#!/usr/bin/env python3
from metaGadget import metaGadetGenerator
from preprocessor import preprocessor

class sentenceGenerator:
    def __init__(self, intermediate : metaGadetGenerator, pre : preprocessor) -> None:
        self.intermediate = intermediate
        self.pre = pre

    def get_num_of_opcodes(self):
        return self.intermediate.get_num_of_opcodes()

    def exit_clean(self):
        self.intermediate.ret2_exit(0)

    def mark(self):
        self.intermediate.marker()

    def pre_assignment(self, addr, value):
        self.intermediate.write_what_where(addr, value)


    # 32 bit
    # TODO: Refactor
    def addition (self, lvar_name, rvar_name):
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


    def move_ptr(self, dir):
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
    def add_ptr(self, positive):
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

    # Performs check on current  data cell
    # and if not 0 jumps back to loopStart
    # otherwise, continues to  next gadget
    def loop_end(self, loopStartOffset):
        # Check if data zero and Yield binary answer
        self.intermediate.rax_equ(self.pre.VAR_PTR)
        self.intermediate.follow_rax_rax()
        self.intermediate.follow_rax_rax()
        self.intermediate.test_rax_rax()

        # Prepare binary
        self.intermediate.rax_equ(1)
        self.intermediate.rdx_equ(0)

        # Do compare
        self.intermediate.cond_mov_rax_rdx()

        # Extract bool to ESI
        self.intermediate.edx_equ_eax()
        self.intermediate.esi_equ_edx()
    
        # Move offset to edx
        self.intermediate.rdx_equ(loopStartOffset)
        self.intermediate.signed_multiply_esi_edx()

        # Add calculate next offset
        self.intermediate.eax_equ_esp()
        self.intermediate.add_eax_esi()

        # TODO: Add to EAX CORRECT_OFFSET (== 24 bytes)
        

        # Do exchange
        self.intermediate.exchange_eax_esp()


    def return_to_main(self):
        self.intermediate.goto_main()
