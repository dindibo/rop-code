#!/usr/bin/env python3

from metaGadget import *
import argparse

EXEC_PATH = './simplecalc'

my_parser = argparse.ArgumentParser(description='Compiles to rop-code binary')

my_parser.add_argument('Input',
                       metavar='input',
                       type=str,
                       help='the path to the source code file')

args = my_parser.parse_args()
input_path = args.Input

class pre_compiler:
    
    def qword_convert(self, ea_start, position):
        return ea_start + position * 8


    RESERVED_VARIABLES = 3

    def __init__(self, ea_data) -> None:
        self.ea_data = ea_data
        self.LVAR       = self.qword_convert(self.ea_data, 0)
        self.RVAR       = self.qword_convert(self.ea_data, 1)
        self.MATH_RES   = self.qword_convert(self.ea_data, 2)

        self.variableDict = dict()
        self.variablesStartAddress = self.qword_convert(self.ea_data, self.RESERVED_VARIABLES)
        self.currentFreeAddress = self.variablesStartAddress

    def get_currentFreeAddress(self, inc=False):
        ret = self.currentFreeAddress
        
        if inc:
            self.currentFreeAddress += 8

        return ret

    def variable_address(self, varName):
        return self.variableDict[varName]

    def declare_variable(self, varName, addr):
        self.variableDict[varName] = addr

    def start(self):
        PRE_ASSIGNMENT(self.LVAR, 0)
        PRE_ASSIGNMENT(self.RVAR, 0)
        PRE_ASSIGNMENT(self.MATH_RES, 0)

    def initialize_variable(self, varName, value):
        new_addr = self.get_currentFreeAddress(inc=True)
        self.declare_variable(varName, new_addr)
        PRE_ASSIGNMENT(new_addr, value)


pre = pre_compiler(0x00000000006C1060)
pre.start()

pre.initialize_variable('x', 5)
pre.initialize_variable('y', 10)
pre.initialize_variable('add', 7)

ADDITION(pre, 'x', 'add')

finalize()
