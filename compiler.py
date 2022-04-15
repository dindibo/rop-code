#!/usr/bin/env python3

import argparse

EXEC_PATH = './simplecalc'

my_parser = argparse.ArgumentParser(description='Compiles to rop-code binary')

my_parser.add_argument('Input',
                       metavar='input',
                       type=str,
                       help='the path to the source code file')

args = my_parser.parse_args()

input_path = args.Path
