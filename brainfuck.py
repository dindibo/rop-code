#!/usr/bin/env python3

from metaGadget import *

class preprocessor:
    
    def qword_convert(self, ea_start, position):
        return ea_start + position * 8

    def __init__(self, ea_data) -> None:
        self.ea_data    = ea_data
        self.TEMP1      = self.qword_convert(self.ea_data, 0)
        self.TEMP2      = self.qword_convert(self.ea_data, 1)
        self.TRASH1     = self.qword_convert(self.ea_data, 2)
        self.VAR_PTR    = self.qword_convert(self.ea_data, 3)
        self.VAR_ARR    = self.qword_convert(self.ea_data, 4)

    def get_currentFreeAddress(self, inc=False):
        ret = self.currentFreeAddress
        
        if inc:
            self.currentFreeAddress += 8

        return ret

    def start(self):
        PRE_ASSIGNMENT(self.VAR_PTR, self.VAR_ARR)


class compiler:
    def __init__(self, preprocessor : preprocessor, ea_data) -> None:
        self.preprocessor = preprocessor
        self.ea_data = ea_data
        self.tokens = '<>+-.,[]'


    def do_ptr_move(self, direction):
        if direction:
            read_toRAX(self.preprocessor.VAR_PTR)
        else:
            pass


    def do_ptr_value(self, positive):
        pass


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

