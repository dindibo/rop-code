from metaGadget import *

class preprocessor:
    
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

    def qword_convert(self, ea_start, position):
        return ea_start + position * 8
