from preprocessor import preprocessor
from sentenceGenerator import sentenceGenerator

class preprocessorInitiator:
    def __init__(self, pre : preprocessor) -> None:
        self.pre = pre

    def initialize(self, upper : sentenceGenerator):
        upper.pre_assignment(self.pre.VAR_PTR, self.pre.VAR_ARR)
