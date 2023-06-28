from commons import Module
from utils import CustomFlow

class NameHere(Module):
    def __init__(self):
        super().__init__("Name Here")
    
    def request(self, obj : CustomFlow):
        pass

    def response(self, obj : CustomFlow):
        pass
