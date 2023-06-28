from abc import ABC, abstractmethod
from mitmproxy.http import HTTPFlow
from utils import CustomFlow

class Module(ABC):
    def __init__(self, name):
        self.name = name

    @abstractmethod
    def request(self, flow : CustomFlow):
        pass

    @abstractmethod
    def response(self, flow : CustomFlow):
        pass