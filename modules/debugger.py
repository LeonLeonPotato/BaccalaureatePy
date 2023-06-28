from commons import Module
from utils import CustomFlow
import os
import json

enabled = True

def dump(folder, obj : CustomFlow):
    if not enabled: return
    name = obj.flow.request.path.rsplit("/", 1)[-1]
    name = name.split("?")[0]

    with open(f"debug\\{folder}\\{name}.json", "w") as f:
        f.write(json.dumps(obj.data, indent=4))

class Debugger():
    def __init__(self):
        if not os.path.exists("debug"): os.mkdir("debug")
        if not os.path.exists("debug\\request"): os.mkdir("debug\\request")
        if not os.path.exists("debug\\response"): os.mkdir("debug\\response")
    
    def request(self, obj : CustomFlow):
        dump("request", obj)

    def response(self, obj : CustomFlow):
        dump("response", obj)
