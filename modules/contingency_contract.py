from commons import Module
from utils import CustomFlow
import json
import mitmproxy.http
import uuid
import time
import frida
import threading
import os
import utils
from utils import info, error, warn

def battleStart(obj : CustomFlow):
    score = 0
    for i in obj.data["rune"]:
        if i.find("buff") > -1:
            score = 0
            break
        if i == "char_blockcnt_add": # Why? HG? Answer?
            score += 1
        else:
            score += int(i.split("_")[-1])

    toReturn = {
        "result": 0,
        "battleId": str(uuid.uuid1()),
        "playerDataDelta": {
            "deleted": {},
            "modified": {}
        },
        "sign": "6b1f67cd31d96a33702ca674b9a71f33ccb35cb3e74ea3dac20bb1d9f698a927a12cc25932ee4b4bea4570e01651f59935f3590d86cf0939ca7f56ee1a95d2f3fcdda9212c6c09e0b72289381f99eefac3fa598b2fdfd8d4a61a98a0f78b32e4ef3000414e268b6c04bedbe6b63d527bab3ce1a35d4a0f4c2894353142e31a1031822280849636d91c634f4b5e7380bb5ceab0203f95359ee1b09a102482348abf68f8a4df73f4e94972533582ae08ee3a012941d987c96b782a950a54851b501a823cdb7127b1fd260a40a7fc4c0bc254b5aaba5e7fa1791c5e0bb415ba36e3be4a39c38b955c07ad2c6bc6806f711bb17c966bbe519b48d70b4aeb86c7bddb",
    }

    obj.flow.response = mitmproxy.http.Response.make(
        200,
        json.dumps(toReturn, indent=4).encode('utf-8')
    )

    return score

def battleEnd(obj : CustomFlow, score):
    if obj.flow.request.path != "/crisis/battleFinish": return

    toReturn = {
        "result": 0,
        "playerDataDelta": {
            "deleted": {},
            "modified": {}
        },
        "score": score,
        "ts": int(time.time()),
        "updateInfo": {
            "point": {
                "after": score,
                "before": 0
            }
        }
    }

    obj.flow.response = mitmproxy.http.Response.make(
        200,
        json.dumps(toReturn, indent=4).encode('utf-8')
    )

class ContingencyContract(Module):
    def __init__(self):
        super().__init__("Contingency Contract")
        self.score = 0

        self.frida_server_thread = threading.Thread(
            target=lambda: utils.runCmd("adb shell \"/data/local/tmp/frida-server\"", False), 
            daemon=True
        )
        self.frida_server_thread.start()
        time.sleep(1)
        self.device = frida.get_usb_device(timeout=5)
        info(self.device.id)

        self.script_thread = threading.Thread(target=self.load_script, daemon=True)
        self.script_thread.start()

    def load_script(self):
        while True:
            b = False
            for i in self.device.enumerate_applications(scope="full"):
                if i.identifier == "com.YoStarEN.Arknights":
                    b = True
                    break
            time.sleep(1)
            if b: break

        time.sleep(1)

        # Very bad code
        aux = [i for i in utils.runCmd("adb shell \"ps -A | grep Arknights\"").stdout.decode().split(" ") if i != '']
        pid = int(aux[1])
        self.session = self.device.attach(pid, realm="emulated")
        script_path = 'cache\\hook.js'
        if os.path.isfile(script_path):
            with open(script_path, 'r', encoding="utf-8") as file:
                self.script = self.session.create_script(file.read())
            self.script.load()
        else:
            error(f"Script {script_path} not found. Contact 3tnt")
            exit()
    
    def request(self, obj : CustomFlow):
        if obj.flow.request.path == "/crisis/battleStart":
            self.score = battleStart(obj)
        elif obj.flow.request.path == "/crisis/battleFinish":
            battleEnd(obj, self.score)
            self.score = 0

    def response(self, obj : CustomFlow):
        pass

class CrisisInfo(Module):
    def __init__(self):
        super().__init__("Crisis Info")
    
    def request(self, obj : CustomFlow):
        pass

    def response(self, obj : CustomFlow):
        if obj.flow.request.path != "/crisis/getInfo": return

        season = list(obj.data["playerDataDelta"]["modified"]["crisis"]["season"].values())
        if len(season) == 0: return

        runes = season[0]["permanent"]["rune"]
        for k, v in runes.items():
            runes[k] = 1