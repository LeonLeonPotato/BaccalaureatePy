from mitmproxy.http import HTTPFlow

import modules.debugger as debug
import modules
import json
from colorama import Fore
import utils
from utils import info, error, warn
import traceback

for m in modules.mods:
    info(f"Loaded module: {Fore.MAGENTA}{m.name}{Fore.RESET}")

debugger = debug.Debugger()

def request(flow: HTTPFlow) -> None:
    print("Request from", flow.request.url)
    if "arknights" not in flow.request.host:
        return

    try: 
        json_data = json.loads(flow.request.text)
    except:
        json_data = None

    custom_flow = utils.CustomFlow(json_data, flow)
    
    for i in modules.mods:
        try:
            i.request(custom_flow)
        except BaseException as e:
            tb = traceback.format_exc()
            error(f"Error in module {Fore.MAGENTA}{i.name}{Fore.RESET}: {e}\n{tb}")

    debugger.request(custom_flow)

    if json_data is not None:
        flow.request.text = json.dumps(custom_flow.data)


def response(flow: HTTPFlow) -> None:
    print("Response from", flow.request.url)
    if "arknights" not in flow.request.host:
        return

    try: 
        json_data = json.loads(flow.response.text)
    except: 
        json_data = None

    custom_flow = utils.CustomFlow(json_data, flow)
    
    for i in modules.mods:
        try:
            i.response(custom_flow)
        except BaseException as e:
            tb = traceback.format_exc()
            error(f"Error in module {Fore.MAGENTA}{i.name}{Fore.RESET}: {e}\n{tb}")
    
    debugger.response(custom_flow)

    if json_data is not None:
        flow.response.text = json.dumps(custom_flow.data)