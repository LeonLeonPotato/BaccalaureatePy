import socket
import re
import subprocess
import logging
import frida
import json
from colorama import Fore
import atexit
from mitmproxy.http import HTTPFlow

_cached_local_ip = None

disable_save = False
logger = None
character_table = None
module_table = None
stage_table = None
story_table = None
skin_table = None
character_config = None
squads = None

charid_to_skinids = {}
name_to_charid = {}
charid_to_name = {}

class CustomFlow:
    def __init__(self, data, flow):
        self.data : dict = data
        self.flow : HTTPFlow = flow

class _ColorFormatter(logging.Formatter):
    _INFO = f'{Fore.GREEN}[%(levelname)s]{Fore.RESET} %(message)s'
    _WARNING = f'{Fore.YELLOW}[%(levelname)s]{Fore.RESET} %(message)s'
    _ERROR = f'{Fore.RED}[%(levelname)s]{Fore.RESET} %(message)s'

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%') 

    def format(self, record):
        format_orig = self._style._fmt

        if record.levelno == logging.WARNING:
            self._style._fmt = _ColorFormatter._WARNING

        elif record.levelno == logging.INFO:
            self._style._fmt = _ColorFormatter._INFO

        elif record.levelno == logging.ERROR:
            self._style._fmt = _ColorFormatter._ERROR

        result = logging.Formatter.format(self, record)

        self._style._fmt = format_orig
        return result

def load_logger():
    global logger
    logger = logging.getLogger('BaccalaureatePy')
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(_ColorFormatter())
    logger.addHandler(console_handler)

load_logger()

def load_tables():
    global character_table, module_table, stage_table, story_table, character_config, skin_table, squads
    with open("cache\\character_table.json", "r", encoding="utf-8") as f:
        character_table = json.load(f)
    with open("cache\\module_table.json", "r", encoding="utf-8") as f:
        module_table = json.load(f)
    with open("cache\\stage_table.json", "r", encoding="utf-8") as f:
        stage_table = json.load(f)
    with open("cache\\story_table.json", "r", encoding="utf-8") as f:
        story_table = json.load(f)
    with open("cache\\skin_table.json", "r", encoding="utf-8") as f:
        skin_table = json.load(f)
    with open("characters.json", "r", encoding="utf-8") as f:
        character_config = json.load(f)
    with open("squads.json", "r", encoding="utf-8") as f:
        squads = json.load(f)

    for i, v in character_table.items():
        if i.startswith("char_"):
            name_to_charid[v["name"]] = i
            charid_to_name[i] = v["name"]

    for i, v in skin_table["charSkins"].items():
        if v["charId"] in charid_to_skinids:
            charid_to_skinids[v["charId"]].append(i)
        else:
            charid_to_skinids[v["charId"]] = [i]

load_tables()

def exit_handler():
    if disable_save: return
    info("Saving characters.json...")
    with open("characters.json", "w", encoding="utf-8") as f:
        f.write(json.dumps(character_config, indent=4, ensure_ascii=False))
    info("Done!")

# comment out this if you do not want to save the characters.json file
atexit.register(exit_handler)

def info(msg):
    logger.log(logging.INFO, msg)

def warn(msg):
    logger.log(logging.WARNING, msg)

def error(msg):
    logger.log(logging.ERROR, msg)

def runCmd(cmd, stdout=subprocess.PIPE):
    return subprocess.run(cmd, shell=True, stdout=stdout)

def root_adb(device):
    runCmd(f"adb -s {device} root")
    runCmd(f"adb -s {device} remount")

def get_devices():
    devices_proc = runCmd("adb devices")
    devices = []

    for line in devices_proc.stdout.decode().splitlines():
        for match in re.findall(r'emulator-\d+', line):
            devices.append(match.split("-")[1])

    return devices

def user_choose_device(devices):
    info(f"Found {Fore.RED}{len(devices)}{Fore.RESET} devices")
    if len(devices) > 1:
        info("Devices found:", devices)
        while True:
            chosen = input(f"{Fore.YELLOW}What device do you want to operate on? {Fore.RESET}")
            if chosen not in devices:
                warn(f"Device {chosen} not found in {devices}")
                continue
            else: break
    else:
        chosen = devices[0]
        info(f"Using device {Fore.RED}{chosen}{Fore.RESET}")
    
    return "emulator-" + chosen

def get_usb_device(port, timeout=0, **kwargs):
    return frida.get_device_matching(lambda d: d.type == 'usb' and d.id == port, timeout, **kwargs)

def get_local_ip():
    global _cached_local_ip
    if not _cached_local_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        _cached_local_ip = s.getsockname()[0]
        s.close()
    return _cached_local_ip