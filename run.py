from colorama import Fore
import utils
import subprocess
import utils
from utils import info, error, warn

utils.disable_save = True

print(f"{Fore.RED}[ BaccalaureatePy by 3tnt ]{Fore.RESET}")
print(f"{Fore.RED}[ Version {Fore.GREEN}0.1.0{Fore.RED} ]{Fore.RESET}")
print("")

devices = utils.get_devices()
if len(devices) == 0: exit()
chosen = utils.user_choose_device(devices)

utils.root_adb(chosen)

info("Setting http(s) proxy...")
utils.runCmd(f"adb -s {chosen} shell settings put global http_proxy {utils.get_local_ip()}:8080")
utils.runCmd(f"adb -s {chosen} shell settings put global https_proxy {utils.get_local_ip()}:8080")

info("Starting mitmproxy...\n")
mitm_proc = subprocess.Popen(f"mitmdump -s main.py --quiet", shell=True)
try:
    mitm_proc.wait()
except KeyboardInterrupt:
    mitm_proc.terminate()

info("Resetting http(s) proxy...")
utils.runCmd(f"adb -s {chosen} shell settings delete global http_proxy")
utils.runCmd(f"adb -s {chosen} shell settings delete global https_proxy")