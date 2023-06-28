import subprocess
import os
from colorama import Fore
from pathlib import Path
import time
import utils

devices = utils.get_devices()
if len(devices) == 0: exit()
chosen = utils.user_choose_device(devices)

mitm_folder = os.path.join(Path.home(), ".mitmproxy")
if not os.path.exists(mitm_folder):
    print(f"{Fore.YELLOW}[WARNING]{Fore.RESET} mitmproxy folder not found, creating it...")
    # hacky way to get certs created
    mitm_folder_proc = subprocess.Popen("mitmdump", shell=True, stdout=subprocess.PIPE)
    while not os.path.exists(mitm_folder):
        time.sleep(0.1)
        pass
    time.sleep(0.2)
    mitm_folder_proc.kill()

cert = os.path.join(mitm_folder, "mitmproxy-ca-cert.pem")

cert_hash_proc = subprocess.run(
    f"openssl x509 -inform PEM -subject_hash_old -in {cert}", 
    shell=True, stdout=subprocess.PIPE
)
cert_hash = cert_hash_proc.stdout.decode().splitlines()[0]

print(f"{Fore.GREEN}[INFO]{Fore.RESET} Cert hash: " + cert_hash)

with open(cert_hash + ".0", "w") as dst:
    with open(cert, "r") as src:
        dst.write(src.read())
        dst.write("\n")

decode_cert_proc = subprocess.run(
    f"openssl x509 -inform PEM -text -in {cert} -noout >> {cert_hash}.0", 
    shell=True, stdout=subprocess.PIPE
)

print(f"{Fore.GREEN}[INFO]{Fore.RESET} Created decoded android-compatible file")
print(f"{Fore.GREEN}[INFO]{Fore.RESET} Pushing cert to device...")

utils.root_adb(chosen)
utils.runCmd(
    f"adb -s {chosen} push {cert_hash}.0 /system/etc/security/cacerts/{cert_hash}.0", 
    stdout=None
)

print(f"{Fore.GREEN}[INFO]{Fore.RESET} Pushed cert to device")

while True:
    restart = input(f"{Fore.YELLOW}Would you like to restart the device? (1/0) {Fore.RESET}")
    if restart not in ["1", "0"]:
        print(f"{Fore.RED}[WARNING]{Fore.RESET} Invalid input")
        continue
    else: break

restart = int(restart)
if restart != 0:
    print(f"{Fore.GREEN}[INFO]{Fore.RESET} Restarting device...")
    utils.runCmd(f"adb -s {chosen} reboot")

