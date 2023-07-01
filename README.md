# BaccalaureatePy

Modern private server made for high-risk CC clears and other gameplay-related shenanigans

## Features
- Configurable settings for every operator
- Squad saving
- CC bypass
- Re-enabled pause glitch

## Setup
1. Install Python [here](https://www.python.org/downloads/release/python-3913/)

2. Open command line at the project's directory and type `pip install -r requirements.txt`
3. Download the ADB executable from [here](https://developer.android.com/tools/releases/platform-tools)
4. Extract `platform-tools` and add it to your path. Restart all terminals.
5. In your emulator's settings, enable `root` and adb debugging:
![image](https://i.imgur.com/S5PqgOH.png)
6. Install mitmproxy from https://mitmproxy.org/
7. Download Frida server version 15.2.2 [here](https://github.com/frida/frida/releases/tag/15.2.2). **Make sure to download the server for your emulator's architecture!**  if you do not know that, run the command `adb shell getprop ro.product.cpu.abi` in a CLI (terminal)
8. Run `python setup.py` in the project's directory, and then reboot your emulator
9. **Temporary fix:** In your terminal, run `adb root` and keep on spamming `adb devices` until you see something
10. Open up Arknights, but do not log in.
11. Run `python run.py` in your terminal
12. Log in to your alt account.

If you encounter any errors, please friend and DM `3tnt` on Discord, or make a post on the `issues` page!

## **IMPORTANT**

**DO NOT RUN THIS ON YOUR MAIN ACCOUNT!**

**Even though this server should be nearly undetectable, I would not risk it!**


## Todo
- Fix funky adb startup error
- Configurable borrowed units
- Non-CC battles
- Save CC progress
- Fix main menu editor
- Re-organize code
- Streamline installation process
