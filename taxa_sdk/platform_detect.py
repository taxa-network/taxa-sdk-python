import os
import platform
import sys
import subprocess

def find_lib_dir():
    this_dir = os.path.dirname(os.path.abspath(__file__))
    for p in sys.path:
        if p == this_dir:
            continue
        if os.path.isdir(p) and 'taxa_sdk' in os.listdir(p):
            install_path = os.path.join(p, 'taxa_sdk')
            break
    else:
        raise Exception(
            "Could not find SDK install path to add taxa_client libs to library path"
        )

    return "%s/bin/libs" % install_path

def parse_os_release(item, start, end, verbose=False):
    before_parsed = subprocess.Popen(
        ["grep '^%s' /etc/os-release" % item], shell=True, stdout=subprocess.PIPE
    ).stdout.read().decode().strip()

    if verbose: print("before parse:", type(before_parsed), before_parsed)
    return before_parsed[start:end]

def get_os_dir():
    plat = platform.platform()
    if plat.startswith("Darwin") or plat.startswith("macOS"):
        return "OSX"
    os_name = parse_os_release("NAME", 6, -1)
    version = parse_os_release("VERSION_ID", 12, -1)
    return "%s_%s" % (os_name, version)

def get_os_specific_lib_dir():
    return os.path.join(find_lib_dir(), get_os_dir())
