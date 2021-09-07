from __future__ import print_function

import sys
import os
import subprocess
from .key_managers import get_os_dir

if __name__ == '__main__':

    os_dir = get_os_dir().lower()

    if "ubuntu" in os_dir:
        desktop_entry_path = "/usr/share/applications/taxa-opener.desktop"

        register_cmd = "xdg-mime default %s x-scheme-handler/taxa; sudo update-desktop-database" % desktop_entry_path

        desktop_entry = """[Desktop Entry]
        Type=Application
        Name=Taxa Scheme Handler
        Exec=python -m taxa_sdk.protocol_opener %u || python3 -m taxa_sdk.protocol_opener %u
        StartupNotify=false
        MimeType=x-scheme-handler/taxa;
        """
        with open(desktop_entry_path, 'w') as f:
            f.write(desktop_entry)
        subprocess.Popen([register_cmd], shell=True)
        print("Ubuntu Protocol handler successfully installed")

    elif "osx" in os_dir:
        this_dir = os.path.dirname(os.path.abspath(__file__))
        app_path = os.path.join(this_dir, "bin/Taxa_SDK.app")
        subprocess.Popen(["open %s" % app_path], shell=True)
        print("OSX protocol handler successfully installed")

    else:
        raise SystemExit("Unknown OS, protocol handler not installed")
