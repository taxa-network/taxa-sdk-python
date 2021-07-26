import sys
import subprocess

pyver = "python"
if sys.version_info.major >= 3:
    pyver = "python3"

desktop_entry_path = "/usr/share/applications/taxa-opener.desktop"

register_cmd = "xdg-mime default %s x-scheme-handler/taxa; sudo update-desktop-database" % desktop_entry_path

desktop_entry = """[Desktop Entry]
Type=Application
Name=Taxa Scheme Handler
Exec=%s -m taxa_sdk.protocol_opener %u
StartupNotify=false
MimeType=x-scheme-handler/taxa;
""" % pyver

if __name__ == '__main__':
    with open(desktop_entry_path, 'w') as f:
        f.write(desktop_entry)

    subprocess.Popen([register_cmd], shell=True)
