import subprocess
from .browser_ui import write_browser_ui
from .key_managers import get_os_dir

filename = write_browser_ui()

os_dir = get_os_dir()

if os_dir.startswith("Ubuntu"):
    subprocess.Popen(['xdg-open %s' % filename], shell=True)
else:
    subprocess.Popen(['open %s' % filename], shell=True)
