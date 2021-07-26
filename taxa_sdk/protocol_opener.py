import subprocess
from .browser_ui import write_browser_ui

filename = write_browser_ui()
subprocess.Popen(['xdg-open %s' % filename], shell=True)
