import sys
import os
import shutil

source_dir = "/usr/local/lib/apple_signed/"

this_path = os.path.dirname(os.path.abspath(__file__))
version = sys.argv[1]

if version == '--catalina':
    dest = "bin/libs/OSX/catalina"
if version == '--bigsur':
    dest = "bin/libs/OSX/bigsur"
if version == '--monterey':
    dest = "bin/libs/OSX/monterey"

lib_path = os.path.normpath(os.path.join(this_path, dest))
os.mkdir(source_dir)
for filename in os.listdir(lib_path):
    full_path = os.path.join(lib_path, filename)
    shutil.copy2(full_path, source_dir)
    print("copied", full_path, "to", source_dir)
