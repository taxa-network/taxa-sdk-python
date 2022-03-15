import sys
import os
import shutil

source_dir = "/usr/local/lib/apple_signed/"

this_path = os.path.dirname(os.path.abspath(__file__))
version = sys.argv[1]

if version == '--catalina':
    lib_path = os.path.normpath(os.path.join(this_path, "bin/libs/OSX/catalina"))

os.mkdir(source_dir)
for filename in os.listdir(lib_path):
    f = os.path.join(lib_path, filename)
    shutil.copy2(f, source_dir)
    print("copied", f, "to", source_dir)
