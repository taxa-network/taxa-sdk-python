import sys
from .key_managers import BaseKeyManager

bm = BaseKeyManager()
bm.write_intel_keys_to_config(sys.argv[1], sys.argv[2])
