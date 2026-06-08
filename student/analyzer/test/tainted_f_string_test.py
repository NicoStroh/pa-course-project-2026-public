import os
import sys

user = sys.argv[1]

cmd = f"ls {user}"

os.system(cmd)