import os
import sys

user = sys.argv[1]

cmd = "ls " + user

os.system(cmd)