import os
import sys
import subprocess

a = sys.argv[1]
b = a
c = b

os.system(c)
os.popen(c)
subprocess.run(c)
subprocess.Popen(c)

os.system(sys.argv[2])
os.system(f"ls {sys.argv[2]}")