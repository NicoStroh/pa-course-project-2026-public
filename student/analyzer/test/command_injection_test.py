import os as o
import sys
import subprocess

a = sys.argv[1]
b = a
c = b

o.system(c)
o.popen(c)
subprocess.run(c)
subprocess.Popen(c)

o.system(sys.argv[2])
o.system(f"ls {sys.argv[2]}")