import sys
import os

filename = sys.argv[1]

open(filename)
os.open(filename, os.O_RDONLY)