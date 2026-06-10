from pathlib import Path
import sys
import os

filename = sys.argv[1]

path = Path(filename)

open(filename)
os.open(filename, os.O_RDONLY)
Path(filename).read_text()
Path(filename).open()
path.read_text()
path.open()

Path("/tmp/test.txt").read_text()