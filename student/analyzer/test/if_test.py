import sys, os

tainted_variable = sys.argv[0]

if tainted_variable == "taint":
    evil_command = "&& rm -rf *"
    os.system(evil_command)