import sys
import os

def foo(x):
    os.open(x)
    return x

a = foo(sys.argv[1])
os.open(a)