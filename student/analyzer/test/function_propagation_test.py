import sys
import os
import pickle
import sqlite3

connection = sqlite3.connect(":memory:")

def foo(x):
    os.system(x)
    eval(x)
    pickle.load(x)
    connection.execute(x)
    os.open(x)
    return x

a = foo(sys.argv[1])
os.system(a)
eval(a)
pickle.load(a)
connection.execute(a)
os.open(a)