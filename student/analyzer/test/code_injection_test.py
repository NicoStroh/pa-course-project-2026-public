import sys

a = sys.argv[1]

eval(a)
exec(a)

b = "random string"
eval(b)
exec(b)