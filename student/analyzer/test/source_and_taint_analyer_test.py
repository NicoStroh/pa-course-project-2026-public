import sys

user = sys.argv[1]

safe = "abc"

cmd_1 = user
cmd_2 = "ls " + user
cmd_3 = f"ls {user}"