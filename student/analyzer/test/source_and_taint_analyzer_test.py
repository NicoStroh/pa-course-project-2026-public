import sys
import argparse

user = sys.argv[1]

safe = "abc"

cmd_1 = user
cmd_2 = "ls " + user
cmd_3 = f"ls {user}"

parser = argparse.ArgumentParser()

parser.add_argument("term")

args = parser.parse_args()

term = args.term