"""
Test case demonstrating control-flow implicit taint propagation.

Example attack: if attacker-controlled input influences a condition,
variables assigned in blocks controlled by that condition become tainted.
"""

import sys

# Attacker injects a value via CLI
user_input = sys.argv[1]

# Scenario 1: conditional assignment
if user_input == "admin":
    cmd = "ls"
else:
    cmd = "cat /etc/passwd"
# cmd is implicitly tainted because it's assigned in both branches
# controlled by the tainted condition (user_input == "admin")

import os
os.system(cmd)  # Should detect command_injection


# Scenario 2: loop-based implicit taint
data = sys.argv[2]

for item in data:
    process = f"process {item}"
    # process is implicitly tainted because assignment happens
    # in loop body controlled by tainted data

import subprocess
subprocess.run(process)  # Should detect command_injection


# Scenario 3: nested control flow
filename = sys.argv[3]

if filename:
    if filename.startswith(".."):
        path = f"/home/user/{filename}"
    else:
        path = filename
    # path is implicitly tainted due to nested conditions

with open(path):
    pass  # Should detect path_traversal
