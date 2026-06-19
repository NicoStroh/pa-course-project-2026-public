"""
Test case demonstrating interprocedural control-flow analysis.

When a function call is in a control-dependent block on tainted data,
the return value should be considered implicitly tainted.
"""

import sys


def get_mode(config):
    """This function returns different values based on config."""
    if config == "debug":
        return "debug_mode"
    else:
        return "normal_mode"


def dangerous_operation(mode):
    """This function performs operations based on mode."""
    if mode:
        import os
        os.system("ls")  # Will be detected as tainted if mode is tainted
    return "done"


# Attacker controls config
config = sys.argv[1]

# Call function in tainted-condition block (interprocedural control-flow)
if config:
    mode = get_mode(config)
    result = dangerous_operation(mode)
    eval(result)  # Should detect: result is implicitly tainted


# Another interprocedural scenario: function return value in control block
user_choice = sys.argv[2]

def build_command(choice):
    if choice == "safe":
        return "echo safe"
    else:
        return "cat /etc/passwd"


# The return value is in control-dependent block
if user_choice:
    cmd = build_command(user_choice)
    import os
    os.system(cmd)  # Should detect: implicitly tainted through control-flow
