import os
import sys
from helper_module import process_input, safe_process


def main():
    # Line 6-7: Cross-file vulnerability - sys.argv flows through helper_module.process_input() to os.system()
    user_input = sys.argv[1]
    result = process_input(user_input)
    os.system(result)

    # Line 11-13: Safe - safe_process() always returns safe output regardless of input
    safe_input = sys.argv[2]
    safe_result = safe_process(safe_input)
    os.system(safe_result)


if __name__ == "__main__":
    main()
