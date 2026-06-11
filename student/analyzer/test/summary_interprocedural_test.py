import os
import sys


def source() -> str:
    return sys.argv[1]


def identity(value: str) -> str:
    return value


def build_command() -> str:
    user = source()
    return identity(user)


def main() -> None:
    command = build_command()
    os.system(command)


main()
