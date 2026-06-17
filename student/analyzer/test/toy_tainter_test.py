import sys
import argparse

def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    job_name = args[0] if args else "daily"
    # Job_name is tainted

    parser = argparse.ArgumentParser(description="Read a note by name.")
    parser.add_argument("name", nargs="?", default="welcome.txt")
    args = parser.parse_args()
    # args and args.name are tainted

    eval(job_name)
    eval(args)
    eval(args.name)