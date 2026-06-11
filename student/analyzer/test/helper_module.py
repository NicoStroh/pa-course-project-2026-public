# helper_module.py
def process_input(user_input: str) -> str:
    """Processes user input and returns a string."""
    return f"processed_{user_input}"


def safe_process(data: str) -> str:
    """Always returns a safe string, independent of input."""
    return "safe_output"
