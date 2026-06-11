import sqlite3
import sys

user = sys.argv[1]

connection = sqlite3.connect(":memory:")

connection.execute(
    "create table customers (name text)"
)

connection.executemany(
    "insert into customers values (?)",
    [("Alice",), ("Bob",)]
)

script = """
DROP TABLE customers;
"""

connection.executescript(script)

connection.execute(
    f"...{user}..."
)
connection.execute(
    f"...{sys.argv[2]}..."
)