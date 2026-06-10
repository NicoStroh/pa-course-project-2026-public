import sqlite3

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