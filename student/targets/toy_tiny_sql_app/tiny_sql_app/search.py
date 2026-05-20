from __future__ import annotations

import sqlite3


CUSTOMERS = [
    ("alice", "alice@example.test", "public"),
    ("bob", "bob@example.test", "public"),
    ("admin", "admin@example.test", "private"),
]


def open_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("create table customers (name text, email text, tier text)")
    connection.executemany("insert into customers values (?, ?, ?)", CUSTOMERS)
    return connection


def search_customers(term: str) -> list[tuple[str, str]]:
    connection = open_database()
    query = (
        "select name, email from customers "
        f"where tier = 'public' and name like '%{term}%'"
    )
    return list(connection.execute(query))
