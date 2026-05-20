# Tiny SQL App

This tiny package searches a pretend customer database. It contains exactly one
intentional `sql_injection` vulnerability.

The vulnerable function is `tiny_sql_app.search.search_customers`. It builds a
SQL query with string interpolation and executes it against sqlite.
