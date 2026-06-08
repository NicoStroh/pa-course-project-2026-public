1. Parse Python Source
2. Build AST
3. Identify Sources (sys.argv) -> Question: is this the only relevant source to check?
4. Perform Taint Propagation

5. Identify Dangerous Sinks
6. Source-to-Sink Analysis
7. Classify Vulnerability Type
8. Generate Security Report