1. Build AST
2. Identify Sources (sys.argv)
3. Perform Taint Propagation
4. Identify Dangerous Sinks
   command injection: `os.system`, `subprocess.run(cmd, shell=True)`, `subprocess.Popen`, `os.popen`
   code injection: `eval`, `exec`
   unsafe deserialization: `pickle.load`, `pickle.loads`
   SQL injection: `execute`, `executescript`
   path traversal: `open`, `os.open`, `pathlib.Path.open`, `pathlib.Path.read_text`
5. function call tainted propagation
6. cfg
7. toy examples testen
8. add exploit patterns to sanitizers.py
9. real word examples testen

10. implement exploit generation and write executable PoC scripts under `/out/exploits/`
11. submission ready

Questions:

- how should exploits look for: if tainted_variable == "taint": path = "../" path.open()
