1. Parse Python Source
2. Build AST
3. Identify Sources (sys.argv)
4. Perform Taint Propagation
5. Identify Dangerous Sinks
   command injection: `os.system`, `subprocess.run(cmd, shell=True)`, `subprocess.Popen`, `os.popen`
   code injection: `eval`, `exec`
   unsafe deserialization: `pickle.load`, `pickle.loads`
   SQL injection: `execute`, `executescript`
   path traversal: `open`, `os.open`, `pathlib.Path.open`, `pathlib.Path.read_text`

6. function call tainted propagation
7. Source-to-Sink Analysis
8. Generate Security Report

Questions:

- alias (bsp. from pathlib import Path as P) auch erkennen?
- wie in source to sink analyser erkennen, dass schwachstellen abgefangen werden (if path.contains(../) path.remove(../) -> nicht mehr tainted)
