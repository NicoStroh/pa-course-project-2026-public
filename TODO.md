1. Build AST
2. Identify Sources (sys.argv)
3. Perform Taint Propagation
4. Identify Dangerous Sinks
   command injection: `os.system`, `subprocess.run(cmd, shell=True)`, `subprocess.Popen`, `os.popen`
   code injection: `eval`, `exec`
   unsafe deserialization: `pickle.load`, `pickle.loads`
   SQL injection: `execute`, `executescript`
   path traversal: `open`, `os.open`, `pathlib.Path.open`, `pathlib.Path.read_text`

////// Diese Woche

5. function call tainted propagation
6. ?Source-to-Sink Analysis?

- toys testen
  //////

7. Refactoring
8. Generate Security Report

Questions:

- identify which sources? (argparse.parse, etc.)
- alias (bsp. from pathlib import Path as P) auch erkennen?
- wie in source to sink analyser erkennen, dass schwachstellen abgefangen werden (if path.contains(../) path.remove(../) -> nicht mehr tainted)
