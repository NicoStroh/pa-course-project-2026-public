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
9. implement exploit generation and write executable PoC scripts under `/out/exploits/`
10. ensure Docker entrypoint supports `analyze /targets /out [single_target_folder]` exactly as required
11. integrate target manifest loading and per-target analysis output in final submission flow

Questions:
