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

6. toy examples testen
7. refactor
8. prof mail schreiben
9. sanitizer approach /OR/ cfg - does source reach sink with exploit in variable

Missing / still needed:

- implement exploit generation and write executable PoC scripts under `/out/exploits/`
- ensure Docker entrypoint supports `analyze /targets /out [single_target_folder]` exactly as required
- integrate target manifest loading and per-target analysis output in final submission flow

Questions:
