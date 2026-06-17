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

1. import alias testen
2. toy examples testen
3. refactor
4. prof mail schreiben
5. sanitizer approach /OR/ cfg - does source reach sink with exploit in variable

Missing / still needed:

- validate against public target packages and shared toy validators
- support import alias resolution and cross-file function call resolution in a real target context
- add sanitization/taint-removal detection so safe paths are not reported as vulnerable

- implement exploit generation and write executable PoC scripts under `/out/exploits/`
- ensure Docker entrypoint supports `analyze /targets /out [single_target_folder]` exactly as required
- integrate target manifest loading and per-target analysis output in final submission flow

Questions: