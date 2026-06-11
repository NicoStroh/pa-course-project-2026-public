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

Missing / still needed:

- detect more source forms beyond `sys.argv[...]` and `argparse.parse_args()`
- support import alias resolution and cross-file function call resolution in a real target context
- add sanitization/taint-removal detection so safe paths are not reported as vulnerable
- improve analyzer support for control flow, branches, loops, and nested scopes
- add method/attribute-level taint tracking for class-based targets
- implement exploit generation and write executable PoC scripts under `/out/exploits/`

- add unit/regression tests for analyzer behavior and expected findings
- validate against public target packages and shared toy validators
- refactor
- ensure Docker entrypoint supports `analyze /targets /out [single_target_folder]` exactly as required
- integrate target manifest loading and per-target analysis output in final submission flow

Questions:
first 5 missing points: are those necessary for project?
