# Getting Started

Use the Makefile from the extracted student bundle root. The analyzer always
runs inside the Docker container.

## 1. Build the Docker image

```sh
make -C student build
```

## 2. Run one target

Run the starter analyzer on a specific public target directory:

```sh
make -C student run-target TARGET=toy_command_runner
```

`TARGET` is the directory name under `student/targets`, such as
`toy_command_runner`, `toy_rule_engine`, `toy_tiny_sql_app`, `toy_note_server`,
`toy_pickle_profile_loader`, `markdown2`, `backup.py`, `fossier`, or `TGConvertor`.

The output is written to `out/` next to `student/` and `shared/` by default. To
choose another output directory:

```sh
make -C student run-target TARGET=toy_command_runner OUT=/tmp/my-analyzer-out
```

## 3. Run all public targets

```sh
make -C student run-all
```

This mounts the full public target bundle read-only at `/targets` in the
container and writes analyzer output to the mounted `/out` directory.

## 4. Validate an exploit

After `make -C student run-all` writes a report and exploits to `out/`, run one
exploit in a container that mirrors the grader:

```sh
make -C student validate-exploit \
  TARGET=toy_command_runner \
  EXPLOIT=exploits/toy-command-runner-command-injection.py \
  VALIDATOR=../shared/toy_ground_truth/validators/public/toy-command-runner-command-injection-001.py
```

The validator receives a writable target copy at `TARGET_ROOT`, the submitted
exploit path at `EXPLOIT_PATH`, and a marker path at `EXPLOIT_MARKER` when the
vulnerability is marker-based. The original public targets remain read-only.

## 5. Next edits

The starter analyzer is the simple AST-based implementation in
`student/analyzer`. It finds one hard-coded command-injection pattern in the toy
target and is meant as a small starting point for your own analyzer.
