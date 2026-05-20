# Program Analysis Course Project

## Goal

Build an automated technique that finds vulnerabilities in Python packages and
produces proof-of-concept exploits for them. Your approach may combine static
analysis, dynamic analysis, fuzzing, symbolic techniques, LLM assistance, or
other program-analysis methods.

You will receive public benchmark targets for development. During grading, the
same submission interface will be used against held-out targets.

## Vulnerability Scope

The benchmark focuses on taint-style Python vulnerabilities, including:

- command injection
- code injection
- SQL injection
- path traversal
- unsafe deserialization

## Submission Overview

Submit your augmented copy of the student package. The grader builds a Docker
image from your `student/Dockerfile`. The image must provide this command:

```sh
analyze /targets /out single_target_folder
```

The last argument is optional. If provided, the command should analyze only the specified target in the folder (e.g., `toy_command_runner`).
If not provided, it should analyze all targets under `/targets`.
The grader may call the command multiple times with different target arguments.
The command must analyze all the targets or the specified target and write:

- `/out/report.json`
- executable PoC scripts under `/out/exploits/` for the vulnerabilities you
  claim to exploit

See `SUBMISSION.md` for the exact contract.

For setup instructions, Docker usage, and the shortest path to running the toy
example, see `GETTING_STARTED.md`.

## LLM Use

If your analyzer uses an LLM, call it through `analyzer.llm.query_llm`. The
starter package includes this API and a default implementation backed by OpenAI
`gpt-5-nano`.

During grading, the same API is pointed at the course proxy. The proxy allows
only OpenAI `gpt-5-nano`, enforces a budget, and records full prompt and
response transcripts.

See `LLM_POLICY.md` for details.

## Budget

The grader enforces a budget on LLM usage and analysis time.  
When running your analyzer, we enforce a budget of `$0.01` per hidden vulnerability.
The time limit is 5 minutes per target.  
Make sure to stay within these limits and write the report output eagerly to avoid timeouts.

## Scoring

The score is split evenly:

- 50% vulnerability identification: sink location and vulnerability type.
- 50% exploitation: executable PoC scripts that demonstrate the bug.

The grader may award partial credit for close locations or correct vulnerability
families without working PoCs. A finding
without a valid exploit can still earn identification credit, but it cannot
earn the exploitation portion of the score.

## Public And Hidden Targets

Public targets are provided for development and self-testing. Hidden targets
are used only during grading. Your approach should generalize beyond the public
cases.  
Each target can contain multiple vulnerabilities.
Each of the teaching scaffold examples contains only one vulnerability.
The real benchmark targets contain in total 5 vulnerabilities, while the hidden targets may contain any number of vulnerabilities.

The current public bundle contains:

- teaching scaffolds for the listed vulnerability kinds:
  `toy-command-runner`, `toy-rule-engine`, `toy-tiny-sql-app`,
  `toy-note-server`, and `toy-pickle-profile-loader`
- four real benchmark-style packages: `markdown2`, `backup.py`, `fossier`, `TGConvertor`

The scaffold targets exist to exercise the tooling and starter analyzer. The
real benchmark targets are the ones that should matter for solving practice.

Refer to `shared/toy_ground_truth` for ground truth vulnerability information including the used exploit validation scripts (validators) for each of the teaching scaffold targets.

## Starter Example

The starter analyzer in `student/analyzer` is a deliberately naive AST-based
analyzer for the teaching target `toy-command-runner`.

It uses Python's built-in `ast` module to find one hard-coded pattern:

1. a variable assigned from an f-string
2. that variable passed to `os.system(...)`

It then writes a schema-valid `report.json` and creates an executable PoC
exploit. After building the Docker image with `make -C student build`, run it
from the extracted student bundle root with:

```sh
make -C student run-target TARGET=toy_command_runner
```

This example is only a starting point. It is intentionally brittle and is not
expected to work on the hidden benchmark.
