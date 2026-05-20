# Submission

The project submission must contain two files:
1) *Implementation*: An augmented copy of this student package as tar archive (including `student`, `shared`, and `out`). The grader builds your Docker image from `student/Dockerfile` and then runs the image. The resulting image must expose an executable command named `analyze`.
2) *Report*: A PDF file that motivates, explains, and illustrates your design choices and implementation. This report must be at most four pages.

## Content of the Implementation Archive

The grader runs:

```sh
analyze /targets /out
```

or:

```sh
analyze /targets /out single_target_folder
```

Before you submit, rebuild your image after your latest changes:

```sh
make -C student build
```

Run the analyzer on all provided public targets with:

```sh
make -C student run-all
```

Both `run-target` and `run-all` execute inside the Docker container and mount
the public targets read-only.

Do not include any private information, such as API keys, in your submission.

## Third-Party Dependencies

List Python package dependencies in `student/requirements.txt`. The starter
Dockerfile installs that file during `make -C student build`:

```dockerfile
COPY requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt
```

Pin dependencies tightly enough that the grader can rebuild your image later.
For example, prefer `package==1.2.3` or a narrow compatible range over an
unbounded dependency.

If you need system packages, add the corresponding `apt-get` commands to
`student/Dockerfile`. Keep them noninteractive and clean the package index in
the same layer. For example:

```dockerfile
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
```

Your analyzer must not need internet access at runtime, except for the provided LLM API. 
Any third-party code or model files needed to run on hidden targets must be installed or copied into
the image during the Docker build.

## Inputs

- `/targets`: read-only directory containing target packages and a
  `manifest.json` file.
- `/out`: writable output directory created by the grader.

## Required Output

Your analyzer must write:

```text
/out/report.json
```

The report must match `shared/schemas/report.schema.json`.

## Exploits

If you claim that a finding is exploitable, include a PoC script under:

```text
/out/exploits/
```

Each exploit referenced from `report.json` must:

- exist under `/out/exploits/`
- be executable
- run without interactive input
- use environment variables supplied by the validator or grader:
  `TARGET_ROOT` points to a writable copy of the target, and marker-style
  exploits should create `EXPLOIT_MARKER`
- avoid destructive payloads

Findings without exploits are allowed, but they can only earn the
vulnerability-identification part of the score.

## Exit Codes

- Exit code `0`: analysis completed and `report.json` was written.
- Non-zero exit code: infrastructure failure. The grader may assign zero for
  missing or invalid outputs.

Finding no vulnerabilities is valid only if a schema-valid empty report is
written.

## Shape of Vulnerability Detection Reports

Each finding includes:

- target id
- vulnerability type
- file path
- line number or function name (of the exploitable sink)
- description (a concise explanation of the security-relevant behavior, such as "user input is passed to `os.system` without sanitization")
- exploit script path, if you claim exploitation credit for that finding

## Grading

The project grade is computed as follows:
 - 25%: Progress meetings and final presentation
   - Can you present and explain your work?
   - Also see MILESTONES.md for details on what is expected in each meeting.
 - 50%: Implementation and results
   - Does the analyzer find vulnerabilities and generate successful exploits?
 - 25%: Report
   - Does the report clearly motivate, describe, and illustrate the design and implementation of the analyzer?
