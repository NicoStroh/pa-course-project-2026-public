# Milestones And Mentor Meetings

As part of tracking project progress, each student is assigned a mentor who is
the first point of contact for all project-related questions.

Each student must hold three 1:1 progress meetings with their mentor. These
meetings are associated with the three milestones described below.

The schedule below lists the recommended weeks for each milestone and the
suggested progress to discuss during the meeting. The schedule is not mandatory:
these meetings are meant for feedback and progress tracking, not as tests.
However, following the suggested pacing is strongly recommended for receiving
timely feedback and preparing for the final presentation.

## Milestone Overview

| Milestone | Recommended Week | Focus | Targets |
| --- | --- | --- | --- |
| 1 | June 1-5 | Command injection and code injection | Toy Command Runner, Toy Rule Engine |
| 2 | June 15-19 | SQL injection, path traversal, and unsafe deserialization | Toy Tiny SQL App, Toy Note Server, Toy Pickle Profile Loader |
| 3 | June 29 - July 3 | Generalization beyond toy targets | markdown2 or other non-toy examples |

## Milestone 1

**Recommended week:** June 1st-5th

**Vulnerabilities to solve:**

- Command injection
- Code injection

**Targets to cover:**

- Toy Command Runner
- Toy Rule Engine

By this milestone, the analyzer should detect the vulnerable location, and generate and run a working exploit for each of the targets above

## Milestone 2

**Recommended week:** June 15th-19th

**Vulnerabilities to solve:**

- SQL injection
- Path traversal
- Unsafe deserialization

**Targets to cover:**

- Toy Tiny SQL App
- Toy Note Server
- Toy Pickle Profile Loader

By this milestone, the analyzer should detect the vulnerable location, and generate and run working exploits for each of the targets above

## Milestone 3

**Recommended week:** June 29th - July 3rd

**Main task:** Generalize the analyzer to non-toy examples.

Suggested focus:

- extend the analyzer so it is no longer specialized only to the first examples
- demonstrate progress on more complex targets such as `markdown2`

## Meeting Expectations

During each meeting, the discussion points are expected to include:

- what currently works in the analyzer
- which targets and vulnerability classes have been covered
- what remains incomplete or unreliable
- blockers, questions, or design decisions where feedback would help
