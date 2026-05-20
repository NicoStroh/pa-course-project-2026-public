# Toy Command Runner

This tiny library is a student-facing teaching target. It offers a toy backup
command and contains exactly one intentional vulnerability.

The vulnerable function is `toybackup.runner.run_backup_job`. It builds a shell
command from a user-controlled job name and executes it with `os.system`.
