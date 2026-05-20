# Note Server

This tiny package reads named notes from a pretend application data directory.
It contains exactly one intentional `path_traversal` vulnerability.

The vulnerable function is `note_server.files.read_note`. It joins a
user-controlled note name to the notes directory without checking that the
resolved path stays inside that directory.
