# Pickle Profile Loader

This tiny package imports base64-encoded profile snapshots. It contains exactly
one intentional `unsafe_deserialization` vulnerability.

The vulnerable function is `profile_loader.loader.load_profile`. It decodes
user-controlled bytes and passes them directly to `pickle.loads`.
