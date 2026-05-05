# Alice's notes

This file is in alice's home folder. Bob cannot see it
through SFTP unless his login_folder is changed to
something that includes /users/alice as an ancestor.

The toy shell uses the same storage layer SFTP does, so
"cat ~/notes.md" (well, "cat notes.md" -- there's no
tilde expansion in this shell) gives the same file.
