AttoSSH demo file root.

This is the storage tree the SSH server exposes to
authenticated users via SFTP and the toy shell. The
layout mirrors AttoFTP's:

    pub/         publicly readable; bob and alice can
                 both list and download.
    users/<u>/   each user's own home directory; alice
                 lands in /users/alice on login, and bob
                 in /users/bob. Both users can read, write,
                 and modify files in their own home.

The "shared password" demo user has read-only access to
the entire tree.

Try uploading a small file via the SFTP tab in the
demo's web UI, then watch it appear in the file
browser.
