<?php
/**
 * seekquarry\atto\MailSite -- a single-file SMTP and IMAP mail server
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 *
 * LICENSE:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license http://www.gnu.org/licenses/ GPL-3.0-or-later
 * @link http://www.seekquarry.com/
 * @copyright 2017-2026
 * @filesource
 */
namespace seekquarry\atto;

/**
 * Abstract base for password / identity backends used by MailSite.
 *
 * A concrete Authenticator answers two questions: "does this user
 * exist?" and "is this candidate password valid for this user?".
 * The default verifyPassword path uses password_verify against a
 * hash returned by getPasswordHash, which keeps subclasses small:
 * a flat-file or DB-backed Authenticator only needs to implement
 * userExists and getPasswordHash. A subclass can override
 * verifyPassword directly when the backend cannot expose hashes
 * (e.g. when delegating to PAM, LDAP bind, or an external HTTP
 * auth endpoint that only returns yes/no).
 *
 * Implementations should treat usernames case-insensitively for
 * lookup but preserve the case the user typed when echoing it
 * back (this matches what most mail clients expect).
 */
abstract class Authenticator
{
    /**
     * Returns whether a user account exists in this backend. Used
     * by the SMTP path to decide whether RCPT TO addresses for
     * local domains are deliverable, independent of authentication
     * (an unauthenticated remote can deliver TO a local user but
     * cannot deliver FROM one).
     *
     * @param string $username the local part of an email address
     *      or the bare username supplied at AUTH/LOGIN time
     * @return bool true if the user is known to this backend
     */
    abstract public function userExists($username);
    /**
     * Returns the password hash stored for this user, in the form
     * accepted by PHP's password_verify. The default
     * verifyPassword implementation uses this. Subclasses that
     * cannot expose a hash should override verifyPassword instead
     * and may make this throw or return false.
     *
     * @param string $username the username to look up
     * @return string|false the hash, or false if user not found
     */
    abstract public function getPasswordHash($username);
    /**
     * Default password check: load the stored hash and use
     * password_verify, which is constant-time and handles the
     * stored algorithm/cost parameters embedded in the hash. A
     * non-existent user gets the same kind of negative answer as
     * a wrong password without leaking the difference through
     * timing, by running password_verify against a fixed dummy
     * hash so the work factor is paid either way.
     *
     * @param string $username
     * @param string $password the candidate plaintext password
     * @return bool true on success
     */
    public function verifyPassword($username, $password)
    {
        $hash = $this->getPasswordHash($username);
        if ($hash === false || $hash === null || $hash === "") {
            /*
                Burn a password_verify call against a known-good
                dummy hash so a missing user takes about the same
                wall-clock time as a wrong password. The exact
                hash value here is irrelevant; what matters is
                that it is a real bcrypt hash so the cost factor
                is paid.
             */
            password_verify($password,
                '$2y$10$abcdefghijklmnopqrstuv1234567890ABCDEFGHIJKLMNOPQ.');
            return false;
        }
        return password_verify($password, $hash);
    }
}
/**
 * Authenticator backed by a flat file in "user:bcrypt-hash" form,
 * one record per line. The format is identical to Apache htpasswd
 * with the bcrypt option, so the same htpasswd -B tool can be
 * used to create or update accounts. Comments (lines beginning
 * with #) and blank lines are ignored.
 *
 * The file is loaded lazily on first access and cached for the
 * lifetime of the process; long-running mail servers should call
 * reload() after editing the file out-of-band, or register a
 * SIGHUP handler that calls reload(). For small deployments (a
 * handful of users on a personal server) the default lazy-load
 * behavior is enough.
 */
class FileAuthenticator extends Authenticator
{
    protected $path;
    protected $users;
    /**
     * @param string $path path to the password file
     */
    public function __construct($path)
    {
        $this->path = $path;
        $this->users = null;
    }
    /**
     * Forces a re-read of the password file on next lookup.
     * Useful after editing accounts with htpasswd while the
     * server is running.
     */
    public function reload()
    {
        $this->users = null;
    }
    /**
     * @inheritdoc
     */
    public function userExists($username)
    {
        $this->load();
        return isset($this->users[strtolower($username)]);
    }
    /**
     * @inheritdoc
     */
    public function getPasswordHash($username)
    {
        $this->load();
        $key = strtolower($username);
        return isset($this->users[$key]) ? $this->users[$key] :
            false;
    }
    /**
     * Reads the password file into the in-memory map keyed by
     * lowercased username. Silently skips malformed lines and
     * comments rather than aborting; a typo in one record should
     * not lock everyone out.
     */
    protected function load()
    {
        if ($this->users !== null) {
            return;
        }
        $this->users = [];
        if (!is_file($this->path) || !is_readable($this->path)) {
            return;
        }
        $lines = file($this->path,
            FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === "" || $line[0] === '#') {
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon === false) {
                continue;
            }
            $user = trim(substr($line, 0, $colon));
            $hash = trim(substr($line, $colon + 1));
            if ($user === "" || $hash === "") {
                continue;
            }
            $this->users[strtolower($user)] = $hash;
        }
    }
}
/**
 * Authenticator that accepts every username with a single
 * shared password. Designed for anonymous-mailbox demos
 * where the address itself is the only identity (e.g. a
 * disposable inbox service): any HTTP visitor can adopt
 * any local-part on a hosted domain, the webmail UI then
 * uses IMAP loopback with the shared password to read that
 * mailbox. Do NOT use this in any deployment where mail
 * confidentiality matters; the design is "the address is
 * the credential" and anyone who guesses or learns the
 * address can read its mail.
 */
class AnonAuthenticator extends Authenticator
{
    /**
     * @var string the shared password every account uses.
     */
    protected $shared_password;
    /**
     * @param string $shared_password password accepted for
     *      every username
     */
    public function __construct($shared_password)
    {
        $this->shared_password = (string) $shared_password;
    }
    /**
     * @inheritdoc
     */
    public function userExists($username)
    {
        return is_string($username) && $username !== "";
    }
    /**
     * @inheritdoc
     */
    public function getPasswordHash($username)
    {
        /*
            Returning a single static hash means verifyPassword
            (inherited) calls password_verify with that hash
            against whatever the client sent; the bcrypt
            comparison is constant-time and the shared
            password is the only thing that succeeds.
         */
        if (!$this->userExists($username)) {
            return false;
        }
        if ($this->cached_hash === null) {
            $this->cached_hash = password_hash(
                $this->shared_password, PASSWORD_BCRYPT);
        }
        return $this->cached_hash;
    }
    /**
     * @var string|null bcrypt hash of $shared_password,
     * computed on first use and reused thereafter.
     */
    protected $cached_hash = null;
}
/**
 * Abstract storage backend for mail folders and messages.
 *
 * The interface is shaped around what IMAP4rev1 needs but is
 * directly callable from any context (a web frontend, a CLI
 * tool, a cron job that imports mbox), not just from inside the
 * IMAP command parser. UIDs are per-user and monotonic across
 * the whole account: a message keeps its UID when moved between
 * folders, which is what IMAP UIDPLUS clients assume.
 *
 * Folder names use "/" as the hierarchy delimiter. The reserved
 * folder INBOX always exists for every user and cannot be
 * deleted or renamed.
 *
 * Flags are the seven RFC 3501 system flags (\Seen, \Answered,
 * \Flagged, \Deleted, \Draft, plus the session-only \Recent) and
 * arbitrary user-defined keywords. Storage should accept any
 * string flag and round-trip it; clients filter for what they
 * understand.
 *
 * Methods are synchronous and may do disk or network I/O. They
 * are not safe to call from inside the event loop's hot path
 * unless the backend is in-memory; concrete file/DB backends
 * assume the IMAP/SMTP command parser is the only caller and
 * accepts the latency.
 */
abstract class MailStorage
{
    /**
     * Provision storage for a user, creating the user's INBOX
     * and any per-user metadata. Idempotent: calling on an
     * existing user is a no-op and returns true.
     *
     * @param string $user the username (no @domain)
     * @return bool true on success
     */
    abstract public function ensureUser($user);
    /**
     * Returns the list of folder names for this user, including
     * INBOX. Names are returned with their full hierarchy path
     * (e.g. "Archive/2026").
     *
     * @param string $user
     * @return array list of folder name strings
     */
    abstract public function listFolders($user);
    /**
     * Creates a new folder. Idempotent: creating an existing
     * folder returns true without error.
     *
     * @param string $user
     * @param string $folder e.g. "Archive/2026/Q1"
     * @return bool true on success
     */
    abstract public function createFolder($user, $folder);
    /**
     * Deletes a folder and all messages in it. Refuses to
     * delete INBOX and refuses to delete a folder that has
     * subfolders (the IMAP convention; clients delete subtrees
     * recursively).
     *
     * @param string $user
     * @param string $folder
     * @return bool true on success
     */
    abstract public function deleteFolder($user, $folder);
    /**
     * Renames a folder. Refuses to rename INBOX (per RFC 3501
     * the rename of INBOX has special semantics; we choose the
     * simpler "no" answer instead).
     *
     * @param string $user
     * @param string $old
     * @param string $new
     * @return bool true on success
     */
    abstract public function renameFolder($user, $old, $new);
    /**
     * Returns whether the named folder exists for this user.
     *
     * @param string $user
     * @param string $folder
     * @return bool
     */
    abstract public function folderExists($user, $folder);
    /**
     * Stores a new message and returns its assigned UID.
     *
     * @param string $user
     * @param string $folder destination folder; will be auto-
     *      created if missing
     * @param string $bytes the full RFC 5322 message including
     *      headers and body, with CRLF line endings
     * @param array $flags initial flag set (e.g. ['\Recent'])
     * @param int $internal_date Unix timestamp; 0 for "now"
     * @return int|false the new UID, or false on failure
     */
    abstract public function appendMessage($user, $folder, $bytes,
        $flags = [], $internal_date = 0);
    /**
     * Returns the raw RFC 5322 bytes of a message, or false if
     * not found.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @return string|false
     */
    abstract public function fetchMessage($user, $folder, $uid);
    /**
     * Returns metadata for every message in a folder, sorted
     * ascending by UID. Each entry is an associative array with
     * keys: uid (int), size (int), flags (array of strings),
     * internal_date (int unix ts).
     *
     * @param string $user
     * @param string $folder
     * @return array list of message metadata records
     */
    abstract public function listMessages($user, $folder);
    /**
     * Returns metadata for one message: same shape as one entry
     * of listMessages, or false if not found.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @return array|false
     */
    abstract public function messageMeta($user, $folder, $uid);
    /**
     * Replaces the flag set for a message. Pass an empty array
     * to clear all flags.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @param array $flags
     * @return bool
     */
    abstract public function setFlags($user, $folder, $uid, $flags);
    /**
     * Permanently removes every message in $folder that has the
     * \Deleted flag set. Returns the UIDs that were removed.
     *
     * @param string $user
     * @param string $folder
     * @return array list of expunged UIDs
     */
    abstract public function expunge($user, $folder);
    /**
     * Moves a message from one folder to another. The UID is
     * preserved (UIDs are per-user, not per-folder).
     *
     * @param string $user
     * @param string $from
     * @param string $to
     * @param int $uid
     * @return bool
     */
    abstract public function moveMessage($user, $from, $to, $uid);
    /**
     * Returns the message count for the named folder.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    abstract public function messageCount($user, $folder);
    /**
     * Returns the UIDVALIDITY value for a folder. IMAP clients
     * cache this and discard their local cache when it changes;
     * we issue one stable value per user account over its
     * lifetime.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    abstract public function uidValidity($user, $folder);
    /**
     * Returns the UID that will be assigned to the next message
     * appended (predicted, may not match reality under concurrent
     * appends).
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    abstract public function uidNext($user, $folder);
    /**
     * Returns true if the user has explicitly subscribed to a
     * folder. INBOX is treated as subscribed by convention even
     * if no SUBSCRIBE command has been issued, since RFC 3501
     * sec 6.3.6 says it is not an error to subscribe an already
     * subscribed mailbox and clients expect INBOX to be listed
     * by LSUB at connect time. Other folders are subscribed
     * only after an explicit SUBSCRIBE.
     *
     * @param string $user
     * @param string $folder
     * @return bool
     */
    abstract public function isSubscribed($user, $folder);
    /**
     * Marks a folder as subscribed for a user. The folder need
     * not exist; RFC 3501 sec 6.3.6 explicitly allows
     * subscribing to non-existent mailboxes (a remote-shared
     * folder might be unmounted at the moment). Idempotent.
     *
     * @param string $user
     * @param string $folder
     * @return bool true on success
     */
    abstract public function subscribe($user, $folder);
    /**
     * Removes a subscription. Idempotent: unsubscribing a
     * folder that is not subscribed succeeds silently.
     *
     * @param string $user
     * @param string $folder
     * @return bool true on success
     */
    abstract public function unsubscribe($user, $folder);
    /**
     * Returns the list of folders this user has subscribed to,
     * sorted ascending. INBOX is always present in the result
     * even if the per-user state file does not list it.
     *
     * @param string $user
     * @return string[]
     */
    abstract public function listSubscribed($user);
    /**
     * High-water mark of the last UIDVALIDITY this storage
     * instance has handed out. Subclasses use this to ensure
     * a strictly monotonic sequence even when two folders are
     * created in the same wall-clock second (RFC 3501 sec
     * 2.3.1.1 monotonic requirement).
     */
    protected $last_uidvalidity = 0;
    /**
     * Returns a fresh UIDVALIDITY value that is strictly
     * greater than any value previously returned by this
     * storage instance. Implementations should call this when
     * a folder is created or recreated.
     */
    protected function nextUidValidity()
    {
        $now = time();
        if ($now <= $this->last_uidvalidity) {
            $now = $this->last_uidvalidity + 1;
        }
        $this->last_uidvalidity = $now;
        return $now;
    }
    /**
     * Canonicalizes a folder path: collapses repeated slashes,
     * strips leading/trailing slashes, and rejects components
     * that could escape the folder root or clobber metadata
     * files. INBOX is normalized to all-uppercase per RFC
     * 3501. Throws InvalidArgumentException on:
     *      empty / "." / ".."  components (path traversal)
     *      NUL byte             (older C-level path injection)
     *      control character    (corrupts line-oriented
     *                            metadata files)
     *      dot-prefixed         (clobbers .uidvalidity, .uidnext,
     *                            .subscribed metadata files)
     */
    protected function normalizeFolder($folder)
    {
        $folder = (string) $folder;
        if (strpos($folder, "\0") !== false) {
            throw new \InvalidArgumentException(
                "folder name contains NUL byte");
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $folder)) {
            throw new \InvalidArgumentException(
                "folder name contains control character");
        }
        $folder = trim($folder, "/");
        if ($folder === "") {
            return "INBOX";
        }
        if (strcasecmp($folder, "INBOX") === 0) {
            return "INBOX";
        }
        $parts = preg_split('#/+#', $folder);
        $clean = [];
        foreach ($parts as $part) {
            if ($part === "" || $part === "." ||
                $part === "..") {
                throw new \InvalidArgumentException(
                    "invalid folder component: '$part'");
            }
            if ($part[0] === '.') {
                throw new \InvalidArgumentException(
                    "folder name may not start with '.'");
            }
            $clean[] = $part;
        }
        return implode("/", $clean);
    }
}
/**
 * Filesystem-backed MailStorage. Directory layout under the
 * configured base path:
 *
 *      $base/
 *          users/
 *              <username>/
 *                  .uidvalidity   (single integer, fixed at create)
 *                  .uidnext       (single integer, monotonic)
 *                  INBOX/
 *                      <uid>.eml
 *                      <uid>.flags    (one flag per line)
 *                      <uid>.date     (single integer unix ts)
 *                  <folder1>/
 *                  <folder2>/...
 *
 * Folder hierarchy is encoded by replacing "/" in folder names
 * with "%2F" at the directory-name level, so "Archive/2026" maps
 * to a single directory "Archive%2F2026" rather than nested
 * ones. This avoids a class of edge cases where a parent folder
 * both holds messages and contains subfolders.
 *
 * Concurrent writes are handled by allocating UIDs through a
 * file-locked counter file; concurrent reads of message bodies
 * are safe because filenames are immutable once written. The
 * append path writes via a temp-then-rename so a partial write
 * does not produce a half-message visible to readers.
 */
class FileMailStorage extends MailStorage
{
    protected $base;
    /**
     * @param string $base directory under which the "users/"
     *      subtree is created
     */
    public function __construct($base)
    {
        $this->base = rtrim($base, "/\\");
    }
    /**
     * Returns the absolute directory path for a user's account.
     * Does not check existence.
     */
    protected function userDir($user)
    {
        return $this->base . DIRECTORY_SEPARATOR . "users" .
            DIRECTORY_SEPARATOR . $this->safeName($user);
    }
    /**
     * Returns the absolute directory path for a folder. Folder
     * names are encoded so "/" in a folder name becomes "%2F" in
     * the directory name.
     */
    protected function folderDir($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        $encoded = rawurlencode($folder);
        return $this->userDir($user) . DIRECTORY_SEPARATOR .
            $encoded;
    }
    /**
     * Strips path separators, dot-prefixed components, and
     * other shell-meta characters from a username so it can be
     * used as a directory name without letting a crafted
     * username escape the user-tree base. Mail usernames in
     * the wild use [A-Za-z0-9._-]; we accept that set and
     * fold every other byte to underscore. Backslashes are
     * folded too because Windows treats them as path
     * separators. After folding, leading dots are stripped to
     * prevent ".." or ".something" inputs from producing a
     * dot-prefixed directory name.
     */
    protected function safeName($user)
    {
        $user = (string) $user;
        $user = preg_replace('/[^A-Za-z0-9._-]/', '_', $user);
        $user = ltrim($user, '._');
        if ($user === "" ||
            preg_match('/^[._]+$/', $user) ||
            strpos($user, '..') !== false) {
            $user = "_invalid_";
        }
        return $user;
    }
    /**
     * @inheritdoc
     */
    public function ensureUser($user)
    {
        $dir = $this->userDir($user);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return false;
        }
        $uidvalidity_file = $dir . DIRECTORY_SEPARATOR .
            ".uidvalidity";
        if (!is_file($uidvalidity_file)) {
            /*
                Per-user UIDVALIDITY is a fallback for folders
                that pre-date the per-folder scheme. The
                monotonic allocator keeps it strictly larger
                than every prior handout in this process and
                still fits in 32-bit unsigned-int range.
             */
            file_put_contents($uidvalidity_file,
                (string) $this->nextUidValidity());
        }
        $uidnext_file = $dir . DIRECTORY_SEPARATOR . ".uidnext";
        if (!is_file($uidnext_file)) {
            file_put_contents($uidnext_file, "1");
        }
        $this->createFolder($user, "INBOX");
        return true;
    }
    /**
     * @inheritdoc
     */
    public function listFolders($user)
    {
        $dir = $this->userDir($user);
        if (!is_dir($dir)) {
            return [];
        }
        $folders = [];
        $entries = @scandir($dir);
        if ($entries === false) {
            return [];
        }
        foreach ($entries as $entry) {
            if ($entry === "." || $entry === ".." ||
                $entry[0] === ".") {
                /*
                    Hide dotfiles such as .uidvalidity and
                    .uidnext from the folder listing; they are
                    metadata, not folders.
                 */
                continue;
            }
            $sub = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($sub)) {
                $folders[] = rawurldecode($entry);
            }
        }
        sort($folders);
        return $folders;
    }
    /**
     * @inheritdoc
     */
    public function createFolder($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        $path = $this->folderDir($user, $folder);
        if (is_dir($path)) {
            return true;
        }
        if (!is_dir($this->userDir($user))) {
            $this->ensureUser($user);
            /*
                ensureUser provisions INBOX as a side effect.
                If the caller asked for a folder that
                ensureUser just created, treat the create as
                already done; otherwise we would fall through
                to mkdir, which would fail on the (now
                existing) path and incorrectly return false.
             */
            if (is_dir($path)) {
                return true;
            }
        }
        if (!@mkdir($path, 0700, true)) {
            return false;
        }
        /*
            Stamp a per-folder UIDVALIDITY so a future delete
            + recreate of the same name always produces a
            different value (RFC 3501 sec 2.3.1.1). The
            allocator is monotonic-by-construction across the
            life of the process, so even rapid recreate cycles
            in the same wall-clock second still bump the
            counter. The value stays in 32-bit unsigned-int
            range and reads as a Unix timestamp for any whole
            second; sub-second reuses appear as the timestamp
            plus a small offset.
         */
        @file_put_contents(
            $path . DIRECTORY_SEPARATOR . ".uidvalidity",
            (string) $this->nextUidValidity());
        return true;
    }
    /**
     * @inheritdoc
     */
    public function deleteFolder($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        if ($folder === "INBOX") {
            return false;
        }
        $path = $this->folderDir($user, $folder);
        if (!is_dir($path)) {
            return false;
        }
        $prefix = $folder . "/";
        foreach ($this->listFolders($user) as $other_folder) {
            if (strpos($other_folder, $prefix) === 0) {
                return false;
            }
        }
        $entries = @scandir($path);
        if ($entries !== false) {
            foreach ($entries as $entry) {
                if ($entry === "." || $entry === "..") {
                    continue;
                }
                @unlink($path . DIRECTORY_SEPARATOR . $entry);
            }
        }
        return @rmdir($path);
    }
    /**
     * @inheritdoc
     */
    public function renameFolder($user, $old, $new)
    {
        $old = $this->normalizeFolder($old);
        $new = $this->normalizeFolder($new);
        if ($old === "INBOX" || $new === "INBOX") {
            return false;
        }
        $old_path = $this->folderDir($user, $old);
        $new_path = $this->folderDir($user, $new);
        if (!is_dir($old_path) || is_dir($new_path)) {
            return false;
        }
        return @rename($old_path, $new_path);
    }
    /**
     * @inheritdoc
     */
    public function folderExists($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        return is_dir($this->folderDir($user, $folder));
    }
    /**
     * Atomically allocates and returns the next per-user UID.
     * Uses an exclusive flock on .uidnext so two concurrent
     * appendMessage calls cannot hand out the same number.
     */
    protected function allocUid($user)
    {
        $file = $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".uidnext";
        $file_handle = @fopen($file, "c+");
        if ($file_handle === false) {
            return false;
        }
        if (!flock($file_handle, LOCK_EX)) {
            fclose($file_handle);
            return false;
        }
        rewind($file_handle);
        $contents = stream_get_contents($file_handle);
        $next = (int) trim($contents);
        if ($next < 1) {
            $next = 1;
        }
        $assigned = $next;
        ftruncate($file_handle, 0);
        rewind($file_handle);
        fwrite($file_handle, (string) ($assigned + 1));
        fflush($file_handle);
        flock($file_handle, LOCK_UN);
        fclose($file_handle);
        return $assigned;
    }
    /**
     * @inheritdoc
     */
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $internal_date = 0)
    {
        if (!$this->folderExists($user, $folder)) {
            if (!$this->createFolder($user, $folder)) {
                return false;
            }
        }
        $uid = $this->allocUid($user);
        if ($uid === false) {
            return false;
        }
        if ($internal_date <= 0) {
            $internal_date = time();
        }
        $dir = $this->folderDir($user, $folder);
        $eml = $dir . DIRECTORY_SEPARATOR . "$uid.eml";
        $temp_path = $eml . ".tmp";
        if (file_put_contents($temp_path, $bytes) === false) {
            return false;
        }
        if (!@rename($temp_path, $eml)) {
            @unlink($temp_path);
            return false;
        }
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . "$uid.flags",
            implode("\n", $flags));
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . "$uid.date",
            (string) $internal_date);
        return $uid;
    }
    /**
     * @inheritdoc
     */
    public function fetchMessage($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $eml = $this->folderDir($user, $folder) .
            DIRECTORY_SEPARATOR . "$uid.eml";
        if (!is_file($eml)) {
            return false;
        }
        $bytes = @file_get_contents($eml);
        return ($bytes === false) ? false : $bytes;
    }
    /**
     * @inheritdoc
     */
    public function listMessages($user, $folder)
    {
        $dir = $this->folderDir($user, $folder);
        if (!is_dir($dir)) {
            return [];
        }
        $messages = [];
        $entries = @scandir($dir);
        if ($entries === false) {
            return [];
        }
        foreach ($entries as $entry) {
            if (substr($entry, -4) !== ".eml") {
                continue;
            }
            $uid = (int) substr($entry, 0, -4);
            if ($uid < 1) {
                continue;
            }
            $meta = $this->messageMeta($user, $folder, $uid);
            if ($meta !== false) {
                $messages[] = $meta;
            }
        }
        usort($messages, function ($a, $b) {
            return $a['uid'] - $b['uid'];
        });
        return $messages;
    }
    /**
     * @inheritdoc
     */
    public function messageMeta($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $dir = $this->folderDir($user, $folder);
        $eml = $dir . DIRECTORY_SEPARATOR . "$uid.eml";
        if (!is_file($eml)) {
            return false;
        }
        $size = (int) @filesize($eml);
        $flags_file = $dir . DIRECTORY_SEPARATOR . "$uid.flags";
        $flags = [];
        if (is_file($flags_file)) {
            $contents = (string) @file_get_contents($flags_file);
            foreach (preg_split('/\r\n|\r|\n/', $contents)
                as $flag) {
                $flag = trim($flag);
                if ($flag !== "") {
                    $flags[] = $flag;
                }
            }
        }
        $date_file = $dir . DIRECTORY_SEPARATOR . "$uid.date";
        $date = is_file($date_file) ?
            (int) @file_get_contents($date_file) : 0;
        if ($date <= 0) {
            $date = (int) @filemtime($eml);
        }
        return [
            'uid' => $uid,
            'size' => $size,
            'flags' => $flags,
            'internal_date' => $date,
        ];
    }
    /**
     * @inheritdoc
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $dir = $this->folderDir($user, $folder);
        $eml = $dir . DIRECTORY_SEPARATOR . "$uid.eml";
        if (!is_file($eml)) {
            return false;
        }
        $clean = [];
        foreach ($flags as $flag) {
            $flag = trim((string) $flag);
            if ($flag !== "") {
                $clean[] = $flag;
            }
        }
        $written = @file_put_contents(
            $dir . DIRECTORY_SEPARATOR . "$uid.flags",
            implode("\n", $clean));
        return $written !== false;
    }
    /**
     * @inheritdoc
     */
    public function expunge($user, $folder)
    {
        $expunged = [];
        foreach ($this->listMessages($user, $folder) as $meta) {
            if (in_array('\Deleted', $meta['flags'])) {
                $dir = $this->folderDir($user, $folder);
                @unlink($dir . DIRECTORY_SEPARATOR .
                    $meta['uid'] . ".eml");
                @unlink($dir . DIRECTORY_SEPARATOR .
                    $meta['uid'] . ".flags");
                @unlink($dir . DIRECTORY_SEPARATOR .
                    $meta['uid'] . ".date");
                $expunged[] = $meta['uid'];
            }
        }
        return $expunged;
    }
    /**
     * @inheritdoc
     */
    public function moveMessage($user, $from, $to, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $from_dir = $this->folderDir($user, $from);
        $to_dir = $this->folderDir($user, $to);
        if (!is_dir($from_dir)) {
            return false;
        }
        if (!is_dir($to_dir)) {
            if (!$this->createFolder($user, $to)) {
                return false;
            }
            $to_dir = $this->folderDir($user, $to);
        }
        foreach (['eml', 'flags', 'date'] as $ext) {
            $src = $from_dir . DIRECTORY_SEPARATOR . "$uid.$ext";
            $dst = $to_dir . DIRECTORY_SEPARATOR . "$uid.$ext";
            if (is_file($src) && !@rename($src, $dst)) {
                return false;
            }
        }
        return true;
    }
    /**
     * @inheritdoc
     */
    public function messageCount($user, $folder)
    {
        return count($this->listMessages($user, $folder));
    }
    /**
     * @inheritdoc
     *
     * UIDVALIDITY is stored per folder so a delete+recreate
     * cycle assigns a fresh value, signaling clients that
     * their cached UID-to-content mapping is stale and must
     * be discarded. The per-user .uidvalidity file remains
     * the fallback for folders that pre-date this scheme so
     * existing message stores keep working without
     * intervention.
     */
    public function uidValidity($user, $folder)
    {
        $folder_file = $this->folderDir($user, $folder) .
            DIRECTORY_SEPARATOR . ".uidvalidity";
        if (is_file($folder_file)) {
            $value = (int) trim((string)
                @file_get_contents($folder_file));
            if ($value > 0) {
                return $value;
            }
        }
        $user_file = $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".uidvalidity";
        if (!is_file($user_file)) {
            $this->ensureUser($user);
        }
        return (int) @file_get_contents($user_file);
    }
    /**
     * @inheritdoc
     */
    public function uidNext($user, $folder)
    {
        $file = $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".uidnext";
        if (!is_file($file)) {
            $this->ensureUser($user);
        }
        return (int) trim((string) @file_get_contents($file));
    }
    /**
     * Returns the absolute path to the per-user subscription
     * state file. The file holds one folder name per line; an
     * empty or missing file means only INBOX is subscribed.
     */
    protected function subscriptionFile($user)
    {
        return $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".subscribed";
    }
    /**
     * Reads the subscription file into a deduplicated array
     * with INBOX always present. The file format is one folder
     * name per line; blank lines and leading/trailing whitespace
     * are ignored. INBOX is treated as implicitly subscribed
     * even if not listed (RFC 3501 sec 6.3.6 idempotency).
     */
    protected function readSubscriptions($user)
    {
        $file = $this->subscriptionFile($user);
        $names = ['INBOX'];
        if (is_file($file)) {
            $lines = @file($file, FILE_IGNORE_NEW_LINES |
                FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line !== '' &&
                        !in_array($line, $names, true)) {
                        $names[] = $line;
                    }
                }
            }
        }
        return $names;
    }
    /**
     * Writes a list of folder names to the subscription file
     * atomically (write-temp-then-rename) to avoid leaving a
     * half-written state file if the process is interrupted.
     */
    protected function writeSubscriptions($user, $folders)
    {
        $this->ensureUser($user);
        $file = $this->subscriptionFile($user);
        $temp_path = $file . '.tmp';
        $payload = '';
        foreach ($folders as $folder_name) {
            $payload .= $folder_name . "\n";
        }
        if (file_put_contents($temp_path, $payload) === false) {
            return false;
        }
        if (!@rename($temp_path, $file)) {
            @unlink($temp_path);
            return false;
        }
        return true;
    }
    /**
     * @inheritdoc
     */
    public function isSubscribed($user, $folder)
    {
        return in_array($folder,
            $this->readSubscriptions($user), true);
    }
    /**
     * @inheritdoc
     */
    public function subscribe($user, $folder)
    {
        $current = $this->readSubscriptions($user);
        if (in_array($folder, $current, true)) {
            return true;
        }
        $current[] = $folder;
        return $this->writeSubscriptions($user, $current);
    }
    /**
     * @inheritdoc
     */
    public function unsubscribe($user, $folder)
    {
        if (strcasecmp($folder, 'INBOX') === 0) {
            /*
                INBOX cannot be unsubscribed (it is implicitly
                in every result); we accept the request and
                return success per RFC 3501 sec 6.3.7
                idempotency, but do not actually remove it.
             */
            return true;
        }
        $current = $this->readSubscriptions($user);
        $index = array_search($folder, $current, true);
        if ($index === false) {
            return true;
        }
        unset($current[$index]);
        return $this->writeSubscriptions($user,
            array_values($current));
    }
    /**
     * @inheritdoc
     */
    public function listSubscribed($user)
    {
        $names = $this->readSubscriptions($user);
        sort($names);
        return $names;
    }
}
/**
 * In-memory MailStorage. State lives entirely in PHP arrays
 * on the storage instance; no filesystem access at all.
 * Everything disappears when the process exits, which is the
 * point: this backend is for ephemeral demos (anonymous mail
 * drops, integration tests, throwaway environments) where
 * persistence would be a bug rather than a feature.
 *
 * Internal layout:
 *
 *      $this->users[$user] = [
 *          'uidnext'       => int,
 *          'uidvalidity'   => int,    // user-level fallback
 *          'subscribed'    => array,  // folder names
 *          'folders'       => [
 *              $folder_name => [
 *                  'uidvalidity' => int,
 *                  'messages'    => [
 *                      $uid => [
 *                          'bytes'         => string,
 *                          'flags'         => array,
 *                          'internal_date' => int,
 *                      ],
 *                  ],
 *              ],
 *          ],
 *      ];
 *
 * UIDs are per-user and monotonic, mirroring FileMailStorage
 * so move-across-folders preserves the UID. UIDVALIDITY is
 * per-folder so deleting and recreating a folder produces a
 * different value (RFC 3501 sec 2.3.1.1). Both counters use
 * the inherited nextUidValidity() helper for monotonicity.
 */
class RamMailStorage extends MailStorage
{
    /**
     * @var array per-user state map; see class docblock for
     * the nested shape.
     */
    protected $users = [];
    /**
     * Returns a reference to the user record, creating it if
     * necessary. The reference shape is documented on the
     * class. Helper used by every mutator so a fresh
     * username gets a real, mutable record on first touch.
     */
    protected function & userRef($user)
    {
        if (!isset($this->users[$user])) {
            $this->users[$user] = [
                'uidnext' => 1,
                'uidvalidity' => $this->nextUidValidity(),
                'subscribed' => ['INBOX'],
                'folders' => [
                    'INBOX' => [
                        'uidvalidity' => $this->nextUidValidity(),
                        'messages' => [],
                    ],
                ],
            ];
        }
        return $this->users[$user];
    }
    /**
     * @inheritdoc
     */
    public function ensureUser($user)
    {
        $this->userRef($user);
        return true;
    }
    /**
     * @inheritdoc
     */
    public function listFolders($user)
    {
        if (!isset($this->users[$user])) {
            return [];
        }
        $names = array_keys($this->users[$user]['folders']);
        sort($names);
        return $names;
    }
    /**
     * @inheritdoc
     */
    public function createFolder($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $u = & $this->userRef($user);
        if (isset($u['folders'][$folder])) {
            return true;
        }
        $u['folders'][$folder] = [
            'uidvalidity' => $this->nextUidValidity(),
            'messages' => [],
        ];
        return true;
    }
    /**
     * @inheritdoc
     */
    public function deleteFolder($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        if ($folder === "INBOX") {
            return false;
        }
        if (!isset($this->users[$user]['folders'][$folder])) {
            return false;
        }
        /*
            Refuse if subfolders exist, matching FileMailStorage
            and the IMAP convention that delete is a leaf
            operation; clients walk the subtree themselves.
         */
        $prefix = $folder . "/";
        foreach (array_keys($this->users[$user]['folders'])
            as $other) {
            if (strpos($other, $prefix) === 0) {
                return false;
            }
        }
        unset($this->users[$user]['folders'][$folder]);
        return true;
    }
    /**
     * @inheritdoc
     */
    public function renameFolder($user, $old, $new)
    {
        try {
            $old = $this->normalizeFolder($old);
            $new = $this->normalizeFolder($new);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        if ($old === "INBOX" || $new === "INBOX") {
            return false;
        }
        if (!isset($this->users[$user]['folders'][$old])) {
            return false;
        }
        if (isset($this->users[$user]['folders'][$new])) {
            return false;
        }
        $this->users[$user]['folders'][$new] =
            $this->users[$user]['folders'][$old];
        unset($this->users[$user]['folders'][$old]);
        return true;
    }
    /**
     * @inheritdoc
     */
    public function folderExists($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        return isset(
            $this->users[$user]['folders'][$folder]);
    }
    /**
     * @inheritdoc
     */
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $internal_date = 0)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $u = & $this->userRef($user);
        if (!isset($u['folders'][$folder])) {
            if (!$this->createFolder($user, $folder)) {
                return false;
            }
        }
        if ($internal_date <= 0) {
            $internal_date = time();
        }
        $clean = [];
        foreach ($flags as $flag) {
            $flag = trim((string) $flag);
            if ($flag !== "") {
                $clean[] = $flag;
            }
        }
        $uid = $u['uidnext']++;
        $u['folders'][$folder]['messages'][$uid] = [
            'bytes' => (string) $bytes,
            'flags' => $clean,
            'internal_date' => (int) $internal_date,
        ];
        return $uid;
    }
    /**
     * @inheritdoc
     */
    public function fetchMessage($user, $folder, $uid)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $uid = (int) $uid;
        if (!isset($this->users[$user]['folders'][$folder]
            ['messages'][$uid])) {
            return false;
        }
        return $this->users[$user]['folders'][$folder]
            ['messages'][$uid]['bytes'];
    }
    /**
     * @inheritdoc
     */
    public function listMessages($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return [];
        }
        if (!isset($this->users[$user]['folders'][$folder])) {
            return [];
        }
        $messages = $this->users[$user]['folders'][$folder]
            ['messages'];
        ksort($messages);
        $output = [];
        foreach ($messages as $uid => $record) {
            $output[] = [
                'uid' => (int) $uid,
                'size' => strlen($record['bytes']),
                'flags' => $record['flags'],
                'internal_date' => $record['internal_date'],
            ];
        }
        return $output;
    }
    /**
     * @inheritdoc
     */
    public function messageMeta($user, $folder, $uid)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $uid = (int) $uid;
        if (!isset($this->users[$user]['folders'][$folder]
            ['messages'][$uid])) {
            return false;
        }
        $record = $this->users[$user]['folders'][$folder]
            ['messages'][$uid];
        return [
            'uid' => $uid,
            'size' => strlen($record['bytes']),
            'flags' => $record['flags'],
            'internal_date' => $record['internal_date'],
        ];
    }
    /**
     * @inheritdoc
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        if (!isset($this->users[$user]['folders'][$folder]
            ['messages'][$uid])) {
            return false;
        }
        $clean = [];
        foreach ($flags as $flag) {
            $flag = trim((string) $flag);
            if ($flag !== "") {
                $clean[] = $flag;
            }
        }
        $this->users[$user]['folders'][$folder]['messages']
            [$uid]['flags'] = $clean;
        return true;
    }
    /**
     * @inheritdoc
     */
    public function expunge($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return [];
        }
        if (!isset($this->users[$user]['folders'][$folder])) {
            return [];
        }
        $expunged = [];
        $messages = & $this->users[$user]['folders'][$folder]
            ['messages'];
        ksort($messages);
        foreach ($messages as $uid => $record) {
            if (in_array('\\Deleted', $record['flags'],
                true)) {
                $expunged[] = (int) $uid;
                unset($messages[$uid]);
            }
        }
        return $expunged;
    }
    /**
     * @inheritdoc
     */
    public function moveMessage($user, $from, $to, $uid)
    {
        try {
            $from = $this->normalizeFolder($from);
            $to = $this->normalizeFolder($to);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $uid = (int) $uid;
        if (!isset($this->users[$user]['folders'][$from]
            ['messages'][$uid])) {
            return false;
        }
        if (!isset($this->users[$user]['folders'][$to])) {
            if (!$this->createFolder($user, $to)) {
                return false;
            }
        }
        $record = $this->users[$user]['folders'][$from]
            ['messages'][$uid];
        $this->users[$user]['folders'][$to]['messages'][$uid]
            = $record;
        unset($this->users[$user]['folders'][$from]
            ['messages'][$uid]);
        return true;
    }
    /**
     * @inheritdoc
     */
    public function messageCount($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return 0;
        }
        if (!isset($this->users[$user]['folders'][$folder])) {
            return 0;
        }
        return count($this->users[$user]['folders'][$folder]
            ['messages']);
    }
    /**
     * @inheritdoc
     */
    public function uidValidity($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return 0;
        }
        if (isset($this->users[$user]['folders'][$folder]
            ['uidvalidity'])) {
            return $this->users[$user]['folders'][$folder]
                ['uidvalidity'];
        }
        $u = & $this->userRef($user);
        return $u['uidvalidity'];
    }
    /**
     * @inheritdoc
     */
    public function uidNext($user, $folder)
    {
        $u = & $this->userRef($user);
        return $u['uidnext'];
    }
    /**
     * @inheritdoc
     */
    public function isSubscribed($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        if ($folder === "INBOX") {
            return true;
        }
        if (!isset($this->users[$user])) {
            return false;
        }
        return in_array($folder,
            $this->users[$user]['subscribed'], true);
    }
    /**
     * @inheritdoc
     */
    public function subscribe($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $u = & $this->userRef($user);
        if (!in_array($folder, $u['subscribed'], true)) {
            $u['subscribed'][] = $folder;
        }
        return true;
    }
    /**
     * @inheritdoc
     */
    public function unsubscribe($user, $folder)
    {
        try {
            $folder = $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        if (!isset($this->users[$user])) {
            return true;
        }
        $u = & $this->users[$user];
        $index = array_search($folder, $u['subscribed'],
            true);
        if ($index !== false) {
            unset($u['subscribed'][$index]);
            $u['subscribed'] = array_values($u['subscribed']);
        }
        return true;
    }
    /**
     * @inheritdoc
     */
    public function listSubscribed($user)
    {
        $names = ['INBOX'];
        if (isset($this->users[$user])) {
            foreach ($this->users[$user]['subscribed']
                as $name) {
                if (!in_array($name, $names, true)) {
                    $names[] = $name;
                }
            }
        }
        sort($names);
        return $names;
    }
}
/**
 * The mail server itself. Single instance per process; binds one
 * SMTP and one IMAP listening socket and pumps the event loop.
 *
 * Configuration shape:
 *      $mail = new MailSite();
 *      $mail->auth($authenticator);
 *      $mail->storage($storage);
 *      $mail->domains(['example.com', 'localhost']);
 *      $mail->onConnect(function ($info, $context) { });
 *      $mail->onMailFrom(function ($info, $context) { });
 *      $mail->onRcptTo(function ($info, $context) { });
 *      $mail->onHeader(function ($info, $context) { });
 *      $mail->onMessage(function ($info, $context) { });
 *      $mail->listen([
 *          'SMTP_PORT' => 2525, 'IMAP_PORT' => 1143,
 *          'SMTPS_PORT' => 4465, 'IMAPS_PORT' => 9933,
 *          'SERVER_CONTEXT' => ['ssl' => [...]]]);
 *
 * Hook stages (each onX call appends a callback; multiple
 * callbacks per stage compose, evaluated in registration order
 * with first-non-null verdict winning):
 *   onBanner   - before greeting; can replace banner string or
 *                close the connection without one
 *   onConnect  - after accept; can refuse the session
 *   onHelo     - after EHLO/HELO; can refuse with 550
 *   onMailFrom - after MAIL FROM; can reject the sender
 *   onRcptTo   - per RCPT TO; can reject one recipient
 *   onHeader   - once the message headers are parsed but before
 *                the body is stored; can reject the message
 *   onMessage  - with full bytes; can drop, redirect, or accept
 * Hook return values:
 *   null / true                       - continue
 *   false                             - drop silently (still
 *                                       250 to the SMTP client
 *                                       so filter behavior is
 *                                       not probeable)
 *   'reject'                          - SMTP-level reject with
 *                                       a hard 550 / 421 reply
 *   string (only at onBanner)         - replacement banner text
 *   ['folder'=>...,'flags'=>[...]]    - at onMessage, redirect
 *                                       delivery to a folder
 *
 * Public methods that web/CLI frontends can call directly bypass
 * the wire protocol entirely; they reach the same MailStorage
 * the IMAP parser uses, so a webmail UI and a Thunderbird
 * connection see consistent state. See deliverMail, listFolders,
 * createFolder, deleteFolder, renameFolder, appendMessage,
 * fetchMessage, listMessages, setFlags, expunge, moveMessage,
 * messageCount.
 */
class MailSite
{
    /* indices into the in_streams / out_streams parallel arrays */
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
    /** @var Authenticator */
    protected $authenticator;
    /** @var MailStorage */
    protected $mail_storage;
    /** @var array hook callbacks keyed by stage */
    protected $hooks = [
        'banner' => [], 'connect' => [], 'helo' => [],
        'mailfrom' => [], 'rcptto' => [], 'header' => [],
        'message' => [],
    ];
    /** @var array list of locally hosted domains */
    protected $local_domains = ['localhost'];
    /** @var array */
    protected $default_server_globals;
    /** @var array */
    protected $immortal_stream_keys = [];
    /** @var array */
    protected $in_streams = [];
    /** @var array */
    protected $out_streams = [];
    /** @var \SplPriorityQueue|null */
    protected $timer_alarms;
    /** @var array */
    protected $timers = [];
    /** @var array stream context array (for TLS) */
    protected $server_context_array = [];
    /** @var bool whether listen() detected an SSL config */
    protected $tls_available = false;
    /**
     * @var array per-folder change counter for IDLE push.
     * Indexed as $mailbox_changes[$user][$folder] = int.
     * Bumped on every storage mutation that adds, removes, or
     * relocates a message. Idling connections snapshot the
     * counter on entry and the per-tick notification step
     * compares the current value to the snapshot to decide
     * whether to emit "* N EXISTS".
     */
    protected $mailbox_changes = [];
    /**
     * Constructs a MailSite. The instance starts unconfigured;
     * the caller must wire an Authenticator via auth(), a
     * MailStorage via storage(), and any per-stage hooks via
     * the onX methods before invoking listen(). Hook callbacks
     * fire in registration order with first-non-null verdict
     * winning, so multiple hooks at the same stage compose.
     */
    public function __construct()
    {
        $this->timer_alarms = new \SplPriorityQueue();
        $this->timer_alarms->setExtractFlags(
            \SplPriorityQueue::EXTR_BOTH);
    }
    /**
     * Sets the authenticator used by SMTP AUTH and IMAP LOGIN.
     */
    public function auth(Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
    /**
     * Sets the storage backend used by both protocols and by
     * the direct-call public API.
     */
    public function storage(MailStorage $storage)
    {
        $this->mail_storage = $storage;
        return $this;
    }
    /**
     * Registers a callback to run before the welcome banner is
     * sent. The callback receives ($info, $context) where $info has
     * 'remote_addr', 'remote_port', 'protocol' ('SMTP'|'IMAP'),
     * 'tls_active', and 'default_banner'. It may return:
     *   - null / true: send the default banner
     *   - a string: replace the banner with this text (the
     *     trailing CRLF is appended automatically)
     *   - 'reject': close the connection; SMTP gets 421, IMAP
     *     gets a "* BYE" before close
     */
    public function onBanner(callable $callback)
    {
        $this->hooks['banner'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run immediately after a client
     * connects (after TLS upgrade for implicit-TLS sockets).
     * $info has 'remote_addr', 'remote_port', 'protocol',
     * 'tls_active'. Returning 'reject' closes the connection.
     * Useful for IP-based allow/deny lists.
     */
    public function onConnect(callable $callback)
    {
        $this->hooks['connect'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run after EHLO/HELO has been
     * parsed. $info has 'domain', 'verb' ('EHLO'|'HELO').
     * Returning 'reject' replies 550 and the session stays in
     * INIT state.
     */
    public function onHelo(callable $callback)
    {
        $this->hooks['helo'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run after MAIL FROM has been
     * parsed. $info has 'from'. Returning 'reject' replies
     * 550 5.7.1 and MAIL FROM is not accepted.
     */
    public function onMailFrom(callable $callback)
    {
        $this->hooks['mailfrom'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run per RCPT TO (the anti-relay
     * check runs first; this hook only sees recipients that
     * survive that check). $info has 'to' and 'local_user' (the
     * resolved local username). Returning 'reject' replies
     * 550 5.7.1 for that recipient only.
     */
    public function onRcptTo(callable $callback)
    {
        $this->hooks['rcptto'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run once the message DATA is in
     * hand and the headers have been parsed, but before the
     * body is stored. $info has 'from', 'to', 'headers' (array
     * of [name, value] pairs preserving order and case),
     * 'header_block', 'bytes'. Returning 'reject' replies
     * 550 5.6.0 and the message is discarded.
     */
    public function onHeader(callable $callback)
    {
        $this->hooks['header'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run with the full message bytes
     * for delivery. $info has 'from', 'to', 'bytes'. Return
     * value:
     *   - null/true: deliver to INBOX with default flags
     *   - false: drop silently (still 250 to client)
     *   - 'reject': SMTP-level reject with 550
     *   - ['folder'=>'Junk','flags'=>['\Recent']]: redirect
     */
    public function onMessage(callable $callback)
    {
        $this->hooks['message'][] = $callback;
        return $this;
    }
    /**
     * Runs all hooks for $stage in registration order. Returns
     * the first non-null verdict, or null if every hook returned
     * null/true. Hooks that throw are caught and treated as if
     * they returned null so a buggy filter cannot kill the loop.
     */
    protected function runHooks($stage, $info, $context)
    {
        if (empty($this->hooks[$stage])) {
            return null;
        }
        foreach ($this->hooks[$stage] as $callback) {
            try {
                $verdict = call_user_func($callback, $info, $context);
            } catch (\Throwable $e) {
                $verdict = null;
            }
            if ($verdict === null || $verdict === true) {
                continue;
            }
            return $verdict;
        }
        return null;
    }
    /**
     * Sets the list of locally hosted domains. RCPT TO addresses
     * whose domain matches (case-insensitively) are treated as
     * local; any other RCPT TO requires that the SMTP session
     * be authenticated, otherwise the server refuses with 550
     * to prevent open-relay use.
     */
    public function domains(array $domains)
    {
        $clean = [];
        foreach ($domains as $domain) {
            $domain = strtolower(trim((string) $domain));
            if ($domain !== "") {
                $clean[] = $domain;
            }
        }
        $this->local_domains = $clean ?: ['localhost'];
        return $this;
    }
    /**
     * Delivers a message into a local user's mailbox, running
     * the configured filter exactly as the SMTP path would. This
     * is the entry point for non-SMTP message ingestion (e.g. a
     * webmail "Save Draft" action, a CLI import tool, an HTTP
     * webhook from a transactional sender). The recipient must
     * be a local user; this method does NOT do outbound queueing.
     *
     * @param string $from RFC 5321 reverse-path (envelope sender)
     * @param string $to RFC 5321 forward-path (one envelope
     *      recipient; multi-recipient delivery should call this
     *      method once per recipient)
     * @param string $bytes the full RFC 5322 message
     * @param array $context optional context array passed to the
     *      onMessage hook (caller supplies arbitrary fields)
     * @return int|false UID of the delivered message, or false
     *      on hook-drop, hook-reject, or unknown recipient
     */
    public function deliverMail($from, $to, $bytes, $context = [])
    {
        $local = $this->resolveLocalUser($to);
        if ($local === false) {
            return false;
        }
        $folder = "INBOX";
        $flags = ['\Recent'];
        $info = ['from' => $from, 'to' => $to, 'bytes' => $bytes];
        $verdict = $this->runHooks('message', $info, $context);
        if ($verdict === false || $verdict === 'reject') {
            return false;
        }
        if (is_array($verdict)) {
            if (isset($verdict['folder'])) {
                $folder = (string) $verdict['folder'];
            }
            if (isset($verdict['flags']) &&
                is_array($verdict['flags'])) {
                $flags = $verdict['flags'];
            }
        }
        $this->mail_storage->ensureUser($local);
        $uid = $this->mail_storage->appendMessage($local, $folder,
            $bytes, $flags);
        if ($uid !== false) {
            $this->bumpMailboxChange($local, $folder);
        }
        return $uid;
    }
    /**
     * Returns the list of folder names for a user, including
     * INBOX. This is the direct-call equivalent of an IMAP LIST
     * "" "*", suitable for a webmail front-end that wants the
     * full folder tree without going through the wire protocol.
     *
     * @param string $user
     * @return array list of folder name strings, sorted
     */
    public function listFolders($user)
    {
        return $this->mail_storage->listFolders($user);
    }
    /**
     * Creates a folder for a user. Idempotent; creating an
     * existing folder is a successful no-op. Mirrors the IMAP
     * CREATE command for direct callers.
     *
     * @param string $user
     * @param string $folder full folder path, e.g. "Archive/2026"
     * @return bool true on success
     */
    public function createFolder($user, $folder)
    {
        return $this->mail_storage->createFolder($user, $folder);
    }
    /**
     * Deletes a folder and all its messages. Refuses to delete
     * INBOX or a folder with subfolders, matching the IMAP
     * DELETE semantics.
     *
     * @param string $user
     * @param string $folder
     * @return bool true on success
     */
    public function deleteFolder($user, $folder)
    {
        return $this->mail_storage->deleteFolder($user, $folder);
    }
    /**
     * Renames a folder. Refuses to rename INBOX. Subfolders move
     * with the renamed folder.
     *
     * @param string $user
     * @param string $old
     * @param string $new
     * @return bool true on success
     */
    public function renameFolder($user, $old, $new)
    {
        return $this->mail_storage->renameFolder($user, $old,
            $new);
    }
    /**
     * Appends a message directly into a user's folder, bypassing
     * SMTP and the configured filter hooks. Useful for webmail
     * "Save Draft" or "Save Sent" actions that want a message
     * placed verbatim with caller-chosen flags.
     *
     * @param string $user
     * @param string $folder
     * @param string $bytes full RFC 5322 message
     * @param array $flags initial flag set
     * @param int $date Unix timestamp; 0 means "now"
     * @return int|false UID assigned on success
     */
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $date = 0)
    {
        $uid = $this->mail_storage->appendMessage($user, $folder,
            $bytes, $flags, $date);
        if ($uid !== false) {
            $this->bumpMailboxChange($user, $folder);
        }
        return $uid;
    }
    /**
     * Returns the raw RFC 5322 bytes of a single message.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @return string|false the bytes, or false if not found
     */
    public function fetchMessage($user, $folder, $uid)
    {
        return $this->mail_storage->fetchMessage($user, $folder,
            $uid);
    }
    /**
     * Returns metadata records for every message in a folder,
     * sorted ascending by UID. Each record is an associative
     * array with keys uid (int), size (int), flags (array of
     * strings), internal_date (Unix timestamp). This is the
     * direct-call shape a webmail message-list view consumes.
     *
     * @param string $user
     * @param string $folder
     * @return array list of metadata records
     */
    public function listMessages($user, $folder)
    {
        return $this->mail_storage->listMessages($user, $folder);
    }
    /**
     * Returns the metadata record for a single message, with
     * the same shape as one entry of listMessages.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @return array|false
     */
    public function messageMeta($user, $folder, $uid)
    {
        return $this->mail_storage->messageMeta($user, $folder,
            $uid);
    }
    /**
     * Replaces the flag set on a message. Pass an empty array
     * to clear all flags.
     *
     * @param string $user
     * @param string $folder
     * @param int $uid
     * @param array $flags
     * @return bool true on success
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        $ok = $this->mail_storage->setFlags($user, $folder, $uid,
            $flags);
        if ($ok) {
            $this->bumpMailboxChange($user, $folder);
        }
        return $ok;
    }
    /**
     * Permanently removes every message in a folder that has the
     * \Deleted flag set, and returns the list of UIDs that were
     * removed. Mirrors IMAP EXPUNGE.
     *
     * @param string $user
     * @param string $folder
     * @return array list of expunged UIDs
     */
    public function expunge($user, $folder)
    {
        $removed = $this->mail_storage->expunge($user, $folder);
        if (!empty($removed)) {
            $this->bumpMailboxChange($user, $folder);
        }
        return $removed;
    }
    /**
     * Moves a message between folders. The UID is preserved
     * because UIDs are per-user, not per-folder; this matches
     * the IMAP UIDPLUS expectation for COPY/MOVE.
     *
     * @param string $user
     * @param string $from source folder
     * @param string $to destination folder
     * @param int $uid
     * @return bool true on success
     */
    public function moveMessage($user, $from, $to, $uid)
    {
        $ok = $this->mail_storage->moveMessage($user, $from, $to,
            $uid);
        if ($ok) {
            $this->bumpMailboxChange($user, $from);
            $this->bumpMailboxChange($user, $to);
        }
        return $ok;
    }
    /**
     * Returns the number of messages currently in a folder.
     * Matches the count IMAP reports as EXISTS in SELECT.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    public function messageCount($user, $folder)
    {
        return $this->mail_storage->messageCount($user, $folder);
    }
    /**
     * Returns whether a folder exists for a user. Slightly more
     * efficient than fetching listFolders() and checking
     * membership when the caller only needs a yes/no answer.
     *
     * @param string $user
     * @param string $folder
     * @return bool
     */
    public function folderExists($user, $folder)
    {
        return $this->mail_storage->folderExists($user, $folder);
    }
    /**
     * Returns the UID that will be assigned to the next message
     * appended to this folder for this user. The value is the
     * direct-call equivalent of the IMAP UIDNEXT response code
     * returned by SELECT/STATUS, suitable for a webmail UI that
     * wants to detect new messages by comparing against a
     * cached high-water mark. The value is a prediction; under
     * concurrent appends the actual UID handed out may be
     * larger by the time the caller acts on it.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    public function uidNext($user, $folder)
    {
        return $this->mail_storage->uidNext($user, $folder);
    }
    /**
     * Returns the UIDVALIDITY value for a folder, the stable
     * per-folder integer IMAP clients use to tell whether their
     * cached UIDs are still valid. A change in this value
     * signals that the client must discard its UID cache and
     * resync. We assign one stable value per user account at
     * provisioning and reuse it for every folder, which is a
     * legal IMAP choice and avoids the complication of
     * tracking per-folder validity stamps.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    public function uidValidity($user, $folder)
    {
        return $this->mail_storage->uidValidity($user, $folder);
    }
    /**
     * Increments the per-folder change counter that drives
     * IDLE push notifications. Called after any storage
     * operation that changes the visible message count of a
     * folder. The counter is per-process and in-memory only;
     * it does not need to persist because IDLE subscribers
     * snapshot the current value at IDLE time and only care
     * about deltas during the idle window.
     *
     * @param string $user
     * @param string $folder
     */
    protected function bumpMailboxChange($user, $folder)
    {
        if (!isset($this->mailbox_changes[$user])) {
            $this->mailbox_changes[$user] = [];
        }
        if (!isset($this->mailbox_changes[$user][$folder])) {
            $this->mailbox_changes[$user][$folder] = 0;
        }
        $this->mailbox_changes[$user][$folder]++;
    }
    /**
     * Returns the current change-counter value for a folder,
     * defaulting to 0 if no mutations have happened in this
     * process. Used by imapCmdIdle to snapshot the value at
     * idle entry, and by processIdleNotifications to compare
     * later.
     *
     * @param string $user
     * @param string $folder
     * @return int
     */
    protected function currentChangeCounter($user, $folder)
    {
        if (!isset($this->mailbox_changes[$user][$folder])) {
            return 0;
        }
        return $this->mailbox_changes[$user][$folder];
    }
    /**
     * Clears every IDLE-related slot in a connection context.
     * Called when the client sends DONE, when the literal-
     * continuation handler decides idle has ended due to a
     * protocol error, and any other place that needs to
     * leave the connection in a clean post-idle state. The
     * three slots are kept null rather than deleted so later
     * isset() checks can short-circuit without keying through
     * an undefined index notice in strict environments.
     */
    protected function clearImapIdleState(&$context)
    {
        $context['IMAP_LIT_PENDING'] = null;
        $context['IDLE_SNAPSHOT'] = null;
        $context['IDLE_FOLDER'] = null;
        $context['IDLE_STATE'] = null;
    }
    /**
     * Resolves a recipient address to a local username, or false
     * if the recipient is not local. The local part is returned
     * in its lowercased form because storage is case-insensitive.
     */
    public function resolveLocalUser($address)
    {
        $address = trim((string) $address, "<> \t\r\n");
        $at = strrpos($address, '@');
        if ($at === false) {
            return false;
        }
        $local = substr($address, 0, $at);
        $domain = strtolower(substr($address, $at + 1));
        if (!in_array($domain, $this->local_domains)) {
            return false;
        }
        if ($this->authenticator === null) {
            return false;
        }
        $local_lc = strtolower($local);
        if (!$this->authenticator->userExists($local_lc)) {
            return false;
        }
        return $local_lc;
    }
    /**
     * Schedules a callable to fire after $time seconds. If
     * $repeating is true (default) the callable fires every
     * $time seconds; if false, just once. Returns an opaque
     * timer id that can be passed to clearTimer.
     */
    public function setTimer($time, callable $callback,
        $repeating = true)
    {
        $id = uniqid("t_", true);
        $this->timers[$id] = [
            'interval' => (float) $time,
            'callback' => $callback,
            'repeating' => (bool) $repeating,
        ];
        $this->timer_alarms->insert([$id, microtime(true) + $time],
            -(microtime(true) + $time));
        return $id;
    }
    /**
     * Cancels a previously scheduled timer. The $id is the
     * value returned by setTimer. Calling with an unknown id
     * is a silent no-op.
     *
     * @param string $id
     */
    public function clearTimer($id)
    {
        unset($this->timers[$id]);
    }
    /**
     * Binds the SMTP and IMAP listening sockets and runs the
     * event loop forever. The $config array overrides the
     * built-in defaults. If the SERVER_CONTEXT.ssl key is set
     * and the SMTPS_PORT or IMAPS_PORT keys are non-zero,
     * additional implicit-TLS sockets are bound on those ports
     * (TLS is negotiated immediately on accept, no plaintext
     * greeting). STARTTLS is advertised on the plaintext SMTP
     * and IMAP listeners whenever a TLS context is configured.
     */
    public function listen($config = [])
    {
        $defaults = [
            'SMTP_PORT' => 2525,
            'IMAP_PORT' => 1143,
            'SMTPS_PORT' => 0,
            'IMAPS_PORT' => 0,
            'BIND' => '0.0.0.0',
            'SERVER_NAME' => 'localhost',
            'SERVER_SOFTWARE' => 'AttoMail',
            'CONNECTION_TIMEOUT' => 30 * 60,
            'MAX_COMMAND_LEN' => 2048,
            'MAX_MESSAGE_LEN' => 25 * 1024 * 1024,
            /*
                If true, AUTH PLAIN/LOGIN on the plaintext SMTP
                and the IMAP LOGIN command are accepted before
                TLS is negotiated. Default false because credentials
                in cleartext are a security hazard on real
                networks; flip on for development against
                127.0.0.1 where there is no eavesdropper.
             */
            'ALLOW_PLAINTEXT_AUTH' => false,
        ];
        $context_array = [];
        if (isset($config['SERVER_CONTEXT'])) {
            $context_array = $config['SERVER_CONTEXT'];
            unset($config['SERVER_CONTEXT']);
        }
        $this->default_server_globals = array_merge($defaults,
            $config);
        $this->server_context_array = $context_array;
        $tls_available = !empty($context_array['ssl']);
        $this->tls_available = $tls_available;
        $bind = $this->default_server_globals['BIND'];
        $listeners = [];
        $listener_streams = [];
        $announce = [];
        /* plaintext SMTP listener */
        $smtp_addr = "tcp://$bind:" .
            $this->default_server_globals['SMTP_PORT'];
        $smtp = @stream_socket_server($smtp_addr, $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$smtp) {
            echo "Failed to bind SMTP $smtp_addr: $errstr\n";
            return false;
        }
        stream_set_blocking($smtp, 0);
        $listeners[(int) $smtp] = ['protocol' => 'SMTP',
            'tls_implicit' => false];
        $listener_streams[(int) $smtp] = $smtp;
        $announce[] = "SMTP at $smtp_addr";
        /* plaintext IMAP listener */
        $imap_addr = "tcp://$bind:" .
            $this->default_server_globals['IMAP_PORT'];
        $imap = @stream_socket_server($imap_addr, $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$imap) {
            echo "Failed to bind IMAP $imap_addr: $errstr\n";
            fclose($smtp);
            return false;
        }
        stream_set_blocking($imap, 0);
        $listeners[(int) $imap] = ['protocol' => 'IMAP',
            'tls_implicit' => false];
        $listener_streams[(int) $imap] = $imap;
        $announce[] = "IMAP at $imap_addr";
        /* implicit-TLS sockets, if configured */
        if ($tls_available &&
            !empty($this->default_server_globals['SMTPS_PORT'])) {
            $smtps_addr = "tcp://$bind:" .
                $this->default_server_globals['SMTPS_PORT'];
            $smtps = @stream_socket_server($smtps_addr,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
            if ($smtps) {
                stream_set_blocking($smtps, 0);
                $listeners[(int) $smtps] = ['protocol' => 'SMTP',
                    'tls_implicit' => true];
                $listener_streams[(int) $smtps] = $smtps;
                $announce[] = "SMTPS at $smtps_addr (implicit TLS)";
            } else {
                echo "Warning: failed to bind SMTPS $smtps_addr:" .
                    " $errstr\n";
            }
        }
        if ($tls_available &&
            !empty($this->default_server_globals['IMAPS_PORT'])) {
            $imaps_addr = "tcp://$bind:" .
                $this->default_server_globals['IMAPS_PORT'];
            $imaps = @stream_socket_server($imaps_addr,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
            if ($imaps) {
                stream_set_blocking($imaps, 0);
                $listeners[(int) $imaps] = ['protocol' => 'IMAP',
                    'tls_implicit' => true];
                $listener_streams[(int) $imaps] = $imaps;
                $announce[] = "IMAPS at $imaps_addr (implicit TLS)";
            } else {
                echo "Warning: failed to bind IMAPS $imaps_addr:" .
                    " $errstr\n";
            }
        }
        $this->immortal_stream_keys = array_keys($listener_streams);
        $this->in_streams = [
            self::CONNECTION => $listener_streams,
            self::DATA => array_fill_keys(
                array_keys($listener_streams), ""),
            self::CONTEXT => [],
            self::MODIFIED_TIME => [],
        ];
        $this->out_streams = [
            self::CONNECTION => [],
            self::DATA => [],
            self::CONTEXT => [],
            self::MODIFIED_TIME => [],
        ];
        foreach ($announce as $listener) {
            echo "AttoMail listening: $listener\n";
        }
        $excepts = null;
        while (true) {
            $reads = $this->in_streams[self::CONNECTION];
            $writes = $this->out_streams[self::CONNECTION];
            /*
                Cap the select timeout at 5 seconds so the loop
                wakes regularly even when nothing is happening.
                IDLE push notifications are emitted on the post-
                select tick, so a long sleep here would delay
                "* N EXISTS" pushes by however long the server
                slept. Five seconds bounds notification latency
                while keeping the idle CPU cost negligible.
             */
            $timeout = 5;
            $microtimeout = 0;
            if (!$this->timer_alarms->isEmpty()) {
                $top = $this->timer_alarms->top();
                $when = $top['data'][1];
                $delta = max(0.0, $when - microtime(true));
                $timer_secs = (int) floor($delta);
                if ($timer_secs < $timeout) {
                    $timeout = $timer_secs;
                    $microtimeout =
                        (int) (($delta - $timeout) * 1e6);
                }
            }
            $n = @stream_select($reads, $writes, $excepts,
                $timeout, $microtimeout);
            $this->processTimers();
            if ($n > 0) {
                foreach ($reads as $stream) {
                    $key = (int) $stream;
                    if (isset($listeners[$key])) {
                        $this->acceptConnection($stream,
                            $listeners[$key]);
                    } else {
                        $this->readClient($stream);
                    }
                }
                foreach ($writes as $stream) {
                    $this->writeClient($stream);
                }
            }
            $this->processIdleNotifications();
            $this->cullDeadStreams();
        }
    }
    /**
     * Accepts a new client connection on one of the listening
     * sockets and installs an initial context with the welcome
     * banner queued for write. The $listener arg is a record
     * {protocol => SMTP|IMAP, tls_implicit => bool}; for
     * implicit-TLS sockets the TLS handshake runs synchronously
     * on the just-accepted socket before any banner is queued.
     * SMTP greets with 220, IMAP with "* OK". The onConnect and
     * onBanner hooks fire after accept (and after TLS upgrade
     * if implicit) so they see the eventual TLS state.
     */
    protected function acceptConnection($server, $listener)
    {
        $connection = @stream_socket_accept($server, 0);
        if (!$connection) {
            return;
        }
        stream_set_blocking($connection, 0);
        $key = (int) $connection;
        $remote = (string) stream_socket_get_name($connection, true);
        $colon = strrpos($remote, ":");
        $remote_addr = ($colon === false) ? $remote :
            substr($remote, 0, $colon);
        $remote_port = ($colon === false) ? 0 :
            (int) substr($remote, $colon + 1);
        $protocol = $listener['protocol'];
        $tls_active = false;
        if (!empty($listener['tls_implicit'])) {
            /*
                Implicit TLS: negotiate the handshake before
                queueing any banner. The crypto call is blocking,
                which is acceptable on accept since we have no
                application-layer state to drain first. Failure
                tears the connection down without ever sending
                bytes (important: we must NOT send a plaintext
                fallback banner because the client is waiting for
                a TLS ServerHello).
             */
            if (!$this->upgradeToTls($connection)) {
                @fclose($connection);
                return;
            }
            $tls_active = true;
        }
        $this->in_streams[self::CONNECTION][$key] = $connection;
        $this->in_streams[self::DATA][$key] = "";
        $this->in_streams[self::MODIFIED_TIME][$key] = time();
        $this->in_streams[self::CONTEXT][$key] = [
            'PROTOCOL' => $protocol,
            'STATE' => 'INIT',
            'REMOTE_ADDR' => $remote_addr,
            'REMOTE_PORT' => $remote_port,
            'AUTH_USER' => null,
            'MAILFROM' => null,
            'RCPTTO' => [],
            'TLS_ACTIVE' => $tls_active,
            'AUTH_USERNAME' => null,
            'PENDING_STARTTLS' => false,
        ];
        $ctx_ref = & $this->in_streams[self::CONTEXT][$key];
        $connect_info = [
            'remote_addr' => $remote_addr,
            'remote_port' => $remote_port,
            'protocol' => $protocol,
            'tls_active' => $tls_active,
        ];
        $verdict = $this->runHooks('connect', $connect_info,
            $ctx_ref);
        if ($verdict === 'reject' || $verdict === false) {
            /*
                Reject before any banner. SMTP convention is to
                send a 421 "service not available" greeting and
                then close; IMAP sends "* BYE". Either is
                non-binding since we are tearing the connection
                down regardless.
             */
            $bye = ($protocol === 'SMTP') ?
                "421 4.7.0 Service not available\r\n" :
                "* BYE Service not available\r\n";
            @fwrite($connection, $bye);
            $this->shutdownStream($key);
            return;
        }
        $name = $this->default_server_globals['SERVER_NAME'];
        if ($protocol === 'SMTP') {
            $default_banner = "220 $name " .
                $this->default_server_globals['SERVER_SOFTWARE'] .
                " ESMTP ready";
        } else {
            $capabilities = $this->imapPreAuthCapabilities($tls_active);
            $default_banner = "* OK [$capabilities] $name ready";
        }
        $banner_info = $connect_info;
        $banner_info['default_banner'] = $default_banner;
        $banner_verdict = $this->runHooks('banner', $banner_info,
            $ctx_ref);
        if ($banner_verdict === 'reject' ||
            $banner_verdict === false) {
            $bye = ($protocol === 'SMTP') ?
                "421 4.7.0 Service not available\r\n" :
                "* BYE Service not available\r\n";
            @fwrite($connection, $bye);
            $this->shutdownStream($key);
            return;
        }
        if (is_string($banner_verdict)) {
            $banner = $banner_verdict;
        } else {
            $banner = $default_banner;
        }
        $this->queueWrite($key, $banner . "\r\n");
    }
    /**
     * Returns the IMAP CAPABILITY string we advertise BEFORE
     * the user authenticates. STARTTLS is offered while the
     * connection is in plaintext and we have a TLS context
     * configured; LOGIN is suppressed (LOGINDISABLED) until TLS
     * is up unless ALLOW_PLAINTEXT_AUTH is set. IDLE is offered
     * unconditionally since RFC 2177 places no auth requirement
     * on advertising it.
     */
    protected function imapPreAuthCapabilities($tls_active)
    {
        $parts = ['CAPABILITY', 'IMAP4rev1', 'IDLE',
            'NAMESPACE', 'ID', 'SPECIAL-USE',
            'CREATE-SPECIAL-USE', 'MOVE', 'UIDPLUS'];
        $allow_plain =
            !empty($this->default_server_globals['ALLOW_PLAINTEXT_AUTH']);
        if (!$tls_active && $this->tls_available) {
            $parts[] = 'STARTTLS';
        }
        if ($tls_active || $allow_plain) {
            $parts[] = 'AUTH=PLAIN';
            $parts[] = 'AUTH=LOGIN';
            /*
                LOGIN (the IMAP command) is the user-friendly
                mechanism that takes "LOGIN user pass" inline.
                It is enabled by default once TLS is up (or in
                dev mode) so manual telnet testing works.
             */
        } else {
            $parts[] = 'LOGINDISABLED';
        }
        return implode(' ', $parts);
    }
    /**
     * Performs the server-side TLS handshake on an accepted
     * client socket. Wraps stream_socket_enable_crypto in a
     * scoped error handler so the actual SSL error message can
     * be attributed to this call (using error_get_last alone is
     * unreliable because that buffer is process-wide). Returns
     * true on success, false on failure (caller closes socket).
     */
    protected function upgradeToTls($connection)
    {
        if (empty($this->server_context_array['ssl'])) {
            return false;
        }
        foreach ($this->server_context_array['ssl']
            as $option_name => $option_value) {
            stream_context_set_option($connection, 'ssl',
                $option_name, $option_value);
        }
        $error = null;
        set_error_handler(
            function ($errno, $errstr) use (&$error) {
                $error = $errstr;
                return true;
            });
        stream_set_blocking($connection, 1);
        $method = STREAM_CRYPTO_METHOD_TLS_SERVER;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
        }
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
        }
        $ok = @stream_socket_enable_crypto($connection, true,
            $method);
        stream_set_blocking($connection, 0);
        restore_error_handler();
        if ($ok === true) {
            return true;
        }
        if ($error !== null) {
            echo "TLS handshake failed: $error\n";
        }
        return false;
    }
    /**
     * Appends bytes to the outbound write buffer for a
     * connection. Allocates the out_streams slot lazily on
     * the first write so connections that never produce
     * output do not pay for an empty buffer. The actual
     * fwrite to the socket happens later in writeClient
     * when the select loop reports the socket writable; this
     * keeps queueWrite cheap and lets handlers emit many
     * lines without blocking.
     *
     * @param int $key connection key
     * @param string $bytes bytes to enqueue (may be empty)
     */
    protected function queueWrite($key, $bytes)
    {
        if (!isset($this->in_streams[self::CONNECTION][$key])) {
            return;
        }
        if (!isset($this->out_streams[self::DATA][$key])) {
            $this->out_streams[self::CONNECTION][$key] =
                $this->in_streams[self::CONNECTION][$key];
            $this->out_streams[self::DATA][$key] = "";
            $this->out_streams[self::CONTEXT][$key] =
                $this->in_streams[self::CONTEXT][$key];
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        }
        $this->out_streams[self::DATA][$key] .= $bytes;
        $this->out_streams[self::MODIFIED_TIME][$key] = time();
    }
    /**
     * Queues a tagged IMAP response of the given status (OK,
     * NO, or BAD) and detail text. Centralizes the CRLF
     * framing so individual command handlers do not have to
     * repeat the "$tag STATUS detail\r\n" pattern at every
     * exit. The detail text MUST NOT contain CR or LF; the
     * helper does no escaping because every existing call
     * site supplies a fixed English literal.
     */
    protected function imapResp($key, $tag, $status, $detail)
    {
        $this->queueWrite($key,
            "$tag $status $detail\r\n");
    }
    /**
     * Common shorthand for the very repetitive "completed"
     * tag-OK acknowledgement that ends most successful IMAP
     * commands. Equivalent to imapResp($key, $tag, 'OK',
     * "$verb completed").
     */
    protected function imapOk($key, $tag, $verb)
    {
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Reads any pending bytes from a client socket into the
     * inbound buffer and drains the buffer by repeatedly
     * calling processOne until no more complete commands can
     * be parsed. Closes the connection if the socket has hit
     * EOF. Tolerates short reads: a single fread chunk may
     * span multiple commands or only part of one, and the
     * remaining bytes carry over to the next select tick.
     *
     * @param resource $stream client socket
     */
    protected function readClient($stream)
    {
        $key = (int) $stream;
        $meta = stream_get_meta_data($stream);
        if ($meta['eof']) {
            $this->shutdownStream($key);
            return;
        }
        $chunk = @fread($stream, 8192);
        if ($chunk === false || $chunk === "") {
            return;
        }
        $this->in_streams[self::DATA][$key] .= $chunk;
        $this->in_streams[self::MODIFIED_TIME][$key] = time();
        /*
            Process as many complete commands as the buffer
            holds. SMTP commands and the IMAP authentication
            subset we support are line-based with CRLF
            terminators; the DATA phase has its own end-of-
            message sentinel.
         */
        while ($this->processOne($key)) {
            /* loop until buffer drains */
        }
    }
    /**
     * Returns true if it consumed a command (caller should loop),
     * false if it needs more bytes or the stream was destroyed.
     */
    protected function processOne($key)
    {
        if (!isset($this->in_streams[self::CONTEXT][$key])) {
            return false;
        }
        $context = & $this->in_streams[self::CONTEXT][$key];
        $proto = $context['PROTOCOL'];
        $buffer = & $this->in_streams[self::DATA][$key];
        if ($proto === 'SMTP' && $context['STATE'] === 'DATA') {
            return $this->consumeSmtpDataPhase($key, $buffer, $context);
        }
        /*
            IMAP APPEND literal: when a synchronizing literal is
            outstanding for an APPEND command, the next bytes are
            the message body, not a command line. Drain exactly
            'remaining' bytes from the buffer regardless of CRLFs
            inside, then once the literal is fully collected let
            the literal continuation handler complete the APPEND.
            Returns true to let the outer loop process whatever
            is left in the buffer (typically a CRLF + the next
            command, or just a CRLF that we silently consume).
         */
        if ($proto === 'IMAP' &&
            !empty($context['IMAP_LIT_PENDING']) &&
            isset($context['IMAP_LIT_PENDING']['continuation']) &&
            $context['IMAP_LIT_PENDING']['continuation'] === 'append'
            ) {
            $pend = & $context['IMAP_LIT_PENDING'];
            $avail = strlen($buffer);
            if ($avail === 0) {
                return false;
            }
            $take = min($pend['remaining'], $avail);
            $pend['collected'] .= substr($buffer, 0, $take);
            $buffer = substr($buffer, $take);
            $pend['remaining'] -= $take;
            if ($pend['remaining'] > 0) {
                return false;
            }
            /*
                Body fully collected. Strip an optional trailing
                CRLF that some clients append AFTER the literal
                bytes (between the body and the next command);
                without this the next processOne would see an
                empty line and reply BAD.
             */
            if (substr($buffer, 0, 2) === "\r\n") {
                $buffer = substr($buffer, 2);
            } else if (substr($buffer, 0, 1) === "\n") {
                $buffer = substr($buffer, 1);
            }
            $this->continueImapLiteral($key, '', $context);
            return true;
        }
        $end_of_line = strpos($buffer, "\r\n");
        if ($end_of_line === false) {
            $end_of_line = strpos($buffer, "\n");
            if ($end_of_line === false) {
                /*
                    Buffer cap: a line-oriented protocol must
                    eventually see a CRLF. If the inbound buffer
                    exceeds 64 KiB without a line terminator the
                    client is either malformed or trying to
                    exhaust memory; drop the connection rather
                    than keep accumulating.
                 */
                if (strlen($buffer) > 65536) {
                    $this->shutdownStream($key);
                }
                return false;
            }
            $line = substr($buffer, 0, $end_of_line);
            $buffer = substr($buffer, $end_of_line + 1);
        } else {
            $line = substr($buffer, 0, $end_of_line);
            $buffer = substr($buffer, $end_of_line + 2);
        }
        $line = rtrim($line, "\r\n");
        if ($proto === 'SMTP') {
            $this->dispatchSmtp($key, $line, $context);
        } else {
            $this->dispatchImap($key, $line, $context);
        }
        return true;
    }
    /**
     * Dispatches one SMTP command line. The state machine is:
     *   INIT  -> after EHLO/HELO -> READY
     *   READY + AUTH ok           -> READY (with AUTH_USER set)
     *   READY + MAIL FROM         -> MAIL
     *   MAIL  + RCPT TO           -> RCPT
     *   RCPT  + DATA              -> DATA
     *   DATA  + ".\r\n"           -> READY (message accepted)
     */
    protected function dispatchSmtp($key, $line, &$context)
    {
        $upper = strtoupper($line);
        if (strncmp($upper, 'EHLO', 4) === 0 ||
            strncmp($upper, 'HELO', 4) === 0) {
            $verb = strncmp($upper, 'EHLO', 4) === 0 ?
                'EHLO' : 'HELO';
            $domain = trim(substr($line, 4));
            $verdict = $this->runHooks('helo',
                ['domain' => $domain, 'verb' => $verb], $context);
            if ($verdict === 'reject' || $verdict === false) {
                $this->queueWrite($key,
                    "550 5.7.1 HELO rejected\r\n");
                return;
            }
            $context['STATE'] = 'READY';
            $name = $this->default_server_globals['SERVER_NAME'];
            $response = "250-$name Hello\r\n";
            $allow_plain =
                !empty($this->default_server_globals['ALLOW_PLAINTEXT_AUTH']);
            if (!empty($context['TLS_ACTIVE']) && $this->tls_available) {
                /*
                    Already in TLS; do not re-advertise STARTTLS.
                 */
            } elseif ($this->tls_available) {
                $response .= "250-STARTTLS\r\n";
            }
            if (!empty($context['TLS_ACTIVE']) || $allow_plain) {
                $response .= "250-AUTH PLAIN LOGIN\r\n";
            }
            $response .= "250-SIZE " .
                $this->default_server_globals['MAX_MESSAGE_LEN'] .
                "\r\n";
            $response .= "250 HELP\r\n";
            $this->queueWrite($key, $response);
            return;
        }
        if (strncmp($upper, 'NOOP', 4) === 0) {
            $this->queueWrite($key, "250 OK\r\n");
            return;
        }
        if (strncmp($upper, 'RSET', 4) === 0) {
            $context['MAILFROM'] = null;
            $context['RCPTTO'] = [];
            $context['STATE'] = 'READY';
            $this->queueWrite($key, "250 OK\r\n");
            return;
        }
        if (strncmp($upper, 'QUIT', 4) === 0) {
            $this->queueWrite($key, "221 Bye\r\n");
            $context['STATE'] = 'QUIT';
            return;
        }
        if (strncmp($upper, 'STARTTLS', 8) === 0) {
            $this->dispatchSmtpStarttls($key, $context);
            return;
        }
        if ($context['STATE'] === 'INIT') {
            $this->queueWrite($key,
                "503 5.5.1 send EHLO/HELO first\r\n");
            return;
        }
        if (strncmp($upper, 'AUTH ', 5) === 0 ||
            $context['STATE'] === 'AUTH-PLAIN' ||
            $context['STATE'] === 'AUTH-LOGIN-USER' ||
            $context['STATE'] === 'AUTH-LOGIN-PASS') {
            $allow_plain =
                !empty($this->default_server_globals['ALLOW_PLAINTEXT_AUTH']);
            if (empty($context['TLS_ACTIVE']) && !$allow_plain) {
                $this->queueWrite($key,
                    "538 5.7.11 Encryption required for AUTH\r\n");
                return;
            }
            $this->dispatchSmtpAuth($key, $line, $context);
            return;
        }
        if (strncmp($upper, 'MAIL FROM', 9) === 0) {
            $this->dispatchSmtpMailFrom($key, $line, $context);
            return;
        }
        if (strncmp($upper, 'RCPT TO', 7) === 0) {
            $this->dispatchSmtpRcptTo($key, $line, $context);
            return;
        }
        if (strncmp($upper, 'DATA', 4) === 0) {
            if ($context['STATE'] !== 'RCPT') {
                $this->queueWrite($key,
                    "503 5.5.1 need RCPT TO first\r\n");
                return;
            }
            $context['STATE'] = 'DATA';
            $this->queueWrite($key,
                "354 End data with <CR><LF>.<CR><LF>\r\n");
            return;
        }
        $this->queueWrite($key,
            "500 5.5.1 Unrecognized command\r\n");
    }
    /**
     * Handles SMTP STARTTLS (RFC 3207). Refuses if already in
     * TLS or if no TLS context is configured. On accept, queues
     * the 220 ready reply and sets a deferred-upgrade flag; the
     * actual stream_socket_enable_crypto call runs in
     * finishWrite once the 220 has been flushed to the wire,
     * because anything written before the handshake corrupts
     * the TLS framing the client expects.
     */
    protected function dispatchSmtpStarttls($key, &$context)
    {
        if (!$this->tls_available) {
            $this->queueWrite($key,
                "454 4.7.0 TLS not available\r\n");
            return;
        }
        if (!empty($context['TLS_ACTIVE'])) {
            $this->queueWrite($key,
                "503 5.5.1 TLS already active\r\n");
            return;
        }
        $context['PENDING_STARTTLS'] = true;
        $this->queueWrite($key, "220 2.0.0 Ready to start TLS\r\n");
    }
    /**
     * Handles AUTH PLAIN and AUTH LOGIN. PLAIN can carry the
     * credentials inline ("AUTH PLAIN <base64>") or in a
     * continuation line after a 334 challenge. LOGIN always
     * uses a two-line continuation: server prompts username
     * then password, both base64-encoded.
     */
    protected function dispatchSmtpAuth($key, $line, &$context)
    {
        if ($context['STATE'] === 'AUTH-PLAIN') {
            $this->finishAuthPlain($key, $line, $context);
            return;
        }
        if ($context['STATE'] === 'AUTH-LOGIN-USER') {
            $context['AUTH_USERNAME'] = (string) base64_decode($line,
                true);
            $context['STATE'] = 'AUTH-LOGIN-PASS';
            $this->queueWrite($key,
                "334 " . base64_encode("Password:") . "\r\n");
            return;
        }
        if ($context['STATE'] === 'AUTH-LOGIN-PASS') {
            $pass = (string) base64_decode($line, true);
            $user = (string) $context['AUTH_USERNAME'];
            $context['AUTH_USERNAME'] = null;
            $this->verifyAndSetAuth($key, $user, $pass, $context);
            return;
        }
        if (preg_match('/^AUTH\s+PLAIN(?:\s+(.+))?$/i', $line,
            $m)) {
            if (!empty($m[1])) {
                $this->finishAuthPlain($key, trim($m[1]), $context);
                return;
            }
            $context['STATE'] = 'AUTH-PLAIN';
            $this->queueWrite($key, "334 \r\n");
            return;
        }
        if (preg_match('/^AUTH\s+LOGIN(?:\s+(.+))?$/i', $line,
            $m)) {
            $context['STATE'] = 'AUTH-LOGIN-USER';
            if (!empty($m[1])) {
                $context['AUTH_USERNAME'] = (string) base64_decode(
                    trim($m[1]), true);
                $context['STATE'] = 'AUTH-LOGIN-PASS';
                $this->queueWrite($key,
                    "334 " . base64_encode("Password:") . "\r\n");
                return;
            }
            $this->queueWrite($key,
                "334 " . base64_encode("Username:") . "\r\n");
            return;
        }
        $this->queueWrite($key,
            "504 5.5.4 Unrecognized authentication mechanism\r\n");
    }
    /**
     * Completes an SMTP AUTH PLAIN exchange. The base64
     * argument is the SASL PLAIN payload "authzid\0authcid
     * \0password" (RFC 4616). On a parse failure the SMTP
     * state is reset to READY and a 535 reply is queued; on
     * success authentication is delegated to verifyAndSetAuth.
     *
     * @param int $key connection key
     * @param string $b64 base64-encoded SASL PLAIN payload
     * @param array &$context connection context (mutated)
     */
    protected function finishAuthPlain($key, $b64, &$context)
    {
        $raw = (string) base64_decode($b64, true);
        $parts = explode("\x00", $raw);
        if (count($parts) !== 3) {
            $context['STATE'] = 'READY';
            $this->queueWrite($key,
                "535 5.7.8 Authentication credentials" .
                " invalid\r\n");
            return;
        }
        list(, $user, $pass) = $parts;
        $this->verifyAndSetAuth($key, $user, $pass, $context);
    }
    /**
     * Verifies a username/password pair against the
     * configured authenticator and updates the SMTP
     * connection state accordingly. On success the lowercased
     * username is stored in AUTH_USER (storage paths are
     * case-insensitive) and a 235 reply is queued; on
     * failure a 535 reply is queued and AUTH_USER is left
     * unset. Either way the SMTP state returns to READY so
     * the client can issue MAIL FROM next.
     *
     * @param int $key connection key
     * @param string $user candidate username
     * @param string $pass candidate password
     * @param array &$context connection context (mutated)
     */
    protected function verifyAndSetAuth($key, $user, $pass, &$context)
    {
        $ok = false;
        if ($this->authenticator !== null) {
            $ok = $this->authenticator->verifyPassword($user,
                $pass);
        }
        if ($ok) {
            $context['AUTH_USER'] = strtolower($user);
            $context['STATE'] = 'READY';
            $this->queueWrite($key,
                "235 2.7.0 Authentication succeeded\r\n");
        } else {
            $context['STATE'] = 'READY';
            $this->queueWrite($key,
                "535 5.7.8 Authentication credentials" .
                " invalid\r\n");
        }
    }
    /**
     * Parses an address string from MAIL FROM or RCPT TO. Accepts
     * the strict RFC 5321 form "<addr>" and also the lenient
     * bareword form "addr" (which most live MTAs tolerate and
     * which is convenient for typing into telnet). Whitespace
     * around the address is ignored. Returns the address (which
     * may be the empty string for the null reverse-path "<>"),
     * or false if the line cannot be parsed.
     */
    protected function parseSmtpAddress($line, $verb)
    {
        $verb_pat = preg_quote(strtoupper($verb), '/');
        $rest_pat = '\s*:?\s*';
        if (strtoupper($verb) === 'MAIL') {
            $verb_pat = 'MAIL\s+FROM';
            $rest_pat = '\s*:\s*';
        } elseif (strtoupper($verb) === 'RCPT') {
            $verb_pat = 'RCPT\s+TO';
            $rest_pat = '\s*:\s*';
        }
        if (!preg_match("/^{$verb_pat}{$rest_pat}(.*)$/i",
            $line, $m)) {
            return false;
        }
        $tail = trim($m[1]);
        /*
            Tolerated forms:
                <addr>
                <>
                addr (bareword)
                <addr> SIZE=123 BODY=8BITMIME (parameters; we
                drop them)
                addr SIZE=123 (parameters with bareword)
            We split off the first whitespace-delimited token as
            the address candidate and discard the rest as ESMTP
            parameters; we do not currently honor SIZE= or other
            extensions but accepting them is harmless.
         */
        $space = strpos($tail, ' ');
        if ($space !== false) {
            $addr_tok = substr($tail, 0, $space);
        } else {
            $addr_tok = $tail;
        }
        if ($addr_tok === '') {
            return false;
        }
        if ($addr_tok[0] === '<') {
            $end = strpos($addr_tok, '>');
            if ($end === false) {
                return false;
            }
            return substr($addr_tok, 1, $end - 1);
        }
        return $addr_tok;
    }
    /**
     * Parses MAIL FROM and stores the envelope sender on the
     * connection. Accepts both "<addr>" and bareword "addr"
     * forms; accepts the empty path "<>" for DSN/bounce. The
     * session does not need to be authenticated to set a sender;
     * what is policed is the RCPT TO step. Fires the onMailFrom
     * hook; a 'reject' verdict refuses with 550 5.7.1.
     */
    protected function dispatchSmtpMailFrom($key, $line, &$context)
    {
        $addr = $this->parseSmtpAddress($line, 'MAIL');
        if ($addr === false) {
            $this->queueWrite($key,
                "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
            return;
        }
        $verdict = $this->runHooks('mailfrom',
            ['from' => $addr], $context);
        if ($verdict === 'reject' || $verdict === false) {
            $this->queueWrite($key,
                "550 5.7.1 Sender rejected\r\n");
            return;
        }
        $context['MAILFROM'] = $addr;
        $context['RCPTTO'] = [];
        $context['STATE'] = 'MAIL';
        $this->queueWrite($key, "250 2.1.0 Ok\r\n");
    }
    /**
     * Parses RCPT TO and applies the anti-relay rule:
     *   - if the recipient is local (a known user at a local
     *     domain), accept regardless of authentication
     *   - if the recipient is non-local, require that the
     *     session be authenticated; otherwise reject 550 5.7.1
     * This is what makes the server NOT an open relay. Fires
     * the onRcptTo hook only after the recipient has passed the
     * anti-relay check.
     */
    protected function dispatchSmtpRcptTo($key, $line, &$context)
    {
        if ($context['STATE'] !== 'MAIL' && $context['STATE'] !== 'RCPT') {
            $this->queueWrite($key,
                "503 5.5.1 need MAIL FROM first\r\n");
            return;
        }
        $addr = $this->parseSmtpAddress($line, 'RCPT');
        if ($addr === false || $addr === '') {
            $this->queueWrite($key,
                "501 5.5.4 Syntax: RCPT TO:<address>\r\n");
            return;
        }
        $local_user = $this->resolveLocalUser($addr);
        if ($local_user === false) {
            if (empty($context['AUTH_USER'])) {
                $this->queueWrite($key,
                    "550 5.7.1 Relay access denied\r\n");
                return;
            }
            /*
                Authenticated submission to a non-local recipient
                would be outbound relay. We do not implement an
                outbound queue in this phase, so reject with a
                clear message. A later phase can hook a smarthost
                or queue here.
             */
            $this->queueWrite($key,
                "550 5.7.1 Outbound relay not configured\r\n");
            return;
        }
        $verdict = $this->runHooks('rcptto',
            ['to' => $addr, 'local_user' => $local_user], $context);
        if ($verdict === 'reject' || $verdict === false) {
            $this->queueWrite($key,
                "550 5.7.1 Recipient rejected\r\n");
            return;
        }
        $context['RCPTTO'][] = ['addr' => $addr, 'user' => $local_user];
        $context['STATE'] = 'RCPT';
        $this->queueWrite($key, "250 2.1.5 Ok\r\n");
    }
    /**
     * Drains DATA bytes from the input buffer until it sees the
     * end-of-data sentinel CRLF.CRLF (or LF.LF as a tolerated
     * variant). Returns true once one full message has been
     * consumed (caller will loop and try the next command).
     * Performs CRLF dot-unstuffing per RFC 5321 sec 4.5.2.
     */
    protected function consumeSmtpDataPhase($key, &$buffer, &$context)
    {
        $marker = "\r\n.\r\n";
        $position = strpos($buffer, $marker);
        $marker_len = 5;
        if ($position === false) {
            $alternative = "\n.\n";
            $alt_pos = strpos($buffer, $alternative);
            if ($alt_pos === false) {
                return false;
            }
            $position = $alt_pos;
            $marker_len = 3;
        }
        $message = substr($buffer, 0, $position + 2);
        $buffer = substr($buffer, $position + $marker_len);
        $message = preg_replace('/(\r\n|\n)\.(\r\n|\n|\.)/',
            '$1$2', $message);
        $max = $this->default_server_globals['MAX_MESSAGE_LEN'];
        if (strlen($message) > $max) {
            $this->queueWrite($key,
                "552 5.3.4 Message exceeds size limit\r\n");
            $context['STATE'] = 'READY';
            $context['MAILFROM'] = null;
            $context['RCPTTO'] = [];
            return true;
        }
        /*
            Fire the onHeader hook before stamping our trace
            header, so policy can examine what the client sent
            unmodified. The header block ends at the first blank
            line; if there is no blank line the entire message
            is treated as headers (defensive: a malformed message
            without a body separator should still see the hook).
         */
        $headers = $this->parseRfc5322Headers($message);
        $first_to = !empty($context['RCPTTO']) ?
            $context['RCPTTO'][0]['addr'] : '';
        $hdr_info = [
            'from' => $context['MAILFROM'],
            'to' => $first_to,
            'recipients' => $context['RCPTTO'],
            'headers' => $headers['list'],
            'header_block' => $headers['block'],
            'bytes' => $message,
        ];
        $verdict = $this->runHooks('header', $hdr_info, $context);
        if ($verdict === 'reject' || $verdict === false) {
            $this->queueWrite($key,
                "550 5.6.0 Message rejected by policy\r\n");
            $context['STATE'] = 'READY';
            $context['MAILFROM'] = null;
            $context['RCPTTO'] = [];
            return true;
        }
        $message = $this->prependReceivedHeader($message, $context);
        $delivered_any = false;
        foreach ($context['RCPTTO'] as $r) {
            $uid = $this->deliverMail($context['MAILFROM'], $r['addr'],
                $message, $context);
            if ($uid !== false) {
                $delivered_any = true;
            }
        }
        $context['STATE'] = 'READY';
        $context['MAILFROM'] = null;
        $context['RCPTTO'] = [];
        if ($delivered_any) {
            $this->queueWrite($key,
                "250 2.0.0 Ok: message accepted\r\n");
        } else {
            /*
                All recipients filtered or unknown. We still
                respond 250 to the sender to avoid leaking
                filter or user-existence info; the message is
                just gone.
             */
            $this->queueWrite($key, "250 2.0.0 Ok\r\n");
        }
        return true;
    }
    /**
     * Splits an RFC 5322 message into the header block (string)
     * and a list of [name, value] pairs preserving order and
     * case. Continuation lines (RFC 5322 sec 2.2.3 folded white
     * space) are unfolded. The returned 'block' is the raw bytes
     * up to but not including the empty CRLF separator.
     */
    protected function parseRfc5322Headers($message)
    {
        $separator = "\r\n\r\n";
        $end = strpos($message, $separator);
        if ($end === false) {
            $end = strpos($message, "\n\n");
            $block = ($end === false) ? $message : substr($message, 0,
                $end);
        } else {
            $block = substr($message, 0, $end);
        }
        $list = [];
        $current_name = null;
        $current_val = "";
        foreach (preg_split('/\r\n|\n/', $block) as $line) {
            if ($line === "") {
                continue;
            }
            if ($line[0] === ' ' || $line[0] === "\t") {
                if ($current_name !== null) {
                    $current_val .= ' ' . trim($line);
                }
                continue;
            }
            if ($current_name !== null) {
                $list[] = [$current_name, $current_val];
            }
            $colon = strpos($line, ':');
            if ($colon === false) {
                $current_name = null;
                $current_val = "";
                continue;
            }
            $current_name = substr($line, 0, $colon);
            $current_val = ltrim(substr($line, $colon + 1));
        }
        if ($current_name !== null) {
            $list[] = [$current_name, $current_val];
        }
        return ['list' => $list, 'block' => $block];
    }
    /**
     * Prepends a Received: trace header per RFC 5321 sec 4.4.
     * Mail clients use this header to render the routing path
     * and SpamAssassin-class tools rely on it to reconstruct
     * the delivery chain. We include the remote address, our
     * server name, the protocol (ESMTPA when authenticated),
     * and the receipt timestamp.
     */
    protected function prependReceivedHeader($message, $context)
    {
        $name = $this->default_server_globals['SERVER_NAME'];
        $server_software =
            $this->default_server_globals['SERVER_SOFTWARE'];
        $with = empty($context['AUTH_USER']) ?
            'ESMTP' : 'ESMTPA';
        $now = gmdate("D, d M Y H:i:s") . " +0000";
        /*
            Defense in depth: Received: header values originate
            from the connection (REMOTE_ADDR), the wire RCPT TO
            line, and the server config (SERVER_NAME,
            SERVER_SOFTWARE). The wire path already strips
            line-level CR and LF before the address parser
            sees it, but a bug or a hook that mutates
            $context['RCPTTO'] could reintroduce them. Scrub
            CR and LF from every interpolated value so a
            malformed entry cannot inject a fake header.
         */
        $strip = function ($value) {
            return str_replace(["\r", "\n"], ['', ''],
                (string) $value);
        };
        $remote = $strip($context['REMOTE_ADDR']);
        $rcpt = "";
        if (!empty($context['RCPTTO'])) {
            $first = $context['RCPTTO'][0];
            $rcpt = "for <" . $strip($first['addr']) . ">";
        }
        $header_value = "Received: from [$remote] by " .
            $strip($name) . " (" . $strip($server_software) .
            ") with $with $rcpt; $now\r\n";
        return $header_value . $message;
    }
    /**
     * Top-level dispatcher for one IMAP command line. Splits
     * out the tag and the verb, then routes to a per-verb
     * handler based on the connection's IMAP STATE. The state
     * machine matches RFC 3501 sec 3:
     *   INIT     -- unauthenticated; only LOGIN, AUTHENTICATE,
     *               STARTTLS, CAPABILITY, NOOP, LOGOUT allowed
     *   AUTH     -- authenticated; mailbox-level commands and
     *               selection commands allowed
     *   SELECTED -- authenticated AND a mailbox is selected;
     *               adds CLOSE; in Phase 4 will add FETCH/STORE
     *               etc.
     * Tags are echoed back in the tagged status response.
     */
    protected function dispatchImap($key, $line, &$context)
    {
        if (!isset($context['IMAP_LIT_PENDING'])) {
            $context['IMAP_LIT_PENDING'] = null;
        }
        if ($context['IMAP_LIT_PENDING'] !== null) {
            $this->continueImapLiteral($key, $line, $context);
            return;
        }
        $tag = "*";
        $space_position = strpos($line, " ");
        $rest = "";
        if ($space_position !== false) {
            $tag = substr($line, 0, $space_position);
            $rest = substr($line, $space_position + 1);
        } else {
            /*
                A bare command word with no tag is a protocol
                violation. We respond with an untagged BAD so
                a misbehaving client at least sees an error.
             */
            $this->queueWrite($key, "* BAD missing tag\r\n");
            return;
        }
        $verb_end = strpos($rest, " ");
        $verb = ($verb_end === false) ? $rest :
            substr($rest, 0, $verb_end);
        $arguments = ($verb_end === false) ? "" :
            substr($rest, $verb_end + 1);
        $V = strtoupper($verb);
        /*
            Always-available commands: do not require any state.
         */
        if ($V === 'CAPABILITY') {
            $this->imapCmdCapability($key, $tag, $context);
            return;
        }
        if ($V === 'NOOP') {
            $this->imapOk($key, $tag, "NOOP");
            return;
        }
        if ($V === 'LOGOUT') {
            $this->queueWrite($key, "* BYE Logging out\r\n");
            $this->imapOk($key, $tag, "LOGOUT");
            $context['STATE'] = 'QUIT';
            return;
        }
        if ($V === 'STARTTLS') {
            $this->dispatchImapStarttls($key, $tag, $context);
            return;
        }
        if ($V === 'ID') {
            $this->imapCmdId($key, $tag, $arguments, $context);
            return;
        }
        /*
            Pre-authenticated commands (only allowed in INIT).
         */
        if ($context['STATE'] === 'INIT') {
            if ($V === 'LOGIN') {
                $this->imapCmdLogin($key, $tag, $arguments, $context);
                return;
            }
            if ($V === 'AUTHENTICATE') {
                $this->imapCmdAuthenticate($key, $tag, $arguments,
                    $context);
                return;
            }
            $this->imapResp($key, $tag, "NO", "Login required");
            return;
        }
        /*
            Authenticated-state and selected-state commands.
            Most are allowed in either AUTH or SELECTED state;
            CLOSE requires SELECTED.
         */
        if ($V === 'NAMESPACE') {
            $this->imapCmdNamespace($key, $tag, $context);
            return;
        }
        if ($V === 'LIST') {
            $this->imapCmdList($key, $tag, $arguments, $context, false);
            return;
        }
        if ($V === 'LSUB') {
            $this->imapCmdList($key, $tag, $arguments, $context, true);
            return;
        }
        if ($V === 'SUBSCRIBE' || $V === 'UNSUBSCRIBE') {
            /*
                We do not maintain per-user subscription state;
                LSUB returns the same list as LIST. SUBSCRIBE
                and UNSUBSCRIBE accept any name that resolves
                to an existing folder and OK without further
                effect.
             */
            $this->imapCmdSubscribe($key, $tag, $arguments, $V, $context);
            return;
        }
        if ($V === 'STATUS') {
            $this->imapCmdStatus($key, $tag, $arguments, $context);
            return;
        }
        if ($V === 'CREATE') {
            $this->imapCmdCreate($key, $tag, $arguments, $context);
            return;
        }
        if ($V === 'DELETE') {
            $this->imapCmdDelete($key, $tag, $arguments, $context);
            return;
        }
        if ($V === 'RENAME') {
            $this->imapCmdRename($key, $tag, $arguments, $context);
            return;
        }
        if ($V === 'SELECT' || $V === 'EXAMINE') {
            $this->imapCmdSelect($key, $tag, $arguments, $context,
                $V === 'EXAMINE');
            return;
        }
        if ($V === 'CLOSE') {
            $this->imapCmdClose($key, $tag, $context);
            return;
        }
        if ($V === 'APPEND') {
            $this->imapCmdAppend($key, $tag, $arguments, $context);
            return;
        }
        if ($V === 'IDLE') {
            $this->imapCmdIdle($key, $tag, $context);
            return;
        }
        /*
            Selected-state commands. FETCH, STORE, COPY, MOVE,
            EXPUNGE, SEARCH, and the UID-prefixed variants
            require a SELECTED mailbox.
         */
        if ($V === 'UID') {
            $this->imapCmdUid($key, $tag, $arguments, $context);
            return;
        }
        $needs_selected = in_array($V, ['FETCH', 'STORE', 'COPY',
            'MOVE', 'EXPUNGE', 'SEARCH'], true);
        if ($needs_selected && $context['STATE'] !== 'SELECTED') {
            $this->imapResp($key, $tag, "NO", "No mailbox selected");
            return;
        }
        if ($V === 'FETCH') {
            $this->imapCmdFetch($key, $tag, $arguments, $context, false);
            return;
        }
        if ($V === 'STORE') {
            $this->imapCmdStore($key, $tag, $arguments, $context, false);
            return;
        }
        if ($V === 'COPY') {
            $this->imapCmdCopy($key, $tag, $arguments, $context, false);
            return;
        }
        if ($V === 'MOVE') {
            $this->imapCmdMove($key, $tag, $arguments, $context, false);
            return;
        }
        if ($V === 'EXPUNGE') {
            $this->imapCmdExpunge($key, $tag, $context);
            return;
        }
        if ($V === 'SEARCH') {
            $this->imapCmdSearch($key, $tag, $arguments, $context, false);
            return;
        }
        $this->imapResp($key, $tag, "BAD",
            "command not implemented in this build");
    }
    /**
     * Sends an untagged CAPABILITY response and tags it OK.
     * Capability advertisement varies based on TLS state and
     * authentication state, both of which imapPreAuthCapabilities
     * handles. Once the client is authenticated, STARTTLS and
     * LOGINDISABLED stop being relevant; the spec lets us
     * advertise the same string post-auth.
     */
    protected function imapCmdCapability($key, $tag, $context)
    {
        $capabilities = $this->imapPreAuthCapabilities(
            !empty($context['TLS_ACTIVE']));
        $this->queueWrite($key, "* $capabilities\r\n");
        $this->imapOk($key, $tag, "CAPABILITY");
    }
    /**
     * Handles ID (RFC 2971): a non-protocol-affecting exchange
     * where the client sends a paren-list of name/value
     * strings identifying itself, and the server replies with
     * its own identification. We accept and discard the
     * client's data (no use for it) and reply with the
     * server's name and version. NIL is a valid argument
     * meaning the client wishes to identify nothing; we
     * accept that and still reply with our own identification.
     */
    protected function imapCmdId($key, $tag, $arguments, $context)
    {
        $name = $this->default_server_globals['SERVER_NAME'];
        $server_software = $this->default_server_globals['SERVER_SOFTWARE'];
        $this->queueWrite($key,
            "* ID (\"name\" \"$server_software\" \"vendor\" \"$name\")\r\n");
        $this->imapOk($key, $tag, "ID");
    }
    /**
     * Handles NAMESPACE (RFC 2342): tells the client about
     * personal, other-users, and shared mailbox namespaces.
     * We have a single personal namespace using "/" as the
     * hierarchy delimiter, and no other-users / shared
     * namespaces. The reply form is three nested paren-lists
     * separated by spaces.
     */
    protected function imapCmdNamespace($key, $tag, $context)
    {
        $this->queueWrite($key,
            "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n");
        $this->imapOk($key, $tag, "NAMESPACE");
    }
    /**
     * Handles "LOGIN <user> <pass>". Refuses if TLS is required
     * (matches the LOGINDISABLED capability) and the connection
     * is plaintext. Both arguments may be atoms, quoted
     * strings, or literals; this implementation accepts atoms
     * and quoted strings inline and the password as a literal
     * for clients that send unprintable bytes (the literal
     * continuation arrives as the next line through
     * continueImapLiteral).
     */
    protected function imapCmdLogin($key, $tag, $arguments, &$context)
    {
        $allow_plain =
            !empty($this->default_server_globals[
                'ALLOW_PLAINTEXT_AUTH']);
        if (empty($context['TLS_ACTIVE']) && !$allow_plain) {
            $this->queueWrite($key,
                "$tag NO [PRIVACYREQUIRED] " .
                "STARTTLS required before LOGIN\r\n");
            return;
        }
        $tokens = $this->parseImapTokens($arguments);
        if (count($tokens) === 1 && $tokens[0][0] === 'literal') {
            /*
                LOGIN with a literal username triggers the
                continuation flow: server sends "+ Ready" and
                accepts the literal bytes on the next line.
                Our literal collector keeps accumulated tokens
                in IMAP_LIT_BUFFER for the eventual full
                command. This case is rare in practice; most
                clients send LOGIN with quoted strings.
             */
            $context['IMAP_LIT_PENDING'] = [
                'remaining' => $tokens[0][1],
                'collected' => [],
                'continuation' => 'login',
                'tag' => $tag,
            ];
            $this->queueWrite($key, "+ Ready for literal\r\n");
            return;
        }
        if (count($tokens) < 2 || $tokens[0][0] === 'literal' ||
            $tokens[1][0] === 'literal') {
            $this->imapResp($key, $tag, "BAD", "LOGIN syntax");
            return;
        }
        $this->finishImapLogin($key, $tag, $tokens[0][1],
            $tokens[1][1], $context);
    }
    /**
     * Final step of IMAP LOGIN: verify credentials, ensure the
     * user's storage is provisioned, and transition the
     * connection to AUTH state. Invoked from the inline path
     * (imapCmdLogin) and from the literal-continuation path
     * (continueImapLiteral).
     */
    protected function finishImapLogin($key, $tag, $user, $pass,
        &$context)
    {
        if ($this->authenticator === null ||
            !$this->authenticator->verifyPassword($user, $pass)) {
            $this->queueWrite($key,
                "$tag NO [AUTHENTICATIONFAILED] " .
                "Authentication failed\r\n");
            return;
        }
        $context['AUTH_USER'] = strtolower($user);
        $context['STATE'] = 'AUTH';
        if ($this->mail_storage !== null) {
            $this->mail_storage->ensureUser($context['AUTH_USER']);
        }
        $this->queueWrite($key,
            "$tag OK [CAPABILITY IMAP4rev1 IDLE] LOGIN " .
            "completed\r\n");
    }
    /**
     * Handles AUTHENTICATE PLAIN and AUTHENTICATE LOGIN. PLAIN
     * uses a single base64 blob in the same "\0user\0pass"
     * format as SMTP AUTH PLAIN; LOGIN uses the two-step
     * username-then-password continuation. The mechanism name
     * is the only positional argument here; everything else
     * arrives via continueImapLiteral on subsequent lines.
     */
    protected function imapCmdAuthenticate($key, $tag, $arguments, &$context)
    {
        $allow_plain =
            !empty($this->default_server_globals[
                'ALLOW_PLAINTEXT_AUTH']);
        if (empty($context['TLS_ACTIVE']) && !$allow_plain) {
            $this->queueWrite($key,
                "$tag NO [PRIVACYREQUIRED] " .
                "STARTTLS required before AUTHENTICATE\r\n");
            return;
        }
        $mech = strtoupper(trim($arguments));
        if ($mech === 'PLAIN') {
            $context['IMAP_LIT_PENDING'] = [
                'continuation' => 'auth-plain',
                'tag' => $tag,
            ];
            $this->queueWrite($key, "+ \r\n");
            return;
        }
        if ($mech === 'LOGIN') {
            $context['IMAP_LIT_PENDING'] = [
                'continuation' => 'auth-login-user',
                'tag' => $tag,
            ];
            $this->queueWrite($key,
                "+ " . base64_encode("Username:") . "\r\n");
            return;
        }
        $this->imapResp($key, $tag, "NO", "[CANNOT] Unsupported mechanism");
    }
    /**
     * Drives the multi-line continuations for AUTHENTICATE and
     * for LOGIN literals. The pending-state record carries a
     * "continuation" key naming the expected next phase; once
     * the final line arrives we finish the operation and clear
     * the pending slot.
     */
    protected function continueImapLiteral($key, $line, &$context)
    {
        $pend = $context['IMAP_LIT_PENDING'];
        $tag = $pend['tag'];
        $continuation = $pend['continuation'];
        if ($continuation === 'auth-plain') {
            $context['IMAP_LIT_PENDING'] = null;
            $raw = (string) base64_decode(trim($line), true);
            $parts = explode("\x00", $raw);
            if (count($parts) !== 3) {
                $this->queueWrite($key,
                    "$tag NO [AUTHENTICATIONFAILED] " .
                    "Authentication failed\r\n");
                return;
            }
            list(, $user, $pass) = $parts;
            $this->finishImapLogin($key, $tag, $user, $pass,
                $context);
            return;
        }
        if ($continuation === 'auth-login-user') {
            $user = (string) base64_decode(trim($line), true);
            $context['IMAP_LIT_PENDING'] = [
                'continuation' => 'auth-login-pass',
                'tag' => $tag,
                'user' => $user,
            ];
            $this->queueWrite($key,
                "+ " . base64_encode("Password:") . "\r\n");
            return;
        }
        if ($continuation === 'auth-login-pass') {
            $context['IMAP_LIT_PENDING'] = null;
            $pass = (string) base64_decode(trim($line), true);
            $this->finishImapLogin($key, $tag, $pend['user'],
                $pass, $context);
            return;
        }
        if ($continuation === 'login') {
            $context['IMAP_LIT_PENDING'] = null;
            /*
                Phase 3 only supports LOGIN literals as a
                fall-back; production clients send LOGIN with
                quoted strings. We do not currently chain a
                second literal for the password.
             */
            $this->imapResp($key, $tag, "BAD",
                "literal LOGIN not fully implemented");
            return;
        }
        if ($continuation === 'append') {
            /*
                APPEND finalization. processOne has already
                drained the byte-counted body into the pending
                record's 'collected' slot and stripped the
                trailing CRLF, so all that's left is to deliver
                the message and emit the tagged OK with a
                [APPENDUID validity uid] response code so the
                client can update its UID cache.
             */
            $folder = $pend['folder'];
            $flags = $pend['flags'];
            $internal_date = $pend['internal_date'];
            $bytes = $pend['collected'];
            $context['IMAP_LIT_PENDING'] = null;
            $user = $context['AUTH_USER'];
            if (!$this->mail_storage->folderExists($user,
                $folder)) {
                $this->queueWrite($key,
                    "$tag NO [TRYCREATE] Mailbox does not " .
                    "exist\r\n");
                return;
            }
            $uid = $this->mail_storage->appendMessage($user,
                $folder, $bytes, $flags, $internal_date);
            if ($uid === false) {
                $this->imapResp($key, $tag, "NO", "APPEND failed");
                return;
            }
            $this->bumpMailboxChange($user, $folder);
            $validity = $this->mail_storage->uidValidity($user,
                $folder);
            $this->queueWrite($key,
                "$tag OK [APPENDUID $validity $uid] " .
                "APPEND completed\r\n");
            return;
        }
        if ($continuation === 'idle') {
            /*
                RFC 2177: while idling, the client sends "DONE"
                on its own line to terminate. Anything else
                during idle is a protocol error per the RFC,
                but we are lenient and just keep waiting if the
                client sends an empty line; non-empty non-DONE
                lines get a BAD response and the idle ends.
             */
            $upper = strtoupper(trim($line));
            if ($upper === 'DONE') {
                $this->clearImapIdleState($context);
                $this->queueWrite($key,
                    "$tag OK IDLE terminated\r\n");
                return;
            }
            if ($upper === '') {
                /* keep idling */
                return;
            }
            $this->clearImapIdleState($context);
            $this->imapResp($key, $tag, "BAD", "Expected DONE");
            return;
        }
        $context['IMAP_LIT_PENDING'] = null;
        $this->queueWrite($key, "$tag BAD continuation lost\r\n");
    }
    /**
     * Tokenizes the argument tail of an IMAP command into a
     * list of [type, value] pairs. Recognized types:
     *   'atom'    -- bare unquoted token
     *   'quoted'  -- characters between matching double-quotes
     *                with backslash-escaped " and \
     *   'literal' -- {N} synchronizing literal; the value is
     *                the byte count, the actual bytes arrive
     *                on the next line and must be reassembled
     *                by the caller via continueImapLiteral
     * NIL is decoded as an atom with the literal value "NIL".
     * Whitespace between tokens is consumed but not represented.
     * Returns an empty array on a parse error mid-string; the
     * caller should treat that as BAD syntax.
     */
    protected function parseImapTokens($s)
    {
        $tokens = [];
        $i = 0;
        $n = strlen($s);
        while ($i < $n) {
            $c = $s[$i];
            if ($c === ' ' || $c === "\t") {
                $i++;
                continue;
            }
            if ($c === '"') {
                $j = $i + 1;
                $value = '';
                while ($j < $n && $s[$j] !== '"') {
                    if ($s[$j] === '\\' && $j + 1 < $n) {
                        $value .= $s[$j + 1];
                        $j += 2;
                        continue;
                    }
                    $value .= $s[$j];
                    $j++;
                }
                if ($j >= $n) {
                    return [];
                }
                $tokens[] = ['quoted', $value];
                $i = $j + 1;
                continue;
            }
            if ($c === '{') {
                $end = strpos($s, '}', $i);
                if ($end === false) {
                    return [];
                }
                $count = (int) substr($s, $i + 1, $end - $i - 1);
                $tokens[] = ['literal', $count];
                $i = $end + 1;
                continue;
            }
            if ($c === '(') {
                /*
                    Parenthesized list: keep all contents as one
                    'list' token. Nested lists are flattened
                    into the outer paren count, which is fine
                    for the IMAP commands we handle in Phase 3
                    where lists are flat (status items, search
                    keys etc).
                 */
                $depth = 1;
                $j = $i + 1;
                while ($j < $n && $depth > 0) {
                    if ($s[$j] === '(') {
                        $depth++;
                    } else if ($s[$j] === ')') {
                        $depth--;
                        if ($depth === 0) {
                            break;
                        }
                    }
                    $j++;
                }
                if ($depth !== 0) {
                    return [];
                }
                $tokens[] = ['list',
                    substr($s, $i + 1, $j - $i - 1)];
                $i = $j + 1;
                continue;
            }
            /*
                Bare atom: take everything up to the next
                whitespace or end of string. List arguments
                like "(\Seen \Answered)" or "(MESSAGES UNSEEN)"
                are atoms in the IMAP grammar; we keep the
                parens as part of the atom and let the caller
                strip them.
             */
            $j = $i;
            while ($j < $n && $s[$j] !== ' ' &&
                $s[$j] !== "\t") {
                $j++;
            }
            $tokens[] = ['atom', substr($s, $i, $j - $i)];
            $i = $j;
        }
        return $tokens;
    }
    /**
     * Convenience: pull the first string-valued token from a
     * tokens list, returning false if the list is empty or the
     * first token is a literal (literals require continuation
     * handling and cannot be returned synchronously).
     */
    protected function tokenString($tokens, $index)
    {
        if (!isset($tokens[$index])) {
            return false;
        }
        $token = $tokens[$index];
        if ($token[0] === 'atom' || $token[0] === 'quoted') {
            return $token[1];
        }
        return false;
    }
    /**
     * Handles LIST and LSUB. Both have the same syntax:
     *      LIST <reference> <mailbox-pattern>
     * where reference is usually "" (or sometimes "INBOX") and
     * the pattern can include "*" (any chars) or "%" (any chars
     * except hierarchy delimiter). Two special cases per
     * RFC 3501 sec 6.3.8:
     *   - empty mailbox argument: server returns the hierarchy
     *     delimiter and root, used by clients to discover the
     *     separator
     *   - "%" with empty reference: returns top-level folders
     * RFC 5258 extends LIST with selection options preceding
     * the reference, e.g. "LIST (SPECIAL-USE) "" "*"" to ask
     * only for special-use folders. We accept these but do not
     * filter on them; the response includes special-use
     * attributes either way, which is the point of the
     * SPECIAL-USE capability.
     * We implement the regex translation locally so we do not
     * need to push wildcard semantics down into MailStorage.
     */
    protected function imapCmdList($key, $tag, $arguments, &$context,
        $is_lsub)
    {
        $verb = $is_lsub ? 'LSUB' : 'LIST';
        /*
            Strip an optional leading selection-options list
            (RFC 5258). We do not currently filter on these,
            but accepting them is necessary so clients that
            send "LIST (SPECIAL-USE) ..." do not get a syntax
            error. We also strip an optional trailing RETURN
            options list, e.g. "LIST "" "*" RETURN (SUBSCRIBED
            CHILDREN SPECIAL-USE)".
         */
        $args_trimmed = ltrim($arguments);
        if ($args_trimmed !== '' && $args_trimmed[0] === '(') {
            $depth = 1;
            $i = 1;
            $n = strlen($args_trimmed);
            while ($i < $n && $depth > 0) {
                if ($args_trimmed[$i] === '(') $depth++;
                else if ($args_trimmed[$i] === ')') $depth--;
                $i++;
            }
            $args_trimmed = ltrim(substr($args_trimmed, $i));
        }
        $tokens = $this->parseImapTokens($args_trimmed);
        $reference = $this->tokenString($tokens, 0);
        $pattern = $this->tokenString($tokens, 1);
        if ($reference === false || $pattern === false) {
            $this->imapResp($key, $tag, "BAD", "$verb syntax");
            return;
        }
        if ($pattern === '') {
            /*
                Empty pattern: respond with the hierarchy
                delimiter and an empty mailbox name, then OK.
             */
            $this->queueWrite($key,
                "* $verb (\\Noselect) \"/\" \"\"\r\n");
            $this->queueWrite($key,
                "$tag OK $verb completed\r\n");
            return;
        }
        $user = $context['AUTH_USER'];
        $folders = $this->mail_storage->listFolders($user);
        /*
            Make sure INBOX is always reported even if the
            storage has not provisioned its directory yet
            (some clients LIST before any message has arrived).
         */
        if (!in_array('INBOX', $folders, true)) {
            $folders[] = 'INBOX';
            sort($folders);
        }
        if ($is_lsub) {
            /*
                LSUB filters to the subscribed set per RFC 3501
                sec 6.3.9. INBOX is implicitly subscribed even
                without a SUBSCRIBE command. We intersect the
                subscribed list with the existing-folders list
                so that LSUB does not advertise folders the
                user has subscribed to but which no longer
                exist (RFC 3501 actually permits returning
                non-existent subscribed folders as well, but
                most clients render them awkwardly).
             */
            $subscribed = $this->mail_storage->listSubscribed(
                $user);
            $folders = array_values(array_intersect($folders,
                $subscribed));
        }
        $combined = $reference === '' ? $pattern :
            $reference . $pattern;
        $regex = $this->imapPatternToRegex($combined);
        foreach ($folders as $folder_name) {
            if (preg_match($regex, $folder_name)) {
                $attrs = $this->imapFolderAttrs($folder_name,
                    $folders);
                $name = $this->imapEncodeMailboxName(
                    $folder_name);
                $this->queueWrite($key,
                    "* $verb ($attrs) \"/\" $name\r\n");
            }
        }
        $this->queueWrite($key, "$tag OK $verb completed\r\n");
    }
    /**
     * Returns the IMAP attribute string for a folder in a
     * LIST / LSUB response. Combines two flag families:
     *   1. Children attributes (RFC 3348): \HasChildren or
     *      \HasNoChildren based on whether any other folder
     *      starts with "<this>/". Modern clients use these
     *      to render the folder tree.
     *   2. Special-use attributes (RFC 6154): \Drafts, \Sent,
     *      \Trash, \Junk, \Archive, \All for folders whose
     *      name matches the convention. INBOX is excluded
     *      since RFC 6154 reserves the special-use flags for
     *      non-INBOX folders.
     * The returned string is space-separated and may be empty.
     */
    protected function imapFolderAttrs($folder, $all_folders)
    {
        $attrs = [];
        $prefix = $folder . '/';
        $has_children = false;
        foreach ($all_folders as $other) {
            if ($other !== $folder &&
                strpos($other, $prefix) === 0) {
                $has_children = true;
                break;
            }
        }
        $attrs[] = $has_children ? '\HasChildren' :
            '\HasNoChildren';
        $special = $this->imapSpecialUseAttr($folder);
        if ($special !== null) {
            $attrs[] = $special;
        }
        return implode(' ', $attrs);
    }
    /**
     * Returns the RFC 6154 special-use attribute for a
     * folder, or null if it is not a special folder. The
     * mapping is by conventional name and is case-
     * insensitive. INBOX is intentionally not flagged because
     * RFC 6154 sec 2 says the special-use attributes apply
     * to non-INBOX folders. Sub-folders under a special-use
     * parent (e.g. "Archive/2025") are not flagged.
     */
    protected function imapSpecialUseAttr($folder)
    {
        if (strpos($folder, '/') !== false) {
            return null;
        }
        $name = strtolower($folder);
        $map = [
            'inbox' => null,
            'drafts' => '\Drafts',
            'draft' => '\Drafts',
            'sent' => '\Sent',
            'sent items' => '\Sent',
            'sent messages' => '\Sent',
            'trash' => '\Trash',
            'deleted' => '\Trash',
            'deleted items' => '\Trash',
            'deleted messages' => '\Trash',
            'junk' => '\Junk',
            'spam' => '\Junk',
            'archive' => '\Archive',
            'archives' => '\Archive',
            'all mail' => '\All',
            'all' => '\All',
        ];
        return isset($map[$name]) ? $map[$name] : null;
    }
    /**
     * Converts an IMAP LIST/LSUB pattern to a PCRE regex.
     * Wildcards: "*" matches any sequence of characters
     * including the hierarchy delimiter; "%" matches any
     * sequence not containing the delimiter. All other regex
     * metacharacters are escaped.
     */
    protected function imapPatternToRegex($pattern)
    {
        $output = '';
        $n = strlen($pattern);
        for ($i = 0; $i < $n; $i++) {
            $c = $pattern[$i];
            if ($c === '*') {
                $output .= '.*';
            } else if ($c === '%') {
                $output .= '[^/]*';
            } else {
                $output .= preg_quote($c, '#');
            }
        }
        return '#^' . $output . '$#';
    }
    /**
    /**
     * Renders a folder name for inclusion in an IMAP response.
     * If the name is a printable ASCII atom (no spaces, no
     * special chars) it is returned bare; otherwise it is
     * wrapped in double-quotes with " and \ escaped. CR and
     * LF bytes are stripped because they would terminate the
     * IMAP response line and let a maliciously named folder
     * inject untagged responses (response splitting). RFC
     * 3501 also allows literals here, but quoted strings are
     * easier for clients to parse and sufficient for our
     * folder namespace.
     */
    protected function imapEncodeMailboxName($name)
    {
        $name = str_replace(["\r", "\n"], ['', ''],
            (string) $name);
        if (preg_match('#^[A-Za-z0-9./_-]+$#', $name)) {
            return $name;
        }
        $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'],
            $name);
        return '"' . $escaped . '"';
    }
    /**
     * Handles SUBSCRIBE and UNSUBSCRIBE: persists the
     * subscription decision through the storage layer's
     * subscribe / unsubscribe methods. RFC 3501 sec 6.3.6
     * says SUBSCRIBE may target a non-existent mailbox (a
     * remote-shared folder might be temporarily offline);
     * we follow that: SUBSCRIBE returns OK regardless of
     * whether the mailbox exists, while UNSUBSCRIBE on a
     * never-subscribed folder returns OK as a no-op
     * (idempotency per RFC 3501 sec 6.3.7).
     */
    protected function imapCmdSubscribe($key, $tag, $arguments, $verb,
        &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $name = $this->tokenString($tokens, 0);
        if ($name === false || $name === '') {
            $this->imapResp($key, $tag, "BAD", "$verb syntax");
            return;
        }
        $user = $context['AUTH_USER'];
        if ($verb === 'SUBSCRIBE') {
            $this->mail_storage->subscribe($user, $name);
        } else {
            $this->mail_storage->unsubscribe($user, $name);
        }
        $this->queueWrite($key, "$tag OK $verb completed\r\n");
    }
    /**
     * Handles STATUS <mailbox> (<items...>). The items list
     * names attributes the client wants reported: any of
     * MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN. Returns
     * an untagged STATUS response then the tagged OK. Folder
     * is NOT made the selected mailbox.
     */
    protected function imapCmdStatus($key, $tag, $arguments, &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $folder = $this->tokenString($tokens, 0);
        $items_str = false;
        if (isset($tokens[1])) {
            if ($tokens[1][0] === 'list') {
                $items_str = $tokens[1][1];
            } else if ($tokens[1][0] === 'atom' ||
                $tokens[1][0] === 'quoted') {
                $items_str = trim($tokens[1][1], '()');
            }
        }
        if ($folder === false || $items_str === false) {
            $this->imapResp($key, $tag, "BAD", "STATUS syntax");
            return;
        }
        $items = preg_split('/\s+/', trim($items_str));
        $user = $context['AUTH_USER'];
        if (!$this->mail_storage->folderExists($user, $folder)) {
            $this->imapResp($key, $tag, "NO", "Mailbox does not exist");
            return;
        }
        $stat = $this->imapFolderStats($user, $folder);
        $parts = [];
        foreach ($items as $item) {
            $item_upper = strtoupper($item);
            if ($item_upper === 'MESSAGES') {
                $parts[] = "MESSAGES " . $stat['messages'];
            } else if ($item_upper === 'RECENT') {
                $parts[] = "RECENT " . $stat['recent'];
            } else if ($item_upper === 'UIDNEXT') {
                $parts[] = "UIDNEXT " . $stat['uidnext'];
            } else if ($item_upper === 'UIDVALIDITY') {
                $parts[] = "UIDVALIDITY " . $stat['uidvalidity'];
            } else if ($item_upper === 'UNSEEN') {
                $parts[] = "UNSEEN " . $stat['unseen'];
            }
        }
        $name = $this->imapEncodeMailboxName($folder);
        $this->queueWrite($key,
            "* STATUS $name (" . implode(' ', $parts) . ")\r\n");
        $this->imapOk($key, $tag, "STATUS");
    }
    /**
     * Computes the metrics SELECT/EXAMINE/STATUS need for a
     * folder: total message count, RECENT count (\Recent flag),
     * UNSEEN UID (UID of the first message lacking \Seen, or
     * 0 if all are seen), and the UIDNEXT / UIDVALIDITY values.
     * Folders with no messages still report well-defined zero/
     * one values rather than failing.
     */
    protected function imapFolderStats($user, $folder)
    {
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        $count = count($messages);
        $recent = 0;
        $unseen_uid = 0;
        $first_unseen_seq = 0;
        foreach ($messages as $index => $m) {
            if (in_array('\Recent', $m['flags'], true)) {
                $recent++;
            }
            if ($first_unseen_seq === 0 &&
                !in_array('\Seen', $m['flags'], true)) {
                $first_unseen_seq = $index + 1;
                $unseen_uid = $m['uid'];
            }
        }
        return [
            'messages' => $count,
            'recent' => $recent,
            'unseen' => $unseen_uid,
            'unseen_seq' => $first_unseen_seq,
            'uidnext' => $this->mail_storage->uidNext($user,
                $folder),
            'uidvalidity' => $this->mail_storage->uidValidity(
                $user, $folder),
        ];
    }
    /**
     * Handles CREATE <mailbox>. Refuses to create INBOX (it
     * already exists) or names that fail the storage layer's
     * folder validation.
     */
    protected function imapCmdCreate($key, $tag, $arguments, &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $name = $this->tokenString($tokens, 0);
        if ($name === false || $name === '') {
            $this->imapResp($key, $tag, "BAD", "CREATE syntax");
            return;
        }
        $user = $context['AUTH_USER'];
        if ($this->mail_storage->folderExists($user, $name)) {
            $this->imapResp($key, $tag, "NO", "Mailbox already exists");
            return;
        }
        try {
            $ok = $this->mail_storage->createFolder($user, $name);
        } catch (\InvalidArgumentException $e) {
            $this->imapResp($key, $tag, "NO", "Invalid mailbox name");
            return;
        }
        if (!$ok) {
            $this->imapResp($key, $tag, "NO", "CREATE failed");
            return;
        }
        /*
            Auto-subscribe newly created folders. Most clients
            (Apple Mail, Thunderbird) issue a SUBSCRIBE right
            after CREATE anyway, but doing it server-side
            covers the case of CREATE via the direct API and
            ensures LSUB advertises new folders without any
            extra round-trip.
         */
        $this->mail_storage->subscribe($user, $name);
        $this->imapOk($key, $tag, "CREATE");
    }
    /**
     * Handles DELETE <mailbox>. The storage layer refuses to
     * delete INBOX or a folder with subfolders; we propagate
     * those as NO responses.
     */
    protected function imapCmdDelete($key, $tag, $arguments, &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $name = $this->tokenString($tokens, 0);
        if ($name === false || $name === '') {
            $this->imapResp($key, $tag, "BAD", "DELETE syntax");
            return;
        }
        $user = $context['AUTH_USER'];
        if (!$this->mail_storage->folderExists($user, $name)) {
            $this->imapResp($key, $tag, "NO", "Mailbox does not exist");
            return;
        }
        if (!$this->mail_storage->deleteFolder($user, $name)) {
            $this->queueWrite($key,
                "$tag NO Cannot delete (INBOX, " .
                "non-empty parent, or I/O error)\r\n");
            return;
        }
        /*
            Folder is gone; remove any matching subscription so
            LSUB does not advertise a non-existent folder.
         */
        $this->mail_storage->unsubscribe($user, $name);
        /*
            If the deleted mailbox was the currently selected
            one, drop selection so subsequent message-level
            commands fail cleanly rather than operating on a
            phantom mailbox.
         */
        if (!empty($context['SELECTED']) &&
            $context['SELECTED'] === $name) {
            $context['SELECTED'] = null;
            $context['STATE'] = 'AUTH';
        }
        $this->imapOk($key, $tag, "DELETE");
    }
    /**
     * Handles RENAME <old> <new>. INBOX is not renameable. If
     * the renamed folder was selected, selection updates to
     * the new name so the SELECTED state stays consistent.
     */
    protected function imapCmdRename($key, $tag, $arguments, &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $old = $this->tokenString($tokens, 0);
        $new = $this->tokenString($tokens, 1);
        if ($old === false || $new === false ||
            $old === '' || $new === '') {
            $this->imapResp($key, $tag, "BAD", "RENAME syntax");
            return;
        }
        $user = $context['AUTH_USER'];
        if (!$this->mail_storage->folderExists($user, $old)) {
            $this->imapResp($key, $tag, "NO", "Source mailbox does not exist");
            return;
        }
        if (!$this->mail_storage->renameFolder($user, $old,
            $new)) {
            $this->imapResp($key, $tag, "NO", "RENAME failed");
            return;
        }
        /*
            Migrate the subscription state with the rename so
            the user's view of LSUB stays consistent.
         */
        if ($this->mail_storage->isSubscribed($user, $old)) {
            $this->mail_storage->unsubscribe($user, $old);
            $this->mail_storage->subscribe($user, $new);
        }
        if (!empty($context['SELECTED']) &&
            $context['SELECTED'] === $old) {
            $context['SELECTED'] = $new;
        }
        $this->imapOk($key, $tag, "RENAME");
    }
    /**
     * Handles SELECT and EXAMINE: open a mailbox for message-
     * level access (SELECT) or read-only inspection (EXAMINE).
     * Returns the standard required untagged responses (EXISTS,
     * RECENT, FLAGS, OK [PERMANENTFLAGS], OK [UIDVALIDITY],
     * OK [UIDNEXT], optional OK [UNSEEN]) followed by the
     * tagged OK [READ-WRITE] or OK [READ-ONLY]. After SELECT
     * the connection STATE is SELECTED.
     */
    protected function imapCmdSelect($key, $tag, $arguments, &$context,
        $is_examine)
    {
        $verb = $is_examine ? 'EXAMINE' : 'SELECT';
        $tokens = $this->parseImapTokens($arguments);
        $folder = $this->tokenString($tokens, 0);
        if ($folder === false) {
            $this->imapResp($key, $tag, "BAD", "$verb syntax");
            return;
        }
        if ($folder === '') {
            /*
                Empty mailbox name. Some clients (Apple Mail
                in particular) issue "SELECT """ as a recovery
                step when they want to deselect without using
                CLOSE. RFC 3501 leaves this case undefined;
                the polite reaction is NO with a clear reason
                rather than BAD, so the client knows we
                understood the syntax but rejected the
                operation. The client typically follows up
                with a real SELECT INBOX immediately after.
             */
            $this->imapResp($key, $tag, "NO", "Empty mailbox name");
            return;
        }
        $user = $context['AUTH_USER'];
        if (!$this->mail_storage->folderExists($user, $folder)) {
            /*
                INBOX should auto-exist; ensureUser created it.
                For any other unknown folder, return NO without
                changing selection state.
             */
            $this->imapResp($key, $tag, "NO", "Mailbox does not exist");
            return;
        }
        $stat = $this->imapFolderStats($user, $folder);
        $flags = '\Answered \Flagged \Deleted \Seen \Draft';
        $this->queueWrite($key,
            "* " . $stat['messages'] . " EXISTS\r\n");
        $this->queueWrite($key,
            "* " . $stat['recent'] . " RECENT\r\n");
        if ($stat['unseen_seq'] > 0) {
            $this->queueWrite($key,
                "* OK [UNSEEN " . $stat['unseen_seq'] .
                "] First unseen message\r\n");
        }
        $this->queueWrite($key,
            "* OK [UIDVALIDITY " . $stat['uidvalidity'] .
            "] UIDs valid\r\n");
        $this->queueWrite($key,
            "* OK [UIDNEXT " . $stat['uidnext'] .
            "] Predicted next UID\r\n");
        $this->queueWrite($key,
            "* FLAGS ($flags)\r\n");
        $this->queueWrite($key,
            "* OK [PERMANENTFLAGS ($flags \\*)] " .
            "Limited\r\n");
        $access = $is_examine ? 'READ-ONLY' : 'READ-WRITE';
        $context['SELECTED'] = $folder;
        $context['SELECTED_READONLY'] = $is_examine;
        $context['STATE'] = 'SELECTED';
        $this->queueWrite($key,
            "$tag OK [$access] $verb completed\r\n");
    }
    /**
     * Handles CLOSE: leave SELECTED state and return to AUTH
     * state. RFC 3501 sec 6.4.2 says CLOSE silently expunges
     * \Deleted messages; Phase 4 will add that semantics
     * along with the EXPUNGE command. For Phase 3 CLOSE just
     * deselects so navigation between folders works.
     */
    protected function imapCmdClose($key, $tag, &$context)
    {
        if ($context['STATE'] !== 'SELECTED') {
            $this->imapResp($key, $tag, "BAD", "CLOSE without SELECT");
            return;
        }
        $context['SELECTED'] = null;
        $context['SELECTED_READONLY'] = false;
        $context['STATE'] = 'AUTH';
        $this->imapOk($key, $tag, "CLOSE");
    }
    /**
     * Handles UID-prefixed variants of FETCH, STORE, COPY,
     * MOVE, and SEARCH. RFC 3501 sec 6.4.8 defines these as
     * "operate by UID rather than by sequence number"; the
     * argument syntax after the verb is identical, only the
     * interpretation of the message-set numbers changes. We
     * dispatch to the same handlers as the non-UID variants
     * with a flag set so they treat the message-set as UIDs
     * and emit "* N FETCH (... UID U ...)" with both the
     * sequence number AND the UID, as required by RFC 3501
     * sec 6.4.8: "any data items returned MUST include the
     * UID data item".
     */
    protected function imapCmdUid($key, $tag, $arguments, &$context)
    {
        if ($context['STATE'] !== 'SELECTED') {
            $this->imapResp($key, $tag, "NO", "No mailbox selected");
            return;
        }
        $space_position = strpos($arguments, ' ');
        $sub_verb = ($space_position === false) ? $arguments :
            substr($arguments, 0, $space_position);
        $sub_args = ($space_position === false) ? "" :
            substr($arguments, $space_position + 1);
        $V = strtoupper($sub_verb);
        if ($V === 'FETCH') {
            $this->imapCmdFetch($key, $tag, $sub_args, $context, true);
            return;
        }
        if ($V === 'STORE') {
            $this->imapCmdStore($key, $tag, $sub_args, $context, true);
            return;
        }
        if ($V === 'COPY') {
            $this->imapCmdCopy($key, $tag, $sub_args, $context, true);
            return;
        }
        if ($V === 'MOVE') {
            $this->imapCmdMove($key, $tag, $sub_args, $context, true);
            return;
        }
        if ($V === 'SEARCH') {
            $this->imapCmdSearch($key, $tag, $sub_args, $context, true);
            return;
        }
        $this->imapResp($key, $tag, "BAD", "UID $V not supported");
    }
    /**
     * Parses an IMAP message-set string ("1", "1:5", "1:*",
     * "*", "1,3,5", "1:3,5:7") into a closure that tests
     * membership. The closure takes (sequence_number, last_seq,
     * uid) and returns true if the message is in the set; the
     * $by_uid flag tells the closure whether to test the
     * sequence or the UID against the parsed ranges. The
     * "*" token expands to last_seq when used in by-sequence
     * mode and to a sentinel large number in by-uid mode (the
     * IMAP grammar treats "*" as "the largest UID currently in
     * use" for UID FETCH purposes).
     */
    protected function imapParseMessageSet($spec, $by_uid)
    {
        $ranges = [];
        foreach (explode(',', $spec) as $piece) {
            $piece = trim($piece);
            if ($piece === '') {
                continue;
            }
            if (strpos($piece, ':') === false) {
                $ranges[] = [$piece, $piece];
            } else {
                $parts = explode(':', $piece, 2);
                $ranges[] = [trim($parts[0]), trim($parts[1])];
            }
        }
        return function ($sequence_number, $last_seq, $uid, $last_uid)
            use ($ranges, $by_uid) {
            $value = $by_uid ? $uid : $sequence_number;
            $last = $by_uid ? $last_uid : $last_seq;
            foreach ($ranges as $r) {
                $low = ($r[0] === '*') ? $last : (int) $r[0];
                $high = ($r[1] === '*') ? $last : (int) $r[1];
                if ($low > $high) {
                    $temp_path = $low;
                    $low = $high;
                    $high = $temp_path;
                }
                if ($value >= $low && $value <= $high) {
                    return true;
                }
            }
            return false;
        };
    }
    /**
     * Resolves the currently selected folder's messages into a
     * filtered list of [seq, meta] pairs that match the given
     * message-set. Used as the front end of FETCH, STORE,
     * COPY, MOVE, and SEARCH. The list is in sequence-number
     * order (which is also UID order, since UIDs are assigned
     * monotonically).
     */
    protected function imapMatchSet($user, $folder, $set, $by_uid)
    {
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        if (empty($messages)) {
            return [];
        }
        $last_seq = count($messages);
        $last_uid = end($messages)['uid'];
        $matcher = $this->imapParseMessageSet($set, $by_uid);
        $output = [];
        foreach ($messages as $index => $meta) {
            $sequence_number = $index + 1;
            if ($matcher($sequence_number, $last_seq, $meta['uid'],
                $last_uid)) {
                $output[] = [$sequence_number, $meta];
            }
        }
        return $output;
    }
    /**
     * Handles APPEND <mailbox> [(<flags>)] [<date-time>]
     * <literal>. The literal byte count triggers the
     * synchronizing-literal continuation: server replies "+
     * Ready", client streams the message body, server
     * accepts and assigns a UID. We extend the
     * IMAP_LIT_PENDING infrastructure with a 'append'
     * continuation kind that collects the literal bytes
     * across multiple readClient ticks (the body usually
     * arrives in many TCP fragments).
     */
    protected function imapCmdAppend($key, $tag, $arguments, &$context)
    {
        $tokens = $this->parseImapTokens($arguments);
        $folder = $this->tokenString($tokens, 0);
        if ($folder === false || $folder === '') {
            $this->imapResp($key, $tag, "BAD", "APPEND syntax");
            return;
        }
        $flags = [];
        $internal_date = 0;
        $literal_idx = -1;
        for ($i = 1; $i < count($tokens); $i++) {
            $token = $tokens[$i];
            if ($token[0] === 'literal') {
                $literal_idx = $i;
                break;
            }
            if ($token[0] === 'list') {
                /*
                    Parenthesized flag list, e.g. "(\Seen \Draft)".
                 */
                foreach (preg_split('/\s+/', trim($token[1]))
                    as $flag) {
                    if ($flag !== '') {
                        $flags[] = $flag;
                    }
                }
                continue;
            }
            if ($token[0] === 'quoted' || $token[0] === 'atom') {
                /*
                    Date-time argument, e.g.
                    "07-Feb-1994 21:52:25 -0800". We accept and
                    parse with strtotime; if parsing fails the
                    server falls back to "now" at delivery time.
                 */
                $maybe = strtotime($token[1]);
                if ($maybe !== false) {
                    $internal_date = $maybe;
                }
                continue;
            }
        }
        if ($literal_idx === -1) {
            $this->imapResp($key, $tag, "BAD",
                "APPEND requires a literal body");
            return;
        }
        $count = (int) $tokens[$literal_idx][1];
        $max = $this->default_server_globals['MAX_MESSAGE_LEN'];
        if ($count < 0 || $count > $max) {
            /*
                Reject impossible or oversized literal counts
                outright. Without this the server would happily
                allocate buffer space for a 10-petabyte APPEND
                announcement, which is a trivial DoS.
             */
            $this->imapResp($key, $tag, "NO",
                "[TOOBIG] APPEND size exceeds limit");
            return;
        }
        $context['IMAP_LIT_PENDING'] = [
            'continuation' => 'append',
            'tag' => $tag,
            'folder' => $folder,
            'flags' => $flags,
            'internal_date' => $internal_date,
            'remaining' => $count,
            'collected' => '',
        ];
        $this->queueWrite($key,
            "+ Ready for $count octets\r\n");
    }
    /**
     * Sends a single FETCH response line for one message,
     * formatting the requested items in the order the client
     * asked for them. The $items_str is the raw paren-list
     * payload, e.g. "(FLAGS UID INTERNALDATE RFC822.SIZE
     * BODY.PEEK[HEADER.FIELDS (Date Subject)])". We parse it
     * by walking and recognizing each top-level item.
     */
    protected function imapEmitFetch($key, $sequence_number, $meta, $body,
        $items_str, $is_uid_variant, &$mark_seen)
    {
        $items = $this->imapParseFetchItems($items_str);
        /*
            UID FETCH responses MUST include the UID data item
            even if the client did not request it.
         */
        if ($is_uid_variant) {
            $has_uid = false;
            foreach ($items as $item) {
                if (strtoupper($item['kind']) === 'UID') {
                    $has_uid = true;
                    break;
                }
            }
            if (!$has_uid) {
                $items[] = ['kind' => 'UID', 'raw' => 'UID',
                    'section' => null, 'fields' => []];
            }
        }
        $parts = [];
        foreach ($items as $item) {
            $rendered = $this->imapRenderFetchItem($item, $meta,
                $body, $mark_seen);
            if ($rendered !== null) {
                $parts[] = $rendered;
            }
        }
        $this->queueWrite($key,
            "* $sequence_number FETCH (" . implode(' ', $parts) . ")\r\n");
    }
    /**
     * Parses the items list of a FETCH command. Accepts both
     * the bare form ("FLAGS"), the macro shortcuts (FAST, ALL,
     * FULL), and the parenthesized list. Returns a list of
     * record arrays:
     *   ['kind' => 'BODY', 'section' => 'HEADER',
     *    'fields' => ['Subject','From'], 'raw' => 'BODY[...]',
     *    'peek' => true]
     */
    protected function imapParseFetchItems($items_str)
    {
        $items_str = trim($items_str);
        if ($items_str === '') {
            return [];
        }
        if ($items_str[0] === '(' &&
            substr($items_str, -1) === ')') {
            $items_str = substr($items_str, 1, -1);
        }
        /*
            Macro shortcuts per RFC 3501 sec 6.4.5. We expand
            them inline before tokenizing.
         */
        $upper = strtoupper(trim($items_str));
        if ($upper === 'FAST') {
            $items_str = 'FLAGS INTERNALDATE RFC822.SIZE';
        } else if ($upper === 'ALL') {
            $items_str = 'FLAGS INTERNALDATE RFC822.SIZE ENVELOPE';
        } else if ($upper === 'FULL') {
            $items_str = 'FLAGS INTERNALDATE RFC822.SIZE ' .
                'ENVELOPE BODY';
        }
        $output = [];
        $i = 0;
        $n = strlen($items_str);
        while ($i < $n) {
            $c = $items_str[$i];
            if ($c === ' ' || $c === "\t") {
                $i++;
                continue;
            }
            /*
                An item is a name optionally followed by a
                bracketed section spec ("BODY[HEADER]") or
                ".PEEK" infix ("BODY.PEEK[]"). We greedy-match
                up to the first whitespace not inside [] or ().
             */
            $start = $i;
            $depth_b = 0;
            $depth_p = 0;
            while ($i < $n) {
                $character = $items_str[$i];
                if ($character === '[') $depth_b++;
                else if ($character === ']') $depth_b--;
                else if ($character === '(') $depth_p++;
                else if ($character === ')') $depth_p--;
                else if (($character === ' ' || $character === "\t") &&
                    $depth_b === 0 && $depth_p === 0) {
                    break;
                }
                $i++;
            }
            $token = substr($items_str, $start, $i - $start);
            $output[] = $this->imapAnalyzeFetchItem($token);
        }
        return $output;
    }
    /**
     * Decomposes one FETCH item token like "BODY.PEEK[HEADER.
     * FIELDS (Subject From)]" into its kind, peek flag,
     * section spec, and field list. The kind is always upper-
     * cased; field names preserve their original case so the
     * response matches the request.
     */
    protected function imapAnalyzeFetchItem($token)
    {
        $record = ['kind' => null, 'peek' => false,
            'section' => null, 'fields' => [],
            'partial' => null, 'raw' => $token];
        $bracket_position = strpos($token, '[');
        if ($bracket_position === false) {
            $record['kind'] = strtoupper($token);
            return $record;
        }
        $name = substr($token, 0, $bracket_position);
        if (substr_compare(strtoupper($name), '.PEEK',
            -5) === 0) {
            $record['peek'] = true;
            $name = substr($name, 0, -5);
        }
        $record['kind'] = strtoupper($name);
        $end = strrpos($token, ']');
        if ($end === false) {
            return $record;
        }
        $section_full = substr($token, $bracket_position + 1,
            $end - $bracket_position - 1);
        /*
            Section may be empty (whole body), HEADER, TEXT,
            HEADER.FIELDS (Subject From), HEADER.FIELDS.NOT
            (...), MIME, or a numeric MIME part path. We
            recognize the textual variants; numeric paths are
            stored as the section name and currently fall back
            to whole-message body.
         */
        if ($section_full === '') {
            $record['section'] = '';
            return $record;
        }
        $paren = strpos($section_full, '(');
        if ($paren === false) {
            $record['section'] = strtoupper(trim($section_full));
            return $record;
        }
        $record['section'] = strtoupper(trim(substr($section_full,
            0, $paren)));
        $field_str = substr($section_full, $paren + 1, -1);
        foreach (preg_split('/\s+/', trim($field_str))
            as $field_name) {
            if ($field_name !== '') {
                $record['fields'][] = $field_name;
            }
        }
        return $record;
    }
    /**
     * Renders one FETCH item to its IMAP-formatted form. The
     * mark_seen flag is set true when a non-PEEK BODY[*] is
     * served and we should set the \Seen flag after responding.
     */
    protected function imapRenderFetchItem($item, $meta, $body,
        &$mark_seen)
    {
        $kind = $item['kind'];
        if ($kind === 'UID') {
            return "UID " . $meta['uid'];
        }
        if ($kind === 'FLAGS') {
            return "FLAGS (" . implode(' ', $meta['flags']) . ")";
        }
        if ($kind === 'INTERNALDATE') {
            return 'INTERNALDATE "' .
                gmdate('d-M-Y H:i:s', $meta['internal_date']) .
                ' +0000"';
        }
        if ($kind === 'RFC822.SIZE') {
            return "RFC822.SIZE " . $meta['size'];
        }
        if ($kind === 'RFC822') {
            return "RFC822 " . $this->imapLiteralOf($body) .
                ($item ? '' : '');
        }
        if ($kind === 'RFC822.HEADER') {
            $header_value = $this->imapHeaderBlock($body);
            return "RFC822.HEADER " .
                $this->imapLiteralOf($header_value);
        }
        if ($kind === 'RFC822.TEXT') {
            $text = $this->imapBodyText($body);
            if (!$item['peek']) {
                $mark_seen = true;
            }
            return "RFC822.TEXT " .
                $this->imapLiteralOf($text);
        }
        if ($kind === 'ENVELOPE') {
            return "ENVELOPE " . $this->imapEnvelope($body);
        }
        if ($kind === 'BODYSTRUCTURE' || $kind === 'BODY') {
            if ($kind === 'BODY' && $item['section'] !== null) {
                $payload = $this->imapBodySection($body,
                    $item['section'], $item['fields']);
                if (!$item['peek']) {
                    $mark_seen = true;
                }
                $section_repr = $item['section'];
                if (!empty($item['fields'])) {
                    $section_repr .= ' (' .
                        implode(' ', $item['fields']) . ')';
                }
                return "BODY[$section_repr] " .
                    $this->imapLiteralOf($payload);
            }
            return "BODYSTRUCTURE " .
                $this->imapBodyStructure($body, $kind);
        }
        return null;
    }
    /**
     * Wraps a string as an IMAP "{N}\r\n<bytes>" literal.
     * Used for any FETCH response data that is not a quoted
     * atom; the client reads exactly N bytes after the {N}\r\n
     * before resuming line-based parsing.
     */
    protected function imapLiteralOf($s)
    {
        return "{" . strlen($s) . "}\r\n" . $s;
    }
    /**
     * Returns the header block of a message: bytes up to and
     * including the blank line CRLF that terminates the header
     * section. If the message has no body separator the entire
     * message is treated as headers.
     */
    protected function imapHeaderBlock($body)
    {
        $separator = "\r\n\r\n";
        $end = strpos($body, $separator);
        if ($end === false) {
            $alternative = strpos($body, "\n\n");
            return ($alternative === false) ? $body :
                substr($body, 0, $alternative + 2);
        }
        return substr($body, 0, $end + 4);
    }
    /**
     * Returns the body text of a message: everything after the
     * header-section separator. Empty string if there is no
     * separator (a malformed message with only headers).
     */
    protected function imapBodyText($body)
    {
        $separator = "\r\n\r\n";
        $end = strpos($body, $separator);
        if ($end === false) {
            $alternative = strpos($body, "\n\n");
            return ($alternative === false) ? '' :
                substr($body, $alternative + 2);
        }
        return substr($body, $end + 4);
    }
    /**
     * Returns the bytes for one BODY[<section>] request.
     * Recognizes empty (whole message), HEADER (header block),
     * TEXT (body text), HEADER.FIELDS (selected headers),
     * HEADER.FIELDS.NOT (all but selected headers), and MIME
     * (currently same as HEADER for non-multipart). Numeric
     * MIME-part paths fall back to the whole body since
     * multipart parsing is out of scope for this phase.
     */
    protected function imapBodySection($body, $section, $fields)
    {
        if ($section === '') {
            return $body;
        }
        if ($section === 'HEADER') {
            return $this->imapHeaderBlock($body);
        }
        if ($section === 'TEXT') {
            return $this->imapBodyText($body);
        }
        if ($section === 'MIME') {
            return $this->imapHeaderBlock($body);
        }
        if ($section === 'HEADER.FIELDS' ||
            $section === 'HEADER.FIELDS.NOT') {
            $header_value = $this->imapHeaderBlock($body);
            return $this->imapFilterHeaders($header_value, $fields,
                $section === 'HEADER.FIELDS.NOT');
        }
        /*
            Numeric MIME path: the section is a dotted sequence
            of 1-based part indices, optionally followed by a
            sub-section keyword (HEADER, MIME, TEXT, or one of
            the HEADER.FIELDS variants). Walk the parsed entity
            tree to find the requested part, then return the
            requested slice. If the path runs past the actual
            structure (out-of-range indices) we return the
            whole-message body as a fallback so well-meaning
            clients still see something rather than an empty
            literal.
         */
        if (preg_match('/^[0-9]+(\.[0-9]+)*(\.[A-Z.]+)?$/',
            $section)) {
            $entity = $this->imapParseEntity($body);
            $tail = '';
            $path_str = $section;
            $dot_alpha = preg_match(
                '/^([0-9]+(?:\.[0-9]+)*)\.([A-Z.]+)$/',
                $section, $m);
            if ($dot_alpha) {
                $path_str = $m[1];
                $tail = $m[2];
            }
            $path = explode('.', $path_str);
            $found = $this->imapNavigateEntity($entity, $path);
            if ($found === null) {
                return $body;
            }
            if ($tail === '' || $tail === 'TEXT') {
                /*
                    Default (no tail) returns the part body
                    bytes; TEXT explicitly the same. RFC 3501
                    says TEXT excludes the header section.
                 */
                return $found['body'];
            }
            if ($tail === 'HEADER' || $tail === 'MIME') {
                return $found['header_block'];
            }
            if ($tail === 'HEADER.FIELDS' ||
                $tail === 'HEADER.FIELDS.NOT') {
                return $this->imapFilterHeaders(
                    $found['header_block'], $fields,
                    $tail === 'HEADER.FIELDS.NOT');
            }
            return $found['body'];
        }
        /*
            Unknown section: fall back to whole body so the
            client at least gets data rather than an error.
         */
        return $body;
    }
    /**
     * Walks a parsed entity tree following a list of 1-based
     * part indices and returns the leaf entity reached, or
     * null if the path does not resolve. For a non-multipart
     * top-level entity, path "1" returns the entity itself
     * (per RFC 3501 sec 6.4.5: a single-part message has its
     * entire body addressable as part 1).
     */
    protected function imapNavigateEntity($entity, $path)
    {
        $current = $entity;
        $first = true;
        foreach ($path as $idx_str) {
            $index = (int) $idx_str;
            if ($index < 1) {
                return null;
            }
            if ($first && $current['type'] !== 'multipart') {
                /*
                    Single-part top-level: path "1" refers to
                    the only part, which IS the entity itself.
                    Anything past 1.X is out of range.
                 */
                if ($index !== 1) {
                    return null;
                }
                $first = false;
                continue;
            }
            $first = false;
            if (empty($current['parts']) ||
                !isset($current['parts'][$index - 1])) {
                return null;
            }
            $current = $current['parts'][$index - 1];
        }
        return $current;
    }
    /**
     * Returns just the header lines whose names match (or do
     * NOT match, when $invert is true) any of the names in
     * $fields, preserving the original line content and
     * terminating with the standard blank line CRLF that
     * RFC 3501 sec 6.4.5 says clients expect.
     */
    protected function imapFilterHeaders($hdr_block, $fields,
        $invert)
    {
        $wanted = [];
        foreach ($fields as $field_name) {
            $wanted[strtolower($field_name)] = true;
        }
        $lines = preg_split('/\r\n|\n/', $hdr_block);
        $output = [];
        $current_kept = null;
        foreach ($lines as $line) {
            if ($line === '') {
                break;
            }
            if ($line[0] === ' ' || $line[0] === "\t") {
                if ($current_kept) {
                    $output[] = $line;
                }
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon === false) {
                $current_kept = false;
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $match = isset($wanted[$name]);
            $current_kept = $invert ? !$match : $match;
            if ($current_kept) {
                $output[] = $line;
            }
        }
        return implode("\r\n", $output) . "\r\n\r\n";
    }
    /**
     * Returns the IMAP ENVELOPE structure for a message as a
     * paren-list. Per RFC 3501 sec 7.4.2 the order is date,
     * subject, from, sender, reply-to, to, cc, bcc, in-reply-
     * to, message-id. Address lists are nested paren-lists
     * containing (name source-route mailbox-name host-name)
     * tuples; absent fields are NIL.
     */
    protected function imapEnvelope($body)
    {
        $headers = $this->imapParseHeaders($body);
        $get = function ($name) use ($headers) {
            $key = strtolower($name);
            return isset($headers[$key]) ? $headers[$key] : null;
        };
        $date = $this->imapEnvelopeNString($get('Date'));
        $subj = $this->imapEnvelopeNString($get('Subject'));
        $from = $this->imapEnvelopeAddrs($get('From'));
        $sender = $this->imapEnvelopeAddrs($get('Sender') ??
            $get('From'));
        $reply = $this->imapEnvelopeAddrs($get('Reply-To') ??
            $get('From'));
        $to = $this->imapEnvelopeAddrs($get('To'));
        $cc = $this->imapEnvelopeAddrs($get('Cc'));
        $bcc = $this->imapEnvelopeAddrs($get('Bcc'));
        $inreply = $this->imapEnvelopeNString(
            $get('In-Reply-To'));
        $msgid = $this->imapEnvelopeNString($get('Message-ID'));
        return "($date $subj $from $sender $reply $to $cc " .
            "$bcc $inreply $msgid)";
    }
    /**
     * Parses RFC 5322 headers into a name => value map (case-
     * insensitive, lower-cased keys). Continuation lines are
     * unfolded with a single space. Repeated headers are
     * concatenated with comma+space (sufficient for envelope
     * use; full fidelity would need an array per name).
     */
    protected function imapParseHeaders($message)
    {
        $sep_pos = strpos($message, "\r\n\r\n");
        $block = ($sep_pos === false) ? $message :
            substr($message, 0, $sep_pos);
        $lines = preg_split('/\r\n|\n/', $block);
        $output = [];
        $current = null;
        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }
            if ($line[0] === ' ' || $line[0] === "\t") {
                if ($current !== null && isset($output[$current])) {
                    $output[$current] .= ' ' . trim($line);
                }
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon === false) {
                $current = null;
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = ltrim(substr($line, $colon + 1));
            if (isset($output[$name])) {
                $output[$name] .= ', ' . $value;
            } else {
                $output[$name] = $value;
            }
            $current = $name;
        }
        return $output;
    }
    /**
     * Decodes RFC 2047 encoded-words in a header value back
     * to plain text. Encoded-words have the form
     *      =?charset?encoding?text?=
     * where encoding is "B" (base64) or "Q" (quoted-printable
     * with "_" meaning space). Multiple consecutive encoded-
     * words separated only by whitespace are concatenated
     * with the whitespace stripped, per RFC 2047 sec 6.2.
     * Bytes outside encoded-words are passed through verbatim.
     * The result is a UTF-8 string when the input charsets
     * are recognized; unrecognized charsets fall back to
     * leaving the text uninterpreted but still removing the
     * encoded-word wrapper, which is good enough for
     * substring searches.
     */
    protected function imapDecodeMimeHeader($value)
    {
        if (strpos($value, '=?') === false) {
            return $value;
        }
        $pattern = '/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/';
        /*
            First pass: replace each encoded-word with a marker
            holding the decoded text, then collapse whitespace
            that sits BETWEEN two markers (RFC 2047 sec 6.2:
            whitespace between adjacent encoded-words is not
            significant). We then unwrap the markers.
         */
        $value = preg_replace_callback($pattern,
            function ($m) {
                $charset = strtoupper(trim($m[1]));
                $enc = strtoupper($m[2]);
                $text = $m[3];
                if ($enc === 'B') {
                    $decoded = (string) base64_decode($text,
                        true);
                } else {
                    $text = str_replace('_', ' ', $text);
                    $decoded = quoted_printable_decode($text);
                }
                if ($charset !== 'UTF-8' &&
                    $charset !== 'US-ASCII' &&
                    function_exists('mb_convert_encoding')) {
                    $converted = @mb_convert_encoding($decoded,
                        'UTF-8', $charset);
                    if ($converted !== false) {
                        $decoded = $converted;
                    }
                }
                return "\x01EW\x01" . $decoded . "\x01/EW\x01";
            }, $value);
        $value = preg_replace(
            '/\x01\/EW\x01\s+\x01EW\x01/', '', $value);
        $value = str_replace(["\x01EW\x01", "\x01/EW\x01"], '',
            $value);
        return $value;
    }
    /**
     * Renders a string as either an IMAP quoted string or NIL
     * if the value is null/empty. Used for ENVELOPE date,
     * subject, in-reply-to, and message-id slots.
     */
    protected function imapEnvelopeNString($value)
    {
        if ($value === null || $value === '') {
            return 'NIL';
        }
        $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'],
            $value);
        return '"' . $escaped . '"';
    }
    /**
     * Renders an address-list header value as an IMAP
     * paren-list of address tuples, or NIL if the value is
     * absent. Each tuple is (display-name source-route
     * mailbox-local host). source-route is always NIL since
     * RFC 5321 deprecated source routes; we just split on the
     * @ to derive mailbox/host. Display names are extracted
     * from the "Name <email>" form when present.
     */
    protected function imapEnvelopeAddrs($value)
    {
        if ($value === null || $value === '') {
            return 'NIL';
        }
        $addrs = $this->imapSplitAddressList($value);
        if (empty($addrs)) {
            return 'NIL';
        }
        $parts = [];
        foreach ($addrs as $addr) {
            $name = $this->imapEnvelopeNString($addr['name']);
            $local = $this->imapEnvelopeNString($addr['local']);
            $host = $this->imapEnvelopeNString($addr['host']);
            $parts[] = "($name NIL $local $host)";
        }
        return '(' . implode(' ', $parts) . ')';
    }
    /**
     * Splits a header value containing one or more email
     * addresses into structured records. Recognizes the
     * "Display Name <local@host>" form and the bare "local@
     * host" form. Quoted display names with embedded commas
     * are handled; comments in parentheses are not preserved.
     * Returns a list of ['name','local','host'] records.
     */
    protected function imapSplitAddressList($s)
    {
        $output = [];
        $tokens = [];
        $current = '';
        $in_q = false;
        $in_b = 0;
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = $s[$i];
            if ($c === '"' && ($i === 0 || $s[$i-1] !== '\\')) {
                $in_q = !$in_q;
                $current .= $c;
                continue;
            }
            if (!$in_q && $c === '<') {
                $in_b++;
                $current .= $c;
                continue;
            }
            if (!$in_q && $c === '>') {
                $in_b--;
                $current .= $c;
                continue;
            }
            if (!$in_q && $in_b === 0 && $c === ',') {
                $tokens[] = trim($current);
                $current = '';
                continue;
            }
            $current .= $c;
        }
        if (trim($current) !== '') {
            $tokens[] = trim($current);
        }
        foreach ($tokens as $address_token) {
            if ($address_token === '') {
                continue;
            }
            $name = '';
            $addr = $address_token;
            if (preg_match(
                '/^(.*?)\s*<\s*([^<>]+?)\s*>\s*$/',
                $address_token, $m)) {
                $name = trim($m[1], " \t\"");
                $addr = $m[2];
            }
            $at = strrpos($addr, '@');
            if ($at === false) {
                $local = $addr;
                $host = '';
            } else {
                $local = substr($addr, 0, $at);
                $host = substr($addr, $at + 1);
            }
            $output[] = ['name' => $name, 'local' => $local,
                'host' => $host];
        }
        return $output;
    }
    /**
     * Returns an IMAP BODYSTRUCTURE (or BODY) representation
     * of a message. Walks the multipart MIME tree per RFC 2046
     * and emits the nested paren-list structure RFC 3501 sec
     * 7.4.2 specifies. For multipart entities this produces a
     * properly nested response that lets clients identify
     * individual parts, their content types, encodings, and
     * sizes; clients that find an attachment part will then
     * issue BODY[part-number] to fetch just that part.
     *   $kind is "BODY" or "BODYSTRUCTURE": both render the
     * same body fields; BODYSTRUCTURE additionally appends
     * the extension fields (md5, disposition, language,
     * location) which are required for that variant.
     */
    protected function imapBodyStructure($body, $kind)
    {
        $entity = $this->imapParseEntity($body);
        $extended = ($kind === 'BODYSTRUCTURE');
        return $this->imapRenderBodyStructure($entity, $extended);
    }
    /**
     * Recursively parses an RFC 5322 / RFC 2045 entity (a
     * complete message or a single part of a multipart) into
     * a structured tree. The entity bytes are treated as one
     * region: the leading header block up to the blank-line
     * separator, then the body. For a multipart entity the
     * body is split along the boundary string declared in the
     * Content-Type, and each part is parsed recursively.
     *
     * Returns an associative array:
     *   type, subtype     -- lowercased MIME type/subtype
     *   params            -- name => value map
     *   encoding          -- transfer encoding (lowercased)
     *   id, description   -- Content-ID, Content-Description
     *   disposition       -- Content-Disposition raw value
     *   header_block      -- bytes of the header section
     *   body              -- bytes of the body section
     *   size              -- byte length of the body
     *   lines             -- number of body lines (text only)
     *   parts             -- list of child entities (multipart
     *                        only; empty for leaves)
     */
    protected function imapParseEntity($bytes)
    {
        $sep_pos = strpos($bytes, "\r\n\r\n");
        if ($sep_pos === false) {
            $alternative = strpos($bytes, "\n\n");
            if ($alternative === false) {
                $header_block = $bytes;
                $body = '';
            } else {
                $header_block = substr($bytes, 0, $alternative + 2);
                $body = substr($bytes, $alternative + 2);
            }
        } else {
            $header_block = substr($bytes, 0, $sep_pos + 4);
            $body = substr($bytes, $sep_pos + 4);
        }
        $headers = $this->imapParseHeaders($header_block);
        $content_type = isset($headers['content-type']) ?
            $headers['content-type'] : 'text/plain';
        $content_type_parts = preg_split('/\s*;\s*/',
            $content_type);
        $type = 'text';
        $subtype = 'plain';
        if (!empty($content_type_parts[0])) {
            $mime = strtolower(trim($content_type_parts[0]));
            $slash = strpos($mime, '/');
            if ($slash !== false) {
                $type = substr($mime, 0, $slash);
                $subtype = substr($mime, $slash + 1);
            }
        }
        $params = [];
        for ($i = 1; $i < count($content_type_parts); $i++) {
            if (preg_match('/^([^=]+)=(.*)$/',
                trim($content_type_parts[$i]), $m)) {
                $params[strtolower(trim($m[1]))] =
                    trim($m[2], " \t\"");
            }
        }
        $encoding = isset($headers['content-transfer-encoding']) ?
            strtolower(trim($headers[
                'content-transfer-encoding'])) : '7bit';
        $entity = [
            'type' => $type,
            'subtype' => $subtype,
            'params' => $params,
            'encoding' => $encoding,
            'id' => isset($headers['content-id']) ?
                $headers['content-id'] : null,
            'description' => isset($headers[
                'content-description']) ?
                $headers['content-description'] : null,
            'disposition' => isset($headers[
                'content-disposition']) ?
                $headers['content-disposition'] : null,
            'header_block' => $header_block,
            'body' => $body,
            'size' => strlen($body),
            'lines' => substr_count($body, "\n"),
            'parts' => [],
        ];
        if ($type === 'multipart' &&
            isset($params['boundary'])) {
            $entity['parts'] = $this->imapSplitMultipart($body,
                $params['boundary']);
        }
        return $entity;
    }
    /**
     * Splits a multipart body into its constituent part
     * entities along the boundary string. Per RFC 2046 sec
     * 5.1.1 the delimiter between parts is "\r\n--<boundary>"
     * and the closing delimiter is "\r\n--<boundary>--". We
     * tolerate "\n--" as well (some agents emit LF-only
     * line endings) and accept the leading boundary without
     * a preceding newline (the very first part).
     * Preamble text before the first delimiter and epilogue
     * text after the closing delimiter are discarded per the
     * RFC. Each part is recursively parsed via imapParseEntity.
     */
    protected function imapSplitMultipart($body, $boundary)
    {
        $delim = '--' . $boundary;
        $close = '--' . $boundary . '--';
        $parts = [];
        $remaining = $body;
        $first = strpos($remaining, $delim);
        if ($first === false) {
            return [];
        }
        $remaining = substr($remaining, $first + strlen($delim));
        while (true) {
            /*
                Eat the trailing CRLF after the boundary line.
             */
            if (substr($remaining, 0, 2) === "\r\n") {
                $remaining = substr($remaining, 2);
            } else if (substr($remaining, 0, 1) === "\n") {
                $remaining = substr($remaining, 1);
            } else if (substr($remaining, 0, 2) === '--') {
                /* This was the closing delimiter; we are done. */
                break;
            }
            /*
                Find the next boundary. We search for both the
                CRLF-prefixed and LF-prefixed forms.
             */
            $next_crlf = strpos($remaining, "\r\n--" . $boundary);
            $next_lf = strpos($remaining, "\n--" . $boundary);
            $next = false;
            if ($next_crlf !== false && $next_lf !== false) {
                $next = min($next_crlf, $next_lf);
            } else if ($next_crlf !== false) {
                $next = $next_crlf;
            } else if ($next_lf !== false) {
                $next = $next_lf;
            }
            if ($next === false) {
                break;
            }
            $part_bytes = substr($remaining, 0, $next);
            $parts[] = $this->imapParseEntity($part_bytes);
            /*
                Advance past the CRLF + delimiter. The
                delimiter itself is consumed; the next-line
                eat at the top of the loop handles the trailing
                CRLF.
             */
            $skip = ($remaining[$next] === "\r") ? 2 : 1;
            $remaining = substr($remaining,
                $next + $skip + strlen($delim));
            if (substr($remaining, 0, 2) === '--') {
                /* Closing delimiter: stop. */
                break;
            }
        }
        return $parts;
    }
    /**
     * Renders a parsed entity as an IMAP BODYSTRUCTURE
     * paren-list. Branches by content type:
     *   multipart:  "(part1 part2 ... \"SUBTYPE\")" with
     *               extension fields if $extended is true
     *               (params disposition language location)
     *   text/*:     8-tuple "(\"TEXT\" \"SUBTYPE\" params id
     *               desc encoding size lines)" with extension
     *               fields md5/disposition/language/location
     *               for $extended
     *   message/rfc822: rare, treated as a generic part
     *   other:      7-tuple as text without the lines field
     */
    protected function imapRenderBodyStructure($entity, $extended)
    {
        if ($entity['type'] === 'multipart' &&
            !empty($entity['parts'])) {
            $part_strs = [];
            foreach ($entity['parts'] as $p) {
                $part_strs[] =
                    $this->imapRenderBodyStructure($p, $extended);
            }
            $output = '(' . implode('', $part_strs) . ' "' .
                strtoupper($entity['subtype']) . '"';
            if ($extended) {
                $output .= ' ' .
                    $this->imapRenderParams($entity['params']);
                /* disposition language location: NIL placeholders */
                $output .= ' NIL NIL NIL';
            }
            $output .= ')';
            return $output;
        }
        $type_repr = '"' . strtoupper($entity['type']) . '"';
        $subtype_repr = '"' .
            strtoupper($entity['subtype']) . '"';
        $params_repr = $this->imapRenderParams($entity['params']);
        $id_repr = $entity['id'] === null ? 'NIL' :
            '"' . addslashes($entity['id']) . '"';
        $desc_repr = $entity['description'] === null ? 'NIL' :
            '"' . addslashes($entity['description']) . '"';
        $enc_repr = '"' . strtoupper($entity['encoding']) . '"';
        $size = $entity['size'];
        $tuple = "$type_repr $subtype_repr $params_repr " .
            "$id_repr $desc_repr $enc_repr $size";
        if ($entity['type'] === 'text') {
            $tuple .= ' ' . $entity['lines'];
        }
        if ($extended) {
            /*
                md5, disposition, language, location are all
                NIL placeholders. A more complete
                implementation would parse Content-MD5 and
                Content-Disposition; clients tolerate NIL.
             */
            $tuple .= ' NIL NIL NIL NIL';
        }
        return "($tuple)";
    }
    /**
     * Renders a params map (lowercased name => value) as the
     * IMAP NIL-or-paren-list form: NIL if empty, else
     * (\"NAME\" \"value\" \"NAME2\" \"value2\" ...). Names are
     * upper-cased per IMAP convention; values keep their case.
     */
    protected function imapRenderParams($params)
    {
        if (empty($params)) {
            return 'NIL';
        }
        $pairs = [];
        foreach ($params as $param_name => $param_value) {
            $pairs[] = '"' . strtoupper($param_name) . '" "' .
                addslashes($param_value) . '"';
        }
        return '(' . implode(' ', $pairs) . ')';
    }
    /**
     * Implements FETCH and UID FETCH. The $by_uid flag tells
     * us whether the message-set is sequence numbers or UIDs
     * and whether to auto-include the UID data item. Each
     * message gets one untagged "* N FETCH (...)" response
     * line; the tagged OK is sent after the loop. \Seen flag
     * is set on messages whose body was served via a non-PEEK
     * BODY request.
     */
    protected function imapCmdFetch($key, $tag, $arguments, &$context,
        $by_uid)
    {
        $space_position = strpos($arguments, ' ');
        if ($space_position === false) {
            $this->imapResp($key, $tag, "BAD", "FETCH syntax");
            return;
        }
        $set = substr($arguments, 0, $space_position);
        $items_str = substr($arguments, $space_position + 1);
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        $matched = $this->imapMatchSet($user, $folder, $set,
            $by_uid);
        $verb = $by_uid ? 'UID FETCH' : 'FETCH';
        foreach ($matched as $entry) {
            list($sequence_number, $meta) = $entry;
            $body = $this->mail_storage->fetchMessage($user,
                $folder, $meta['uid']);
            if ($body === false) {
                continue;
            }
            $mark_seen = false;
            $this->imapEmitFetch($key, $sequence_number, $meta, $body,
                $items_str, $by_uid, $mark_seen);
            if ($mark_seen &&
                empty($context['SELECTED_READONLY']) &&
                !in_array('\Seen', $meta['flags'], true)) {
                $new_flags = $meta['flags'];
                $new_flags[] = '\Seen';
                $this->mail_storage->setFlags($user, $folder,
                    $meta['uid'], $new_flags);
                $this->bumpMailboxChange($user, $folder);
            }
        }
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Implements STORE and UID STORE. Handles the three
     * mutation modes: FLAGS (replace), +FLAGS (add), -FLAGS
     * (remove), each with optional .SILENT suffix that
     * suppresses the per-message FETCH response. The flag
     * list itself is a parenthesized atom list.
     */
    protected function imapCmdStore($key, $tag, $arguments, &$context,
        $by_uid)
    {
        if (!preg_match(
            '/^(\S+)\s+([+-]?FLAGS(?:\.SILENT)?)\s+(.+)$/i',
            $arguments, $m)) {
            $this->imapResp($key, $tag, "BAD", "STORE syntax");
            return;
        }
        $set = $m[1];
        $operator = strtoupper($m[2]);
        $flags_str = trim($m[3]);
        if ($flags_str !== '' && $flags_str[0] === '(' &&
            substr($flags_str, -1) === ')') {
            $flags_str = substr($flags_str, 1, -1);
        }
        $req_flags = [];
        foreach (preg_split('/\s+/', trim($flags_str))
            as $flag) {
            if ($flag !== '') {
                $req_flags[] = $flag;
            }
        }
        $silent = (substr($operator, -7) === '.SILENT');
        $mode = $silent ? substr($operator, 0, -7) : $operator;
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        $matched = $this->imapMatchSet($user, $folder, $set,
            $by_uid);
        $verb = $by_uid ? 'UID STORE' : 'STORE';
        if (!empty($context['SELECTED_READONLY'])) {
            $this->imapResp($key, $tag, "NO", "Mailbox is read-only");
            return;
        }
        foreach ($matched as $entry) {
            list($sequence_number, $meta) = $entry;
            $existing = $meta['flags'];
            $new = $existing;
            if ($mode === 'FLAGS') {
                $new = $req_flags;
            } else if ($mode === '+FLAGS') {
                foreach ($req_flags as $flag) {
                    if (!in_array($flag, $new, true)) {
                        $new[] = $flag;
                    }
                }
            } else if ($mode === '-FLAGS') {
                $new = array_values(array_diff($new,
                    $req_flags));
            }
            $this->mail_storage->setFlags($user, $folder,
                $meta['uid'], $new);
            $this->bumpMailboxChange($user, $folder);
            if (!$silent) {
                $extras = [];
                $extras[] = "FLAGS (" .
                    implode(' ', $new) . ")";
                if ($by_uid) {
                    $extras[] = "UID " . $meta['uid'];
                }
                $this->queueWrite($key,
                    "* $sequence_number FETCH (" .
                    implode(' ', $extras) . ")\r\n");
            }
        }
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Implements COPY and UID COPY. Each matched message is
     * appended to the target folder via the storage backend's
     * appendMessage, preserving flags but assigning a fresh
     * UID in the target. Note: this differs from MOVE, which
     * preserves UIDs (because moveMessage just renames the
     * file). Copying inherently allocates new UIDs because
     * the same per-user UID counter is used for the new
     * message.
     */
    protected function imapCmdCopy($key, $tag, $arguments, &$context,
        $by_uid)
    {
        $space_position = strrpos(rtrim($arguments), ' ');
        if ($space_position === false) {
            $this->imapResp($key, $tag, "BAD", "COPY syntax");
            return;
        }
        $set = trim(substr($arguments, 0, $space_position));
        $folder_tok = trim(substr($arguments, $space_position + 1));
        if ($folder_tok === '' || $folder_tok[0] === '"') {
            $tokens = $this->parseImapTokens($folder_tok);
            $target = $this->tokenString($tokens, 0);
        } else {
            $target = $folder_tok;
        }
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        if ($target === false || $target === '') {
            $this->imapResp($key, $tag, "BAD", "COPY syntax");
            return;
        }
        if (!$this->mail_storage->folderExists($user, $target)) {
            $this->queueWrite($key,
                "$tag NO [TRYCREATE] Target mailbox " .
                "does not exist\r\n");
            return;
        }
        $matched = $this->imapMatchSet($user, $folder, $set,
            $by_uid);
        $verb = $by_uid ? 'UID COPY' : 'COPY';
        $copied = 0;
        foreach ($matched as $entry) {
            list($sequence_number, $meta) = $entry;
            $body = $this->mail_storage->fetchMessage($user,
                $folder, $meta['uid']);
            if ($body === false) {
                continue;
            }
            $this->mail_storage->appendMessage($user, $target,
                $body, $meta['flags'], $meta['internal_date']);
            $copied++;
        }
        if ($copied > 0) {
            $this->bumpMailboxChange($user, $target);
        }
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Implements MOVE and UID MOVE (RFC 6851). Unlike COPY,
     * MOVE preserves the source UID in the target folder
     * because the storage layer's moveMessage operation
     * relocates the same file rather than allocating a new
     * UID. Per the RFC the server emits an EXPUNGE response
     * for each removed source message after the move.
     */
    protected function imapCmdMove($key, $tag, $arguments, &$context,
        $by_uid)
    {
        $space_position = strrpos(rtrim($arguments), ' ');
        if ($space_position === false) {
            $this->imapResp($key, $tag, "BAD", "MOVE syntax");
            return;
        }
        $set = trim(substr($arguments, 0, $space_position));
        $folder_tok = trim(substr($arguments, $space_position + 1));
        if ($folder_tok === '' || $folder_tok[0] === '"') {
            $tokens = $this->parseImapTokens($folder_tok);
            $target = $this->tokenString($tokens, 0);
        } else {
            $target = $folder_tok;
        }
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        if ($target === false || $target === '') {
            $this->imapResp($key, $tag, "BAD", "MOVE syntax");
            return;
        }
        if (!$this->mail_storage->folderExists($user, $target)) {
            $this->queueWrite($key,
                "$tag NO [TRYCREATE] Target mailbox " .
                "does not exist\r\n");
            return;
        }
        $matched = $this->imapMatchSet($user, $folder, $set,
            $by_uid);
        $verb = $by_uid ? 'UID MOVE' : 'MOVE';
        /*
            Emit EXPUNGE responses in descending sequence order
            so the client's count of remaining messages stays
            consistent as each is removed. The IMAP convention
            is that an EXPUNGE for sequence N implies the
            message was deleted and all sequence numbers > N
            shift down by one.
         */
        $seqs_to_expunge = [];
        foreach ($matched as $entry) {
            list($sequence_number, $meta) = $entry;
            if ($this->mail_storage->moveMessage($user, $folder,
                $target, $meta['uid'])) {
                $seqs_to_expunge[] = $sequence_number;
            }
        }
        if (!empty($seqs_to_expunge)) {
            $this->bumpMailboxChange($user, $folder);
            $this->bumpMailboxChange($user, $target);
        }
        rsort($seqs_to_expunge);
        foreach ($seqs_to_expunge as $sequence_number) {
            $this->queueWrite($key, "* $sequence_number EXPUNGE\r\n");
        }
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Implements EXPUNGE: permanently removes every message
     * in the selected folder that has the \Deleted flag set.
     * Emits an untagged EXPUNGE response per removed message,
     * in descending sequence order so the client's running
     * count stays consistent as each removal shifts higher
     * sequences down. Not allowed on read-only mailboxes
     * (EXAMINE).
     */
    protected function imapCmdExpunge($key, $tag, &$context)
    {
        if (!empty($context['SELECTED_READONLY'])) {
            $this->imapResp($key, $tag, "NO", "Mailbox is read-only");
            return;
        }
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        $seqs_removed = [];
        foreach ($messages as $index => $meta) {
            if (in_array('\Deleted', $meta['flags'], true)) {
                $seqs_removed[] = $index + 1;
            }
        }
        $this->mail_storage->expunge($user, $folder);
        if (!empty($seqs_removed)) {
            $this->bumpMailboxChange($user, $folder);
        }
        rsort($seqs_removed);
        foreach ($seqs_removed as $sequence_number) {
            $this->queueWrite($key, "* $sequence_number EXPUNGE\r\n");
        }
        $this->imapOk($key, $tag, "EXPUNGE");
    }
    /**
     * Implements SEARCH and UID SEARCH. Returns one untagged
     * "* SEARCH ..." response listing the matching sequence
     * numbers (or UIDs, in UID SEARCH mode), then a tagged
     * OK. Supports the common single-key forms (ALL, SEEN/
     * UNSEEN, FLAGGED/UNFLAGGED, DELETED/UNDELETED, RECENT/
     * OLD, ANSWERED/UNANSWERED, DRAFT/UNDRAFT, KEYWORD/
     * UNKEYWORD), header substring searches (FROM, TO, CC,
     * BCC, SUBJECT, BODY, TEXT, HEADER), date predicates
     * (SINCE, BEFORE, ON), size predicates (LARGER, SMALLER),
     * and the boolean operators NOT and OR. AND is implicit
     * (juxtaposed keys are conjuncted). Sequence-set and
     * UID-set restrictions also work.
     */
    protected function imapCmdSearch($key, $tag, $arguments, &$context,
        $by_uid)
    {
        $tokens = $this->imapTokenizeSearch($arguments);
        if ($tokens === null) {
            $this->imapResp($key, $tag, "BAD", "SEARCH syntax");
            return;
        }
        $user = $context['AUTH_USER'];
        $folder = $context['SELECTED'];
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        $last_seq = count($messages);
        $last_uid = empty($messages) ? 0 :
            end($messages)['uid'];
        $hits = [];
        foreach ($messages as $index => $meta) {
            $sequence_number = $index + 1;
            if ($this->imapEvalSearch($tokens, $meta, $sequence_number,
                $last_seq, $last_uid, $user, $folder)) {
                $hits[] = $by_uid ? $meta['uid'] : $sequence_number;
            }
        }
        $verb = $by_uid ? 'UID SEARCH' : 'SEARCH';
        $this->queueWrite($key,
            "* SEARCH" . ($hits ? ' ' . implode(' ', $hits) :
                '') . "\r\n");
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Tokenizes a SEARCH argument string into a flat list of
     * uppercased keyword atoms and their string operands.
     * Quoted strings are unwrapped, parenthesized subgroups
     * are bracketed with synthetic '(' and ')' markers, and
     * literal forms are collapsed to their string content.
     * Returns null on a parse error.
     */
    protected function imapTokenizeSearch($s)
    {
        $output = [];
        $i = 0;
        $n = strlen($s);
        while ($i < $n) {
            $c = $s[$i];
            if ($c === ' ' || $c === "\t") {
                $i++;
                continue;
            }
            if ($c === '(') {
                $output[] = ['(', '('];
                $i++;
                continue;
            }
            if ($c === ')') {
                $output[] = [')', ')'];
                $i++;
                continue;
            }
            if ($c === '"') {
                $j = $i + 1;
                $value = '';
                while ($j < $n && $s[$j] !== '"') {
                    if ($s[$j] === '\\' && $j + 1 < $n) {
                        $value .= $s[$j + 1];
                        $j += 2;
                        continue;
                    }
                    $value .= $s[$j];
                    $j++;
                }
                if ($j >= $n) {
                    return null;
                }
                $output[] = ['STR', $value];
                $i = $j + 1;
                continue;
            }
            $j = $i;
            while ($j < $n && $s[$j] !== ' ' &&
                $s[$j] !== "\t" && $s[$j] !== '(' &&
                $s[$j] !== ')') {
                $j++;
            }
            $token = substr($s, $i, $j - $i);
            $output[] = ['ATOM', $token];
            $i = $j;
        }
        return $output;
    }
    /**
     * Recursive evaluator for a SEARCH key list against one
     * message. Conjuncts adjacent keys; OR <a> <b> as a
     * disjunction; NOT <key> as inversion; (...) grouping for
     * arbitrary boolean trees. Side-loads the message body
     * lazily for keys that need it (BODY, TEXT, HEADER).
     */
    protected function imapEvalSearch(&$tokens, $meta, $sequence_number,
        $last_seq, $last_uid, $user, $folder)
    {
        $cursor = 0;
        $body_cache = null;
        $get_body = function () use (&$body_cache, $user,
            $folder, $meta) {
            if ($body_cache === null) {
                $body_cache = $this->mail_storage->fetchMessage(
                    $user, $folder, $meta['uid']);
                if ($body_cache === false) {
                    $body_cache = '';
                }
            }
            return $body_cache;
        };
        $eval_one = function () use (&$cursor, &$tokens, $meta,
            $sequence_number, $last_seq, $last_uid, $get_body, &$eval_one) {
            if ($cursor >= count($tokens)) {
                return null;
            }
            $token = $tokens[$cursor++];
            if ($token[0] === '(') {
                $r = true;
                while ($cursor < count($tokens) &&
                    $tokens[$cursor][0] !== ')') {
                    $r = $r && $eval_one();
                }
                if ($cursor < count($tokens)) {
                    $cursor++;
                }
                return $r;
            }
            $keyword = strtoupper($token[1]);
            /*
                Flag-presence keywords map to a single
                in_array check, optionally negated. Folding
                them into a table cuts a 50-line repeated
                pattern down to a single lookup so the
                interpreter does the same work on a fraction
                of the code.
             */
            static $flag_keywords = [
                'NEW' => ['\Recent', true, '\Seen', false],
                'OLD' => ['\Recent', false],
                'RECENT' => ['\Recent', true],
                'SEEN' => ['\Seen', true],
                'UNSEEN' => ['\Seen', false],
                'FLAGGED' => ['\Flagged', true],
                'UNFLAGGED' => ['\Flagged', false],
                'DELETED' => ['\Deleted', true],
                'UNDELETED' => ['\Deleted', false],
                'ANSWERED' => ['\Answered', true],
                'UNANSWERED' => ['\Answered', false],
                'DRAFT' => ['\Draft', true],
                'UNDRAFT' => ['\Draft', false],
            ];
            if ($keyword === 'ALL') {
                return true;
            }
            if (isset($flag_keywords[$keyword])) {
                $rule = $flag_keywords[$keyword];
                $present = in_array($rule[0], $meta['flags'],
                    true);
                if ($present !== $rule[1]) {
                    return false;
                }
                if (isset($rule[2])) {
                    $present = in_array($rule[2],
                        $meta['flags'], true);
                    if ($present !== $rule[3]) {
                        return false;
                    }
                }
                return true;
            }
            if ($keyword === 'NOT') {
                return !$eval_one();
            }
            if ($keyword === 'OR') {
                $a = $eval_one();
                $b = $eval_one();
                return $a || $b;
            }
            if ($keyword === 'KEYWORD' ||
                $keyword === 'UNKEYWORD') {
                $argument = $tokens[$cursor++][1] ?? '';
                $has = in_array($argument, $meta['flags'],
                    true);
                return $keyword === 'KEYWORD' ? $has : !$has;
            }
            if ($keyword === 'FROM' || $keyword === 'TO' ||
                $keyword === 'CC' || $keyword === 'BCC' ||
                $keyword === 'SUBJECT') {
                $argument = $tokens[$cursor++][1] ?? '';
                $header_map = $this->imapParseHeaders(
                    $get_body());
                $header_key = strtolower($keyword);
                $value = $header_map[$header_key] ?? '';
                /*
                    Decode RFC 2047 encoded-words before
                    matching so a search for "Café" finds
                    headers stored as "=?UTF-8?Q?Caf=C3=A9?=".
                 */
                $value = $this->imapDecodeMimeHeader($value);
                return stripos($value, $argument) !== false;
            }
            if ($keyword === 'HEADER') {
                $name = $tokens[$cursor++][1] ?? '';
                $argument = $tokens[$cursor++][1] ?? '';
                $header_map = $this->imapParseHeaders(
                    $get_body());
                $value = $header_map[strtolower($name)] ?? '';
                $value = $this->imapDecodeMimeHeader($value);
                return $argument === '' ? $value !== '' :
                    stripos($value, $argument) !== false;
            }
            if ($keyword === 'BODY' || $keyword === 'TEXT') {
                $argument = $tokens[$cursor++][1] ?? '';
                $haystack = ($keyword === 'BODY') ?
                    $this->imapBodyText($get_body()) :
                    $get_body();
                return stripos($haystack, $argument) !== false;
            }
            if ($keyword === 'SINCE' ||
                $keyword === 'BEFORE' || $keyword === 'ON') {
                $argument = $tokens[$cursor++][1] ?? '';
                $when = strtotime($argument);
                if ($when === false) {
                    return false;
                }
                $message_day = strtotime(gmdate('Y-m-d',
                    $meta['internal_date']));
                $argument_day = strtotime(gmdate('Y-m-d',
                    $when));
                if ($keyword === 'SINCE') {
                    return $message_day >= $argument_day;
                }
                if ($keyword === 'BEFORE') {
                    return $message_day < $argument_day;
                }
                return $message_day === $argument_day;
            }
            if ($keyword === 'LARGER' ||
                $keyword === 'SMALLER') {
                $argument = (int)
                    ($tokens[$cursor++][1] ?? '0');
                if ($keyword === 'LARGER') {
                    return $meta['size'] > $argument;
                }
                return $meta['size'] < $argument;
            }
            if ($keyword === 'UID') {
                $argument = $tokens[$cursor++][1] ?? '';
                $matcher = $this->imapParseMessageSet(
                    $argument, true);
                return $matcher($sequence_number, $last_seq, $meta['uid'],
                    $last_uid);
            }
            /*
                Bare numeric or set: treat as sequence-number
                set per RFC 3501 sec 6.4.4.
             */
            if (preg_match('/^[0-9*,:]+$/', $token[1])) {
                $matcher = $this->imapParseMessageSet($token[1],
                    false);
                return $matcher($sequence_number, $last_seq,
                    $meta['uid'], $last_uid);
            }
            return true;
        };
        $r = true;
        while ($cursor < count($tokens)) {
            $r = $r && $eval_one();
        }
        return $r;
    }
    /**
     * Implements IDLE (RFC 2177): the client says IDLE, the
     * server replies with "+ idling" and keeps the connection
     * open. While idling, processIdleNotifications walks the
     * idle subscribers each main-loop tick and emits untagged
     * responses for changes that have happened to the
     * selected folder since IDLE began. The push set covers
     * three event types per RFC 2177 / RFC 3501:
     *   * N EXISTS         -- a new message was added
     *   * N EXPUNGE        -- a message was permanently
     *                          removed
     *   * N FETCH (FLAGS)  -- flag changes on an existing
     *                          message
     * The IDLE_STATE entry holds a per-message map and the
     * change-counter snapshot taken at IDLE entry so the
     * tick-side code can compute the delta cheaply: when the
     * counter has not moved, no diff is needed. The client
     * terminates by sending "DONE", after which we ack with
     * the tagged OK and clear all idle state.
     */
    protected function imapCmdIdle($key, $tag, &$context)
    {
        $this->clearImapIdleState($context);
        $context['IMAP_LIT_PENDING'] = [
            'continuation' => 'idle',
            'tag' => $tag,
        ];
        if (!empty($context['SELECTED'])) {
            $user = $context['AUTH_USER'];
            $folder = $context['SELECTED'];
            $context['IDLE_FOLDER'] = $folder;
            $context['IDLE_SNAPSHOT'] =
                $this->currentChangeCounter($user, $folder);
            $context['IDLE_STATE'] =
                $this->captureFolderState($user, $folder);
        }
        $this->queueWrite($key, "+ idling\r\n");
    }
    /**
     * Captures the per-message state of a folder for IDLE
     * diff purposes. Returns:
     *   uids   -- ordered list of UIDs in the folder, in the
     *             same order listMessages returns them (which
     *             is also sequence-number order)
     *   flags  -- map UID => flag-string (sorted, joined) so
     *             a flag change shows up as a string change
     *             rather than requiring deep array compare
     *   count  -- number of messages, kept separate so the
     *             EXISTS push can use the new count without
     *             a second listMessages call
     */
    protected function captureFolderState($user, $folder)
    {
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        $uids = [];
        $flags = [];
        foreach ($messages as $meta) {
            $uids[] = $meta['uid'];
            $sorted = $meta['flags'];
            sort($sorted);
            $flags[$meta['uid']] = implode(' ', $sorted);
        }
        return [
            'uids' => $uids,
            'flags' => $flags,
            'count' => count($messages),
        ];
    }
    /**
     * Handles IMAP STARTTLS (RFC 2595). Same deferred-upgrade
     * pattern as SMTP: queue the OK reply, set the pending flag,
     * the actual stream_socket_enable_crypto runs in finishWrite
     * once the OK has been flushed. After upgrade, all CAPABILITY
     * results changes (LOGINDISABLED disappears) so a well-
     * behaved client re-issues CAPABILITY.
     */
    protected function dispatchImapStarttls($key, $tag, &$context)
    {
        if (!$this->tls_available) {
            $this->imapResp($key, $tag, "NO", "STARTTLS not available");
            return;
        }
        if (!empty($context['TLS_ACTIVE'])) {
            $this->imapResp($key, $tag, "BAD", "TLS already active");
            return;
        }
        $context['PENDING_STARTTLS'] = true;
        $this->queueWrite($key,
            "$tag OK Begin TLS negotiation now\r\n");
    }
    /**
     * Drains pending bytes from a connection's outbound
     * buffer to its socket, called when the select loop
     * reports the socket writable. Tolerates partial writes:
     * fwrite may consume fewer bytes than offered (TCP buffer
     * full), in which case the unwritten tail stays queued
     * for the next tick. When the buffer fully drains, hands
     * off to finishWrite to clean up and trigger any deferred
     * actions (e.g. STARTTLS handshake or QUIT-driven close).
     *
     * @param resource $stream client socket
     */
    protected function writeClient($stream)
    {
        $key = (int) $stream;
        if (!isset($this->out_streams[self::DATA][$key])) {
            return;
        }
        $data = $this->out_streams[self::DATA][$key];
        if ($data === "") {
            $this->finishWrite($key);
            return;
        }
        $n = @fwrite($stream, $data);
        if ($n === false) {
            $this->shutdownStream($key);
            return;
        }
        if ($n > 0) {
            $this->out_streams[self::DATA][$key] =
                substr($data, $n);
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        }
        if ($this->out_streams[self::DATA][$key] === "") {
            $this->finishWrite($key);
        }
    }
    /**
     * Called once the out_streams buffer for $key has fully
     * drained: clears the entry and, if the connection was set
     * to QUIT during command processing, tears the stream down
     * for real. Splitting this out keeps writeClient short.
     */
    protected function finishWrite($key)
    {
        unset(
            $this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]);
        if (!isset($this->in_streams[self::CONTEXT][$key])) {
            return;
        }
        $context = & $this->in_streams[self::CONTEXT][$key];
        if (!empty($context['PENDING_STARTTLS'])) {
            /*
                The 220 reply (or IMAP "OK Begin TLS negotiation
                now") has been fully flushed. Negotiate the TLS
                handshake on the same socket; on success, reset
                the protocol state to INIT (RFC 3207 sec 4.2: the
                client must re-EHLO after TLS comes up; same idea
                for IMAP CAPABILITY).
             */
            $context['PENDING_STARTTLS'] = false;
            $connection = $this->in_streams[self::CONNECTION][$key];
            if ($this->upgradeToTls($connection)) {
                $context['TLS_ACTIVE'] = true;
                $context['STATE'] = 'INIT';
                $context['MAILFROM'] = null;
                $context['RCPTTO'] = [];
                $context['AUTH_USER'] = null;
                $context['AUTH_USERNAME'] = null;
                $this->in_streams[self::DATA][$key] = "";
            } else {
                /*
                    Handshake failure mid-session is unrecoverable
                    per RFC 3207 sec 4.1: drop the connection.
                 */
                $this->shutdownStream($key);
                return;
            }
        }
        if ($context && isset($context['STATE']) &&
            $context['STATE'] === 'QUIT') {
            $this->shutdownStream($key);
        }
    }
    /**
     * Tears down a client connection: shutdown(), fclose(),
     * and clears every per-connection slot in both in_streams
     * and out_streams. No-op for immortal listening sockets,
     * which would otherwise close themselves and stop
     * accepting new clients.
     *
     * @param int $key connection key
     */
    protected function shutdownStream($key)
    {
        if (in_array($key, $this->immortal_stream_keys)) {
            return;
        }
        if (isset($this->in_streams[self::CONNECTION][$key])) {
            $stream = $this->in_streams[self::CONNECTION][$key];
            @stream_socket_shutdown($stream, STREAM_SHUT_RDWR);
            @fclose($stream);
        }
        unset(
            $this->in_streams[self::CONNECTION][$key],
            $this->in_streams[self::DATA][$key],
            $this->in_streams[self::CONTEXT][$key],
            $this->in_streams[self::MODIFIED_TIME][$key],
            $this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]);
    }
    /**
     * Closes connections that have been idle longer than the
     * configured CONNECTION_TIMEOUT. Called once per main
     * loop iteration; cheap to skip-call when no streams are
     * outstanding. Listening sockets are exempt via the
     * immortal-streams set.
     */
    protected function cullDeadStreams()
    {
        $timeout =
            $this->default_server_globals['CONNECTION_TIMEOUT'];
        $now = time();
        foreach ($this->in_streams[self::MODIFIED_TIME]
            as $key => $modified_time) {
            if (in_array($key, $this->immortal_stream_keys)) {
                continue;
            }
            if ($now - $modified_time > $timeout) {
                $this->shutdownStream($key);
            }
        }
    }
    /**
     * Drains the timer-alarm priority queue: every timer
     * whose firing time has arrived gets its callback invoked.
     * Repeating timers are re-queued at firing-time +
     * interval; one-shot timers are removed. Exceptions inside
     * a callback are swallowed so a single buggy timer cannot
     * take down the event loop.
     */
    protected function processTimers()
    {
        if ($this->timer_alarms->isEmpty()) {
            return;
        }
        $now = microtime(true);
        while (!$this->timer_alarms->isEmpty()) {
            $top = $this->timer_alarms->top();
            $when = $top['data'][1];
            if ($when > $now) {
                return;
            }
            $this->timer_alarms->extract();
            $id = $top['data'][0];
            if (!isset($this->timers[$id])) {
                continue;
            }
            $timer = $this->timers[$id];
            try {
                call_user_func($timer['callback']);
            } catch (\Throwable $e) {
                /* keep loop alive */
            }
            if (!empty($timer['repeating']) &&
                isset($this->timers[$id])) {
                $next = microtime(true) + $timer['interval'];
                $this->timer_alarms->insert([$id, $next],
                    -$next);
            } else {
                unset($this->timers[$id]);
            }
        }
    }
    /**
     * Walks every active connection and emits IDLE push
     * notifications (EXISTS, EXPUNGE, FETCH FLAGS) for any
     * that are idling and whose subscribed folder has changed
     * since their snapshot. The notification set captures
     * RFC 2177 / RFC 3501 expectations: clients see the same
     * untagged responses they would have seen if they had
     * SELECTed the folder fresh.
     *
     * Called once per main-loop iteration. Cheap when no
     * folder has changed: the change-counter compare is O(1)
     * per subscriber. Folder state is read from disk at most
     * once per (user, folder) per tick via $folder_state_cache,
     * so N idle subscribers on the same active folder share a
     * single listMessages walk instead of doing N independent
     * walks. Worst case improves from O(messages * subscribers)
     * to O(messages + subscribers) per tick.
     */
    protected function processIdleNotifications()
    {
        if (empty($this->in_streams[self::CONTEXT])) {
            return;
        }
        $folder_state_cache = [];
        foreach ($this->in_streams[self::CONTEXT] as $key =>
            $context) {
            if (empty($context['IDLE_FOLDER'])) {
                continue;
            }
            if (empty($context['IMAP_LIT_PENDING']) ||
                !isset($context['IMAP_LIT_PENDING'][
                    'continuation']) ||
                $context['IMAP_LIT_PENDING']['continuation'] !==
                    'idle') {
                continue;
            }
            $user = $context['AUTH_USER'];
            $folder = $context['IDLE_FOLDER'];
            $current = $this->currentChangeCounter($user,
                $folder);
            $snapshot = $context['IDLE_SNAPSHOT'];
            if ($snapshot === null || $current <= $snapshot) {
                continue;
            }
            /*
                The folder has changed since the last tick.
                Reuse a tick-scoped cache of the fresh state
                so multiple subscribers on the same folder do
                a single listMessages walk together. Each
                subscriber then runs the diff against its own
                IDLE_STATE to emit personalized untagged
                responses (different subscribers may have
                joined idle at different points and need
                different deltas).
             */
            $cache_key = $user . '|' . $folder;
            if (!isset($folder_state_cache[$cache_key])) {
                $folder_state_cache[$cache_key] =
                    $this->captureFolderState($user, $folder);
            }
            $fresh = $folder_state_cache[$cache_key];
            $old_state = $context['IDLE_STATE'];
            if ($old_state === null) {
                $old_state = [
                    'uids' => [],
                    'flags' => [],
                    'count' => 0,
                ];
            }
            $expunged_seqs = [];
            $new_seq_by_uid = [];
            foreach ($fresh['uids'] as $index => $uid) {
                $new_seq_by_uid[$uid] = $index + 1;
            }
            foreach ($old_state['uids'] as $index => $uid) {
                if (!in_array($uid, $fresh['uids'], true)) {
                    $expunged_seqs[] = $index + 1;
                }
            }
            rsort($expunged_seqs);
            foreach ($expunged_seqs as $sequence_number) {
                $this->queueWrite($key, "* $sequence_number EXPUNGE\r\n");
            }
            if ($fresh['count'] !== $old_state['count']) {
                /*
                    The EXISTS count is the post-expunge total.
                    Clients update their local view by issuing
                    UID FETCH for the gap between old and new
                    UIDNEXT, which they already track.
                 */
                $this->queueWrite($key,
                    "* " . $fresh['count'] . " EXISTS\r\n");
            }
            foreach ($fresh['flags'] as $uid => $flag_str) {
                if (!isset($old_state['flags'][$uid])) {
                    /* newly arrived; covered by EXISTS above */
                    continue;
                }
                if ($old_state['flags'][$uid] === $flag_str) {
                    continue;
                }
                $sequence_number = $new_seq_by_uid[$uid];
                $this->queueWrite($key,
                    "* $sequence_number FETCH (FLAGS (" . $flag_str .
                    ") UID $uid)\r\n");
            }
            $this->in_streams[self::CONTEXT][$key][
                'IDLE_SNAPSHOT'] = $current;
            $this->in_streams[self::CONTEXT][$key][
                'IDLE_STATE'] = $fresh;
        }
    }
}
