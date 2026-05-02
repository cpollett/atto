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
    public function userExists($username)
    {
        $this->load();
        return isset($this->users[strtolower($username)]);
    }
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
     * Strips path separators and dot-prefixed components from a
     * username so it can be used as a directory name without
     * letting a crafted username escape the user-tree base. Mail
     * usernames in the wild use [A-Za-z0-9._-]; we accept that
     * set and normalize the rest to underscore.
     */
    protected function safeName($user)
    {
        $user = (string) $user;
        $user = preg_replace('/[^A-Za-z0-9._-]/', '_', $user);
        $user = ltrim($user, '.');
        if ($user === "" || $user === "_") {
            $user = "_invalid_";
        }
        return $user;
    }
    /**
     * Canonicalizes a folder path: collapses repeated slashes,
     * strips leading/trailing slashes, and rejects "." or ".."
     * components. INBOX is normalized to all-uppercase per RFC
     * 3501. Throws on invalid input.
     */
    protected function normalizeFolder($folder)
    {
        $folder = (string) $folder;
        $folder = trim($folder, "/");
        if ($folder === "") {
            return "INBOX";
        }
        if (strcasecmp($folder, "INBOX") === 0) {
            return "INBOX";
        }
        $parts = preg_split('#/+#', $folder);
        $clean = [];
        foreach ($parts as $p) {
            if ($p === "" || $p === "." || $p === "..") {
                throw new \InvalidArgumentException(
                    "invalid folder component: '$p'");
            }
            $clean[] = $p;
        }
        return implode("/", $clean);
    }
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
                UIDVALIDITY must be a 32-bit unsigned int that
                strictly increases across recreations of the
                folder. time() at account creation is the standard
                trick: monotonic per-user across deletes and fits
                in 32 bits until 2106.
             */
            file_put_contents($uidvalidity_file, (string) time());
        }
        $uidnext_file = $dir . DIRECTORY_SEPARATOR . ".uidnext";
        if (!is_file($uidnext_file)) {
            file_put_contents($uidnext_file, "1");
        }
        $this->createFolder($user, "INBOX");
        return true;
    }
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
    public function createFolder($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        $path = $this->folderDir($user, $folder);
        if (is_dir($path)) {
            return true;
        }
        if (!is_dir($this->userDir($user))) {
            $this->ensureUser($user);
        }
        return @mkdir($path, 0700, true);
    }
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
        foreach ($this->listFolders($user) as $f) {
            if (strpos($f, $prefix) === 0) {
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
        $fp = @fopen($file, "c+");
        if ($fp === false) {
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return false;
        }
        rewind($fp);
        $contents = stream_get_contents($fp);
        $next = (int) trim($contents);
        if ($next < 1) {
            $next = 1;
        }
        $assigned = $next;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, (string) ($assigned + 1));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return $assigned;
    }
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
        $tmp = $eml . ".tmp";
        if (file_put_contents($tmp, $bytes) === false) {
            return false;
        }
        if (!@rename($tmp, $eml)) {
            @unlink($tmp);
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
            foreach (preg_split('/\r\n|\r|\n/', $contents) as $f) {
                $f = trim($f);
                if ($f !== "") {
                    $flags[] = $f;
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
        foreach ($flags as $f) {
            $f = trim((string) $f);
            if ($f !== "") {
                $clean[] = $f;
            }
        }
        $written = @file_put_contents(
            $dir . DIRECTORY_SEPARATOR . "$uid.flags",
            implode("\n", $clean));
        return $written !== false;
    }
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
    public function messageCount($user, $folder)
    {
        return count($this->listMessages($user, $folder));
    }
    public function uidValidity($user, $folder)
    {
        $file = $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".uidvalidity";
        if (!is_file($file)) {
            $this->ensureUser($user);
        }
        return (int) @file_get_contents($file);
    }
    public function uidNext($user, $folder)
    {
        $file = $this->userDir($user) . DIRECTORY_SEPARATOR .
            ".uidnext";
        if (!is_file($file)) {
            $this->ensureUser($user);
        }
        return (int) trim((string) @file_get_contents($file));
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
 *      $mail->filter(function ($from, $to, $bytes, $ctx) { });
 *      $mail->domains(['example.com', 'localhost']);
 *      $mail->listen(['SMTP_PORT' => 2525, 'IMAP_PORT' => 1143,
 *          'SERVER_CONTEXT' => ['ssl' => [...]]]);
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
    /** @var callable|null filter callable(from, to, bytes, ctx) */
    protected $filter_fn;
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
     * Sets the optional filter callable run when a message
     * arrives via SMTP for a local user. Signature:
     *      function($from, $to, $bytes, $ctx): array|bool|null
     * The return value either:
     *   - false to drop the message silently (still 250 to the
     *     sender so spam senders cannot probe filter behavior)
     *   - an array ['folder' => 'Junk', 'flags' => ['\Seen']]
     *     to redirect delivery to a different folder and/or set
     *     initial flags
     *   - true or null to deliver to INBOX with default flags
     * The $ctx is the per-connection context array containing
     * REMOTE_ADDR, REMOTE_PORT, AUTH_USER (if authenticated),
     * etc., useful for sender-policy decisions.
     */
    public function filter(callable $filter)
    {
        $this->filter_fn = $filter;
        return $this;
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
        foreach ($domains as $d) {
            $d = strtolower(trim((string) $d));
            if ($d !== "") {
                $clean[] = $d;
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
     * @param array $ctx optional context array passed to the
     *      filter (caller supplies arbitrary fields)
     * @return int|false UID of the delivered message, or false
     *      on filter-drop or unknown recipient
     */
    public function deliverMail($from, $to, $bytes, $ctx = [])
    {
        $local = $this->resolveLocalUser($to);
        if ($local === false) {
            return false;
        }
        $folder = "INBOX";
        $flags = ['\Recent'];
        if (is_callable($this->filter_fn)) {
            $verdict = call_user_func($this->filter_fn, $from, $to,
                $bytes, $ctx);
            if ($verdict === false) {
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
        }
        $this->mail_storage->ensureUser($local);
        return $this->mail_storage->appendMessage($local, $folder,
            $bytes, $flags);
    }
    public function listFolders($user)
    {
        return $this->mail_storage->listFolders($user);
    }
    public function createFolder($user, $folder)
    {
        return $this->mail_storage->createFolder($user, $folder);
    }
    public function deleteFolder($user, $folder)
    {
        return $this->mail_storage->deleteFolder($user, $folder);
    }
    public function renameFolder($user, $old, $new)
    {
        return $this->mail_storage->renameFolder($user, $old,
            $new);
    }
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $date = 0)
    {
        return $this->mail_storage->appendMessage($user, $folder,
            $bytes, $flags, $date);
    }
    public function fetchMessage($user, $folder, $uid)
    {
        return $this->mail_storage->fetchMessage($user, $folder,
            $uid);
    }
    public function listMessages($user, $folder)
    {
        return $this->mail_storage->listMessages($user, $folder);
    }
    public function messageMeta($user, $folder, $uid)
    {
        return $this->mail_storage->messageMeta($user, $folder,
            $uid);
    }
    public function setFlags($user, $folder, $uid, $flags)
    {
        return $this->mail_storage->setFlags($user, $folder, $uid,
            $flags);
    }
    public function expunge($user, $folder)
    {
        return $this->mail_storage->expunge($user, $folder);
    }
    public function moveMessage($user, $from, $to, $uid)
    {
        return $this->mail_storage->moveMessage($user, $from, $to,
            $uid);
    }
    public function messageCount($user, $folder)
    {
        return $this->mail_storage->messageCount($user, $folder);
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
    public function clearTimer($id)
    {
        unset($this->timers[$id]);
    }
    /**
     * Binds the SMTP and IMAP listening sockets and runs the
     * event loop forever. The $config array overrides the
     * built-in defaults; the SERVER_CONTEXT key (if present) is
     * passed through to stream_context_create for TLS settings.
     */
    public function listen($config = [])
    {
        $defaults = [
            'SMTP_PORT' => 2525,
            'IMAP_PORT' => 1143,
            'BIND' => '0.0.0.0',
            'SERVER_NAME' => 'localhost',
            'SERVER_SOFTWARE' => 'AttoMail',
            'CONNECTION_TIMEOUT' => 30 * 60,
            'MAX_COMMAND_LEN' => 2048,
            'MAX_MESSAGE_LEN' => 25 * 1024 * 1024,
        ];
        $context_array = [];
        if (isset($config['SERVER_CONTEXT'])) {
            $context_array = $config['SERVER_CONTEXT'];
            unset($config['SERVER_CONTEXT']);
        }
        $this->default_server_globals = array_merge($defaults,
            $config);
        $bind = $this->default_server_globals['BIND'];
        $smtp_addr = "tcp://$bind:" .
            $this->default_server_globals['SMTP_PORT'];
        $imap_addr = "tcp://$bind:" .
            $this->default_server_globals['IMAP_PORT'];
        $ctx = stream_context_create($context_array);
        $smtp = @stream_socket_server($smtp_addr, $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
        if (!$smtp) {
            echo "Failed to bind SMTP $smtp_addr: $errstr\n";
            return false;
        }
        stream_set_blocking($smtp, 0);
        $imap = @stream_socket_server($imap_addr, $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
        if (!$imap) {
            echo "Failed to bind IMAP $imap_addr: $errstr\n";
            fclose($smtp);
            return false;
        }
        stream_set_blocking($imap, 0);
        $this->immortal_stream_keys = [(int) $smtp, (int) $imap];
        $this->in_streams = [
            self::CONNECTION => [(int) $smtp => $smtp,
                (int) $imap => $imap],
            self::DATA => [(int) $smtp => "", (int) $imap => ""],
            self::CONTEXT => [],
            self::MODIFIED_TIME => [],
        ];
        $this->out_streams = [
            self::CONNECTION => [],
            self::DATA => [],
            self::CONTEXT => [],
            self::MODIFIED_TIME => [],
        ];
        $listeners = [(int) $smtp => 'SMTP', (int) $imap => 'IMAP'];
        echo "AttoMail SMTP listening at $smtp_addr\n";
        echo "AttoMail IMAP listening at $imap_addr\n";
        $excepts = null;
        while (true) {
            $reads = $this->in_streams[self::CONNECTION];
            $writes = $this->out_streams[self::CONNECTION];
            $timeout = null;
            $microtimeout = 0;
            if (!$this->timer_alarms->isEmpty()) {
                $top = $this->timer_alarms->top();
                $when = $top['data'][1];
                $delta = max(0.0, $when - microtime(true));
                $timeout = (int) floor($delta);
                $microtimeout = (int) (($delta - $timeout) * 1e6);
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
            $this->cullDeadStreams();
        }
    }
    /**
     * Accepts a new client connection on one of the listening
     * sockets and installs an initial context with the welcome
     * banner queued for write. SMTP greets with 220, IMAP with
     * "* OK".
     */
    protected function acceptConnection($server, $protocol)
    {
        $conn = @stream_socket_accept($server, 0);
        if (!$conn) {
            return;
        }
        stream_set_blocking($conn, 0);
        $key = (int) $conn;
        $remote = (string) stream_socket_get_name($conn, true);
        $colon = strrpos($remote, ":");
        $remote_addr = ($colon === false) ? $remote :
            substr($remote, 0, $colon);
        $remote_port = ($colon === false) ? 0 :
            (int) substr($remote, $colon + 1);
        $name = $this->default_server_globals['SERVER_NAME'];
        $this->in_streams[self::CONNECTION][$key] = $conn;
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
            'TLS' => false,
            'AUTH_USERNAME' => null,
        ];
        if ($protocol === 'SMTP') {
            $banner = "220 $name " .
                $this->default_server_globals['SERVER_SOFTWARE'] .
                " ESMTP ready\r\n";
        } else {
            $banner = "* OK [CAPABILITY IMAP4rev1 STARTTLS " .
                "LOGINDISABLED] $name ready\r\n";
        }
        $this->queueWrite($key, $banner);
    }
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
        $ctx = & $this->in_streams[self::CONTEXT][$key];
        $proto = $ctx['PROTOCOL'];
        $buf = & $this->in_streams[self::DATA][$key];
        if ($proto === 'SMTP' && $ctx['STATE'] === 'DATA') {
            return $this->consumeSmtpDataPhase($key, $buf, $ctx);
        }
        $eol = strpos($buf, "\r\n");
        if ($eol === false) {
            $eol = strpos($buf, "\n");
            if ($eol === false) {
                return false;
            }
            $line = substr($buf, 0, $eol);
            $buf = substr($buf, $eol + 1);
        } else {
            $line = substr($buf, 0, $eol);
            $buf = substr($buf, $eol + 2);
        }
        $line = rtrim($line, "\r\n");
        if ($proto === 'SMTP') {
            $this->dispatchSmtp($key, $line, $ctx);
        } else {
            $this->dispatchImap($key, $line, $ctx);
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
    protected function dispatchSmtp($key, $line, &$ctx)
    {
        $upper = strtoupper($line);
        if (strncmp($upper, 'EHLO', 4) === 0 ||
            strncmp($upper, 'HELO', 4) === 0) {
            $ctx['STATE'] = 'READY';
            $name = $this->default_server_globals['SERVER_NAME'];
            $resp = "250-$name Hello\r\n";
            $resp .= "250-AUTH PLAIN LOGIN\r\n";
            $resp .= "250-SIZE " .
                $this->default_server_globals['MAX_MESSAGE_LEN'] .
                "\r\n";
            $resp .= "250 HELP\r\n";
            $this->queueWrite($key, $resp);
            return;
        }
        if (strncmp($upper, 'NOOP', 4) === 0) {
            $this->queueWrite($key, "250 OK\r\n");
            return;
        }
        if (strncmp($upper, 'RSET', 4) === 0) {
            $ctx['MAILFROM'] = null;
            $ctx['RCPTTO'] = [];
            $ctx['STATE'] = 'READY';
            $this->queueWrite($key, "250 OK\r\n");
            return;
        }
        if (strncmp($upper, 'QUIT', 4) === 0) {
            $this->queueWrite($key, "221 Bye\r\n");
            $ctx['STATE'] = 'QUIT';
            return;
        }
        if ($ctx['STATE'] === 'INIT') {
            $this->queueWrite($key,
                "503 5.5.1 send EHLO/HELO first\r\n");
            return;
        }
        if (strncmp($upper, 'AUTH ', 5) === 0 ||
            $ctx['STATE'] === 'AUTH-PLAIN' ||
            $ctx['STATE'] === 'AUTH-LOGIN-USER' ||
            $ctx['STATE'] === 'AUTH-LOGIN-PASS') {
            $this->dispatchSmtpAuth($key, $line, $ctx);
            return;
        }
        if (strncmp($upper, 'MAIL FROM', 9) === 0) {
            $this->dispatchSmtpMailFrom($key, $line, $ctx);
            return;
        }
        if (strncmp($upper, 'RCPT TO', 7) === 0) {
            $this->dispatchSmtpRcptTo($key, $line, $ctx);
            return;
        }
        if (strncmp($upper, 'DATA', 4) === 0) {
            if ($ctx['STATE'] !== 'RCPT') {
                $this->queueWrite($key,
                    "503 5.5.1 need RCPT TO first\r\n");
                return;
            }
            $ctx['STATE'] = 'DATA';
            $this->queueWrite($key,
                "354 End data with <CR><LF>.<CR><LF>\r\n");
            return;
        }
        $this->queueWrite($key,
            "500 5.5.1 Unrecognized command\r\n");
    }
    /**
     * Handles AUTH PLAIN and AUTH LOGIN. PLAIN can carry the
     * credentials inline ("AUTH PLAIN <base64>") or in a
     * continuation line after a 334 challenge. LOGIN always
     * uses a two-line continuation: server prompts username
     * then password, both base64-encoded.
     */
    protected function dispatchSmtpAuth($key, $line, &$ctx)
    {
        if ($ctx['STATE'] === 'AUTH-PLAIN') {
            $this->finishAuthPlain($key, $line, $ctx);
            return;
        }
        if ($ctx['STATE'] === 'AUTH-LOGIN-USER') {
            $ctx['AUTH_USERNAME'] = (string) base64_decode($line,
                true);
            $ctx['STATE'] = 'AUTH-LOGIN-PASS';
            $this->queueWrite($key,
                "334 " . base64_encode("Password:") . "\r\n");
            return;
        }
        if ($ctx['STATE'] === 'AUTH-LOGIN-PASS') {
            $pass = (string) base64_decode($line, true);
            $user = (string) $ctx['AUTH_USERNAME'];
            $ctx['AUTH_USERNAME'] = null;
            $this->verifyAndSetAuth($key, $user, $pass, $ctx);
            return;
        }
        if (preg_match('/^AUTH\s+PLAIN(?:\s+(.+))?$/i', $line,
            $m)) {
            if (!empty($m[1])) {
                $this->finishAuthPlain($key, trim($m[1]), $ctx);
                return;
            }
            $ctx['STATE'] = 'AUTH-PLAIN';
            $this->queueWrite($key, "334 \r\n");
            return;
        }
        if (preg_match('/^AUTH\s+LOGIN(?:\s+(.+))?$/i', $line,
            $m)) {
            $ctx['STATE'] = 'AUTH-LOGIN-USER';
            if (!empty($m[1])) {
                $ctx['AUTH_USERNAME'] = (string) base64_decode(
                    trim($m[1]), true);
                $ctx['STATE'] = 'AUTH-LOGIN-PASS';
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
    protected function finishAuthPlain($key, $b64, &$ctx)
    {
        $raw = (string) base64_decode($b64, true);
        $parts = explode("\x00", $raw);
        if (count($parts) !== 3) {
            $ctx['STATE'] = 'READY';
            $this->queueWrite($key,
                "535 5.7.8 Authentication credentials" .
                " invalid\r\n");
            return;
        }
        list(, $user, $pass) = $parts;
        $this->verifyAndSetAuth($key, $user, $pass, $ctx);
    }
    protected function verifyAndSetAuth($key, $user, $pass, &$ctx)
    {
        $ok = false;
        if ($this->authenticator !== null) {
            $ok = $this->authenticator->verifyPassword($user,
                $pass);
        }
        if ($ok) {
            $ctx['AUTH_USER'] = strtolower($user);
            $ctx['STATE'] = 'READY';
            $this->queueWrite($key,
                "235 2.7.0 Authentication succeeded\r\n");
        } else {
            $ctx['STATE'] = 'READY';
            $this->queueWrite($key,
                "535 5.7.8 Authentication credentials" .
                " invalid\r\n");
        }
    }
    /**
     * Parses MAIL FROM:<addr> and stores the envelope sender on
     * the connection. Accepts an empty path "<>" (DSN/bounce).
     * The session does not need to be authenticated to set a
     * sender; what is policed is the RCPT TO step.
     */
    protected function dispatchSmtpMailFrom($key, $line, &$ctx)
    {
        if (!preg_match(
            '/^MAIL\s+FROM\s*:\s*<([^>]*)>(?:\s+.*)?$/i',
            $line, $m)) {
            $this->queueWrite($key,
                "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
            return;
        }
        $ctx['MAILFROM'] = trim($m[1]);
        $ctx['RCPTTO'] = [];
        $ctx['STATE'] = 'MAIL';
        $this->queueWrite($key, "250 2.1.0 Ok\r\n");
    }
    /**
     * Parses RCPT TO:<addr> and applies the anti-relay rule:
     *   - if the recipient is local (a known user at a local
     *     domain), accept regardless of authentication
     *   - if the recipient is non-local, require that the
     *     session be authenticated; otherwise reject 550 5.7.1
     * This is what makes the server NOT an open relay.
     */
    protected function dispatchSmtpRcptTo($key, $line, &$ctx)
    {
        if ($ctx['STATE'] !== 'MAIL' && $ctx['STATE'] !== 'RCPT') {
            $this->queueWrite($key,
                "503 5.5.1 need MAIL FROM first\r\n");
            return;
        }
        if (!preg_match(
            '/^RCPT\s+TO\s*:\s*<([^>]*)>(?:\s+.*)?$/i',
            $line, $m)) {
            $this->queueWrite($key,
                "501 5.5.4 Syntax: RCPT TO:<address>\r\n");
            return;
        }
        $rcpt = trim($m[1]);
        $local_user = $this->resolveLocalUser($rcpt);
        if ($local_user === false) {
            if (empty($ctx['AUTH_USER'])) {
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
        $ctx['RCPTTO'][] = ['addr' => $rcpt, 'user' => $local_user];
        $ctx['STATE'] = 'RCPT';
        $this->queueWrite($key, "250 2.1.5 Ok\r\n");
    }
    /**
     * Drains DATA bytes from the input buffer until it sees the
     * end-of-data sentinel CRLF.CRLF (or LF.LF as a tolerated
     * variant). Returns true once one full message has been
     * consumed (caller will loop and try the next command).
     * Performs CRLF dot-unstuffing per RFC 5321 sec 4.5.2.
     */
    protected function consumeSmtpDataPhase($key, &$buf, &$ctx)
    {
        $marker = "\r\n.\r\n";
        $pos = strpos($buf, $marker);
        $marker_len = 5;
        if ($pos === false) {
            $alt = "\n.\n";
            $alt_pos = strpos($buf, $alt);
            if ($alt_pos === false) {
                return false;
            }
            $pos = $alt_pos;
            $marker_len = 3;
        }
        $msg = substr($buf, 0, $pos + 2);
        $buf = substr($buf, $pos + $marker_len);
        $msg = preg_replace('/(\r\n|\n)\.(\r\n|\n|\.)/',
            '$1$2', $msg);
        $max = $this->default_server_globals['MAX_MESSAGE_LEN'];
        if (strlen($msg) > $max) {
            $this->queueWrite($key,
                "552 5.3.4 Message exceeds size limit\r\n");
            $ctx['STATE'] = 'READY';
            $ctx['MAILFROM'] = null;
            $ctx['RCPTTO'] = [];
            return true;
        }
        $msg = $this->prependReceivedHeader($msg, $ctx);
        $delivered_any = false;
        foreach ($ctx['RCPTTO'] as $r) {
            $uid = $this->deliverMail($ctx['MAILFROM'], $r['addr'],
                $msg, $ctx);
            if ($uid !== false) {
                $delivered_any = true;
            }
        }
        $ctx['STATE'] = 'READY';
        $ctx['MAILFROM'] = null;
        $ctx['RCPTTO'] = [];
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
     * Prepends a Received: trace header per RFC 5321 sec 4.4.
     * Mail clients use this header to render the routing path
     * and SpamAssassin-class tools rely on it to reconstruct
     * the delivery chain. We include the remote address, our
     * server name, the protocol (ESMTPA when authenticated),
     * and the receipt timestamp.
     */
    protected function prependReceivedHeader($msg, $ctx)
    {
        $name = $this->default_server_globals['SERVER_NAME'];
        $sw = $this->default_server_globals['SERVER_SOFTWARE'];
        $with = empty($ctx['AUTH_USER']) ? 'ESMTP' : 'ESMTPA';
        $now = gmdate("D, d M Y H:i:s") . " +0000";
        $remote = $ctx['REMOTE_ADDR'];
        $rcpt = "";
        if (!empty($ctx['RCPTTO'])) {
            $first = $ctx['RCPTTO'][0];
            $rcpt = "for <" . $first['addr'] . ">";
        }
        $hdr = "Received: from [$remote] by $name ($sw)" .
            " with $with $rcpt; $now\r\n";
        return $hdr . $msg;
    }
    /**
     * Stubs out IMAP for Phase 1: replies BAD to any command so
     * a client probing the port gets a clear error rather than
     * a hang. Phase 3 will replace this with real LOGIN, LIST,
     * SELECT, FETCH, etc.
     */
    protected function dispatchImap($key, $line, &$ctx)
    {
        $tag = "*";
        $sp = strpos($line, " ");
        if ($sp !== false) {
            $tag = substr($line, 0, $sp);
        }
        $upper = strtoupper(trim(substr($line, $sp === false ?
            0 : $sp + 1)));
        if (strncmp($upper, 'LOGOUT', 6) === 0) {
            $this->queueWrite($key, "* BYE Logging out\r\n");
            $this->queueWrite($key,
                "$tag OK LOGOUT completed\r\n");
            $ctx['STATE'] = 'QUIT';
            return;
        }
        if (strncmp($upper, 'CAPABILITY', 10) === 0) {
            $this->queueWrite($key, "* CAPABILITY IMAP4rev1\r\n");
            $this->queueWrite($key,
                "$tag OK CAPABILITY completed\r\n");
            return;
        }
        if (strncmp($upper, 'NOOP', 4) === 0) {
            $this->queueWrite($key,
                "$tag OK NOOP completed\r\n");
            return;
        }
        $this->queueWrite($key,
            "$tag BAD IMAP not yet implemented in this build\r\n");
    }
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
        $ctx = isset($this->in_streams[self::CONTEXT][$key]) ?
            $this->in_streams[self::CONTEXT][$key] : null;
        if ($ctx && isset($ctx['STATE']) &&
            $ctx['STATE'] === 'QUIT') {
            $this->shutdownStream($key);
        }
    }
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
    protected function cullDeadStreams()
    {
        $timeout =
            $this->default_server_globals['CONNECTION_TIMEOUT'];
        $now = time();
        foreach ($this->in_streams[self::MODIFIED_TIME]
            as $key => $t) {
            if (in_array($key, $this->immortal_stream_keys)) {
                continue;
            }
            if ($now - $t > $timeout) {
                $this->shutdownStream($key);
            }
        }
    }
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
            $t = $this->timers[$id];
            try {
                call_user_func($t['callback']);
            } catch (\Throwable $e) {
                /* keep loop alive */
            }
            if (!empty($t['repeating']) &&
                isset($this->timers[$id])) {
                $next = microtime(true) + $t['interval'];
                $this->timer_alarms->insert([$id, $next], -$next);
            } else {
                unset($this->timers[$id]);
            }
        }
    }
}
