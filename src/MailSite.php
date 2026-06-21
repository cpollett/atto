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
     * @param string $username login name used to look up the credential record
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
    /**
     * Lazily-loaded credential map (username => password); null
     * until the file is first read.
     * @var array|null
     */
    protected $users;
    /**
     * @param string $path path to the password file from which
     *      credentials are loaded
     */
    public function __construct(protected $path)
    {
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
     * @param string $username login name
     */
    public function userExists($username)
    {
        $this->load();
        return isset($this->users[strtolower($username)]);
    }
    /**
     * @inheritdoc
     * @param string $username login name
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
     * @param string $username login name
     */
    public function userExists($username)
    {
        return is_string($username) && $username !== "";
    }
    /**
     * @inheritdoc
     * @param string $username login name
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
 * Shared vocabulary of magic-string values used across the mail
 * storage engines and the IMAP/SMTP server: the RFC 3501 system
 * flag atoms, the canonical INBOX folder name, and the filename
 * extension for a stored raw message. Centralizing them gives each
 * value a single definition that every implementing class reaches
 * through self::, so changing a value (or checking for a typo)
 * happens in exactly one place.
 */
interface MailVocabulary
{
    /** RFC 3501 system flag marking a message as read. */
    const FLAG_SEEN = '\Seen';
    /** RFC 3501 system flag marking a message as answered. */
    const FLAG_ANSWERED = '\Answered';
    /** RFC 3501 system flag marking a message as flagged. */
    const FLAG_FLAGGED = '\Flagged';
    /** RFC 3501 system flag marking a message for expunge. */
    const FLAG_DELETED = '\Deleted';
    /** RFC 3501 system flag marking a message as a draft. */
    const FLAG_DRAFT = '\Draft';
    /** RFC 3501 session-only system flag for recent arrival. */
    const FLAG_RECENT = '\Recent';
    /** Canonical name of the always-present base folder. */
    const FOLDER_INBOX = 'INBOX';
    /** Canonical Sent folder (RFC 6154 \Sent special-use). */
    const FOLDER_SENT = 'Sent';
    /** Canonical Drafts folder (RFC 6154 \Drafts special-use). */
    const FOLDER_DRAFTS = 'Drafts';
    /** Canonical Junk folder (RFC 6154 \Junk special-use). */
    const FOLDER_JUNK = 'Junk';
    /** Canonical Trash folder (RFC 6154 \Trash special-use). */
    const FOLDER_TRASH = 'Trash';
    /**
     * Filename extension (without the leading dot) for a stored
     * raw RFC822 message, shared by the file backend's per-message
     * files and the SQL backend's blob store.
     */
    const MESSAGE_FILE_EXTENSION = 'eml';
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
abstract class MailStorage implements MailVocabulary
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
     * @param string $user username (no @domain) identifying the mail account
     * @return array list of folder name strings
     */
    abstract public function listFolders($user);
    /**
     * Creates a new folder. Idempotent: creating an existing
     * folder returns true without error.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder e.g. "Archive/2026/Q1"
     * @return bool true on success
     */
    abstract public function createFolder($user, $folder);
    /**
     * Provisions the standard RFC 6154 special-use folders
     * (Sent, Drafts, Junk, Trash) for a user and consolidates
     * onto them. For each role the canonical folder is created
     * if missing; then any other existing folder that maps to
     * the same role by a conventional alias (e.g. "Deleted
     * Messages" for Trash, "Sent Messages" for Sent) has its
     * messages moved into the canonical folder and is removed.
     * This converges an account on one folder per role so
     * clients such as Apple Mail stop creating duplicates. Safe
     * to call on every login: when an account is already clean
     * the alias scan finds nothing and it is a no-op aside from
     * the idempotent createFolder calls.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @return array list of consolidations performed; each entry
     *      has 'from' (the non-canonical folder), 'into' (the
     *      canonical folder), 'moved' (messages copied), 'failed'
     *      (messages that could not be copied), and 'deleted'
     *      (whether the source folder was removed; false when any
     *      message failed so the source is kept for a retry).
     *      Empty when nothing needed consolidating.
     */
    public function ensureStandardFolders($user)
    {
        /*
            Each canonical special-use folder, paired with the
            other conventional names clients use for the same
            role. When a non-canonical role-equivalent exists we
            move its messages into the canonical folder and remove
            the emptied original so an account converges on one
            folder per role. The match is case-insensitive.
         */
        $roles = [
            self::FOLDER_SENT => ['sent items', 'sent messages'],
            self::FOLDER_DRAFTS => ['draft'],
            self::FOLDER_JUNK => ['spam'],
            self::FOLDER_TRASH => ['deleted', 'deleted items',
                'deleted messages'],
        ];
        $consolidations = [];
        foreach ($roles as $canonical => $aliases) {
            $this->createFolder($user, $canonical);
            $canonical_lower = strtolower($canonical);
            foreach ($this->listFolders($user) as $existing) {
                $existing_lower = strtolower($existing);
                if ($existing_lower === $canonical_lower) {
                    continue;
                }
                if (!in_array($existing_lower, $aliases, true)) {
                    continue;
                }
                $moved = 0;
                $failed = 0;
                $copied_uids = [];
                foreach ($this->listMessages($user, $existing)
                    as $meta) {
                    $body = $this->fetchMessage($user, $existing,
                        $meta['uid']);
                    if ($body === false) {
                        $failed++;
                        continue;
                    }
                    $new_uid = $this->appendMessage($user,
                        $canonical, $body, $meta['flags'],
                        $meta['internal_date']);
                    if ($new_uid === false) {
                        $failed++;
                        continue;
                    }
                    $moved++;
                    $copied_uids[] = (int) $meta['uid'];
                }
                /*
                    Remove from the source only the messages that
                    were actually copied into the canonical folder.
                    A message whose fetch or append failed stays in
                    the source so its mail is never lost, and
                    because the copied ones are removed here a retry
                    on the next login re-copies only the failures
                    rather than duplicating what already moved.
                 */
                foreach ($copied_uids as $copied_uid) {
                    $this->setFlags($user, $existing, $copied_uid,
                        [self::FLAG_DELETED]);
                }
                if (!empty($copied_uids)) {
                    $this->expunge($user, $existing, $copied_uids);
                }
                /*
                    Drop the now-empty source only when every
                    message moved; otherwise keep it holding the
                    failures for the next attempt.
                 */
                $deleted = false;
                if ($failed === 0) {
                    $deleted = $this->deleteFolder($user, $existing);
                }
                $consolidations[] = ['from' => $existing,
                    'into' => $canonical, 'moved' => $moved,
                    'failed' => $failed, 'deleted' => $deleted];
            }
        }
        return $consolidations;
    }
    /**
     * Deletes a folder and all messages in it. Refuses to
     * delete INBOX and refuses to delete a folder that has
     * subfolders (the IMAP convention; clients delete subtrees
     * recursively).
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool true on success
     */
    abstract public function deleteFolder($user, $folder);
    /**
     * Renames a folder. Refuses to rename INBOX (per RFC 3501
     * the rename of INBOX has special semantics; we choose the
     * simpler "no" answer instead).
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $old current folder name to rename from
     * @param string $new target folder name to rename to
     * @return bool true on success
     */
    abstract public function renameFolder($user, $old, $new);
    /**
     * Returns whether the named folder exists for this user.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool true if the named folder exists under $user, false otherwise
     */
    abstract public function folderExists($user, $folder);
    /**
     * Stores a new message and returns its assigned UID.
     *
     * @param string $user username (no @domain) identifying the mail account
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
     * Maximum bytes to read when fetching just the header block.
     * Higher than any real-world RFC 5322 header set; sized so a
     * file-backed storage can extract headers without slurping
     * an entire message-with-attachments off disk.
     */
    const MAX_HEADER_BYTES = 65536;
    /**
     * Returns the raw RFC 5322 header block for a message
     * (everything before the first blank line). Designed for
     * inbox-listing UIs and other callers that need Subject /
     * From / Date / Delivered-To without paying to read the
     * full body. Backends may read up to MAX_HEADER_BYTES
     * from the underlying message; if a message's header
     * block somehow exceeds that cap, the returned prefix
     * may not contain the terminator and downstream parsers
     * should treat the result as a best-effort header view.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder path with hierarchy (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return string|false the header block (no trailing CRLF
     *      CRLF), or false if the message does not exist
     */
    abstract public function messageHeaderBytes($user, $folder, $uid);
    /**
     * Returns the raw RFC 5322 bytes of a message, or false if
     * not found.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return string|false
     */
    abstract public function fetchMessage($user, $folder, $uid);
    /**
     * Returns metadata for every message in a folder, sorted
     * ascending by UID. Each entry is an associative array with
     * keys: uid (int), size (int), flags (array of strings),
     * internal_date (int unix ts).
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return array list of message metadata records
     */
    abstract public function listMessages($user, $folder);
    /**
     * Returns the uids of the messages in a folder whose subject,
     * from, or to header contains the given query string,
     * case-insensitive. Each storage implements this with whatever
     * index is natural to it (a flat per-folder search file, a SQL
     * column with LIKE, an in-memory scan), so a message-list
     * filter does not have to open and parse every message. An
     * empty query returns an empty list.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param string $query substring to match against subject/from/to
     * @return array list of matching uids that are present in the folder
     */
    abstract public function searchMessages($user, $folder,
        $query);
    /**
     * Returns metadata for one message: same shape as one entry
     * of listMessages, or false if not found.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return array|false metadata record (uid, size, flags, internal_date), or false if the message does not exist
     */
    abstract public function messageMeta($user, $folder, $uid);
    /**
     * Replaces the flag set for a message. Pass an empty array
     * to clear all flags.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @param array $flags list of IMAP flag strings to set on the message
     * @return bool
     */
    abstract public function setFlags($user, $folder, $uid, $flags);
    /**
     * Permanently removes every message in $folder that has the
     * \Deleted flag set. Returns the UIDs that were removed.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param array $uid_restriction when non-null, only deleted
     *      messages whose UID is in this list are removed (the
     *      UID EXPUNGE case, RFC 4315); when null every deleted
     *      message is removed (plain EXPUNGE)
     * @return array list of expunged UIDs
     */
    abstract public function expunge($user, $folder,
        $uid_restriction = null);
    /**
     * Moves a message from one folder to another. The UID is
     * preserved (UIDs are per-user, not per-folder).
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $from source folder for the move operation
     * @param string $to destination folder for the move operation
     * @param int $uid persistent IMAP unique identifier of the message
     * @return bool
     */
    abstract public function moveMessage($user, $from, $to, $uid);
    /**
     * Returns the message count for the named folder.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int number of messages currently in the folder, or -1 if the folder is unknown
     */
    abstract public function messageCount($user, $folder);
    /**
     * Returns the UIDVALIDITY value for a folder. IMAP clients
     * cache this and discard their local cache when it changes;
     * we issue one stable value per user account over its
     * lifetime.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int fixed UIDVALIDITY value for the folder per RFC 3501 sec 2.3.1.1
     */
    abstract public function uidValidity($user, $folder);
    /**
     * Returns the UID that will be assigned to the next message
     * appended (predicted, may not match reality under concurrent
     * appends).
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int next UID that will be assigned for an appended message in the folder
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool
     */
    abstract public function isSubscribed($user, $folder);
    /**
     * Marks a folder as subscribed for a user. The folder need
     * not exist; RFC 3501 sec 6.3.6 explicitly allows
     * subscribing to non-existent mailboxes (a remote-shared
     * folder might be unmounted at the moment). Idempotent.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool true on success
     */
    abstract public function subscribe($user, $folder);
    /**
     * Removes a subscription. Idempotent: unsubscribing a
     * folder that is not subscribed succeeds silently.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool true on success
     */
    abstract public function unsubscribe($user, $folder);
    /**
     * Returns the list of folders this user has subscribed to,
     * sorted ascending. INBOX is always present in the result
     * even if the per-user state file does not list it.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @return string[]
     */
    abstract public function listSubscribed($user);
    /**
     * Returns metadata describing where the body bytes for
     * (user, folder, uid) physically live. Used by callers
     * that need to make content-addressed storage visible:
     * two messages with byte-identical bodies on a
     * deduplicating backend report the same path / hash,
     * while a non-deduplicating backend reports per-message
     * paths.
     *
     * Returns an associative array on success, false if the
     * message does not exist.
     *
     * Keys returned (all backends):
     *   'backend'     - one of 'file', 'ram', 'sql'
     *   'path'        - on-disk path, or null for in-memory
     *
     * Keys returned where applicable:
     *   'hash'        - sha256 of body bytes (sql, ram)
     *   'refcount'    - shared-with count (sql only); always
     *                   1 on the file backend (no dedup);
     *                   not exposed on ram (no shared store)
     *   'size'        - body length in bytes
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return array|false metadata record describing where the body bytes live, or false if (user, folder, uid) does not resolve to a stored message
     */
    abstract public function messageBodyLocation($user,
        $folder, $uid);
    /**
     * High-water mark of the last UIDVALIDITY this storage
     * instance has handed out. Subclasses use this to ensure
     * a strictly monotonic sequence even when two folders are
     * created in the same wall-clock second (RFC 3501 sec
     * 2.3.1.1 monotonic requirement).
     * @var int
     */
    protected $last_uidvalidity = 0;
    /**
     * Returns a fresh UIDVALIDITY value that is strictly
     * greater than any value previously returned by this
     * storage instance. Implementations should call this when
     * a folder is created or recreated.
     * @return int fresh UIDVALIDITY value for a new folder
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
     * strips leading/trailing slashes, strips leading dots from
     * each component, and rejects components that could escape
     * the folder root. INBOX is normalized to all-uppercase per
     * RFC 3501. Backends that map folder names to filesystem
     * paths layer additional checks on top of this; see
     * FileMailStorage::folderDir for the reserved-basename
     * collision check. Throws InvalidArgumentException on:
     *      empty / "." / ".."  components (path traversal)
     *      NUL byte             (path injection)
     *      control character    (corrupts metadata files)
     * Leading dots in a component are silently stripped:
     * ".foo" -> "foo", "...bar" -> "bar". A component that
     * reduces to empty after stripping is rejected.
     * @param string $folder folder name with full hierarchy path
     * @return string folder name normalized to canonical case and separator
     */
    protected function normalizeFolder($folder)
    {
        $folder = (string) $folder;
        if (str_contains($folder, "\0")) {
            throw new \InvalidArgumentException(
                "folder name contains NUL byte");
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $folder)) {
            throw new \InvalidArgumentException(
                "folder name contains control character");
        }
        $folder = trim($folder, "/");
        if ($folder === "") {
            return self::FOLDER_INBOX;
        }
        if (strcasecmp($folder, self::FOLDER_INBOX) === 0) {
            return self::FOLDER_INBOX;
        }
        $parts = preg_split('#/+#', $folder);
        $clean = [];
        foreach ($parts as $part) {
            if ($part === "" || $part === "." ||
                $part === "..") {
                throw new \InvalidArgumentException(
                    "invalid folder component: '$part'");
            }
            $part = ltrim($part, '.');
            if ($part === "") {
                throw new \InvalidArgumentException(
                    "folder component is all dots");
            }
            $clean[] = $part;
        }
        return implode("/", $clean);
    }
    /**
     * Convenience wrapper around normalizeFolder that returns
     * false on rejection rather than throwing. Saves a 5-line
     * try/catch at every public-method entry point. Callers
     * pattern: $folder = $this->safeNormalizeFolder($folder);
     * if ($folder === false) { return <appropriate sentinel>; }
     * @param string $folder folder name with full hierarchy path
     * @return string|false normalized folder name, or false if the input was unsafe
     */
    protected function safeNormalizeFolder($folder)
    {
        try {
            return $this->normalizeFolder($folder);
        } catch (\InvalidArgumentException $e) {
            return false;
        }
    }
    /**
     * Crops a message-bytes prefix to just the header block:
     * everything before the first blank line. Accepts both
     * CRLFCRLF (RFC-strict) and LFLF (lenient, since not all
     * MTAs emit strict CRLF). When no terminator is found in
     * the input, returns the input unchanged so callers always
     * get a best-effort header view rather than empty.
     *
     * @param string $bytes a prefix of an RFC 5322 message;
     *      typically the first MAX_HEADER_BYTES of the body
     * @return string the header block without trailing blank line
     */
    protected function cropToHeaders($bytes)
    {
        $end = strpos($bytes, "\r\n\r\n");
        if ($end === false) {
            $end = strpos($bytes, "\n\n");
        }
        return ($end === false) ? $bytes : substr($bytes, 0, $end);
    }
    /**
     * Extracts the value of a single header from a header block,
     * unfolding continuation lines. Self-contained (no dependency
     * on the Yioop library) because this class is shared with the
     * standalone atto project. Case-insensitive on the field name.
     * @param string $header_block the message header text
     * @param string $name header field name, e.g. "Subject"
     * @return string the header value with folding removed, or ""
     */
    protected function headerValue($header_block, $name)
    {
        $lines = preg_split("/\r\n|\n/", $header_block);
        $needle = strtolower($name) . ":";
        $value = "";
        $capturing = false;
        foreach ($lines as $line) {
            if ($capturing) {
                if ($line !== "" &&
                    ($line[0] === " " || $line[0] === "\t")) {
                    $value .= " " . trim($line);
                    continue;
                }
                break;
            }
            if (strlen($line) >= strlen($needle) &&
                strtolower(substr($line, 0, strlen($needle))) ===
                $needle) {
                $value = trim(substr($line, strlen($needle)));
                $capturing = true;
            }
        }
        return $value;
    }
    /**
     * Builds the lowercased search haystack (subject, from, to)
     * for a message from its raw bytes. Shared by every storage's
     * search index so the matched text is identical regardless of
     * backend.
     * @param string $bytes the raw message bytes (or header block)
     * @return string lowercased "subject from to" text
     */
    protected function searchHaystackFromBytes($bytes)
    {
        $header_block = $this->cropToHeaders($bytes);
        $haystack = $this->headerValue($header_block, "Subject") .
            " " . $this->headerValue($header_block, "From") .
            " " . $this->headerValue($header_block, "To");
        $haystack = preg_replace("/\s+/", " ", $haystack);
        return strtolower(trim($haystack));
    }
}
/**
 * Filesystem-backed MailStorage. Directory layout under the
 * configured base path:
 *
 *      $base/
 *          users/
 *              <username>/
 *                  uidvalidity.txt  (single integer, fixed at create)
 *                  uidnext.txt      (single integer, monotonic)
 *                  subscribed.txt   (one folder name per line)
 *                  INBOX/
 *                      <uid>.eml
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
    /**
     * Per-folder file holding a single integer UIDVALIDITY
     * (RFC 3501 sec 2.3.1.1). Fixed at folder-create time.
     */
    const FOLDER_UIDVALIDITY_FILE = "uidvalidity.txt";
    /**
     * Per-folder file holding this mailbox's UIDNEXT high-water
     * value: one greater than the largest UID ever assigned in
     * this folder. RFC 3501 sec 2.3.1.1 makes UIDNEXT a per-
     * mailbox value, so it is tracked per folder here even though
     * UIDs are drawn from a single monotonic per-user allocator.
     * Bumped on append and never decreased, so it stays valid
     * even after the highest-UID message is removed. Absent for
     * folders created before this file existed; uidNext then
     * derives the value from the index and writes it once.
     */
    const FOLDER_UIDNEXT_FILE = "foldernext.txt";
    /**
     * Per-folder file holding the durable flag state as one
     * "uid<TAB>space-joined-flags" line per message. The index is
     * the live flag store; this snapshot is refreshed whenever the
     * index is rebuilt (compaction) and is read only to recover
     * flags when the index is rebuilt from disk, so flags survive
     * an index that is lost or edited directly. Flags set after
     * the last compaction are not in the snapshot.
     */
    const FOLDER_FLAGS_SNAPSHOT_FILE = "flags.snapshot";
    /**
     * Per-folder journal written before a UID renumber touches any
     * message file. It records the planned old-to-new UID mapping
     * (with each message's size, date, and flags) and the new
     * UIDVALIDITY, so a renumber interrupted by a crash can be
     * resumed: its presence means a renumber is in progress, and
     * it is deleted only once the folder's index, snapshot, and
     * UID files have been written. Every rename step is idempotent
     * against the journal, so resuming repeats no completed work.
     */
    const FOLDER_REUID_JOURNAL_FILE = "reuid.journal";
    /**
     * Per-user file holding a single integer counter for the
     * next UID to assign. Bumped under flock so concurrent
     * appends never hand out the same UID.
     */
    const USER_UIDNEXT_FILE = "uidnext.txt";
    /**
     * Per-user file listing subscribed folder names, one per
     * line. Absent or empty means only INBOX is subscribed.
     */
    const USER_SUBSCRIBED_FILE = "subscribed.txt";
    /**
     * Per-folder append-only metadata index. Each line records one
     * mutation: "+ uid size date flag..." for an appended or
     * moved-in message, "f uid flag..." for a flag change, and
     * "- uid" for a removed message. listMessages replays the log
     * into a uid map so a folder listing costs one sequential read
     * instead of opening and parsing every message file. The
     * .eml files stay the source of truth: a missing or unparseable
     * index is rebuilt from the message files (plus the folder's
     * flags snapshot for flag state) on demand, and message
     * presence is taken from the directory itself so a stale index
     * can neither hide nor invent a message. The name is visible
     * (no leading dot) by project convention, and does not end in
     * .eml so the listing scan skips it.
     */
    const MESSAGE_INDEX_FILE = "messages.index";
    /**
     * Per-folder search index. Each line is "uid\tHAYSTACK" where
     * HAYSTACK is the lowercased subject, from, and to header text
     * of the message joined by spaces. It lets a substring filter
     * scan one sequential file instead of opening and parsing the
     * header block of every message in the folder, which is the
     * difference between a sub-second and a many-second filter on a
     * folder with tens of thousands of messages. Append-only and
     * written alongside the metadata index when a message arrives;
     * a missing index is rebuilt lazily on the next search. Like
     * the metadata index it is advisory: message presence is taken
     * from the directory, so a stale line for a removed uid is
     * intersected away rather than trusted. The name has no leading
     * dot (project convention) and does not end in .eml so the
     * folder listing scan skips it.
     */
    const MESSAGE_SEARCH_FILE = "messages.search";
    /**
     * Filename extension (without the leading dot) for a
     * per-message flags file. These files are no longer written —
     * flags live in the folder index, with the flags snapshot as
     * the rebuild fallback. The constant is retained so the
     * cleanup tool can recognize and remove orphaned <uid>.flags
     * files left by the earlier storage format, and so directory
     * scans skip them.
     */
    const FLAGS_FILE_EXTENSION = "flags";
    /**
     * Filename extension (without the leading dot) for a
     * per-message internal-date file. No longer written —
     * internal_date is recovered from the message Date header (then
     * file mtime). Retained for the same orphan-cleanup and
     * scan-skipping reason as the flags extension.
     */
    const DATE_FILE_EXTENSION = "date";
    /**
     * Leading character of an index record describing a present
     * message ("+ uid size date flag...").
     */
    const INDEX_PRESENT_MARKER = "+";
    /**
     * Leading character of an index record describing a flag
     * change on an existing message ("f uid flag...").
     */
    const INDEX_FLAG_MARKER = "f";
    /**
     * Leading character of an index record describing a removed
     * message ("- uid").
     */
    const INDEX_REMOVE_MARKER = "-";
    /**
     * Filesystem directory under which the per-user storage
     * tree is created. Set once by the constructor and never
     * changed.
     * @var string
     */
    protected $base;
    /**
     * In-memory cache of parsed folder indexes, keyed by
     * "user\0folder". A single IMAP command sequence reads a
     * folder's index several times (SELECT for stats, then FETCH
     * or STORE to match the set), so serving the parsed map from
     * memory avoids re-streaming the whole index file each time.
     * Invalidated whenever the folder's index is written, rebuilt,
     * or the folder is removed or renamed, so it never serves a
     * stale view.
     * @var array
     */
    protected $index_cache = [];
    /**
     * @param string $base directory under which the "users/"
     *      subtree is created
     */
    public function __construct($base)
    {
        $this->base = rtrim($base, "/\\");
        $this->index_cache = [];
    }
    /**
     * Returns the absolute directory path for a user's account.
     * Does not check existence.
     * @param string $user username (no @domain) identifying the mail account
     * @return string absolute directory path for $user
     */
    protected function userDir($user)
    {
        return $this->base . "/users/" . $this->safeName($user);
    }
    /**
     * Returns the absolute directory path for a folder. Folder
     * names are encoded so "/" in a folder name becomes "%2F" in
     * the directory name. Rejects folder names that would
     * collide with the per-user metadata files (uidvalidity.txt,
     * uidnext.txt, subscribed.txt) since both live as siblings
     * under the same user directory.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return string absolute directory path for the folder
     */
    protected function folderDir($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        $reserved = [
            self::FOLDER_UIDVALIDITY_FILE,
            self::FOLDER_UIDNEXT_FILE,
            self::FOLDER_FLAGS_SNAPSHOT_FILE,
            self::FOLDER_REUID_JOURNAL_FILE,
            self::USER_UIDNEXT_FILE,
            self::USER_SUBSCRIBED_FILE,
            self::MESSAGE_INDEX_FILE,
            self::MESSAGE_SEARCH_FILE,
        ];
        foreach (explode("/", $folder) as $part) {
            if (in_array($part, $reserved, true)) {
                throw new \InvalidArgumentException(
                    "folder name '$part' is reserved");
            }
        }
        /*
            Folders are stored as real nested directories with
            their literal names (a space stays a space, "a/b"
            becomes the directory "a" with child "b"), matching
            the layout a dovecot administrator expects on the
            command line. normalizeFolder has already rejected
            empty, "." and ".." components and control bytes, so
            joining the parts onto the user directory cannot walk
            outside it.
         */
        return $this->userDir($user) . "/" . $folder;
    }
    /**
     * Returns the path of a per-message file. The live file is
     * <uid>.eml (raw bytes); the <uid>.flags and <uid>.date
     * extensions are no longer written and are passed here only by
     * the cleanup path that removes orphaned files left by the
     * earlier storage format. Callers pass the extension as a
     * string without the leading dot.
     * @param string $folder_dir absolute folder directory path
     * @param int $uid persistent IMAP unique identifier of the message
     * @param string $ext filename extension without leading dot
     * @return string absolute path of the per-message file with the given extension
     */
    protected function messagePath($folder_dir, $uid, $ext)
    {
        return $folder_dir . "/" .
            $uid . "." . $ext;
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
     * @param string $user username (no @domain) identifying the mail account
     * @return string sanitized username safe to use as a directory name
     */
    protected function safeName($user)
    {
        $user = (string) $user;
        $user = preg_replace('/[^A-Za-z0-9._-]/', '_', $user);
        $user = ltrim($user, '._');
        if ($user === "" ||
            preg_match('/^[._]+$/', $user) ||
            str_contains($user, '..')) {
            $user = "_invalid_";
        }
        return $user;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     */
    public function ensureUser($user)
    {
        $dir = $this->userDir($user);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return false;
        }
        $uidvalidity_file = $dir . "/" .
            self::FOLDER_UIDVALIDITY_FILE;
        if (!is_file($uidvalidity_file)) {
            /*
                Per-user UIDVALIDITY: fallback for folders that
                pre-date the per-folder scheme.
             */
            file_put_contents($uidvalidity_file,
                (string) $this->nextUidValidity());
        }
        $uidnext_file = $dir . "/" .
            self::USER_UIDNEXT_FILE;
        if (!is_file($uidnext_file)) {
            file_put_contents($uidnext_file, "1");
        }
        $this->createFolder($user, self::FOLDER_INBOX);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     */
    public function listFolders($user)
    {
        $base = $this->userDir($user);
        if (!is_dir($base)) {
            return [];
        }
        $folders = [];
        $this->collectFolderTree($base, "", $folders);
        sort($folders);
        return $folders;
    }
    /**
     * Recursively gathers folder paths under a directory. Folders
     * are stored as real nested directories, so every
     * subdirectory of a folder directory is a child folder; the
     * per-message <uid>.eml files (and any orphaned <uid>.flags or
     * <uid>.date files from the earlier storage format) and the
     * per-folder metadata files (messages.index, messages.search,
     * uidvalidity.txt) are plain files and are skipped by the
     * is_dir test, as are the user-level metadata files
     * (uidnext.txt, subscribed.txt) that sit only at the top.
     *
     * @param string $dir absolute directory to scan
     * @param string $prefix slash-terminated folder path of $dir,
     *      empty at the user root
     * @param array $folders accumulator of folder path strings,
     *      passed by reference
     * @return void
     */
    protected function collectFolderTree($dir, $prefix, &$folders)
    {
        $handle = @opendir($dir);
        if ($handle === false) {
            return;
        }
        /*
            A folder directory holds one <uid>.eml file per message
            plus a little per-folder metadata (and possibly orphaned
            <uid>.flags/.date files from the earlier storage format),
            so on a large mailbox almost every entry is a message
            file. scandir would pull all of those hundreds of
            thousands of names into one array (and sort it) on every
            listing, which is what made folder listing and the
            create/delete/rename paths that check for child folders
            take tens of seconds. Streaming with readdir examines one
            name at a time and keeps nothing but the few real child
            folders. Message and metadata files are recognized by
            name and skipped before any is_dir, so the only stats are
            for child-folder candidates. The .flags/.date suffixes
            stay in the skip-list so any such orphans are not
            mistaken for child folders.
         */
        $message_suffixes = [
            "." . self::MESSAGE_FILE_EXTENSION,
            "." . self::FLAGS_FILE_EXTENSION,
            "." . self::DATE_FILE_EXTENSION,
        ];
        $metadata_files = [
            self::MESSAGE_INDEX_FILE,
            self::MESSAGE_SEARCH_FILE,
            self::FOLDER_UIDVALIDITY_FILE,
            self::FOLDER_UIDNEXT_FILE,
            self::FOLDER_FLAGS_SNAPSHOT_FILE,
            self::FOLDER_REUID_JOURNAL_FILE,
            self::USER_UIDNEXT_FILE,
            self::USER_SUBSCRIBED_FILE,
        ];
        $children = [];
        while (($entry = readdir($handle)) !== false) {
            if ($entry === "." || $entry === "..") {
                continue;
            }
            if (in_array($entry, $metadata_files, true)) {
                continue;
            }
            $is_message_file = false;
            foreach ($message_suffixes as $suffix) {
                if (str_ends_with($entry, $suffix)) {
                    $is_message_file = true;
                    break;
                }
            }
            if ($is_message_file) {
                continue;
            }
            $sub = $dir . "/" . $entry;
            if (!is_dir($sub)) {
                continue;
            }
            $name = $prefix . $entry;
            $folders[] = $name;
            $children[] = [$sub, $name . "/"];
        }
        closedir($handle);
        /*
            Recurse only after the directory handle is closed so a
            deep tree does not hold one open handle per level.
         */
        foreach ($children as $child) {
            $this->collectFolderTree($child[0], $child[1],
                $folders);
        }
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
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
                ensureUser provisions INBOX as a side effect;
                if that's the folder requested, we are done.
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
            allocator is monotonic-by-construction even across
            recreate cycles in the same wall-clock second.
         */
        @file_put_contents(
            $path . "/" .
                self::FOLDER_UIDVALIDITY_FILE,
            (string) $this->nextUidValidity());
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function deleteFolder($user, $folder)
    {
        $folder = $this->normalizeFolder($folder);
        if ($folder === self::FOLDER_INBOX) {
            return false;
        }
        $path = $this->folderDir($user, $folder);
        if (!is_dir($path)) {
            return false;
        }
        /*
            A folder has children only if its own directory holds a
            subdirectory, so check that directly rather than
            listing the whole account tree (which would walk every
            folder, INBOX included). Stream the directory with
            readdir and unlink the message and metadata files as we
            go, so a folder holding hundreds of thousands of files
            is never pulled into one scandir array. The directory
            handle is closed before rmdir.
         */
        $handle = @opendir($path);
        if ($handle === false) {
            return false;
        }
        $to_unlink = [];
        $has_child = false;
        while (($entry = readdir($handle)) !== false) {
            if ($entry === "." || $entry === "..") {
                continue;
            }
            $entry_path = $path . "/" . $entry;
            if (is_dir($entry_path)) {
                $has_child = true;
                break;
            }
            $to_unlink[] = $entry_path;
        }
        closedir($handle);
        if ($has_child) {
            return false;
        }
        foreach ($to_unlink as $entry_path) {
            @unlink($entry_path);
        }
        $this->invalidateIndexCache($user, $folder);
        return @rmdir($path);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $old current folder name to rename from
     * @param string $new target folder name to rename to
     */
    public function renameFolder($user, $old, $new)
    {
        $old = $this->normalizeFolder($old);
        $new = $this->normalizeFolder($new);
        if ($old === self::FOLDER_INBOX || $new === self::FOLDER_INBOX) {
            return false;
        }
        $old_path = $this->folderDir($user, $old);
        $new_path = $this->folderDir($user, $new);
        if (!is_dir($old_path) || is_dir($new_path)) {
            return false;
        }
        $this->invalidateIndexCache($user, $old);
        $this->invalidateIndexCache($user, $new);
        return @rename($old_path, $new_path);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function folderExists($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        return is_dir($this->folderDir($user, $folder));
    }
    /**
     * Atomically allocates and returns the next per-user UID.
     * Uses an exclusive flock on uidnext.txt so two concurrent
     * appendMessage calls cannot hand out the same number.
     * @param string $user username (no @domain) identifying the mail account
     * @return int next UID to assign to a new message in the user/folder
     */
    protected function allocUid($user)
    {
        $file = $this->userDir($user) . "/" .
            self::USER_UIDNEXT_FILE;
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $bytes number of bytes
     * @param array $flags list of IMAP flag strings
     * @param int $internal_date Unix timestamp to record as the message internal date
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
        $eml = $this->messagePath($dir, $uid, self::MESSAGE_FILE_EXTENSION);
        /* Direct write instead of write-temp-then-rename: the
           UID just allocated is unique to this writer (allocUid
           is single-process), so there is no concurrent reader
           who could see a half-written .eml. A mid-write crash
           leaves a partial file at the new UID, but the UID has
           not yet been observed by any reader and the caller
           has not yet recorded delivery, so a retry that
           re-issues appendMessage simply overwrites it. Cutting
           the rename removes one filesystem barrier per append.
           */
        if (file_put_contents($eml, $bytes) === false) {
            return false;
        }
        /*
            No per-message flag or date file is written: the index
            record below carries flags, size, and internal_date as
            the live store, the flags snapshot (refreshed on
            compaction) is the durable flag fallback, and the
            message Date header recovers internal_date on a rebuild.
         */
        $this->appendIndexRecord($user, $folder,
            $this->formatPresentRecord($uid, strlen($bytes),
            $internal_date, $flags));
        $this->appendSearchRecord($user, $folder, $uid,
            $this->searchHaystackFromBytes($bytes));
        $this->bumpFolderUidNext($user, $folder, $uid + 1);
        return $uid;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function fetchMessage($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $eml = $this->messagePath(
            $this->folderDir($user, $folder), $uid,
            self::MESSAGE_FILE_EXTENSION);
        if (!is_file($eml)) {
            return false;
        }
        $bytes = @file_get_contents($eml);
        return ($bytes === false) ? false : $bytes;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageHeaderBytes($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $eml = $this->messagePath(
            $this->folderDir($user, $folder), $uid,
            self::MESSAGE_FILE_EXTENSION);
        if (!is_readable($eml)) {
            return false;
        }
        $fh = fopen($eml, 'rb');
        if ($fh === false) {
            return false;
        }
        $chunk = fread($fh, self::MAX_HEADER_BYTES);
        fclose($fh);
        if ($chunk === false) {
            return false;
        }
        return $this->cropToHeaders($chunk);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function listMessages($user, $folder)
    {
        $dir = $this->folderDir($user, $folder);
        if (!is_dir($dir)) {
            return [];
        }
        $line_count = 0;
        $records =
            $this->readFolderIndex($user, $folder, $line_count);
        if ($records === null) {
            return $this->rebuildFolderIndex($user, $folder);
        }
        /*
            Trust the index as the live set rather than scanning the
            folder directory first. The directory holds one message
            file per message, so the old scan walked hundreds of
            thousands of entries and built a second large array on
            every list; on a big mailbox that was both the slow path
            and a doubled memory footprint. appendMessage writes the
            message file and then the index line, and removals are
            logged too, so the index reflects what is live. A file
            left on disk without its index line is a crash artifact
            healed by the compaction rebuild below.
         */
        $messages = array_values($records);
        $live_count = count($messages);
        unset($records);
        usort($messages, function ($first, $second) {
            return $first['uid'] <=> $second['uid'];
        });
        /*
            Compact a log that has grown well past the live set (its
            append-only flag and remove lines accumulate over time).
            rebuildFolderIndex rescans the directory to write a
            fresh snapshot, which also reconciles any drift.
         */
        if ($line_count > 2 * $live_count && $live_count > 0) {
            $this->rebuildFolderIndex($user, $folder);
        }
        return $messages;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageMeta($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $dir = $this->folderDir($user, $folder);
        $eml = $this->messagePath($dir, $uid, self::MESSAGE_FILE_EXTENSION);
        if (!is_file($eml)) {
            return false;
        }
        $size = (int) @filesize($eml);
        /*
            internal_date is recovered from the message's own Date
            header (then the file mtime) rather than a per-message
            companion file. Flags are not read here: the index is
            the live flag store, and the folder's flags snapshot is
            the rebuild fallback, layered on by scanFolderMessages.
         */
        $date = $this->internalDateFromHeaders($user, $folder,
            $uid);
        if ($date <= 0) {
            $date = (int) @filemtime($eml);
        }
        return [
            'uid' => $uid,
            'size' => $size,
            'flags' => [],
            'internal_date' => $date,
        ];
    }
    /**
     * Recovers a message's internal date from its Date header,
     * used when rebuilding the index from disk. Returns 0 when no
     * parsable Date header is present so the caller can fall back
     * to the file mtime.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     * @return int unix timestamp, or 0 when no Date header parses
     */
    protected function internalDateFromHeaders($user, $folder, $uid)
    {
        $header_bytes = $this->messageHeaderBytes($user, $folder,
            $uid);
        if ($header_bytes === false) {
            return 0;
        }
        if (!preg_match('/^Date:[ \t]*(.+?)\r?$/im', $header_bytes,
            $matches)) {
            return 0;
        }
        $parsed = strtotime(trim($matches[1]));
        if ($parsed === false || $parsed <= 0) {
            return 0;
        }
        return $parsed;
    }
    /**
     * Absolute path to a folder's metadata index file.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return string absolute path to the folder's messages.index
     */
    protected function messageIndexPath($user, $folder)
    {
        return $this->folderDir($user, $folder) .
            "/" . self::MESSAGE_INDEX_FILE;
    }
    /**
     * Absolute path to a folder's UIDNEXT high-water file.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return string absolute path to the folder's foldernext.txt
     */
    protected function folderUidNextPath($user, $folder)
    {
        return $this->folderDir($user, $folder) .
            "/" . self::FOLDER_UIDNEXT_FILE;
    }
    /**
     * Absolute path to a folder's flags snapshot file.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return string absolute path to the folder's flags.snapshot
     */
    protected function flagsSnapshotPath($user, $folder)
    {
        return $this->folderDir($user, $folder) .
            "/" . self::FOLDER_FLAGS_SNAPSHOT_FILE;
    }
    /**
     * Absolute path to a folder's reuid journal file.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return string absolute path to the folder's reuid.journal
     */
    protected function reuidJournalPath($user, $folder)
    {
        return $this->folderDir($user, $folder) .
            "/" . self::FOLDER_REUID_JOURNAL_FILE;
    }
    /**
     * Staging path for a message mid-renumber: the target UID with
     * a suffix that the message-file scan ignores, so a partially
     * renamed folder never exposes a staged file as a live message
     * and a resumed run can tell staged from finished files.
     * @param string $dir folder directory
     * @param int $new_uid target UID being staged
     * @return string staging file path
     */
    protected function reuidStagePath($dir, $new_uid)
    {
        return $this->messagePath($dir, $new_uid,
            self::MESSAGE_FILE_EXTENSION) . ".reuid";
    }
    /**
     * Atomically writes the reuid journal: a first line with the
     * new UIDVALIDITY, then one tab-separated line per message of
     * old UID, new UID, size, internal date, and flags. Written to
     * a temporary file and renamed into place so the journal is
     * never observed half-written.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param array $plan list of ['old','new','size','date','flags']
     * @param int $uidvalidity new UIDVALIDITY to apply on completion
     * @return bool whether the journal was written
     */
    protected function writeReuidJournal($user, $folder, $plan,
        $uidvalidity)
    {
        $buffer = "uidvalidity\t" . (int) $uidvalidity . "\n";
        foreach ($plan as $entry) {
            $buffer .= (int) $entry['old'] . "\t" .
                (int) $entry['new'] . "\t" . (int) $entry['size'] .
                "\t" . (int) $entry['date'] . "\t" .
                implode(" ", $entry['flags']) . "\n";
        }
        $path = $this->reuidJournalPath($user, $folder);
        $temp = $path . ".tmp";
        if (@file_put_contents($temp, $buffer, LOCK_EX) === false) {
            return false;
        }
        return @rename($temp, $path);
    }
    /**
     * Takes an advisory lock on an open file without freezing the web
     * server while it waits. Outside the cooperative server (the ordinary
     * case for the mail daemon and command-line tools) this is a plain
     * blocking lock, so behaviour there is unchanged. Inside the
     * cooperative web server (a fiber), it asks for the lock without
     * blocking and, if another process holds it, hands the event loop a
     * turn and tries again, so reading a local mailbox cannot freeze every
     * other web connection while the mail daemon is mid-write on the same
     * folder. The lock is the same one a plain flock would take, so it
     * still keeps readers and the daemon's writer from stepping on each
     * other.
     *
     * @param resource $handle open file handle to lock
     * @param int $operation the lock to take, LOCK_SH or LOCK_EX
     * @return void
     */
    protected static function cooperativeFlock($handle, $operation)
    {
        if (\Fiber::getCurrent() === null) {
            @flock($handle, $operation);
            return;
        }
        while (!@flock($handle, $operation | LOCK_NB)) {
            \Fiber::suspend();
        }
    }
    /**
     * Reads a folder's reuid journal into the planned UIDVALIDITY
     * and per-message mapping, or null when no journal is present.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return array|null ['uidvalidity'=>int, 'plan'=>array] or null
     */
    protected function readReuidJournal($user, $folder)
    {
        $path = $this->reuidJournalPath($user, $folder);
        if (!is_file($path)) {
            return null;
        }
        $handle = @fopen($path, "rb");
        if ($handle === false) {
            return null;
        }
        self::cooperativeFlock($handle, LOCK_SH);
        $uidvalidity = 0;
        $plan = [];
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === "") {
                continue;
            }
            $parts = explode("\t", $line);
            if ($parts[0] === "uidvalidity") {
                $uidvalidity = (int) ($parts[1] ?? 0);
                continue;
            }
            if (count($parts) < 4) {
                continue;
            }
            $flags = [];
            if (isset($parts[4]) && $parts[4] !== "") {
                foreach (explode(" ", $parts[4]) as $flag) {
                    if ($flag !== "") {
                        $flags[] = $flag;
                    }
                }
            }
            $plan[] = [
                'old' => (int) $parts[0],
                'new' => (int) $parts[1],
                'size' => (int) $parts[2],
                'date' => (int) $parts[3],
                'flags' => $flags,
            ];
        }
        @flock($handle, LOCK_UN);
        fclose($handle);
        return ['uidvalidity' => $uidvalidity, 'plan' => $plan];
    }
    /**
     * Writes a folder's flags snapshot from its current index, so
     * the rebuild fallback exists without waiting for the next
     * compaction. Used after an import populates a folder. A
     * folder with no index is left without a snapshot, which reads
     * as "no flags" on a later rebuild.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return void
     */
    public function refreshFlagsSnapshot($user, $folder)
    {
        $line_count = 0;
        $records = $this->readFolderIndex($user, $folder,
            $line_count);
        if ($records === null) {
            return;
        }
        $this->writeFlagsSnapshot($user, $folder, $records);
    }
    /**
     * Rewrites a folder's flags snapshot from a uid-keyed records
     * map, one "uid<TAB>space-joined-flags" line per message that
     * has any flags. Messages with no flags are omitted to keep
     * the file small; their absence on read means no flags.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param array $records uid-keyed metadata records
     * @return void
     */
    protected function writeFlagsSnapshot($user, $folder, $records)
    {        $buffer = "";
        foreach ($records as $uid => $record) {
            if (empty($record['flags'])) {
                continue;
            }
            $buffer .= (int) $uid . "\t" .
                implode(" ", $record['flags']) . "\n";
        }
        @file_put_contents(
            $this->flagsSnapshotPath($user, $folder), $buffer,
            LOCK_EX);
    }
    /**
     * Reads a folder's flags snapshot into a uid-keyed map of flag
     * lists, used to recover flags when rebuilding the index from
     * disk. Returns an empty map when the snapshot is absent.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return array uid-keyed map of flag-string lists
     */
    protected function readFlagsSnapshot($user, $folder)
    {
        $path = $this->flagsSnapshotPath($user, $folder);
        $flags_by_uid = [];
        if (!is_file($path)) {
            return $flags_by_uid;
        }
        $handle = @fopen($path, "rb");
        if ($handle === false) {
            return $flags_by_uid;
        }
        self::cooperativeFlock($handle, LOCK_SH);
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === "") {
                continue;
            }
            $tab = strpos($line, "\t");
            if ($tab === false) {
                continue;
            }
            $uid = (int) substr($line, 0, $tab);
            if ($uid < 1) {
                continue;
            }
            $flags = [];
            foreach (explode(" ", substr($line, $tab + 1))
                as $flag) {
                if ($flag !== "") {
                    $flags[] = $flag;
                }
            }
            $flags_by_uid[$uid] = $flags;
        }
        @flock($handle, LOCK_UN);
        fclose($handle);
        return $flags_by_uid;
    }
    /**
     * Raises a folder's UIDNEXT high-water to at least the given
     * value, never lowering it. Held under an exclusive lock so
     * concurrent appends converge on the maximum.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param int $candidate proposed next-uid value
     * @return void
     */
    protected function bumpFolderUidNext($user, $folder, $candidate)
    {
        $path = $this->folderUidNextPath($user, $folder);
        $file_handle = @fopen($path, "c+");
        if ($file_handle === false) {
            return;
        }
        if (!flock($file_handle, LOCK_EX)) {
            fclose($file_handle);
            return;
        }
        rewind($file_handle);
        $current = (int) trim((string) stream_get_contents(
            $file_handle));
        if ($candidate > $current) {
            ftruncate($file_handle, 0);
            rewind($file_handle);
            fwrite($file_handle, (string) $candidate);
            fflush($file_handle);
        }
        flock($file_handle, LOCK_UN);
        fclose($file_handle);
    }
    /**
     * Renders a flag list as a space-prefixed suffix for an index
     * line. IMAP flag atoms contain no spaces, so the joined
     * suffix parses back unambiguously by splitting on spaces.
     * @param array $flags list of IMAP flag strings
     * @return string a leading-space-per-flag suffix, or "" if none
     */
    protected function indexFlagSuffix($flags)
    {
        $suffix = "";
        foreach ($flags as $flag) {
            $flag = trim((string) $flag);
            if ($flag !== "") {
                $suffix .= " " . $flag;
            }
        }
        return $suffix;
    }
    /**
     * Builds one newline-terminated index line for a present
     * message ("+ uid size date flag...").
     * @param int $uid message unique identifier
     * @param int $size message size in bytes
     * @param int $internal_date Unix timestamp of the internal date
     * @param array $flags list of IMAP flag strings
     * @return string the formatted, newline-terminated line
     */
    protected function formatPresentRecord($uid, $size,
        $internal_date, $flags)
    {
        return self::INDEX_PRESENT_MARKER . " " . (int) $uid .
            " " . (int) $size . " " . (int) $internal_date .
            $this->indexFlagSuffix($flags) . "\n";
    }
    /**
     * Appends one line to a folder's index, creating the index
     * file if absent. The append is exclusive-locked so a writer
     * in the clone process and a reader in the web process cannot
     * interleave. On any write failure the index is removed so the
     * next read rebuilds it from the message files rather than
     * trusting a partial log.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param string $line one or more newline-terminated records
     */
    protected function appendIndexRecord($user, $folder, $line)
    {
        $path = $this->messageIndexPath($user, $folder);
        $written = @file_put_contents($path, $line,
            FILE_APPEND | LOCK_EX);
        if ($written === false) {
            @unlink($path);
        }
        $this->invalidateIndexCache($user, $folder);
    }
    /**
     * Drops a folder's cached parsed index so the next read
     * re-parses from disk. Called from every path that changes a
     * folder's index or removes the folder, which keeps the cache
     * from ever serving a view that disagrees with the file.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return void
     */
    protected function invalidateIndexCache($user, $folder)
    {
        unset($this->index_cache[$user . "\0" . $folder]);
    }
    /**
     * Absolute path to a folder's search index file.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return string absolute path to the folder's messages.search
     */
    protected function messageSearchPath($user, $folder)
    {
        return $this->folderDir($user, $folder) .
            "/" . self::MESSAGE_SEARCH_FILE;
    }
    /**
     * Appends one "uid\tHAYSTACK" line to a folder's search index,
     * creating the file if absent. On write failure the index is
     * removed so the next search rebuilds it from the messages
     * rather than trusting a partial log.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param int $uid message unique identifier
     * @param string $haystack the lowercased search text
     */
    protected function appendSearchRecord($user, $folder, $uid,
        $haystack)
    {
        $path = $this->messageSearchPath($user, $folder);
        $haystack = str_replace(["\t", "\n", "\r"], " ",
            $haystack);
        $line = (int) $uid . "\t" . $haystack . "\n";
        $written = @file_put_contents($path, $line,
            FILE_APPEND | LOCK_EX);
        if ($written === false) {
            @unlink($path);
        }
    }
    /**
     * Rebuilds a folder's search index from the messages on disk.
     * Reads each present message's header block once, extracts the
     * search haystack, and writes the whole index in a single
     * locked write. Used the first time a folder that predates the
     * search index is filtered, or after a write failure left the
     * index missing.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return array map of present uid => haystack just written
     */
    protected function rebuildSearchIndex($user, $folder)
    {
        $dir = $this->folderDir($user, $folder);
        $uids = $this->folderMessageUids($dir);
        $map = [];
        $buffer = "";
        foreach ($uids as $uid) {
            $header_bytes = $this->messageHeaderBytes($user,
                $folder, $uid);
            if ($header_bytes === false) {
                continue;
            }
            $haystack = $this->searchHaystackFromBytes(
                $header_bytes);
            $haystack = str_replace(["\t", "\n", "\r"], " ",
                $haystack);
            $map[(int) $uid] = $haystack;
            $buffer .= (int) $uid . "\t" . $haystack . "\n";
        }
        $path = $this->messageSearchPath($user, $folder);
        $written = @file_put_contents($path, $buffer, LOCK_EX);
        if ($written === false) {
            @unlink($path);
        }
        return $map;
    }
    /**
     * Reads a folder's search index into a uid => haystack map,
     * rebuilding it from the messages when the file is missing.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @return array map of uid => lowercased haystack
     */
    protected function loadSearchIndex($user, $folder)
    {
        $path = $this->messageSearchPath($user, $folder);
        if (!is_readable($path)) {
            return $this->rebuildSearchIndex($user, $folder);
        }
        $handle = @fopen($path, "rb");
        if ($handle === false) {
            return $this->rebuildSearchIndex($user, $folder);
        }
        $map = [];
        while (($line = fgets($handle)) !== false) {
            $tab = strpos($line, "\t");
            if ($tab === false) {
                continue;
            }
            $uid = (int) substr($line, 0, $tab);
            if ($uid < 1) {
                continue;
            }
            $map[$uid] = rtrim(substr($line, $tab + 1), "\r\n");
        }
        fclose($handle);
        return $map;
    }
    /**
     * Returns the uids in a folder whose subject, from, or to
     * header contains the query string (case-insensitive),
     * intersected with the messages actually present on disk so a
     * stale index line for a removed message cannot match. Uses
     * the per-folder search index for a single sequential read
     * instead of opening every message; the index is rebuilt
     * lazily when missing.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param string $query substring to match
     * @return array list of matching present uids
     */
    public function searchMessages($user, $folder, $query)
    {
        $needle = strtolower(trim((string) $query));
        if ($needle === "") {
            return [];
        }
        $map = $this->loadSearchIndex($user, $folder);
        if (empty($map)) {
            return [];
        }
        $present = array_flip(
            $this->folderMessageUids($this->folderDir($user,
            $folder)));
        $hits = [];
        foreach ($map as $uid => $haystack) {
            if (!isset($present[$uid])) {
                continue;
            }
            if (strpos($haystack, $needle) !== false) {
                $hits[] = $uid;
            }
        }
        return $hits;
    }
    /**
     * Lists the integer uids of the .eml files in a folder
     * directory. One directory read with no per-message stat,
     * used as the authoritative set of present messages so the
     * metadata index is never trusted to invent or hide a message.
     * @param string $dir absolute folder directory path
     * @return array list of integer uids present on disk
     */
    protected function folderMessageUids($dir)
    {
        $entries = @scandir($dir);
        if ($entries === false) {
            return [];
        }
        $uids = [];
        $suffix = "." . self::MESSAGE_FILE_EXTENSION;
        $suffix_length = strlen($suffix);
        foreach ($entries as $entry) {
            if (!str_ends_with($entry, $suffix)) {
                continue;
            }
            $uid = (int) substr($entry, 0, -$suffix_length);
            if ($uid > 0) {
                $uids[] = $uid;
            }
        }
        return $uids;
    }
    /**
     * Directory scan that reads every message's metadata from the
     * message file (size and date) and the folder's flags snapshot
     * (flag state), and sorts by ascending uid. This is the
     * pre-index code path, retained as the rebuild and cache-miss
     * source of truth.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array list of metadata records sorted by ascending uid
     */
    protected function scanFolderMessages($user, $folder)
    {
        $dir = $this->folderDir($user, $folder);
        if (!is_dir($dir)) {
            return [];
        }
        /*
            messageMeta recovers size and date from the message
            file but returns no flags, so layer flags in from the
            folder's snapshot (the durable flag store consulted
            only on a disk rebuild). A uid absent from the snapshot
            has no flags.
         */
        $snapshot_flags = $this->readFlagsSnapshot($user, $folder);
        $messages = [];
        foreach ($this->folderMessageUids($dir) as $uid) {
            $meta = $this->messageMeta($user, $folder, $uid);
            if ($meta !== false) {
                if (isset($snapshot_flags[(int) $uid])) {
                    $meta['flags'] = $snapshot_flags[(int) $uid];
                }
                $messages[] = $meta;
            }
        }
        usort($messages, function ($left, $right) {
            return $left['uid'] - $right['uid'];
        });
        return $messages;
    }
    /**
     * Streams a folder's index log and returns the set of live
     * uids as a uid-keyed boolean map. Unlike readFolderIndex this
     * keeps no per-message metadata record, so counting a folder
     * with tens of thousands of messages costs one small integer
     * key per live message rather than a full record map. Returns
     * null when the index is absent so the caller can fall back to
     * a directory scan.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array|null uid-keyed map of present messages, null if absent
     */
    protected function liveUidsFromIndex($user, $folder)
    {
        $cache_key = $user . "\0" . $folder;
        if (isset($this->index_cache[$cache_key])) {
            $live = [];
            foreach ($this->index_cache[$cache_key]['records']
                as $uid => $record) {
                $live[$uid] = true;
            }
            return $live;
        }
        $path = $this->messageIndexPath($user, $folder);
        if (!is_file($path)) {
            return null;
        }
        $handle = @fopen($path, "rb");
        if ($handle === false) {
            return null;
        }
        self::cooperativeFlock($handle, LOCK_SH);
        $live = [];
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === "") {
                continue;
            }
            $space = strpos($line, " ");
            if ($space === false) {
                continue;
            }
            $operation = substr($line, 0, $space);
            $rest = substr($line, $space + 1);
            $next = strpos($rest, " ");
            $uid = (int) ($next === false ? $rest :
                substr($rest, 0, $next));
            if ($uid < 1) {
                continue;
            }
            if ($operation === self::INDEX_PRESENT_MARKER) {
                $live[$uid] = true;
            } else if ($operation === self::INDEX_REMOVE_MARKER) {
                unset($live[$uid]);
            }
        }
        @flock($handle, LOCK_UN);
        fclose($handle);
        return $live;
    }
    /**
     * Reads and replays a folder's index log into a uid-keyed map
     * of metadata records. Returns null when the index is absent
     * so the caller can rebuild it. A trailing partial line (a
     * reader racing a concurrent append) is dropped. The shared
     * lock blocks only during the brief exclusive window of an
     * append or compaction.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int &$line_count set to the number of records replayed
     * @return array|null map of uid => metadata record, null if absent
     */
    protected function readFolderIndex($user, $folder,
        &$line_count)
    {
        $line_count = 0;
        $cache_key = $user . "\0" . $folder;
        if (isset($this->index_cache[$cache_key])) {
            $line_count =
                $this->index_cache[$cache_key]['line_count'];
            return $this->index_cache[$cache_key]['records'];
        }
        $path = $this->messageIndexPath($user, $folder);
        if (!is_file($path)) {
            return null;
        }
        $handle = @fopen($path, "rb");
        if ($handle === false) {
            return null;
        }
        self::cooperativeFlock($handle, LOCK_SH);
        /*
            Read the log one line at a time rather than slurping
            the whole file and exploding it. A busy folder's
            append-only index can hold many tens of thousands of
            present/flag/remove lines; keeping the full file
            string, the exploded line array, and the records map
            all resident at once was enough to exhaust memory on a
            large mailbox. Streaming keeps only the records map and
            a single line live.
         */
        $records = [];
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === "") {
                continue;
            }
            $parts = explode(" ", $line);
            $operation = $parts[0];
            $uid = (int) ($parts[1] ?? 0);
            if ($uid < 1) {
                continue;
            }
            $line_count++;
            if ($operation === self::INDEX_PRESENT_MARKER) {
                $records[$uid] = [
                    'uid' => $uid,
                    'size' => (int) ($parts[2] ?? 0),
                    'flags' => array_slice($parts, 4),
                    'internal_date' => (int) ($parts[3] ?? 0),
                ];
            } else if ($operation === self::INDEX_FLAG_MARKER) {
                if (isset($records[$uid])) {
                    $records[$uid]['flags'] =
                        array_slice($parts, 2);
                }
            } else if ($operation === self::INDEX_REMOVE_MARKER) {
                unset($records[$uid]);
            }
        }
        @flock($handle, LOCK_UN);
        fclose($handle);
        $this->index_cache[$cache_key] = [
            'records' => $records,
            'line_count' => $line_count,
        ];
        return $records;
    }
    /**
     * Rebuilds a folder's index from the message files and
     * writes a fresh snapshot (one present-record per live
     * message). Used when the index is absent, has drifted from
     * the directory, or has grown long enough to warrant
     * compaction. The directory scan here is the slow path the
     * index exists to avoid; it runs once, then later listings
     * read the snapshot.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array list of metadata records for the live messages
     */
    protected function rebuildFolderIndex($user, $folder)
    {
        $records = $this->scanFolderMessages($user, $folder);
        /*
            scanFolderMessages takes flags from the snapshot, which
            is the right source when the index was lost. When the
            index is still readable (the compaction case) it holds
            fresher flags than the last snapshot, so prefer those
            and let the refreshed snapshot below capture them.
         */
        $line_count = 0;
        $current = $this->readFolderIndex($user, $folder,
            $line_count);
        if ($current !== null) {
            foreach ($records as $position => $record) {
                $uid = (int) $record['uid'];
                if (isset($current[$uid])) {
                    $records[$position]['flags'] =
                        $current[$uid]['flags'];
                }
            }
        }
        $snapshot = "";
        foreach ($records as $record) {
            $snapshot .= $this->formatPresentRecord(
                $record['uid'], $record['size'],
                $record['internal_date'], $record['flags']);
        }
        @file_put_contents(
            $this->messageIndexPath($user, $folder),
            $snapshot, LOCK_EX);
        $by_uid = [];
        foreach ($records as $record) {
            $by_uid[(int) $record['uid']] = $record;
        }
        $this->writeFlagsSnapshot($user, $folder, $by_uid);
        $this->invalidateIndexCache($user, $folder);
        return $records;
    }
    /**
     * Renumbers a folder's messages to sequential per-folder UIDs
     * starting at 1, preserving message order by ascending current
     * UID. Used to repair folders whose messages were assigned
     * from the old global allocator and so carry large UIDs that
     * clients render as a message count. A journal recording the
     * full old-to-new mapping is written before any message file
     * moves, so a run interrupted by a crash resumes from the
     * journal on the next call; each message is staged to a
     * target-UID file the message scan ignores and then finalized,
     * and every step is idempotent, so no message is lost or moved
     * twice. A fresh UIDVALIDITY is written because the UIDs
     * change, which tells clients to discard cached per-UID state
     * and re-sync (RFC 3501 sec 2.3.1.1). The per-folder high-water
     * is reset and both indexes are rebuilt; the journal is removed
     * only once all of that has been written.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param callable $progress optional callback invoked with
     *      (done, total, phase) during long runs
     * @return int the number of messages renumbered
     */
    public function renumberFolderUids($user, $folder,
        $progress = null)
    {
        $folder = $this->normalizeFolder($folder);
        $dir = $this->folderDir($user, $folder);
        if (!is_dir($dir)) {
            return 0;
        }
        /*
            Resume an interrupted renumber from its journal, or plan
            a fresh one. The journal records the full old-to-new
            mapping and is written (atomically) before any message
            file is touched, so its presence means a renumber is in
            progress and every step below can be safely repeated.
         */
        $journal = $this->readReuidJournal($user, $folder);
        if ($journal === null) {
            $messages = $this->listMessages($user, $folder);
            $plan = [];
            $sequence = 0;
            foreach ($messages as $message) {
                $sequence++;
                $plan[] = [
                    'old' => (int) $message['uid'],
                    'new' => $sequence,
                    'size' => (int) $message['size'],
                    'date' => (int) $message['internal_date'],
                    'flags' => $message['flags'],
                ];
            }
            $uidvalidity = $this->nextUidValidity();
            if (!$this->writeReuidJournal($user, $folder, $plan,
                $uidvalidity)) {
                return 0;
            }
        } else {
            $plan = $journal['plan'];
            $uidvalidity = $journal['uidvalidity'];
        }
        $total = count($plan);
        $done = 0;
        foreach ($plan as $entry) {
            $final = $this->messagePath($dir, $entry['new'],
                self::MESSAGE_FILE_EXTENSION);
            $stage = $this->reuidStagePath($dir, $entry['new']);
            $source = $this->messagePath($dir, $entry['old'],
                self::MESSAGE_FILE_EXTENSION);
            if (!is_file($final) && !is_file($stage) &&
                is_file($source)) {
                @rename($source, $stage);
            }
            $done++;
            if ($progress !== null && $done % 1000 === 0) {
                call_user_func($progress, $done, $total, "staged");
            }
        }
        $done = 0;
        foreach ($plan as $entry) {
            $final = $this->messagePath($dir, $entry['new'],
                self::MESSAGE_FILE_EXTENSION);
            $stage = $this->reuidStagePath($dir, $entry['new']);
            if (is_file($stage) && !is_file($final)) {
                @rename($stage, $final);
            }
            $done++;
            if ($progress !== null && $done % 1000 === 0) {
                call_user_func($progress, $done, $total, "finalized");
            }
        }
        /*
            Write the index and snapshot from the journal plan
            mapped to the new uids, then the per-folder UID files,
            and only then remove the journal so an interrupted run
            re-runs the whole finalize. The flags came from the
            journal, so this does not depend on a disk scan.
         */
        $renumbered = [];
        $index_text = "";
        foreach ($plan as $entry) {
            $record = [
                'uid' => $entry['new'],
                'size' => $entry['size'],
                'flags' => $entry['flags'],
                'internal_date' => $entry['date'],
            ];
            $renumbered[$entry['new']] = $record;
            $index_text .= $this->formatPresentRecord(
                $record['uid'], $record['size'],
                $record['internal_date'], $record['flags']);
        }
        @file_put_contents($this->messageIndexPath($user, $folder),
            $index_text, LOCK_EX);
        $this->writeFlagsSnapshot($user, $folder, $renumbered);
        @file_put_contents($this->folderUidNextPath($user, $folder),
            (string) ($total + 1), LOCK_EX);
        @file_put_contents(
            $dir . "/" . self::FOLDER_UIDVALIDITY_FILE,
            (string) $uidvalidity, LOCK_EX);
        $this->invalidateIndexCache($user, $folder);
        $this->rebuildSearchIndex($user, $folder);
        @unlink($this->reuidJournalPath($user, $folder));
        if ($progress !== null) {
            call_user_func($progress, $total, $total, "done");
        }
        return $total;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     * @param array $flags list of IMAP flag strings
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $dir = $this->folderDir($user, $folder);
        $eml = $this->messagePath($dir, $uid, self::MESSAGE_FILE_EXTENSION);
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
        $this->appendIndexRecord($user, $folder,
            self::INDEX_FLAG_MARKER . " " . (int) $uid .
            $this->indexFlagSuffix($clean) . "\n");
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function expunge($user, $folder, $uid_restriction = null)
    {
        $expunged = [];
        foreach ($this->listMessages($user, $folder) as $meta) {
            if (in_array(self::FLAG_DELETED, $meta['flags'])) {
                if ($uid_restriction !== null &&
                    !in_array((int) $meta['uid'], $uid_restriction,
                    true)) {
                    continue;
                }
                $dir = $this->folderDir($user, $folder);
                @unlink($this->messagePath($dir, $meta['uid'],
                    self::MESSAGE_FILE_EXTENSION));
                $expunged[] = $meta['uid'];
            }
        }
        if (!empty($expunged)) {
            $removals = "";
            foreach ($expunged as $expunged_uid) {
                $removals .= self::INDEX_REMOVE_MARKER . " " .
                    (int) $expunged_uid . "\n";
            }
            $this->appendIndexRecord($user, $folder, $removals);
        }
        return $expunged;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $from source folder for the move operation
     * @param string $to destination folder for the move operation
     * @param int $uid persistent IMAP unique identifier of the message
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
        /*
            Capture the source flags from the index before moving,
            since flags no longer travel in a per-message file and
            messageMeta in the destination would report none until
            the next rebuild.
         */
        $source_flags = [];
        foreach ($this->listMessages($user, $from) as $source_meta) {
            if ((int) $source_meta['uid'] === $uid) {
                $source_flags = $source_meta['flags'];
                break;
            }
        }
        foreach ([self::MESSAGE_FILE_EXTENSION]
            as $ext) {
            $src = $this->messagePath($from_dir, $uid, $ext);
            $dst = $this->messagePath($to_dir, $uid, $ext);
            if (is_file($src) && !@rename($src, $dst)) {
                return false;
            }
        }
        $this->appendIndexRecord($user, $from,
            self::INDEX_REMOVE_MARKER . " " . (int) $uid . "\n");
        $moved_meta = $this->messageMeta($user, $to, $uid);
        if ($moved_meta !== false) {
            $this->appendIndexRecord($user, $to,
                $this->formatPresentRecord($moved_meta['uid'],
                $moved_meta['size'], $moved_meta['internal_date'],
                $source_flags));
            $moved_header = $this->messageHeaderBytes($user, $to,
                $uid);
            if ($moved_header !== false) {
                $this->appendSearchRecord($user, $to, $uid,
                    $this->searchHaystackFromBytes(
                    $moved_header));
            }
        }
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageCount($user, $folder)
    {
        $dir = $this->folderDir($user, $folder);
        if (!is_dir($dir)) {
            return 0;
        }
        /*
            The index already records every live message, so count
            from it rather than scanning the folder directory. On a
            large mailbox that directory holds one file per message,
            so the old scandir-and-count walked hundreds of
            thousands of entries on every SELECT. When the index
            is absent (a folder that predates it) fall back to the
            scan, which also primes a rebuild on the next list.
         */
        $live = $this->liveUidsFromIndex($user, $folder);
        if ($live !== null) {
            return count($live);
        }
        return count($this->folderMessageUids($dir));
    }
    /**
     * @inheritdoc
     *
     * UIDVALIDITY is stored per folder so a delete+recreate
     * cycle assigns a fresh value, signaling clients that
     * their cached UID-to-content mapping is stale and must
     * be discarded. The per-user uidvalidity.txt file remains
     * the fallback for folders that pre-date this scheme so
     * existing message stores keep working without
     * intervention.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidValidity($user, $folder)
    {
        $folder_file = $this->folderDir($user, $folder) .
            "/" . self::FOLDER_UIDVALIDITY_FILE;
        if (is_file($folder_file)) {
            $value = (int) trim((string)
                @file_get_contents($folder_file));
            if ($value > 0) {
                return $value;
            }
        }
        $user_file = $this->userDir($user) . "/" .
            self::FOLDER_UIDVALIDITY_FILE;
        if (!is_file($user_file)) {
            $this->ensureUser($user);
        }
        return (int) @file_get_contents($user_file);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidNext($user, $folder)
    {
        $path = $this->folderUidNextPath($user, $folder);
        if (is_file($path)) {
            $stored = (int) trim((string) @file_get_contents(
                $path));
            if ($stored >= 1) {
                return $stored;
            }
        }
        /*
            A folder created before the per-folder high-water file
            existed has no foldernext.txt yet. Derive UIDNEXT from
            the largest live UID in the index (UIDs only ever
            increase, so max live uid + 1 is a valid next value),
            then persist it so later reads skip the index scan. An
            empty folder reports 1.
         */
        $next = 1;
        $live = $this->liveUidsFromIndex($user, $folder);
        if (!empty($live)) {
            $next = max(array_keys($live)) + 1;
        }
        if (is_dir($this->folderDir($user, $folder))) {
            $this->bumpFolderUidNext($user, $folder, $next);
        }
        return $next;
    }
    /**
     * Returns the absolute path to the per-user subscription
     * state file. The file holds one folder name per line; an
     * empty or missing file means only INBOX is subscribed.
     * @param string $user username (no @domain) identifying the mail account
     * @return string absolute path to the per-user subscriptions file
     */
    protected function subscriptionFile($user)
    {
        return $this->userDir($user) . "/" .
            self::USER_SUBSCRIBED_FILE;
    }
    /**
     * Reads the subscription file into a deduplicated array
     * with INBOX always present. The file format is one folder
     * name per line; blank lines and leading/trailing whitespace
     * are ignored. INBOX is treated as implicitly subscribed
     * even if not listed (RFC 3501 sec 6.3.6 idempotency).
     * @param string $user username (no @domain) identifying the mail account
     * @return array list of subscribed folder names
     */
    protected function readSubscriptions($user)
    {
        $file = $this->subscriptionFile($user);
        $names = [self::FOLDER_INBOX];
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
     * @param string $user username (no @domain) identifying the mail account
     * @param mixed $folders folders parameter
     * @return bool true on successful write
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function isSubscribed($user, $folder)
    {
        return in_array($folder,
            $this->readSubscriptions($user), true);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function unsubscribe($user, $folder)
    {
        if (strcasecmp($folder, self::FOLDER_INBOX) === 0) {
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
     * @param string $user username (no @domain) identifying the mail account
     */
    public function listSubscribed($user)
    {
        $names = $this->readSubscriptions($user);
        sort($names);
        return $names;
    }
    /**
     * @inheritdoc
     *
     * The file backend stores each message as its own .eml
     * file under the per-user folder directory. There is no
     * dedup -- two messages with byte-identical bodies use
     * two separate files -- so refcount is always 1 and the
     * hash is computed on demand from the file's bytes.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageBodyLocation($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $eml = $this->messagePath(
            $this->folderDir($user, $folder), $uid,
            self::MESSAGE_FILE_EXTENSION);
        if (!is_file($eml)) {
            return false;
        }
        $size = @filesize($eml);
        $bytes = @file_get_contents($eml);
        $hash = $bytes === false ? null : hash('sha256', $bytes);
        return [
            'backend' => 'file',
            'path' => $eml,
            'hash' => $hash,
            'refcount' => 1,
            'size' => $size === false ? null : (int) $size,
        ];
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
 *          'uidnext' => int,
 *          'uidvalidity' => int,    // user-level fallback
 *          'subscribed' => array,  // folder names
 *          'folders' => [
 *              $folder_name => [
 *                  'uidvalidity' => int,
 *                  'messages' => [
 *                      $uid => [
 *                          'bytes' => string,
 *                          'flags' => array,
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
     *
     * @param string $user username (no @domain)
     * @return array reference to the user record (mutable; see
     *      class docblock for shape)
     */
    protected function & userRef($user)
    {
        if (!isset($this->users[$user])) {
            $this->users[$user] = [
                'uidnext' => 1,
                'uidvalidity' => $this->nextUidValidity(),
                'subscribed' => [self::FOLDER_INBOX],
                'folders' => [
                    self::FOLDER_INBOX => [
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
     * @param string $user username (no @domain) identifying the mail account
     */
    public function ensureUser($user)
    {
        $this->userRef($user);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function createFolder($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $u = & $this->userRef($user);
        /*
            Create each ancestor along the path as well, matching
            the on-disk backend whose recursive mkdir materializes
            intermediate parents (so "Archive/2026" yields both
            "Archive" and "Archive/2026").
         */
        $parts = explode("/", $folder);
        $path = "";
        foreach ($parts as $part) {
            $path = ($path === "") ? $part : $path . "/" . $part;
            if (!isset($u['folders'][$path])) {
                $u['folders'][$path] = [
                    'uidvalidity' => $this->nextUidValidity(),
                    'messages' => [],
                ];
            }
        }
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function deleteFolder($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        if ($folder === self::FOLDER_INBOX) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $old current folder name to rename from
     * @param string $new target folder name to rename to
     */
    public function renameFolder($user, $old, $new)
    {
        $old = $this->safeNormalizeFolder($old);
        $new = $this->safeNormalizeFolder($new);
        if ($old === false || $new === false) {
            return false;
        }
        if ($old === self::FOLDER_INBOX || $new === self::FOLDER_INBOX) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function folderExists($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        return isset(
            $this->users[$user]['folders'][$folder]);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $bytes number of bytes
     * @param array $flags list of IMAP flag strings
     * @param int $internal_date Unix timestamp to record as the message internal date
     */
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $internal_date = 0)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function fetchMessage($user, $folder, $uid)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageHeaderBytes($user, $folder, $uid)
    {
        $bytes = $this->fetchMessage($user, $folder, $uid);
        if ($bytes === false) {
            return false;
        }
        $prefix = substr($bytes, 0, self::MAX_HEADER_BYTES);
        return $this->cropToHeaders($prefix);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function listMessages($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * In-memory backend: scans the folder's records directly,
     * building each haystack on the fly. No persistent index is
     * needed because the store is process-local and ephemeral.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param string $query substring to match against subject/from/to
     */
    public function searchMessages($user, $folder, $query)
    {
        $needle = strtolower(trim((string) $query));
        if ($needle === "") {
            return [];
        }
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return [];
        }
        if (!isset($this->users[$user]['folders'][$folder])) {
            return [];
        }
        $messages = $this->users[$user]['folders'][$folder]
            ['messages'];
        ksort($messages);
        $hits = [];
        foreach ($messages as $uid => $record) {
            $haystack = $this->searchHaystackFromBytes(
                $record['bytes']);
            if (strpos($haystack, $needle) !== false) {
                $hits[] = (int) $uid;
            }
        }
        return $hits;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageMeta($user, $folder, $uid)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     * @param array $flags list of IMAP flag strings
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function expunge($user, $folder, $uid_restriction = null)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
            if (in_array(self::FLAG_DELETED, $record['flags'],
                true)) {
                if ($uid_restriction !== null &&
                    !in_array((int) $uid, $uid_restriction, true)) {
                    continue;
                }
                $expunged[] = (int) $uid;
                unset($messages[$uid]);
            }
        }
        return $expunged;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $from source folder for the move operation
     * @param string $to destination folder for the move operation
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function moveMessage($user, $from, $to, $uid)
    {
        $from = $this->safeNormalizeFolder($from);
        $to = $this->safeNormalizeFolder($to);
        if ($from === false || $to === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageCount($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidValidity($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidNext($user, $folder)
    {
        $u = & $this->userRef($user);
        return $u['uidnext'];
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function isSubscribed($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        if ($folder === self::FOLDER_INBOX) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function subscribe($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function unsubscribe($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
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
     * @param string $user username (no @domain) identifying the mail account
     */
    public function listSubscribed($user)
    {
        $names = [self::FOLDER_INBOX];
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
    /**
     * @inheritdoc
     *
     * The RAM backend keeps every message body as its own
     * separate string on the storage instance. There is no
     * dedup, no on-disk path, and no refcount; we report the
     * computed hash for callers that want to compare bodies
     * across messages even though storage slots are not
     * shared.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageBodyLocation($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        if (!isset($this->users[$user]['folders'][$folder]
            ['messages'][$uid])) {
            return false;
        }
        $msg = $this->users[$user]['folders'][$folder]
            ['messages'][$uid];
        return [
            'backend' => 'ram',
            'path' => null,
            'hash' => hash('sha256', $msg['bytes']),
            'refcount' => 1,
            'size' => strlen($msg['bytes']),
        ];
    }
}
/**
 * Database-backed MailStorage. Mail metadata (users, folders,
 * messages, subscriptions, blob refcounts) lives in a relational
 * store via PDO; message bodies live on disk in a content-
 * addressed blob store with refcounted dedup. The database
 * stores body hashes only, so two messages with byte-identical
 * bodies share one on-disk file regardless of how many users
 * received the message or which folders it lives in.
 *
 * Construction.
 *
 *      new SqlMailStorage($dsn_or_pdo, $blobs_dir = null,
 *          $username = null, $password = null,
 *          $dialect_overrides = []);
 *
 * $dsn_or_pdo is either a PDO DSN string ("sqlite:/path/to.db",
 * "mysql:host=h;dbname=d", etc.) or an already-constructed PDO
 * instance (lets a host app like Yioop hand in its existing
 * pooled connection instead of opening a second one).
 *
 * $blobs_dir is the directory under which content-addressed
 * blobs are stored. For "sqlite:<path>" DSNs we default to
 * "<path>.blobs/" if null; for any other DSN or PDO instance
 * the caller MUST pass an explicit directory.
 *
 * SQL portability.
 *
 * The schema and every DML statement is the intersection of SQL
 * accepted by SQLite, MySQL, PostgreSQL, DB2, and Oracle. Per-
 * DBMS differences (integer-PK column declaration, big-int type
 * name, INSERT-or-ignore prefix/suffix, post-connect pragmas)
 * live in a per-driver dialect array; built-in entries cover
 * sqlite, mysql, and pgsql. Anyone running against db2 or oci
 * passes a dialect override into the constructor.
 *
 * Schema auto-creation.
 *
 * On construction CREATE TABLE IF NOT EXISTS runs for
 * mail_users, mail_folders, mail_messages, mail_subscriptions,
 * mail_blobs. There is no migration story yet; schema changes
 * require dropping tables manually.
 *
 * Blob layout and refcount integrity.
 *
 *      $blobs_dir/ab/cd/abcd1234...ef.eml   -- raw message bytes
 *      mail_blobs (body_hash, refcount,     -- transactional
 *                  size, created_at)           refcount table
 *
 * Refcounts live in the database alongside the message rows
 * that reference them, so each appendMessage commits the
 * refcount bump and the mail_messages INSERT in one
 * transaction. The .eml write is outside the transaction; a
 * rollback can leave an orphan .eml file, recovered by a
 * periodic filesystem-vs-mail_blobs reaper.
 */
class SqlMailStorage extends MailStorage
{
    /**
     * @var \PDO open connection used for every query.
     */
    protected $pdo;
    /**
     * @var string absolute directory under which blobs live.
     */
    protected $blobs_dir;
    /**
     * @var array per-DBMS dialect strings (pk_int, big_int,
     * text) and an optional post_connect closure for any
     * driver-specific tuning (PRAGMA journal_mode for SQLite,
     * etc.).
     */
    protected $dialect;
    /**
     * @var array name => SQL template string. Each call to
     * prepareStatement() prepares a fresh PDOStatement from these to
     * avoid cursor-state leakage between unrelated callers
     * (see prepareStatement()'s docblock for the full reasoning).
     */
    protected $sql_templates;
    /**
     * Constructs a SqlMailStorage.
     *
     * @param mixed $dsn_or_pdo either a PDO DSN string
     *      (e.g. "sqlite:/var/mail/atto.db",
     *      "mysql:host=db;dbname=atto",
     *      "pgsql:host=db;dbname=atto") or an already-open
     *      PDO instance from a host application.
     * @param string $blobs_dir absolute directory under which
     *      content-addressed message bodies are stored. May be
     *      null only when $dsn_or_pdo is an SQLite DSN of the
     *      form "sqlite:<path>"; we then default to
     *      "<path>.blobs". Otherwise required.
     * @param string $username PDO connection username if a DSN
     *      string was supplied (ignored for PDO instances).
     * @param string $password PDO connection password if a DSN
     *      string was supplied.
     * @param array $dialect_overrides dialect entries to merge
     *      over the built-in sqlite/mysql/pgsql ones; use this
     *      to add db2/oci or to override a built-in.
     */
    public function __construct($dsn_or_pdo, $blobs_dir = null,
        $username = null, $password = null,
        $dialect_overrides = [])
    {
        $built_in = $this->builtInDialects();
        $dialects = array_merge($built_in, $dialect_overrides);
        if ($dsn_or_pdo instanceof \PDO) {
            $this->pdo = $dsn_or_pdo;
            $driver = $this->pdo->getAttribute(
                \PDO::ATTR_DRIVER_NAME);
        } else {
            $dsn = (string) $dsn_or_pdo;
            $colon = strpos($dsn, ':');
            if ($colon === false) {
                throw new \InvalidArgumentException(
                    "DSN must contain a driver prefix: $dsn");
            }
            $driver = substr($dsn, 0, $colon);
            $this->pdo = new \PDO($dsn, $username, $password);
            /*
                Default blobs directory for SQLite DSNs. For
                "sqlite:/var/mail/atto.db" we assume the caller
                wants blobs under "/var/mail/atto.db.blobs". Any
                other driver requires an explicit directory.
             */
            if ($blobs_dir === null && $driver === 'sqlite') {
                $sqlite_path = substr($dsn, $colon + 1);
                if ($sqlite_path !== '' && $sqlite_path !== ':memory:') {
                    $blobs_dir = $sqlite_path . '.blobs';
                }
            }
        }
        if ($blobs_dir === null || $blobs_dir === '') {
            throw new \InvalidArgumentException(
                "blobs_dir is required for non-SQLite DSNs");
        }
        if (!isset($dialects[$driver])) {
            throw new \InvalidArgumentException(
                "no dialect entry for driver '$driver'; pass " .
                "one in via the dialect_overrides argument");
        }
        $this->dialect = $dialects[$driver];
        $this->blobs_dir = rtrim($blobs_dir, "/\\");
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE,
            \PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE,
            \PDO::FETCH_ASSOC);
        if (!empty($this->dialect['post_connect'])) {
            call_user_func($this->dialect['post_connect'],
                $this->pdo);
        }
        if (!is_dir($this->blobs_dir)) {
            @mkdir($this->blobs_dir, 0700, true);
        }
        $this->createSchema();
        $this->sql_templates = $this->buildSqlTemplates();
    }
    /**
     * Returns the built-in dialect map keyed by PDO driver
     * name. Each entry supplies SQL-fragment strings used by
     * createSchema, plus an optional post_connect closure that
     * runs against the PDO instance immediately after open
     * (used to set per-connection pragmas, character sets, or
     * isolation levels).
     * @return array map of SQL dialect name => template overrides
     */
    protected function builtInDialects()
    {
        return [
            'sqlite' => [
                'pk_int' => 'INTEGER PRIMARY KEY AUTOINCREMENT',
                'big_int' => 'INTEGER',
                'text' => 'TEXT',
                /*
                    Per-dialect INSERT-or-ignore. See
                    insertIgnoreSql() for the rewrite logic
                    (Yioop's DatasourceManager::insertIgnore
                    is the design reference).
                 */
                'insert_ignore_prefix' => 'INSERT OR IGNORE',
                'insert_ignore_suffix' => '',
                'post_connect' => function ($pdo) {
                    /*
                        WAL (write-ahead logging) lets readers
                        and writers run concurrently -- matters
                        once IDLE clients camp on a SELECT.
                        foreign_keys=ON enables FK cascade
                        (off by default in SQLite).
                     */
                    $pdo->exec('PRAGMA journal_mode=WAL');
                    $pdo->exec('PRAGMA foreign_keys=ON');
                },
            ],
            'mysql' => [
                'pk_int' =>
                    'BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY',
                'big_int' => 'BIGINT',
                'text' => 'TEXT',
                'insert_ignore_prefix' => 'INSERT IGNORE',
                'insert_ignore_suffix' => '',
                'post_connect' => function ($pdo) {
                    $pdo->exec("SET NAMES 'utf8mb4'");
                },
            ],
            'pgsql' => [
                'pk_int' => 'BIGSERIAL PRIMARY KEY',
                'big_int' => 'BIGINT',
                'text' => 'TEXT',
                'insert_ignore_prefix' => 'INSERT',
                'insert_ignore_suffix' => 'ON CONFLICT DO NOTHING',
                'post_connect' => null,
            ],
        ];
    }
    /**
     * Creates the four mail_* tables if they do not exist.
     * Schema is fully portable across the dialects we support;
     * dialect strings are substituted for the integer-PK
     * declaration and the big-int and text type names.
     */
    protected function createSchema()
    {
        $pk = $this->dialect['pk_int'];
        $big = $this->dialect['big_int'];
        $text = $this->dialect['text'];
        $statements = [
            "CREATE TABLE IF NOT EXISTS mail_users (
                id $pk,
                username VARCHAR(255) NOT NULL UNIQUE,
                uidnext $big NOT NULL,
                uidvalidity $big NOT NULL,
                created_at $big NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS mail_folders (
                id $pk,
                user_id $big NOT NULL,
                name VARCHAR(512) NOT NULL,
                uidvalidity $big NOT NULL,
                created_at $big NOT NULL,
                CONSTRAINT mail_folders_unique
                    UNIQUE (user_id, name)
            )",
            "CREATE TABLE IF NOT EXISTS mail_messages (
                id $pk,
                folder_id $big NOT NULL,
                uid $big NOT NULL,
                flags $text NOT NULL,
                internal_date $big NOT NULL,
                size $big NOT NULL,
                body_hash CHAR(64) NOT NULL,
                search_text $text,
                CONSTRAINT mail_messages_unique
                    UNIQUE (folder_id, uid)
            )",
            "CREATE TABLE IF NOT EXISTS mail_subscriptions (
                user_id $big NOT NULL,
                folder VARCHAR(512) NOT NULL,
                CONSTRAINT mail_subscriptions_pk
                    PRIMARY KEY (user_id, folder)
            )",
            "CREATE TABLE IF NOT EXISTS mail_blobs (
                body_hash CHAR(64) NOT NULL PRIMARY KEY,
                refcount $big NOT NULL,
                size $big NOT NULL,
                created_at $big NOT NULL
            )",
        ];
        foreach ($statements as $sql) {
            $this->pdo->exec($sql);
        }
        /* Older installs created mail_messages before the
           search_text column existed; add it if missing. The
           ALTER is wrapped because a second run (column already
           present) raises on every supported driver, and there is
           no portable IF NOT EXISTS for ADD COLUMN across SQLite,
           MySQL, Postgres, Oracle, and DB2. */
        try {
            $this->pdo->exec("ALTER TABLE mail_messages " .
                "ADD COLUMN search_text $text");
        } catch (\Throwable $already_present) {
            /* column already exists; nothing to do */
            $already_present = null;
        }
    }
    /**
     * Returns the prepared-statement-template lookup table.
     * Statements are identified by short symbolic names so the
     * call sites read like English rather than SQL fragments.
     * Every template uses positional ? placeholders to keep
     * parameter binding identical across drivers.
     * @return array map of template key => SQL fragment for the active dialect
     */
    protected function buildSqlTemplates()
    {
        $templates = [
            'user_by_name' =>
                "SELECT * FROM mail_users WHERE username = ?",
            'user_insert' =>
                "INSERT INTO mail_users " .
                "(username, uidnext, uidvalidity, created_at) " .
                "VALUES (?, ?, ?, ?)",
            'user_update_uidnext' =>
                "UPDATE mail_users SET uidnext = ? " .
                "WHERE id = ?",
            'folder_by_user_name' =>
                "SELECT * FROM mail_folders " .
                "WHERE user_id = ? AND name = ?",
            'folders_by_user' =>
                "SELECT name FROM mail_folders " .
                "WHERE user_id = ? ORDER BY name",
            'folder_insert' =>
                "INSERT INTO mail_folders " .
                "(user_id, name, uidvalidity, created_at) " .
                "VALUES (?, ?, ?, ?)",
            'folder_delete' =>
                "DELETE FROM mail_folders WHERE id = ?",
            'folder_rename' =>
                "UPDATE mail_folders SET name = ? WHERE id = ?",
            'folder_children' =>
                "SELECT id FROM mail_folders " .
                "WHERE user_id = ? AND name LIKE ?",
            'message_by_uid' =>
                "SELECT * FROM mail_messages " .
                "WHERE folder_id = ? AND uid = ?",
            'messages_by_folder' =>
                "SELECT * FROM mail_messages " .
                "WHERE folder_id = ? ORDER BY uid",
            'message_meta_by_folder' =>
                "SELECT uid, size, flags, internal_date " .
                "FROM mail_messages " .
                "WHERE folder_id = ? ORDER BY uid",
            'message_count' =>
                "SELECT COUNT(*) AS c FROM mail_messages " .
                "WHERE folder_id = ?",
            'message_insert' =>
                "INSERT INTO mail_messages (folder_id, uid, " .
                "flags, internal_date, size, body_hash, " .
                "search_text) " .
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
            'message_search' =>
                "SELECT uid FROM mail_messages " .
                "WHERE folder_id = ? AND search_text LIKE ? " .
                "ESCAPE '\\' ORDER BY uid",
            'messages_missing_search' =>
                "SELECT id, uid, body_hash FROM mail_messages " .
                "WHERE folder_id = ? AND search_text IS NULL",
            'message_set_search' =>
                "UPDATE mail_messages SET search_text = ? " .
                "WHERE id = ?",
            'message_delete' =>
                "DELETE FROM mail_messages WHERE id = ?",
            'message_update_flags' =>
                "UPDATE mail_messages SET flags = ? " .
                "WHERE id = ?",
            'message_move' =>
                "UPDATE mail_messages SET folder_id = ? " .
                "WHERE id = ?",
            'messages_in_folder_with_deleted' =>
                "SELECT id, uid, flags, body_hash " .
                "FROM mail_messages " .
                "WHERE folder_id = ? ORDER BY uid",
            'subscription_check' =>
                "SELECT 1 FROM mail_subscriptions " .
                "WHERE user_id = ? AND folder = ?",
            'subscription_insert' =>
                "INSERT INTO mail_subscriptions " .
                "(user_id, folder) VALUES (?, ?)",
            'subscription_delete' =>
                "DELETE FROM mail_subscriptions " .
                "WHERE user_id = ? AND folder = ?",
            'subscriptions_by_user' =>
                "SELECT folder FROM mail_subscriptions " .
                "WHERE user_id = ? ORDER BY folder",
            'blob_select' =>
                "SELECT body_hash, refcount, size, " .
                "created_at FROM mail_blobs " .
                "WHERE body_hash = ?",
            'blob_insert_or_ignore' =>
                /* placeholders spliced by buildSqlTemplates */
                "__insert_ignore__ INTO mail_blobs " .
                "(body_hash, refcount, size, created_at) " .
                "VALUES (?, 1, ?, ?) __insert_ignore_suffix__",
            'blob_increment' =>
                "UPDATE mail_blobs " .
                "SET refcount = refcount + 1 " .
                "WHERE body_hash = ?",
            'blob_decrement' =>
                "UPDATE mail_blobs " .
                "SET refcount = refcount - 1 " .
                "WHERE body_hash = ?",
            'blob_delete_zero' =>
                "DELETE FROM mail_blobs " .
                "WHERE body_hash = ? AND refcount <= 0",
        ];
        /*
            Splice the dialect-correct INSERT IGNORE shape
            into the template once, here, rather than on
            every prepareStatement() call.
         */
        $templates['blob_insert_or_ignore'] = str_replace(
            ['__insert_ignore__', '__insert_ignore_suffix__'],
            [
                $this->dialect['insert_ignore_prefix'],
                $this->dialect['insert_ignore_suffix'],
            ],
            $templates['blob_insert_or_ignore']);
        return $templates;
    }
    /**
     * Returns a freshly-prepared PDOStatement for the named
     * template. We deliberately do NOT cache prepared
     * statements across calls: PDO holds an open cursor on a
     * statement after execute() returns until every row is
     * consumed via fetch() or closeCursor() is called, and
     * cached prepared statements leak that cursor state
     * between unrelated callers. Per-call preparation costs
     * ~50 microseconds in SQLite, irrelevant against the disk
     * and network costs dominating mail-server throughput.
     * @param string $name name
     * @return \PDOStatement prepared statement ready to execute
     */
    protected function prepareStatement($name)
    {
        if (!isset($this->sql_templates[$name])) {
            throw new \LogicException(
                "no SQL template named '$name'");
        }
        return $this->pdo->prepare(
            $this->sql_templates[$name]);
    }
    /**
     * Returns a dialect-correct INSERT-or-ignore form of
     * $insert_sql, which must begin with "INSERT INTO ...".
     * The semantics: if the row's primary or unique key is
     * already present, the statement is silently a no-op
     * (rowCount() == 0) rather than raising a duplicate-key
     * error. Followed by a discriminating UPDATE this gives
     * portable INSERT-or-UPDATE behaviour.
     *
     * Pattern follows Yioop's DatasourceManager::insertIgnore:
     * SQLite swaps "INSERT" for "INSERT OR IGNORE", MySQL uses
     * "INSERT IGNORE", Postgres keeps the leading verb and
     * appends "ON CONFLICT DO NOTHING".
     * @param mixed $insert_sql insert_sql parameter
     * @return string INSERT ... ON CONFLICT IGNORE statement appropriate to the active dialect
     */
    protected function insertIgnoreSql($insert_sql)
    {
        $insert_sql = ltrim($insert_sql);
        if (!str_starts_with($insert_sql, 'INSERT')) {
            throw new \InvalidArgumentException(
                "insertIgnoreSql expects an INSERT statement");
        }
        $prefix = $this->dialect['insert_ignore_prefix'];
        $suffix = $this->dialect['insert_ignore_suffix'];
        $rewritten = $prefix . substr($insert_sql, 6);
        if ($suffix !== '') {
            $rewritten .= ' ' . $suffix;
        }
        return $rewritten;
    }
    /**
     * Returns the user record (id, uidnext, uidvalidity) for
     * $username, creating the user lazily on first reference.
     * Mirrors RamMailStorage::userRef + FileMailStorage's
     * ensureUser side effect: any operation that touches a
     * username for the first time materializes a user row and
     * an INBOX folder row.
     * @param string $user username (no @domain) identifying the mail account
     * @return array|false user database row, or false if no such user exists
     */
    protected function userRow($user)
    {
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $row = $stmt->fetch();
        if ($row !== false) {
            return $row;
        }
        $now = time();
        $uv = $this->nextUidValidity();
        $this->prepareStatement('user_insert')->execute(
            [$user, 1, $uv, $now]);
        $user_id = (int) $this->pdo->lastInsertId();
        $inbox_uv = $this->nextUidValidity();
        $this->prepareStatement('folder_insert')->execute(
            [$user_id, self::FOLDER_INBOX, $inbox_uv, $now]);
        return [
            'id' => $user_id,
            'username' => $user,
            'uidnext' => 1,
            'uidvalidity' => $uv,
            'created_at' => $now,
        ];
    }
    /**
     * Returns the folder row for ($user, $folder) or false if
     * neither the user nor the folder exists.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array|false folder database row, or false if no such folder exists
     */
    protected function folderRow($user, $folder)
    {
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('folder_by_user_name');
        $stmt->execute([$user_row['id'], $folder]);
        $folder_row = $stmt->fetch();
        if ($folder_row === false) {
            return false;
        }
        $folder_row['user_id'] = $user_row['id'];
        return $folder_row;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     */
    public function ensureUser($user)
    {
        $this->userRow($user);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     */
    public function listFolders($user)
    {
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            return [];
        }
        $stmt = $this->prepareStatement('folders_by_user');
        $stmt->execute([$user_row['id']]);
        $names = [];
        while ($row = $stmt->fetch()) {
            $names[] = $row['name'];
        }
        return $names;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function createFolder($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $u = $this->userRow($user);
        $stmt = $this->prepareStatement('folder_by_user_name');
        $stmt->execute([$u['id'], $folder]);
        if ($stmt->fetch() !== false) {
            return true;
        }
        $this->prepareStatement('folder_insert')->execute([
            $u['id'], $folder, $this->nextUidValidity(), time()
        ]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function deleteFolder($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        if ($folder === self::FOLDER_INBOX) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('folder_children');
        $stmt->execute([$row['user_id'], $folder . '/%']);
        if ($stmt->fetch() !== false) {
            return false;
        }
        /*
            Wholesale folder drop: decrement refcounts for every
            message, then drop the message rows, then drop the
            folder row, all inside one transaction so a crash
            mid-drop cannot leave a partially-deleted folder
            with stale refcounts.
         */
        $this->pdo->beginTransaction();
        try {
            $msgs = $this->prepareStatement('messages_by_folder');
            $msgs->execute([$row['id']]);
            $hashes = [];
            while ($m = $msgs->fetch()) {
                $hashes[] = $m['body_hash'];
            }
            foreach ($hashes as $hash) {
                $this->blobDecRef($hash);
            }
            $this->pdo->exec("DELETE FROM mail_messages " .
                "WHERE folder_id = " . (int) $row['id']);
            $this->prepareStatement('folder_delete')->execute([$row['id']]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            return false;
        }
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $old current folder name to rename from
     * @param string $new target folder name to rename to
     */
    public function renameFolder($user, $old, $new)
    {
        $old = $this->safeNormalizeFolder($old);
        $new = $this->safeNormalizeFolder($new);
        if ($old === false || $new === false) {
            return false;
        }
        if ($old === self::FOLDER_INBOX || $new === self::FOLDER_INBOX) {
            return false;
        }
        $row = $this->folderRow($user, $old);
        if ($row === false) {
            return false;
        }
        if ($this->folderRow($user, $new) !== false) {
            return false;
        }
        $this->prepareStatement('folder_rename')->execute(
            [$new, $row['id']]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function folderExists($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        return $this->folderRow($user, $folder) !== false;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $bytes number of bytes
     * @param array $flags list of IMAP flag strings
     * @param int $internal_date Unix timestamp to record as the message internal date
     */
    public function appendMessage($user, $folder, $bytes,
        $flags = [], $internal_date = 0)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $u = $this->userRow($user);
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            if (!$this->createFolder($user, $folder)) {
                return false;
            }
            $row = $this->folderRow($user, $folder);
            if ($row === false) {
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
        $bytes = (string) $bytes;
        $hash = hash('sha256', $bytes);
        /*
            One transaction across blob refcount, UID counter,
            and mail_messages insert. The UNIQUE (folder_id,
            uid) constraint prevents collisions if two appends
            race. The .eml file write happens inside
            blobIncRef and is not transactional; an orphan .eml
            after a rollback is recovered by a filesystem-vs-
            mail_blobs reaper -- see blobIncRef's docblock.
         */
        $this->pdo->beginTransaction();
        try {
            if (!$this->blobIncRef($hash, $bytes)) {
                $this->pdo->rollBack();
                return false;
            }
            $stmt = $this->prepareStatement('user_by_name');
            $stmt->execute([$user]);
            $fresh = $stmt->fetch();
            $uid = (int) $fresh['uidnext'];
            $this->prepareStatement('user_update_uidnext')->execute(
                [$uid + 1, $u['id']]);
            $this->prepareStatement('message_insert')->execute([
                $row['id'], $uid, implode(' ', $clean),
                (int) $internal_date, strlen($bytes), $hash,
                $this->searchHaystackFromBytes($bytes)
            ]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            return false;
        }
        return $uid;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function fetchMessage($user, $folder, $uid)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$row['id'], (int) $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        return $this->blobRead($msg['body_hash']);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageHeaderBytes($user, $folder, $uid)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$row['id'], (int) $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        $prefix = $this->blobReadPrefix($msg['body_hash'],
            self::MAX_HEADER_BYTES);
        if ($prefix === false) {
            return false;
        }
        return $this->cropToHeaders($prefix);
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function listMessages($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return [];
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return [];
        }
        $stmt = $this->prepareStatement('message_meta_by_folder');
        $stmt->execute([$row['id']]);
        $output = [];
        while ($msg = $stmt->fetch()) {
            $output[] = $this->messageRecord($msg);
        }
        return $output;
    }
    /**
     * @inheritdoc
     * SQL backend: matches on the indexed search_text column with
     * LIKE for messages that have it populated, and lazily
     * backfills rows that predate the column (search_text IS NULL)
     * by reading the body once, matching in PHP, and writing the
     * computed search_text back so later searches are fast.
     * @param string $user username (no @domain)
     * @param string $folder folder name with full hierarchy path
     * @param string $query substring to match against subject/from/to
     */
    public function searchMessages($user, $folder, $query)
    {
        $needle = strtolower(trim((string) $query));
        if ($needle === "") {
            return [];
        }
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return [];
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return [];
        }
        $hits = [];
        $like = "%" . $this->escapeLike($needle) . "%";
        $stmt = $this->prepareStatement('message_search');
        $stmt->execute([$row['id'], $like]);
        while ($found = $stmt->fetch()) {
            $hits[(int) $found['uid']] = true;
        }
        $stale = $this->prepareStatement(
            'messages_missing_search');
        $stale->execute([$row['id']]);
        $pending = [];
        while ($msg = $stale->fetch()) {
            $pending[] = $msg;
        }
        foreach ($pending as $msg) {
            $bytes = $this->blobRead($msg['body_hash']);
            $haystack = ($bytes === false) ? "" :
                $this->searchHaystackFromBytes($bytes);
            $this->prepareStatement('message_set_search')->execute(
                [$haystack, $msg['id']]);
            if ($haystack !== "" &&
                strpos($haystack, $needle) !== false) {
                $hits[(int) $msg['uid']] = true;
            }
        }
        $uids = array_keys($hits);
        sort($uids);
        return $uids;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageMeta($user, $folder, $uid)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$row['id'], (int) $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        return $this->messageRecord($msg);
    }
    /**
     * Escapes the LIKE wildcards in a user-supplied search term so
     * they match literally rather than as wildcards. The backslash
     * escape character is itself escaped first; the search query
     * pairs this with an explicit ESCAPE '\' clause, which is
     * standard SQL honored by every backend Yioop targets.
     * @param string $term raw search term
     * @return string term with backslash, percent, and underscore
     *      escaped
     */
    protected function escapeLike($term)
    {
        return str_replace(
            ["\\", "%", "_"],
            ["\\\\", "\\%", "\\_"],
            (string) $term);
    }
    /**
     * Shapes a raw mail_messages row into the public record
     * format that the abstract MailStorage interface promises.
     * @param array $row database row
     * @return array|false message metadata row, or false if no such message exists
     */
    protected function messageRecord($row)
    {
        $flags = preg_split('/\s+/', trim((string) $row['flags']));
        $flags = array_values(array_filter($flags,
            function ($flag) { return $flag !== ''; }));
        return [
            'uid' => (int) $row['uid'],
            'size' => (int) $row['size'],
            'flags' => $flags,
            'internal_date' => (int) $row['internal_date'],
        ];
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     * @param array $flags list of IMAP flag strings
     */
    public function setFlags($user, $folder, $uid, $flags)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$row['id'], $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        $clean = [];
        foreach ($flags as $flag) {
            $flag = trim((string) $flag);
            if ($flag !== "") {
                $clean[] = $flag;
            }
        }
        $this->prepareStatement('message_update_flags')->execute(
            [implode(' ', $clean), $msg['id']]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function expunge($user, $folder, $uid_restriction = null)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return [];
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return [];
        }
        $stmt = $this->prepareStatement('messages_in_folder_with_deleted');
        $stmt->execute([$row['id']]);
        $expunged = [];
        $to_drop = [];
        while ($msg = $stmt->fetch()) {
            $flags = preg_split('/\s+/',
                trim((string) $msg['flags']));
            if (!in_array(self::FLAG_DELETED, $flags, true)) {
                continue;
            }
            if ($uid_restriction !== null &&
                !in_array((int) $msg['uid'], $uid_restriction,
                true)) {
                continue;
            }
            $expunged[] = (int) $msg['uid'];
            $to_drop[] = $msg;
        }
        if (empty($to_drop)) {
            return $expunged;
        }
        /*
            Wrap the per-message DELETE plus refcount drop in
            a single transaction so a partial expunge cannot
            leave the database with mail_messages rows
            removed but their refcounts still elevated, or
            vice versa.
         */
        $this->pdo->beginTransaction();
        try {
            foreach ($to_drop as $msg) {
                $this->prepareStatement('message_delete')->execute(
                    [$msg['id']]);
                $this->blobDecRef($msg['body_hash']);
            }
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            return [];
        }
        sort($expunged);
        return $expunged;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $from source folder for the move operation
     * @param string $to destination folder for the move operation
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function moveMessage($user, $from, $to, $uid)
    {
        $from = $this->safeNormalizeFolder($from);
        $to = $this->safeNormalizeFolder($to);
        if ($from === false || $to === false) {
            return false;
        }
        $uid = (int) $uid;
        $from_row = $this->folderRow($user, $from);
        if ($from_row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$from_row['id'], $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        $to_row = $this->folderRow($user, $to);
        if ($to_row === false) {
            if (!$this->createFolder($user, $to)) {
                return false;
            }
            $to_row = $this->folderRow($user, $to);
            if ($to_row === false) {
                return false;
            }
        }
        $this->prepareStatement('message_move')->execute(
            [$to_row['id'], $msg['id']]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function messageCount($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return 0;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return 0;
        }
        $stmt = $this->prepareStatement('message_count');
        $stmt->execute([$row['id']]);
        $count_row = $stmt->fetch();
        return (int) $count_row['c'];
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidValidity($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return 0;
        }
        $row = $this->folderRow($user, $folder);
        if ($row !== false) {
            return (int) $row['uidvalidity'];
        }
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            return 0;
        }
        return (int) $user_row['uidvalidity'];
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function uidNext($user, $folder)
    {
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            $u = $this->userRow($user);
            return (int) $u['uidnext'];
        }
        return (int) $user_row['uidnext'];
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function isSubscribed($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        if ($folder === self::FOLDER_INBOX) {
            return true;
        }
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('subscription_check');
        $stmt->execute([$user_row['id'], $folder]);
        return $stmt->fetch() !== false;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function subscribe($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $u = $this->userRow($user);
        $stmt = $this->prepareStatement('subscription_check');
        $stmt->execute([$u['id'], $folder]);
        if ($stmt->fetch() !== false) {
            return true;
        }
        $this->prepareStatement('subscription_insert')->execute(
            [$u['id'], $folder]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     */
    public function unsubscribe($user, $folder)
    {
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row === false) {
            return true;
        }
        $this->prepareStatement('subscription_delete')->execute(
            [$user_row['id'], $folder]);
        return true;
    }
    /**
     * @inheritdoc
     * @param string $user username (no @domain) identifying the mail account
     */
    public function listSubscribed($user)
    {
        $names = [self::FOLDER_INBOX];
        $stmt = $this->prepareStatement('user_by_name');
        $stmt->execute([$user]);
        $user_row = $stmt->fetch();
        if ($user_row !== false) {
            $stmt = $this->prepareStatement('subscriptions_by_user');
            $stmt->execute([$user_row['id']]);
            while ($row = $stmt->fetch()) {
                if (!in_array($row['folder'], $names, true)) {
                    $names[] = $row['folder'];
                }
            }
        }
        sort($names);
        return $names;
    }
    /**
     * @inheritdoc
     *
     * The SQL backend's content-addressed body store is the
     * star of this method: two messages with byte-identical
     * bodies report the same path and hash, and the refcount
     * field shows how many other messages share the blob.
     * Callers can fetch messageBodyLocation for two messages
     * delivered to different users and observe that the
     * storage location coincides.
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param int $uid persistent IMAP unique identifier of the message
     */
    public function messageBodyLocation($user, $folder, $uid)
    {
        $uid = (int) $uid;
        if ($uid < 1) {
            return false;
        }
        $folder = $this->safeNormalizeFolder($folder);
        if ($folder === false) {
            return false;
        }
        $row = $this->folderRow($user, $folder);
        if ($row === false) {
            return false;
        }
        $stmt = $this->prepareStatement('message_by_uid');
        $stmt->execute([$row['id'], $uid]);
        $msg = $stmt->fetch();
        if ($msg === false) {
            return false;
        }
        $hash = $msg['body_hash'];
        $blob_stmt = $this->prepareStatement('blob_select');
        $blob_stmt->execute([$hash]);
        $blob = $blob_stmt->fetch();
        return [
            'backend' => 'sql',
            'path' => $this->blobPath($hash),
            'hash' => $hash,
            'refcount' => $blob === false ? 0 :
                (int) $blob['refcount'],
            'size' => (int) $msg['size'],
        ];
    }
    /**
     * Returns the on-disk path to the blob for $hash. Layout
     * is two-byte / two-byte directory prefix to bound the
     * fan-out of any one directory; a hash starting with
     * "abcd1234..." goes under "ab/cd/abcd1234.eml". The blob
     * store contains only .eml files; refcounts live in the
     * mail_blobs table for ACID crash-recovery.
     * @param mixed $hash hash parameter
     * @return string absolute filesystem path of the BLOB by content-id
     */
    protected function blobPath($hash)
    {
        return $this->blobs_dir . '/' .
            substr($hash, 0, 2) . '/' .
            substr($hash, 2, 2) . '/' .
            $hash . '.' . self::MESSAGE_FILE_EXTENSION;
    }
    /**
     * Increments the refcount for $hash, creating the blob
     * file from $bytes if it does not already exist. Returns
     * true on success. Caller wraps in the same transaction
     * as the corresponding mail_messages INSERT so a crash
     * never leaves the refcount out of sync. The .eml write
     * is outside the transaction (filesystems are not
     * transactional; we use temp-then-atomic-rename to avoid
     * torn writes). A rolled-back transaction can leave an
     * orphan .eml; a periodic reaper recovers it.
     * @param mixed $hash hash parameter
     * @param int $bytes number of bytes
     * @return int new refcount after the increment
     */
    protected function blobIncRef($hash, $bytes)
    {
        /*
            Insert at refcount=1; if a row already exists
            the IGNORE makes that a no-op and we UPDATE
            instead. Either way the refcount tracks the new
            reference.
         */
        $stmt = $this->prepareStatement('blob_insert_or_ignore');
        $stmt->execute([$hash, strlen($bytes), time()]);
        $inserted = $stmt->rowCount();
        if ($inserted === 0) {
            $this->prepareStatement('blob_increment')->execute([$hash]);
        }
        $eml_path = $this->blobPath($hash);
        if (!is_file($eml_path)) {
            $dir = dirname($eml_path);
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }
            $temp = $eml_path . '.tmp';
            $written = @file_put_contents($temp, $bytes);
            if ($written === false ||
                !@rename($temp, $eml_path)) {
                @unlink($temp);
                return false;
            }
        }
        return true;
    }
    /**
     * Decrements the refcount for $hash. When the count
     * reaches zero the row is deleted and the .eml file is
     * unlinked. The caller wraps this in the same transaction
     * as the mail_messages DELETE that triggered the drop,
     * so a crash mid-expunge cannot leave a row orphaned
     * with a stale refcount.
     * @param mixed $hash hash parameter
     * @return int new refcount after the decrement; zero triggers deletion
     */
    protected function blobDecRef($hash)
    {
        $this->prepareStatement('blob_decrement')->execute([$hash]);
        $stmt = $this->prepareStatement('blob_select');
        $stmt->execute([$hash]);
        $row = $stmt->fetch();
        if ($row === false) {
            return true;
        }
        if ((int) $row['refcount'] > 0) {
            return true;
        }
        $this->prepareStatement('blob_delete_zero')->execute([$hash]);
        @unlink($this->blobPath($hash));
        return true;
    }
    /**
     * Reads the bytes of the blob identified by $hash, or
     * returns false if the blob is missing (a bug rather
     * than an expected condition once mail_blobs is the
     * authoritative refcount).
     * @param mixed $hash hash parameter
     * @return string|false raw blob bytes, or false if the content-id is unknown
     */
    protected function blobRead($hash)
    {
        $eml_path = $this->blobPath($hash);
        if (!is_file($eml_path)) {
            return false;
        }
        return @file_get_contents($eml_path);
    }
    /**
     * Reads up to $max bytes from the head of a content-
     * addressed blob. Used by messageHeaderBytes to avoid
     * reading the full body when the caller only needs the
     * header block.
     *
     * @param string $hash content hash identifying the blob
     * @param int $max maximum bytes to read from the head
     * @return string|false the prefix bytes, or false on I/O
     *      error or unknown hash
     */
    protected function blobReadPrefix($hash, $max)
    {
        $eml_path = $this->blobPath($hash);
        if (!is_readable($eml_path)) {
            return false;
        }
        $fh = fopen($eml_path, 'rb');
        if ($fh === false) {
            return false;
        }
        $chunk = fread($fh, $max);
        fclose($fh);
        return $chunk;
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
class MailSite implements MailVocabulary
{
    /* indices into the in_streams / out_streams parallel arrays */
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    /**
     * Maximum nesting depth for recursive MIME multipart parsing.
     * A well-formed message nests a few levels at most (for
     * example multipart/mixed wrapping multipart/alternative
     * wrapping text and html); this bound still stops a malformed
     * or hostile message whose parts keep declaring themselves
     * multipart from recursing without limit and exhausting
     * memory.
     */
    const MAX_MIME_DEPTH = 20;
    /**
     * Largest body, in bytes, that is split into its multipart
     * parts for BODYSTRUCTURE. A multipart body larger than this
     * (typically a message dominated by a big base64 attachment)
     * is left as a single part rather than parsed apart, because
     * the string-copying parser would peak at several times the
     * body size and could exhaust memory on a large message. A
     * client fetching BODYSTRUCTURE then sees a single-part
     * structure, which is acceptable, and can still fetch the
     * whole body; the cap is well above ordinary mail.
     */
    const MAX_STRUCTURE_PARSE_BYTES = 8388608;
    /**
     * When a FETCH response loop has queued at least this many
     * bytes for a connection, the loop drains the write buffer to
     * the socket before fetching the next message. Without this a
     * range fetch (e.g. "1:* BODY[]") over a large mailbox would
     * buffer every message at once and exhaust memory; the flush
     * bounds resident memory to roughly one message plus this
     * threshold. The unit is bytes.
     */
    const FETCH_FLUSH_THRESHOLD = 4194304;
    const CONTEXT = 3;
    /** @var Authenticator */
    protected $authenticator;
    /**
     * Optional callback that maps an alias local-part to the
     * username of the Yioop user who owns it, or returns an empty
     * string when the local-part is not a registered alias. It is
     * injected (rather than the atto-namespace MailSite reaching
     * into a Yioop model directly) so this server stays usable in
     * the standalone atto project where mail aliases do not exist.
     * @var callable|null
     */
    protected $alias_resolver;
    /** @var MailStorage */
    protected $mail_storage;
    /** @var array hook callbacks keyed by stage */
    protected $hooks = [
        'banner' => [], 'connect' => [], 'helo' => [],
        'mailfrom' => [], 'rcptto' => [], 'header' => [],
        'message' => [], 'secure' => [], 'outbound' => [],
        'log' => [],
    ];
    /** @var array list of locally hosted domains */
    protected $local_domains = ['localhost'];
    /** @var array */
    protected $default_server_globals;
    /** @var array */
    protected $immortal_stream_keys = [];
    /** @var array */
    protected $in_streams = [];
    /**
     * In-progress non-blocking TLS handshakes, keyed by stream
     * key. Each entry is an array with 'mode'
     * ('implicit'|'starttls'), 'protocol', 'remote_addr',
     * 'remote_port', 'listener' (the accept listener record, for
     * implicit handshakes that still need their banner once TLS is
     * up), and 'deadline' (a microtime float after which a stalled
     * handshake is abandoned). A key present here is mid-handshake
     * and is driven a step at a time by driveHandshake on each
     * select wake rather than blocking the loop.
     * @var array
     */
    protected $handshakes = [];
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
     * @param mixed $authenticator authenticator parameter
     * @return Authenticator currently installed authenticator
     */
    public function auth(Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
    /**
     * Sets the callback that resolves an alias local-part to the
     * owning user's mailbox username. The callback receives the
     * lowercased local-part and should return the owner's username
     * (a non-empty string) or an empty string when the local-part
     * is not a registered alias. When no resolver is installed,
     * aliases are simply not recognized, matching the behavior of
     * the standalone atto project.
     * @param callable $alias_resolver alias-to-owner lookup
     * @return MailSite this instance, for chaining
     */
    public function aliasResolver(callable $alias_resolver)
    {
        $this->alias_resolver = $alias_resolver;
        return $this;
    }
    /**
     * Sets the storage backend used by both protocols and by
     * the direct-call public API.
     * @param mixed $storage storage parameter
     * @return MailStorage currently installed mail storage backend
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
     * @param callable $callback callback to invoke
     * @return bool false to suppress emission of the banner; true to send it
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
     * @param callable $callback callback to invoke
     * @return bool false to immediately drop the connection; true to accept
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
     * @param callable $callback callback to invoke
     * @return bool false to reject HELO/EHLO; true to accept
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
     * @param callable $callback callback to invoke
     * @return bool false to reject MAIL FROM; true to accept
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
     * @param callable $callback callback to invoke
     * @return bool false to reject RCPT TO; true to accept
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
     * @param callable $callback callback to invoke
     * @return bool false to reject the message during header phase; true to continue
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
     * @param callable $callback callback to invoke
     * @return bool false to reject the delivered message; true to accept
     */
    public function onMessage(callable $callback)
    {
        $this->hooks['message'][] = $callback;
        return $this;
    }
    /**
     * Registers the callback that receives MailSite log events.
     * The callback is passed a single already-formatted message
     * string. Multiple callbacks may be registered; each is
     * invoked in registration order for every event. Embedding
     * daemons use this to forward events into their own logging
     * without MailSite reaching across namespaces to call a
     * logger directly.
     *
     * @param callable $callback receives one string argument
     * @return self this, for chaining
     */
    public function onLog(callable $callback)
    {
        $this->hooks['log'][] = $callback;
        return $this;
    }
    /**
     * Sends a message to every registered log callback; a no-op
     * when none are registered. MailSite uses this rather than
     * any external logger so the atto-namespace class stays free
     * of Yioop-specific code.
     *
     * @param string $message the text to log
     * @return void
     */
    protected function emitLog($message)
    {
        foreach ($this->hooks['log'] as $callback) {
            $callback($message);
        }
    }
    /**
     * Registers a callback invoked at the end of a DATA command
     * for each recipient that is remote (not a local mailbox) on
     * an authenticated session whose envelope sender is a local
     * domain. $info has 'from' (envelope MAIL FROM), 'recipients'
     * (a list of the remote recipient addresses), and 'bytes' (the
     * complete RFC 5322 message). The callback is expected to queue
     * the message for background outbound delivery; its return
     * value is ignored. Outbound delivery is not done inside the
     * server itself because the atto-namespace MailSite must stay
     * free of Yioop-specific delivery and DNS code, which lives in
     * the factory that registers this callback.
     * @param callable $callback callback to invoke
     * @return object this MailSite, for chaining
     */
    public function onOutbound(callable $callback)
    {
        $this->hooks['outbound'][] = $callback;
        return $this;
    }
    /**
     * Registers a callback to run after a TLS handshake attempt,
     * for either an implicit-TLS connection or a STARTTLS upgrade.
     * $info has 'remote_addr', 'remote_port', 'protocol'
     * ('SMTP'|'IMAP'), 'mode' ('implicit'|'starttls'), 'ok'
     * (bool), and 'error' (string, the handshake error when ok is
     * false, otherwise ''). Purely observational: the return value
     * is ignored, so a logging hook cannot disturb the session.
     * @param callable $callback callback to invoke
     * @return object this MailSite, for chaining
     */
    public function onSecure(callable $callback)
    {
        $this->hooks['secure'][] = $callback;
        return $this;
    }
    /**
     * Runs all hooks for $stage in registration order. Returns
     * the first non-null verdict, or null if every hook returned
     * null/true. Hooks that throw are caught and treated as if
     * they returned null so a buggy filter cannot kill the loop.
     * @param mixed $stage stage parameter
     * @param mixed $info info parameter
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return bool true if every hook returned true; false if any returned false
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
     * @param mixed $domains domains parameter
     * @return array list of configured mail domain names
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
     * the configured filter as the SMTP path would. Entry
     * point for non-SMTP ingestion (webmail "Save Draft", CLI
     * import, HTTP webhook from a transactional sender). The
     * recipient must be a local user; no outbound queueing.
     *
     * @param string $from RFC 5321 reverse-path (envelope sender)
     * @param string $to one envelope recipient (call once per
     *      recipient for multi-recipient delivery)
     * @param string $bytes the full RFC 5322 message
     * @param array $context optional context array passed to
     *      the onMessage hook
     * @return int|false UID of the delivered message, or false
     *      on hook-drop, hook-reject, or unknown recipient
     */
    public function deliverMail($from, $to, $bytes, $context = [])
    {
        $local = $this->resolveLocalUser($to);
        if ($local === false) {
            return false;
        }
        $folder = self::FOLDER_INBOX;
        $flags = [self::FLAG_RECENT];
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
        if ($to !== '') {
            $bytes = "Delivered-To: $to\r\n" . $bytes;
        }
        /* Record the envelope sender (the SMTP MAIL FROM reverse
           path) as a Return-Path header, as the final delivery
           server is meant to under RFC 5321 section 4.4. An empty
           reverse path (a bounce or DSN) is written as <> per the
           standard. This preserves who actually sent the message,
           which the From header need not match, so later features
           such as trusting a sender act on the real envelope
           address the spam routing keyed on. */
        $return_path = ($from === "") ? "<>" : "<$from>";
        $bytes = "Return-Path: $return_path\r\n" . $bytes;
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
     * @param string $user username (no @domain) identifying the mail account
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
     * @param string $user username (no @domain) identifying the mail account
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $old current folder name to rename from
     * @param string $new target folder name to rename to
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return string|false the bytes, or false if not found
     */
    public function fetchMessage($user, $folder, $uid)
    {
        return $this->mail_storage->fetchMessage($user, $folder,
            $uid);
    }
    /**
     * Returns the raw RFC 5322 header block of a message,
     * stopping at the first blank line. Faster than fetchMessage
     * for callers that need only Subject / From / Date /
     * Delivered-To; the backend may read up to
     * MailStorage::MAX_HEADER_BYTES to find the terminator,
     * which is well above any real-world header size.
     *
     * @param string $user username (no @domain)
     * @param string $folder full folder path
     * @param int $uid persistent IMAP UID
     * @return string|false header block, or false if not found
     */
    public function messageHeaderBytes($user, $folder, $uid)
    {
        return $this->mail_storage->messageHeaderBytes($user,
            $folder, $uid);
    }
    /**
     * Returns metadata describing where the body bytes for
     * (user, folder, uid) physically live. See
     * MailStorage::messageBodyLocation for the return shape.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return array|false metadata record describing where the body bytes live, or false if (user, folder, uid) does not resolve to a stored message
     */
    public function messageBodyLocation($user, $folder, $uid)
    {
        return $this->mail_storage->messageBodyLocation(
            $user, $folder, $uid);
    }
    /**
     * Returns metadata records for every message in a folder,
     * sorted ascending by UID. Each record is an associative
     * array with keys uid (int), size (int), flags (array of
     * strings), internal_date (Unix timestamp). This is the
     * direct-call shape a webmail message-list view consumes.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return array list of metadata records
     */
    public function listMessages($user, $folder)
    {
        return $this->mail_storage->listMessages($user, $folder);
    }
    /**
     * Returns the uids in a folder whose subject, from, or to
     * header contains the query string (case-insensitive),
     * delegating to the configured storage's search index.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param string $query substring to match against subject/from/to
     * @return array list of matching uids present in the folder
     */
    public function searchMessages($user, $folder, $query)
    {
        return $this->mail_storage->searchMessages($user, $folder,
            $query);
    }
    /**
     * Returns the metadata record for a single message, with
     * the same shape as one entry of listMessages.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @return array|false metadata record (uid, size, flags, internal_date), or false if the message does not exist
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param int $uid persistent IMAP unique identifier of the message
     * @param array $flags list of IMAP flag strings to set on the message
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @param array $uid_restriction when non-null, only deleted
     *      messages whose UID is in this list are removed (UID
     *      EXPUNGE, RFC 4315); when null every deleted message is
     *      removed (plain EXPUNGE)
     * @return array list of expunged UIDs
     */
    public function expunge($user, $folder, $uid_restriction = null)
    {
        $removed = $this->mail_storage->expunge($user, $folder,
            $uid_restriction);
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $from source folder
     * @param string $to destination folder
     * @param int $uid persistent IMAP unique identifier of the message
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int number of messages currently in the folder, or -1 if the folder is unknown
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return bool true if the named folder exists under $user, false otherwise
     */
    public function folderExists($user, $folder)
    {
        return $this->mail_storage->folderExists($user, $folder);
    }
    /**
     * Returns the UID that will be assigned to the next
     * message appended to this folder. Direct-call equivalent
     * of the IMAP UIDNEXT response from SELECT/STATUS; useful
     * for webmail UIs detecting new mail by comparing against
     * a cached high-water mark. Under concurrent appends the
     * actual UID handed out may be larger by the time the
     * caller acts on it.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int next UID that will be assigned for an appended message in the folder
     */
    public function uidNext($user, $folder)
    {
        return $this->mail_storage->uidNext($user, $folder);
    }
    /**
     * Returns the UIDVALIDITY value for a folder. IMAP
     * clients compare this against their cached value to
     * decide whether their UID cache is still valid; a
     * change forces resync. UIDVALIDITY is stamped per
     * folder at create time, so deleting and recreating a
     * folder hands out a fresh value.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int fixed UIDVALIDITY value for the folder per RFC 3501 sec 2.3.1.1
     */
    public function uidValidity($user, $folder)
    {
        return $this->mail_storage->uidValidity($user, $folder);
    }
    /**
     * Increments the per-folder change counter that drives
     * IDLE push notifications. Called after any storage
     * operation that changes a folder's visible state. In-
     * memory and per-process; persistence isn't needed
     * because IDLE subscribers only care about deltas during
     * the idle window.
     *
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path (e.g. "Archive/2026")
     * @return int monotonic counter incremented on each storage change, used by IMAP IDLE to detect changes
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
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; IDLE state for the session is reset
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
     * A local-part that is not itself a user but is a registered
     * alias resolves to the alias owner's mailbox username, so a
     * message to chris@domain lands in cpollett's mailbox when
     * "chris" is an alias owned by cpollett. The original
     * recipient address is preserved by deliverMail in the
     * Delivered-To header, so a reply can still default to the
     * alias the sender used.
     * @param string $address address
     * @return string|false local username if the address resolves to a local mailbox, false otherwise
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
        if ($this->authenticator->userExists($local_lc)) {
            return $local_lc;
        }
        if ($this->alias_resolver !== null) {
            $owner = (string) call_user_func($this->alias_resolver,
                $local_lc, $domain);
            if ($owner !== '') {
                return strtolower($owner);
            }
        }
        return false;
    }
    /**
     * Schedules a callable to fire after $time seconds. If
     * $repeating is true (default) the callable fires every
     * $time seconds; if false, just once. Returns an opaque
     * timer id that can be passed to clearTimer.
     * @param int $time Unix timestamp
     * @param callable $callback callback to invoke
     * @param mixed $repeating repeating parameter
     * @return string opaque timer id usable with clearTimer
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
     * @param string $id timer identifier returned by setTimer
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
     * @param array $config configuration overrides
     * @return void no return; the event loop runs until the process is killed or a fatal listener error
     */
    public function listen($config = [])
    {
        $defaults = [
            'SMTP_PORT' => 2525,
            'SUBMISSION_PORT' => 0,
            'IMAP_PORT' => 1143,
            'SMTPS_PORT' => 0,
            'IMAPS_PORT' => 0,
            'BIND' => '0.0.0.0',
            'SERVER_NAME' => 'localhost',
            'SERVER_SOFTWARE' => 'AttoMail',
            'CONNECTION_TIMEOUT' => 30 * 60,
            'TLS_HANDSHAKE_TIMEOUT' => 10,
            'MAX_COMMAND_LEN' => 2048,
            'MAX_MESSAGE_LEN' => 25 * 1024 * 1024,
            /*
                Accept AUTH PLAIN/LOGIN before TLS. Default
                false; flip on for loopback dev where there
                is no eavesdropper.
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
        /*
            bindOne() opens a TCP listener, registers it,
            and returns the stream resource. Null return
            means the bind failed; required listeners
            (plaintext SMTP/IMAP) treat that as fatal,
            optional ones (implicit-TLS variants) warn and
            continue.
         */
        $bindOne = function ($port_key, $protocol, $tls_implicit,
            $label) use (
            $bind, &$listeners, &$listener_streams, &$announce
        ) {
            if (empty($this->default_server_globals[$port_key])) {
                return null;
            }
            $address = "tcp://$bind:" .
                $this->default_server_globals[$port_key];
            $stream = @stream_socket_server($address,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
            if (!$stream) {
                echo "Failed to bind $label $address: $errstr\n";
                return null;
            }
            stream_set_blocking($stream, 0);
            $listeners[(int) $stream] = [
                'protocol' => $protocol,
                'tls_implicit' => $tls_implicit,
            ];
            $listener_streams[(int) $stream] = $stream;
            $suffix = $tls_implicit ? " (implicit TLS)" : "";
            $announce[] = "$label at $address$suffix";
            return $stream;
        };
        /* plaintext SMTP and IMAP are required */
        $smtp = $bindOne('SMTP_PORT', 'SMTP', false, 'SMTP');
        if (!$smtp) {
            return false;
        }
        $imap = $bindOne('IMAP_PORT', 'IMAP', false, 'IMAP');
        if (!$imap) {
            fclose($smtp);
            return false;
        }
        /* submission (conventionally 587) is an optional second
           plaintext SMTP listener that upgrades with STARTTLS; it
           shares the SMTP handling and the plaintext-auth gate, so
           a client must STARTTLS before AUTH unless plaintext auth
           is allowed. */
        $bindOne('SUBMISSION_PORT', 'SMTP', false, 'SUBMISSION');
        /* implicit-TLS sockets are optional and require ssl */
        if ($tls_available) {
            $bindOne('SMTPS_PORT', 'SMTP', true, 'SMTPS');
            $bindOne('IMAPS_PORT', 'IMAP', true, 'IMAPS');
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
                A socket mid TLS handshake stays in the read set
                (via in_streams) and is driven when the peer sends
                its next handshake record. It is deliberately not
                added to the write set: a connected socket is almost
                always writable, so watching a pending handshake for
                write readiness makes stream_select return at once on
                every iteration and the loop spins at full CPU for as
                long as any handshake is outstanding. The crypto step
                returning "would block" is waiting to read the peer's
                next record, so read readiness is the correct wake
                condition; a stalled handshake is bounded by its
                deadline in cullDeadStreams.
             */
            /*
                Cap select timeout at 5s so the loop wakes
                regularly. IDLE pushes happen post-select, so
                a long sleep would delay "* N EXISTS"
                notifications by that long.
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
                $driven = [];
                foreach ($reads as $stream) {
                    $key = (int) $stream;
                    if (isset($this->handshakes[$key])) {
                        $driven[$key] = true;
                    }
                }
                foreach ($writes as $stream) {
                    $key = (int) $stream;
                    if (isset($this->handshakes[$key])) {
                        $driven[$key] = true;
                    }
                }
                foreach (array_keys($driven) as $key) {
                    $this->driveHandshake($key);
                }
                foreach ($reads as $stream) {
                    $key = (int) $stream;
                    if (isset($driven[$key])) {
                        continue;
                    }
                    if (isset($listeners[$key])) {
                        $this->acceptConnection($stream,
                            $listeners[$key]);
                    } else {
                        $this->readClient($stream);
                    }
                }
                foreach ($writes as $stream) {
                    $key = (int) $stream;
                    if (isset($driven[$key])) {
                        continue;
                    }
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
     * @param mixed $server server parameter
     * @param mixed $listener listener parameter
     * @return void no return; the new connection is registered in $this->in_streams
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
        if (!empty($listener['tls_implicit'])) {
            /*
                Implicit TLS: the client is waiting for a TLS
                ServerHello, so we MUST NOT queue a plaintext
                banner. Start the handshake non-blocking and let
                the select loop drive it; completeAccept runs once
                TLS is up. A plaintext fallback banner is never
                sent on these ports.
             */
            $this->beginHandshake($connection, $key, 'implicit',
                $protocol, $remote_addr, $remote_port, $listener);
            return;
        }
        $this->completeAccept($connection, $key, $protocol,
            $remote_addr, $remote_port, false);
    }
    /**
     * Finishes setting up an accepted connection once it is ready
     * for protocol traffic: registers it in the stream tables,
     * builds its session context, fires the connect and banner
     * hooks, and queues the greeting banner. Reached directly for
     * a plaintext accept, or from the handshake driver once an
     * implicit-TLS connection has completed its handshake.
     * @param resource $connection open connection resource
     * @param int $key stream key for $connection
     * @param string $protocol 'SMTP' or 'IMAP'
     * @param string $remote_addr client address
     * @param int $remote_port client port
     * @param bool $tls_active whether the connection is already
     *      wrapped in TLS
     * @return void
     */
    protected function completeAccept($connection, $key, $protocol,
        $remote_addr, $remote_port, $tls_active)
    {
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
            'HELO' => null,
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
     * @param mixed $tls_active tls_active parameter
     * @return string CAPABILITY response string appropriate to the current TLS / auth state
     */
    protected function imapPreAuthCapabilities($tls_active)
    {
        $parts = ['CAPABILITY', 'IMAP4rev1', 'IDLE',
            'NAMESPACE', 'ID', 'SPECIAL-USE',
            'CREATE-SPECIAL-USE', 'MOVE', 'UIDPLUS'];
        $allow_plain = $this->allowsPlaintextAuth();
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
     * Prepares a just-accepted (or STARTTLS-upgrading) socket for
     * a non-blocking TLS handshake: copies the configured SSL
     * context options onto the stream. The handshake itself is
     * driven in steps by stepCrypto from the select loop, so this
     * never blocks. Returns false (and sets the error) when no
     * certificate is configured.
     * @param resource $connection open connection resource
     * @param string $handshake_error set to the reason on failure
     * @return bool true if crypto options were applied
     */
    protected function prepareCrypto($connection, &$handshake_error = '')
    {
        $handshake_error = '';
        if (empty($this->server_context_array['ssl'])) {
            $handshake_error = 'no server certificate configured';
            return false;
        }
        foreach ($this->server_context_array['ssl']
            as $option_name => $option_value) {
            stream_context_set_option($connection, 'ssl',
                $option_name, $option_value);
        }
        return true;
    }
    /**
     * The TLS crypto method bitmask the server offers: the generic
     * TLS server method plus the 1.2 and 1.3 variants when the
     * build defines them.
     * @return int crypto method flags for stream_socket_enable_crypto
     */
    protected function cryptoMethod()
    {
        $method = STREAM_CRYPTO_METHOD_TLS_SERVER;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
        }
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
        }
        return $method;
    }
    /**
     * Runs one non-blocking step of the server-side TLS handshake.
     * The socket stays non-blocking so the call returns at once:
     * true when the handshake has completed, false when it has
     * failed, and 0 when it needs more socket I/O and should be
     * retried on a later select wake. Wraps the call in a scoped
     * error handler so the SSL error text can be attributed to
     * this step (error_get_last alone is process-wide and
     * unreliable).
     * @param resource $connection open connection resource
     * @param string $handshake_error set to the SSL error text
     *      when the step fails
     * @return bool|int true done, false failed, 0 needs more I/O
     */
    protected function stepCrypto($connection, &$handshake_error = '')
    {
        $handshake_error = '';
        $error = null;
        set_error_handler(
            function ($errno, $errstr) use (&$error) {
                $error = $errstr;
                return true;
            });
        $result = @stream_socket_enable_crypto($connection, true,
            $this->cryptoMethod());
        restore_error_handler();
        if ($result === true) {
            return true;
        }
        if ($result === 0) {
            return 0;
        }
        if ($error !== null) {
            $handshake_error = $error;
        } else {
            $handshake_error = 'handshake failed';
        }
        return false;
    }
    /**
     * Starts a non-blocking TLS handshake on a socket and registers
     * it in the handshakes table so the select loop can drive it a
     * step at a time. Used for both an implicit-TLS accept (the
     * $listener record is carried so completeAccept can queue the
     * banner once TLS is up) and a STARTTLS upgrade (no listener;
     * the session context already exists). Attempts the first
     * crypto step immediately; if that already resolves the
     * handshake, finishes right away rather than waiting for the
     * next wake.
     * @param resource $connection open connection resource
     * @param int $key stream key for $connection
     * @param string $mode 'implicit' or 'starttls'
     * @param string $protocol 'SMTP' or 'IMAP'
     * @param string $remote_addr client address
     * @param int $remote_port client port
     * @param array|null $listener accept listener record for an
     *      implicit handshake, or null for a STARTTLS upgrade
     * @return void
     */
    protected function beginHandshake($connection, $key, $mode,
        $protocol, $remote_addr, $remote_port, $listener = null)
    {
        $handshake_error = '';
        if (!$this->prepareCrypto($connection, $handshake_error)) {
            $this->runHooks('secure', [
                'remote_addr' => $remote_addr,
                'remote_port' => $remote_port,
                'protocol' => $protocol,
                'mode' => $mode,
                'ok' => false,
                'error' => $handshake_error,
            ], []);
            if ($mode === 'starttls') {
                $this->shutdownStream($key);
            } else {
                @fclose($connection);
            }
            return;
        }
        $timeout = (int) ($this->default_server_globals[
            'TLS_HANDSHAKE_TIMEOUT'] ?? 10);
        if ($timeout < 1) {
            $timeout = 1;
        }
        $this->handshakes[$key] = [
            'mode' => $mode,
            'protocol' => $protocol,
            'remote_addr' => $remote_addr,
            'remote_port' => $remote_port,
            'listener' => $listener,
            'deadline' => microtime(true) + $timeout,
        ];
        /*
            An implicit-TLS socket is not yet in the stream tables
            (completeAccept adds it once TLS is up), but it must be
            selectable so the loop wakes to drive the handshake, so
            register its connection slot now. A STARTTLS socket is
            already registered from its plaintext phase.
         */
        if ($mode === 'implicit') {
            $this->in_streams[self::CONNECTION][$key] = $connection;
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
        }
        $this->driveHandshake($key);
    }
    /**
     * Drives one step of an in-progress TLS handshake for the
     * given stream key, then dispatches on the outcome: a
     * completed handshake finishes the connection (queues the
     * banner for an implicit accept, or resets an upgraded session
     * to its post-STARTTLS INIT state), a failed handshake logs
     * and tears down, and a handshake that needs more I/O is left
     * registered for the next select wake. Called from the select
     * loop whenever a handshaking socket is readable or writable.
     * @param int $key stream key of the handshaking socket
     * @return void
     */
    protected function driveHandshake($key)
    {
        if (!isset($this->handshakes[$key]) ||
            !isset($this->in_streams[self::CONNECTION][$key])) {
            unset($this->handshakes[$key]);
            return;
        }
        $connection = $this->in_streams[self::CONNECTION][$key];
        $handshake_error = '';
        $result = $this->stepCrypto($connection, $handshake_error);
        if ($result === 0) {
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
            return;
        }
        $info = $this->handshakes[$key];
        $secure_info = [
            'remote_addr' => $info['remote_addr'],
            'remote_port' => $info['remote_port'],
            'protocol' => $info['protocol'],
            'mode' => $info['mode'],
            'ok' => ($result === true),
            'error' => ($result === true) ? '' : $handshake_error,
        ];
        unset($this->handshakes[$key]);
        if ($result !== true) {
            if ($info['mode'] === 'starttls') {
                $this->runHooks('secure', $secure_info,
                    $this->in_streams[self::CONTEXT][$key] ?? []);
                $this->shutdownStream($key);
            } else {
                $this->runHooks('secure', $secure_info, []);
                @fclose($connection);
                unset($this->in_streams[self::CONNECTION][$key]);
                unset($this->in_streams[self::MODIFIED_TIME][$key]);
            }
            return;
        }
        if ($info['mode'] === 'implicit') {
            $this->runHooks('secure', $secure_info, []);
            $this->completeAccept($connection, $key,
                $info['protocol'], $info['remote_addr'],
                $info['remote_port'], true);
            return;
        }
        /* STARTTLS success: reset the existing session per RFC
           3207 sec 4.2 (client must re-EHLO; same for IMAP). */
        $context = & $this->in_streams[self::CONTEXT][$key];
        $context['TLS_ACTIVE'] = true;
        $context['STATE'] = 'INIT';
        $context['MAILFROM'] = null;
        $context['RCPTTO'] = [];
        $context['AUTH_USER'] = null;
        $context['AUTH_USERNAME'] = null;
        $this->in_streams[self::DATA][$key] = "";
        $this->runHooks('secure', $secure_info, $context);
    }
    /**
     * Appends bytes to the outbound write buffer. Allocates
     * the out_streams slot lazily on the first write. The
     * actual fwrite happens later in writeClient when the
     * select loop reports the socket writable, so handlers
     * can emit many lines without blocking.
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
     * Queues a tagged IMAP response (OK, NO, or BAD).
     * Centralizes CRLF framing. The detail text must not
     * contain CR or LF; we do no escaping because all call
     * sites supply fixed English literals.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $status status
     * @param mixed $detail detail parameter
     */
    protected function imapResp($key, $tag, $status, $detail)
    {
        $this->queueWrite($key,
            "$tag $status $detail\r\n");
    }
    /**
     * Shorthand for the "$tag OK $verb completed" reply that
     * ends most successful IMAP commands.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param mixed $verb verb parameter
     */
    protected function imapOk($key, $tag, $verb)
    {
        $this->queueWrite($key,
            "$tag OK $verb completed\r\n");
    }
    /**
     * Returns true if the server is configured to accept
     * AUTH PLAIN / LOGIN over a plaintext (non-TLS) channel.
     * Default false; deployments that explicitly opt in to
     * loopback-only or test setups can flip this.
     * @return bool true if plaintext AUTH (PLAIN/LOGIN) is permitted on this connection
     */
    protected function allowsPlaintextAuth()
    {
        return !empty(
            $this->default_server_globals['ALLOW_PLAINTEXT_AUTH']);
    }
    /**
     * Reads pending bytes from a client socket into the
     * inbound buffer and drains the buffer by calling
     * processOne until no more complete commands parse.
     * Closes the connection on end-of-file or a read fault
     * (for example a TLS layer error on an established secure
     * connection); a readable socket that simply has no bytes
     * ready yet is left untouched so it ages out on the idle
     * timeout rather than spinning the loop. Short reads are
     * tolerated: leftover bytes carry over to the next tick.
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
        /* select reported this socket readable. A false return
           means the read faulted (for example a TLS "bad record
           mac" on an established secure connection); an empty read
           at end-of-file means the peer closed. Either way the
           connection is finished, so close it now instead of
           leaving it perpetually readable and spinning the loop
           until the idle timeout (30 minutes) eventually reaps it. */
        if ($chunk === false || ($chunk === "" && feof($stream))) {
            $this->shutdownStream($key);
            return;
        }
        if ($chunk === "") {
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
     * @param int $key connection key in the in_streams map
     * @return bool true if one command line was processed; false if more input is needed
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
            IMAP APPEND literal: when a synchronizing literal
            is outstanding for an APPEND, the next bytes are
            the message body, not a command. Drain exactly
            'remaining' bytes regardless of CRLFs inside, then
            let the literal continuation finish the APPEND.
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
            if (str_starts_with($buffer, "\r\n")) {
                $buffer = substr($buffer, 2);
            } else if (str_starts_with($buffer, "\n")) {
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
                    Line-buffer DoS cap: drop the connection
                    if a 64 KiB buffer never produces a CRLF.
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
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; one SMTP line was processed inline
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
            $context['HELO'] = $domain;
            $name = $this->default_server_globals['SERVER_NAME'];
            $response = "250-$name Hello\r\n";
            $allow_plain = $this->allowsPlaintextAuth();
            /* Re-advertise STARTTLS only if not already in TLS */
            if (empty($context['TLS_ACTIVE']) && $this->tls_available) {
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
            if (empty($context['TLS_ACTIVE']) &&
                !$this->allowsPlaintextAuth()) {
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
     * @param int $key connection key in the in_streams map
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the STARTTLS response was queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the AUTH continuation was queued for the client
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
     * Verifies a username/password pair and updates the SMTP
     * connection state. On success: lowercased username
     * stored in AUTH_USER (storage paths are case-insensitive)
     * and 235 queued. On failure: 535 queued and AUTH_USER
     * left unset. Either way state returns to READY for
     * MAIL FROM.
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
     * @param string $line raw line received from the client
     * @param mixed $verb verb parameter
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
            Tolerated forms: <addr>, <>, bareword addr, and
            any of those followed by ESMTP parameters
            (SIZE=123, BODY=8BITMIME, etc.) which we accept
            but do not honor.
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
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the MAIL FROM response was queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the RCPT TO response was queued for the client
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
                is outbound relay. We permit it only when the
                envelope sender is one of our own domains (a local
                user sending out); we never relay on behalf of an
                external sender. Accepted remote recipients are
                tagged so DATA queues them for background MX
                delivery rather than local mailbox delivery.
             */
            if (!$this->senderDomainIsLocal($context['MAILFROM'])) {
                $this->queueWrite($key,
                    "550 5.7.1 Sender not local; relay denied\r\n");
                return;
            }
            $context['RCPTTO'][] = ['addr' => $addr,
                'user' => false, 'remote' => true];
            $context['STATE'] = 'RCPT';
            $this->queueWrite($key, "250 2.1.5 Ok\r\n");
            return;
        }
        $verdict = $this->runHooks('rcptto',
            ['to' => $addr, 'local_user' => $local_user], $context);
        if ($verdict === 'reject' || $verdict === false) {
            $this->queueWrite($key,
                "550 5.7.1 Recipient rejected\r\n");
            return;
        }
        $context['RCPTTO'][] = ['addr' => $addr,
            'user' => $local_user, 'remote' => false];
        $context['STATE'] = 'RCPT';
        $this->queueWrite($key, "250 2.1.5 Ok\r\n");
    }
    /**
     * True when an envelope sender address belongs to one of the
     * server's own local domains. Used to gate outbound relay:
     * an authenticated session may relay to remote recipients
     * only when its MAIL FROM is local, so the server never
     * relays on behalf of an external sender. A missing or
     * malformed sender is treated as not local.
     * @param string|null $address envelope MAIL FROM address
     * @return bool true when the sender's domain is local
     */
    protected function senderDomainIsLocal($address)
    {
        $address = trim((string) $address, "<> \t\r\n");
        $at = strrpos($address, '@');
        if ($at === false) {
            return false;
        }
        $domain = strtolower(substr($address, $at + 1));
        return in_array($domain, $this->local_domains);
    }
    /**
     * Drains DATA bytes from the input buffer until it sees the
     * end-of-data sentinel CRLF.CRLF (or LF.LF as a tolerated
     * variant). Returns true once one full message has been
     * consumed (caller will loop and try the next command).
     * Performs CRLF dot-unstuffing per RFC 5321 sec 4.5.2.
     * @param int $key connection key in the in_streams map
     * @param mixed $buffer buffer parameter
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return bool true if the DATA phase produced a complete message and was delivered
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
            header, so policy sees what the client sent
            unmodified.
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
        $remote_recipients = [];
        foreach ($context['RCPTTO'] as $recipient) {
            if (!empty($recipient['remote'])) {
                $remote_recipients[] = $recipient['addr'];
                continue;
            }
            $uid = $this->deliverMail($context['MAILFROM'],
                $recipient['addr'], $message, $context);
            if ($uid !== false) {
                $delivered_any = true;
            }
        }
        if (!empty($remote_recipients)) {
            /*
                Hand remote recipients to the outbound hook, which
                queues the message for background direct-MX
                delivery. Queueing succeeds locally and at once, so
                this counts as delivered for the client's reply;
                actual remote delivery (and any bounce on permanent
                failure) happens off the event loop.
             */
            $this->runHooks('outbound', [
                'from' => $context['MAILFROM'],
                'recipients' => $remote_recipients,
                'bytes' => $message,
            ], $context);
            $delivered_any = true;
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
     * @param string $message raw RFC 5322 message bytes
     * @return array list of [name, value] header pairs in document order
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
     * server name, the RFC 3848 with-protocol keyword (the S
     * suffix when the hop used TLS, the A suffix when it was
     * authenticated), and the receipt timestamp.
     * @param string $message raw RFC 5322 message bytes
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return string message with a Received: header prepended
     */
    protected function prependReceivedHeader($message, $context)
    {
        $name = $this->default_server_globals['SERVER_NAME'];
        $server_software =
            $this->default_server_globals['SERVER_SOFTWARE'];
        /* RFC 3848 with-protocol keyword: the S suffix marks a
           TLS-protected hop and the A suffix marks an
           authenticated one, so a reader (and Yioop's own
           insecure-arrival notice) can tell from the trace header
           whether this hop used TLS. */
        $secure = !empty($context['TLS_ACTIVE']);
        $authed = !empty($context['AUTH_USER']);
        if ($secure) {
            $with = $authed ? 'ESMTPSA' : 'ESMTPS';
        } else {
            $with = $authed ? 'ESMTPA' : 'ESMTP';
        }
        $now = gmdate("D, d M Y H:i:s") . " +0000";
        /*
            Defense in depth: scrub CR and LF from every
            interpolated value so a malformed
            REMOTE_ADDR/RCPT/SERVER_NAME cannot inject a fake
            header. The wire path strips them already, but a
            buggy hook mutating $context could reintroduce
            them.
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
     * handler based on the connection's IMAP STATE. State
     * machine per RFC 3501 sec 3:
     *   INIT     -- unauthenticated; LOGIN, AUTHENTICATE,
     *               STARTTLS, CAPABILITY, NOOP, LOGOUT only
     *   AUTH     -- authenticated; mailbox-level + select
     *               commands
     *   SELECTED -- authenticated + selected mailbox; adds
     *               FETCH/STORE/SEARCH/COPY/MOVE/CLOSE/etc.
     * Tags are echoed back in the tagged status response.
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; one command was processed inline
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
     */
    protected function imapCmdLogin($key, $tag, $arguments, &$context)
    {
        if (empty($context['TLS_ACTIVE']) &&
            !$this->allowsPlaintextAuth()) {
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $user username (no @domain) identifying the mail account
     * @param mixed $pass pass parameter
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the login response was queued for the client
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
        $this->mail_storage?->ensureUser($context['AUTH_USER']);
        $consolidations = $this->mail_storage?->ensureStandardFolders(
            $context['AUTH_USER']) ?? [];
        foreach ($consolidations as $consolidation) {
            $outcome = $consolidation['deleted'] ?
                "and removed \"" . $consolidation['from'] . "\"" :
                "but kept \"" . $consolidation['from'] . "\" (" .
                $consolidation['failed'] . " could not be copied)";
            $this->emitLog("MailSite consolidated " .
                $consolidation['moved'] . " message(s) from \"" .
                $consolidation['from'] . "\" into \"" .
                $consolidation['into'] . "\" " . $outcome .
                " for user " . $context['AUTH_USER']);
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
     */
    protected function imapCmdAuthenticate($key, $tag, $arguments, &$context)
    {
        if (empty($context['TLS_ACTIVE']) &&
            !$this->allowsPlaintextAuth()) {
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
     * @param int $key connection key in the in_streams map
     * @param string $line raw line received from the client
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return bool true if the literal was fully consumed and the command was dispatched
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
                LOGIN literals are accepted as a fall-back;
                production clients send LOGIN with quoted
                strings. We do not currently chain a second
                literal for the password.
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
                RFC 2177: client sends "DONE" alone on a line
                to terminate. Empty lines are tolerated;
                anything else gets BAD and ends the IDLE.
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
     * list of [type, value] pairs. Types:
     *   'atom'    -- bare unquoted token
     *   'quoted'  -- between double-quotes, backslash escapes
     *                " and \
     *   'literal' -- {N} synchronizing literal; value is the
     *                byte count; bytes arrive on the next
     *                line and are reassembled by the caller
     *                via continueImapLiteral
     * NIL decodes as an atom with value "NIL". Whitespace
     * between tokens is consumed. Returns an empty array on
     * a parse error; caller should treat that as BAD syntax.
     * @param mixed $s s parameter
     * @return array list of parsed IMAP tokens (strings, literals, paren-lists)
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
                    Parenthesized list: keep contents as one
                    'list' token. Nested lists flatten into
                    the outer paren count, which is fine
                    because all our list uses (STATUS items,
                    SEARCH keys, etc.) are flat.
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
     * @param mixed $tokens tokens parameter
     * @param mixed $index index parameter
     * @return string IMAP wire representation of the token value (quoted, literal, or atom)
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
     * where reference is usually "" and the pattern can
     * include "*" (any chars) or "%" (any chars except
     * hierarchy delimiter). Two special cases per RFC 3501
     * sec 6.3.8:
     *   - empty mailbox argument: returns hierarchy
     *     delimiter and root (delimiter discovery)
     *   - "%" with empty reference: returns top-level folders
     * RFC 5258 selection options before the reference (e.g.
     * "LIST (SPECIAL-USE) ...") are accepted but not filtered;
     * special-use attributes appear in the response either
     * way.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $is_lsub is_lsub parameter
     * @return void no return; the response is queued for the client
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
                if ($args_trimmed[$i] === '(') {
                    $depth++;
                } else if ($args_trimmed[$i] === ')') {
                    $depth--;
                }
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
        if (!in_array(self::FOLDER_INBOX, $folders, true)) {
            $folders[] = self::FOLDER_INBOX;
            sort($folders);
        }
        if ($is_lsub) {
            /*
                LSUB filters to the subscribed set (RFC 3501
                sec 6.3.9; INBOX is implicitly subscribed).
                We intersect with the existing-folders list
                so LSUB does not advertise stale folders.
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
     *   1. Children (RFC 3348): \HasChildren or
     *      \HasNoChildren based on prefix match against
     *      $all_folders.
     *   2. Special-use (RFC 6154): \Drafts, \Sent, \Trash,
     *      \Junk, \Archive, \All. INBOX is excluded; RFC 6154
     *      reserves special-use flags for non-INBOX folders.
     * Space-separated; may be empty.
     * @param string $folder folder name with full hierarchy path
     * @param mixed $all_folders all_folders parameter
     * @return string space-separated IMAP folder attribute list
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
     * @param string $folder folder name with full hierarchy path
     * @return string IMAP SPECIAL-USE attribute (\\Trash, \\Sent, ...) or empty string
     */
    protected function imapSpecialUseAttr($folder)
    {
        if (str_contains($folder, '/')) {
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
     * @param string $pattern pattern string
     * @return string regex equivalent of the IMAP LIST pattern (% / * wildcards)
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
     * @param string $name name
     * @return string IMAP mailbox name in the wire-format encoding
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param mixed $verb verb parameter
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array folder statistics record (counts, uid info)
     */
    protected function imapFolderStats($user, $folder)
    {
        $messages = $this->mail_storage->listMessages($user,
            $folder);
        $count = count($messages);
        $recent = 0;
        $unseen_uid = 0;
        $first_unseen_seq = 0;
        foreach ($messages as $index => $message) {
            if (in_array(self::FLAG_RECENT, $message['flags'],
                true)) {
                $recent++;
            }
            if ($first_unseen_seq === 0 &&
                !in_array(self::FLAG_SEEN, $message['flags'],
                true)) {
                $first_unseen_seq = $index + 1;
                $unseen_uid = $message['uid'];
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
        /*
            A DELETE for a folder that is already gone leaves the
            mailbox in exactly the state the client asked for, so
            we answer OK rather than NO. This lets a client clear
            a stale folder from its local cache (e.g. Apple Mail
            removing a phantom "Deleted Messages") without the
            server reporting a hard error for a no-op.
         */
        if (!$this->mail_storage->folderExists($user, $name)) {
            $this->imapOk($key, $tag, "DELETE");
            return;
        }
        if (!$this->mail_storage->deleteFolder($user, $name)) {
            $this->emitLog("MailSite refused DELETE of folder \"" .
                $name . "\" for user " . $user .
                " (INBOX, has subfolders, or I/O error)");
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $is_examine is_examine parameter
     * @return void no return; the response is queued for the client
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
        $flags = self::FLAG_ANSWERED . " " .
            self::FLAG_FLAGGED . " " . self::FLAG_DELETED . " " .
            self::FLAG_SEEN . " " . self::FLAG_DRAFT;
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
     * state. RFC 3501 sec 6.4.2 specifies that CLOSE also
     * silently expunges \Deleted messages; this implementation
     * does not auto-expunge on CLOSE -- callers wanting that
     * behavior should issue EXPUNGE before CLOSE. Mainstream
     * clients (Thunderbird, Outlook, mutt) issue an explicit
     * EXPUNGE either way, so the deviation is rarely visible.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * MOVE, SEARCH, and EXPUNGE. RFC 3501 sec 6.4.8 and RFC
     * 4315: same argument syntax as the non-UID forms, but the
     * message-set numbers are interpreted as UIDs. We dispatch
     * to the same handlers with a by-uid flag, and the FETCH
     * responses always include the UID data item per the RFC.
     * UID EXPUNGE (RFC 4315) expunges only the deleted messages
     * whose UID is in the given set, which is how UIDPLUS
     * clients such as iOS Mail delete a single message.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
        if ($V === 'EXPUNGE') {
            $user = $context['AUTH_USER'];
            $folder = $context['SELECTED'];
            $matched = $this->imapMatchSet($user, $folder,
                trim($sub_args), true);
            $restrict_uids = [];
            foreach ($matched as $entry) {
                $restrict_uids[] = (int) $entry[1]['uid'];
            }
            $this->imapCmdExpunge($key, $tag, $context, $restrict_uids);
            return;
        }
        $this->imapResp($key, $tag, "BAD", "UID $V not supported");
    }
    /**
     * Parses an IMAP message-set string ("1", "1:5", "1:*",
     * "*", "1,3,5", "1:3,5:7") into a closure that tests
     * membership. The closure takes (sequence_number, last_seq,
     * uid, last_uid); $by_uid selects whether the sequence or
     * UID is tested. "*" expands to last_seq in by-sequence
     * mode and to last_uid in by-uid mode.
     * @param mixed $spec spec parameter
     * @param mixed $by_uid by_uid parameter
     * @return array list of integer UIDs covered by the sequence set
     */
    protected function imapParseMessageSet($spec, $by_uid)
    {
        $ranges = [];
        foreach (explode(',', $spec) as $piece) {
            $piece = trim($piece);
            if ($piece === '') {
                continue;
            }
            if (!str_contains($piece, ':')) {
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
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @param array $set set of items
     * @param mixed $by_uid by_uid parameter
     * @return bool true if the candidate is in the IMAP message set
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     * Reports whether any requested FETCH item needs the message
     * body bytes. UID, FLAGS, INTERNALDATE and RFC822.SIZE all
     * answer from the metadata record alone, so a client sync that
     * asks only for those (as Apple Mail does) can be served
     * without reading the message file off disk. Reading every
     * message body for a metadata-only fetch made an initial sync
     * of a large folder read tens of thousands of files.
     * @param array $items parsed FETCH item descriptions
     * @return bool true if at least one item requires the body
     */
    protected function fetchItemsNeedBody($items)
    {
        $body_kinds = ['RFC822', 'RFC822.HEADER', 'RFC822.TEXT',
            'ENVELOPE', 'BODY', 'BODYSTRUCTURE'];
        foreach ($items as $item) {
            if (in_array(strtoupper($item['kind']), $body_kinds,
                true)) {
                return true;
            }
        }
        return false;
    }
    /**
     * Sends a single FETCH response line for one message,
     * formatting the requested items in the order the client
     * asked for them. The $items_str is the raw paren-list
     * payload, e.g. "(FLAGS UID INTERNALDATE RFC822.SIZE
     * BODY.PEEK[HEADER.FIELDS (Date Subject)])". We parse it
     * by walking and recognizing each top-level item.
     * @param int $key connection key in the in_streams map
     * @param mixed $sequence_number sequence_number parameter
     * @param array $meta metadata record
     * @param string $body message body bytes
     * @param mixed $items_str items_str parameter
     * @param mixed $is_uid_variant is_uid_variant parameter
     * @param mixed $mark_seen mark_seen parameter
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
        /*
            Queue the response pieces directly rather than
            collecting them into an array and imploding. A
            BODY[]/RFC822 item can be the whole message (tens of
            megabytes); holding it in a parts array and then
            imploding would keep two extra full-size copies of it
            alive at once, which is what exhausted memory on large
            fetches. Appending each piece straight to the write
            buffer keeps only the single queued copy.
         */
        $this->queueWrite($key, "* $sequence_number FETCH (");
        $first = true;
        foreach ($items as $item) {
            $rendered = $this->imapRenderFetchItem($item, $meta,
                $body, $mark_seen);
            if ($rendered === null) {
                continue;
            }
            if (!$first) {
                $this->queueWrite($key, " ");
            }
            $this->queueWrite($key, $rendered);
            $first = false;
            unset($rendered);
        }
        $this->queueWrite($key, ")\r\n");
    }
    /**
     * Parses the items list of a FETCH command. Accepts both
     * the bare form ("FLAGS"), the macro shortcuts (FAST, ALL,
     * FULL), and the parenthesized list. Returns a list of
     * record arrays:
     *   ['kind' => 'BODY', 'section' => 'HEADER',
     *    'fields' => ['Subject','From'], 'raw' => 'BODY[...]',
     *    'peek' => true]
     * @param mixed $items_str items_str parameter
     * @return array list of parsed FETCH item descriptions
     */
    protected function imapParseFetchItems($items_str)
    {
        $items_str = trim($items_str);
        if ($items_str === '') {
            return [];
        }
        if ($items_str[0] === '(' &&
            str_ends_with($items_str, ')')) {
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
                if ($character === '[') {
                    $depth_b++;
                } else if ($character === ']') {
                    $depth_b--;
                } else if ($character === '(') {
                    $depth_p++;
                } else if ($character === ')') {
                    $depth_p--;
                } else if (($character === ' ' ||
                    $character === "\t") &&
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
     * @param string $token token string
     * @return array parsed FETCH item description
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
     * @param mixed $item item
     * @param array $meta metadata record
     * @param string $body message body bytes
     * @param mixed $mark_seen mark_seen parameter
     * @return string IMAP wire encoding of one FETCH item
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
            return "RFC822 " . $this->imapLiteralOf($body);
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
     * @param mixed $s s parameter
     * @return string IMAP literal-syntax encoding of the value (with {n}\r\n prefix)
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
     * @param string $body message body bytes
     * @return string serialized RFC 5322 header block
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
     * @param string $body message body bytes
     * @return string extracted text body of the message
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
     * Recognizes empty (whole message), HEADER, TEXT,
     * HEADER.FIELDS, HEADER.FIELDS.NOT, MIME, and numeric
     * MIME-part paths (e.g. "1", "2.1", "1.HEADER"). The
     * multipart tree is parsed via imapParseEntity. Out-of-
     * range or unrecognized sections fall back to the whole
     * body so clients see data rather than an empty literal.
     * @param string $body message body bytes
     * @param string $section IMAP FETCH BODY section specifier
     * @param mixed $fields fields parameter
     * @return string requested BODY[section] data
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
     * @param mixed $entity entity parameter
     * @param string $path filesystem path
     * @return mixed sub-entity of the parsed MIME tree at the requested section
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
     * @param mixed $hdr_block hdr_block parameter
     * @param mixed $fields fields parameter
     * @param mixed $invert invert parameter
     * @return string filtered subset of headers as a single bytes-string
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
     * @param string $body message body bytes
     * @return string IMAP ENVELOPE response value
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
     * @param string $message raw RFC 5322 message bytes
     * @return array parsed [name => value] header map
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
     * words separated only by whitespace are concatenated with
     * the whitespace stripped, per RFC 2047 sec 6.2. Bytes
     * outside encoded-words pass through. Unrecognized
     * charsets are left uninterpreted but still unwrapped,
     * good enough for substring searches.
     * @param string $value value
     * @return string decoded UTF-8 form of the header value
     */
    protected function imapDecodeMimeHeader($value)
    {
        if (!str_contains($value, '=?')) {
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
     * @param string $value value
     * @return string IMAP nstring response value (quoted or NIL)
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
     * @param string $value value
     * @return string IMAP envelope address-list response
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
     * @param mixed $s s parameter
     * @return array list of address records (each [display, mailbox, host])
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
     * of a message. Walks the multipart MIME tree (RFC 2046)
     * and emits the nested paren-list per RFC 3501 sec 7.4.2.
     * Clients use this to identify individual parts, their
     * types, encodings, and sizes, then fetch with
     * BODY[part-number].
     *   $kind is "BODY" or "BODYSTRUCTURE"; the latter adds
     * extension fields (md5, disposition, language, location).
     * @param string $body message body bytes
     * @param mixed $kind kind parameter
     * @return string IMAP BODYSTRUCTURE response value
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
     * @param string $bytes the entity bytes (header block plus
     *      body)
     * @param int $depth current nesting depth, used to bound
     *      recursion on pathologically nested multipart messages
     * @return array parsed MIME entity (headers + body or multipart parts)
     */
    protected function imapParseEntity($bytes, $depth = 0)
    {
        $sep_pos = strpos($bytes, "\r\n\r\n");
        if ($sep_pos === false) {
            $alternative = strpos($bytes, "\n\n");
            if ($alternative === false) {
                $header_block = $bytes;
                $body_offset = strlen($bytes);
            } else {
                $header_block = substr($bytes, 0, $alternative + 2);
                $body_offset = $alternative + 2;
            }
        } else {
            $header_block = substr($bytes, 0, $sep_pos + 4);
            $body_offset = $sep_pos + 4;
        }
        $body_size = strlen($bytes) - $body_offset;
        /* Only materialize the body as its own string when it is
           small enough to be split into parts (see the cap below).
           For a large body -- typically a big base64 attachment --
           copying it out again would roughly double the memory
           already held for $bytes and risk exhausting the limit on
           a single large message; the size and line count needed
           for BODYSTRUCTURE are computed from the original bytes
           instead, and the body string is left empty. */
        if ($body_size <= self::MAX_STRUCTURE_PARSE_BYTES) {
            $body = substr($bytes, $body_offset);
            $lines = substr_count($body, "\n");
        } else {
            $body = '';
            $lines = substr_count($bytes, "\n", $body_offset);
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
            'size' => $body_size,
            'lines' => $lines,
            'parts' => [],
        ];
        if ($type === 'multipart' &&
            isset($params['boundary'])) {
            $boundary = (string) $params['boundary'];
            if (trim($boundary) !== '' &&
                $depth < self::MAX_MIME_DEPTH &&
                $body_size <= self::MAX_STRUCTURE_PARSE_BYTES) {
                $entity['parts'] = $this->imapSplitMultipart($body,
                    $boundary, $depth + 1);
            }
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
     * @param string $body message body bytes
     * @param mixed $boundary boundary parameter
     * @param int $depth current nesting depth, propagated to the
     *      recursive parse of each part
     * @return array list of MIME part bodies split at the boundary
     */
    protected function imapSplitMultipart($body, $boundary, $depth = 0)
    {
        $delim = '--' . $boundary;
        $delim_len = strlen($delim);
        $parts = [];
        /* Scan with a moving cursor into $body rather than
           repeatedly slicing the remaining tail. Each substr of the
           whole tail would allocate a fresh copy of everything left,
           so a large message (a big attachment) would peak at many
           simultaneous multi-megabyte copies and exhaust memory.
           With an offset cursor only the individual part bytes are
           copied out, one at a time, so peak memory is proportional
           to the largest single part, not the message size times
           the part count. */
        $first = strpos($body, $delim);
        if ($first === false) {
            return [];
        }
        $pos = $first + $delim_len;
        $length = strlen($body);
        while ($pos < $length) {
            /* Eat the trailing CRLF (or bare LF) after the boundary
               line; a leading "--" here marks the closing delimiter,
               so stop. */
            if (substr_compare($body, "\r\n", $pos, 2) === 0) {
                $pos += 2;
            } else if (substr_compare($body, "\n", $pos, 1) === 0) {
                $pos += 1;
            } else if (substr_compare($body, '--', $pos, 2) === 0) {
                break;
            }
            /* Find the next boundary from the cursor, trying both
               the CRLF- and LF-prefixed forms and taking the
               earlier. */
            $next_crlf = strpos($body, "\r\n" . $delim, $pos);
            $next_lf = strpos($body, "\n" . $delim, $pos);
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
            $part_bytes = substr($body, $pos, $next - $pos);
            $parts[] = $this->imapParseEntity($part_bytes, $depth);
            /* Advance past the line ending plus the delimiter; the
               trailing-CRLF eat at the top of the loop handles the
               line ending after this delimiter. */
            $skip = ($body[$next] === "\r") ? 2 : 1;
            $pos = $next + $skip + $delim_len;
            if (substr_compare($body, '--', $pos, 2) === 0) {
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
     * @param mixed $entity entity parameter
     * @param mixed $extended extended parameter
     * @return string IMAP BODYSTRUCTURE wire string
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
     * @param mixed $params params parameter
     * @return string IMAP wire encoding of a MIME parameter list
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $by_uid by_uid parameter
     * @return void no return; the response is queued for the client
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
        $needs_body = $this->fetchItemsNeedBody(
            $this->imapParseFetchItems($items_str));
        foreach ($matched as $entry) {
            list($sequence_number, $meta) = $entry;
            /*
                Only read the message file when a requested item
                actually needs its bytes. A metadata-only fetch
                (FLAGS/UID/INTERNALDATE/RFC822.SIZE), which is what
                a client issues to sync a folder, is answered from
                the index record alone, so syncing a large folder
                no longer reads every message off disk.
             */
            if ($needs_body) {
                $body = $this->mail_storage->fetchMessage($user,
                    $folder, $meta['uid']);
                if ($body === false) {
                    continue;
                }
            } else {
                $body = "";
            }
            $mark_seen = false;
            $this->imapEmitFetch($key, $sequence_number, $meta, $body,
                $items_str, $by_uid, $mark_seen);
            unset($body);
            if (isset($this->out_streams[self::DATA][$key]) &&
                strlen($this->out_streams[self::DATA][$key]) >=
                self::FETCH_FLUSH_THRESHOLD) {
                $this->drainWriteBuffer($key);
            }
            if ($mark_seen &&
                empty($context['SELECTED_READONLY']) &&
                !in_array(self::FLAG_SEEN, $meta['flags'], true)) {
                $new_flags = $meta['flags'];
                $new_flags[] = self::FLAG_SEEN;
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $by_uid by_uid parameter
     * @return void no return; the response is queued for the client
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
            str_ends_with($flags_str, ')')) {
            $flags_str = substr($flags_str, 1, -1);
        }
        $req_flags = [];
        foreach (preg_split('/\s+/', trim($flags_str))
            as $flag) {
            if ($flag !== '') {
                $req_flags[] = $flag;
            }
        }
        $silent = (str_ends_with($operator, '.SILENT'));
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $by_uid by_uid parameter
     * @return void no return; the response is queued for the client
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $by_uid by_uid parameter
     * @return void no return; the response is queued for the client
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
     * (EXAMINE). When a UID restriction is supplied (the UID
     * EXPUNGE case, RFC 4315) only deleted messages whose UID
     * is in that list are removed, which is how a UIDPLUS
     * client deletes a single message.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param array $restrict_uids when non-null, only deleted
     *      messages whose UID is in this list are expunged; when
     *      null every deleted message in the folder is expunged
     * @return void no return; the response is queued for the client
     */
    protected function imapCmdExpunge($key, $tag, &$context,
        $restrict_uids = null)
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
            if (in_array(self::FLAG_DELETED, $meta['flags'], true)) {
                if ($restrict_uids !== null &&
                    !in_array((int) $meta['uid'], $restrict_uids, true)) {
                    continue;
                }
                $seqs_removed[] = $index + 1;
            }
        }
        $this->mail_storage->expunge($user, $folder, $restrict_uids);
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param string $arguments arguments substring following the IMAP command verb
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @param mixed $by_uid by_uid parameter
     * @return void no return; the response is queued for the client
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
     * @param mixed $s s parameter
     * @return array list of SEARCH-key tokens
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
     * @param mixed $tokens tokens parameter
     * @param array $meta metadata record
     * @param mixed $sequence_number sequence_number parameter
     * @param mixed $last_seq last_seq parameter
     * @param mixed $last_uid last_uid parameter
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return bool true if the message matches the parsed SEARCH expression
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
                Flag-presence keywords: each maps to one or
                two flag/expected-presence pairs.
             */
            static $flag_keywords = [
                'NEW' => [self::FLAG_RECENT, true, self::FLAG_SEEN, false],
                'OLD' => [self::FLAG_RECENT, false],
                'RECENT' => [self::FLAG_RECENT, true],
                'SEEN' => [self::FLAG_SEEN, true],
                'UNSEEN' => [self::FLAG_SEEN, false],
                'FLAGGED' => [self::FLAG_FLAGGED, true],
                'UNFLAGGED' => [self::FLAG_FLAGGED, false],
                'DELETED' => [self::FLAG_DELETED, true],
                'UNDELETED' => [self::FLAG_DELETED, false],
                'ANSWERED' => [self::FLAG_ANSWERED, true],
                'UNANSWERED' => [self::FLAG_ANSWERED, false],
                'DRAFT' => [self::FLAG_DRAFT, true],
                'UNDRAFT' => [self::FLAG_DRAFT, false],
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
     * open. processIdleNotifications walks the idle
     * subscribers each main-loop tick and emits untagged
     * responses for changes since IDLE began. Push set per
     * RFC 2177 / RFC 3501:
     *   * N EXISTS         -- new message added
     *   * N EXPUNGE        -- message permanently removed
     *   * N FETCH (FLAGS)  -- flag change on existing message
     * IDLE_STATE caches a per-message map and the change-
     * counter at IDLE entry so the tick-side diff is cheap
     * (no diff if counter unchanged). The client sends DONE
     * to terminate; we ack with tagged OK and clear state.
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response is queued for the client
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
     *   uids   -- ordered list of UIDs (sequence order)
     *   flags  -- map UID => sorted-and-joined flag string,
     *             so a flag change shows up as a string
     *             change without deep array compare
     *   count  -- number of messages, kept separate so the
     *             EXISTS push can use it without rewalking
     * @param string $user username (no @domain) identifying the mail account
     * @param string $folder folder name with full hierarchy path
     * @return array snapshot of folder counters and uids used by IMAP IDLE notifications
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
     * @param int $key connection key in the in_streams map
     * @param string $tag IMAP tag prefix the client used on the command line
     * @param array $context per-session context array (TLS state, auth state, selected folder, etc.)
     * @return void no return; the response was queued for the client
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
     * Best-effort partial write of a connection's outbound buffer,
     * used to relieve memory pressure in the middle of a long
     * response loop (FETCH over a large message range) without
     * waiting for the select loop. Writes once in non-blocking
     * mode and keeps any unwritten tail queued for the normal
     * writeClient path. Unlike writeClient it never calls
     * finishWrite, so it does not fire deferred actions (STARTTLS,
     * QUIT close) that must only run once the buffer is fully and
     * intentionally drained at end of command.
     * @param int $key connection key in the in_streams map
     * @return void no return; the outbound buffer is shortened by
     *      however many bytes the socket accepted
     */
    protected function drainWriteBuffer($key)
    {
        if (empty($this->out_streams[self::DATA][$key])) {
            return;
        }
        $stream = $this->out_streams[self::CONNECTION][$key] ??
            ($this->in_streams[self::CONNECTION][$key] ?? null);
        if (!is_resource($stream)) {
            return;
        }
        $written = @fwrite($stream,
            $this->out_streams[self::DATA][$key]);
        if ($written !== false && $written > 0) {
            $this->out_streams[self::DATA][$key] =
                substr($this->out_streams[self::DATA][$key], $written);
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        }
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
     * @param int $key connection key in the in_streams map
     * @return void no return; out_streams entry is cleared
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
                now") has been fully flushed. Start the TLS
                handshake non-blocking and let the select loop
                drive it; driveHandshake resets the session to its
                post-STARTTLS INIT state on success (RFC 3207 sec
                4.2: the client must re-EHLO after TLS comes up;
                same idea for IMAP CAPABILITY) and drops the
                connection on failure (RFC 3207 sec 4.1).
             */
            $context['PENDING_STARTTLS'] = false;
            $connection = $this->in_streams[self::CONNECTION][$key];
            $this->beginHandshake($connection, $key, 'starttls',
                $context['PROTOCOL'] ?? '',
                $context['REMOTE_ADDR'] ?? '',
                $context['REMOTE_PORT'] ?? 0);
            return;
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
        $now_float = microtime(true);
        foreach ($this->handshakes as $key => $info) {
            if ($now_float <= $info['deadline']) {
                continue;
            }
            $this->runHooks('secure', [
                'remote_addr' => $info['remote_addr'],
                'remote_port' => $info['remote_port'],
                'protocol' => $info['protocol'],
                'mode' => $info['mode'],
                'ok' => false,
                'error' => 'handshake timed out',
            ], $this->in_streams[self::CONTEXT][$key] ?? []);
            unset($this->handshakes[$key]);
            if ($info['mode'] === 'starttls') {
                $this->shutdownStream($key);
            } else {
                if (isset($this->in_streams[self::CONNECTION][$key])) {
                    @fclose($this->in_streams[self::CONNECTION][$key]);
                }
                unset($this->in_streams[self::CONNECTION][$key]);
                unset($this->in_streams[self::MODIFIED_TIME][$key]);
            }
        }
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
     * since their snapshot, per RFC 2177 / RFC 3501.
     *
     * Called once per main-loop iteration. The change-counter
     * compare is O(1) per subscriber so unchanged folders
     * cost almost nothing. Folder state is read from disk at
     * most once per (user, folder) per tick via
     * $folder_state_cache, so N idle subscribers on the same
     * folder share a single listMessages walk.
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
                Folder changed since the last tick. Cache the
                fresh state per-tick so multiple subscribers
                on the same folder share one listMessages
                walk; each subscriber still diffs against its
                own IDLE_STATE since they may have joined at
                different points.
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
