<?php
/**
 * seekquarry\atto\FtpSite -- a single-file FTP server with
 * optional TLS (RFC 4217 explicit FTPS, RFC 7151 implicit
 * FTPS). Supports the command set Filezilla and similar
 * mainstream clients use, including MLSD machine listings,
 * passive and active data connections, and a path-traversal
 * guard that prevents clients escaping the configured root.
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
 * Abstract authenticator. A concrete authenticator inspects
 * a (username, password) pair and returns either an
 * associative array of user info or false. The user-info
 * array is stored on the FtpConnection and is consulted by
 * the storage layer for per-user policies (read-only,
 * login folder, quota, etc.).
 *
 * Recognized keys in the returned user-info array:
 *
 *   'user'          (string) the canonical username; required
 *   'login_folder'  (string) cwd to set on login, relative to
 *                   the configured FTP root; defaults to "/"
 *   'read_only'     (bool)   if true, the connection rejects
 *                   STOR / DELE / MKD / RMD / RNFR / RNTO;
 *                   defaults to false
 *
 * Authenticators may return additional keys for application-
 * specific use; FtpSite ignores them. Returning false means
 * the credentials are invalid; the protocol layer then sends
 * a 530 response.
 */
abstract class FtpAuthenticator
{
    /**
     * @param string $user the USER value from the client
     * @param string $password the PASS value, or "" if the
     *      client never sent one
     * @return array|false user-info array on success, false
     *      on credential mismatch
     */
    abstract public function authenticate($user, $password);
}
/**
 * Anonymous authenticator. Accepts the conventional "anonymous"
 * (and "ftp" as an RFC 1635 synonym) with any password. By
 * convention the client sends an email address as the
 * password but we do not validate it; some clients send a
 * literal "anonymous" or the string "guest@". Per RFC 1635,
 * anonymous logins are read-only by convention and we enforce
 * that by setting read_only on the returned user info.
 *
 * The anonymous user lands in the configured login folder,
 * which defaults to "/" but is typically set to "/pub" by
 * the demo's launcher to match the long-standing convention
 * (anonymous FTP archives historically published downloadable
 * content under /pub).
 */
class AnonAuthenticator extends FtpAuthenticator
{
    /**
     * @var string folder anonymous users land in.
     */
    protected $login_folder;
    /**
     * @param string $login_folder folder relative to the FTP
     *      root, e.g. "/pub". Use "/" for the root itself.
     */
    public function __construct($login_folder = "/pub")
    {
        $this->login_folder = $login_folder;
    }
    /**
     * @inheritdoc
     */
    public function authenticate($user, $password)
    {
        $lower = strtolower((string) $user);
        if ($lower !== "anonymous" && $lower !== "ftp") {
            return false;
        }
        return [
            'user' => 'anonymous',
            'login_folder' => $this->login_folder,
            'read_only' => true,
        ];
    }
}
/**
 * Static-list authenticator. Constructed with a list of users
 * keyed by username; each entry can be either a plaintext
 * password string (simplest, fine for demos) or an
 * associative array carrying the password plus any of the
 * recognized user-info keys (login_folder, read_only).
 *
 * Example:
 *
 *      new StaticUserAuthenticator([
 *          'alice' => ['password' => 'hunter2',
 *              'login_folder' => '/users/alice'],
 *          'bob' => ['password' => 'sekret',
 *              'login_folder' => '/users/bob',
 *              'read_only' => true],
 *          'guest' => 'guest123',
 *      ]);
 *
 * Production deployments would replace this with a closure-
 * based authenticator hooked into a real user store. Plaintext
 * passwords on disk are a demo convenience; nothing in the
 * authenticator interface forces this design.
 */
class StaticUserAuthenticator extends FtpAuthenticator
{
    /**
     * @var array username => entry (string or array)
     */
    protected $users;
    /**
     * @param array $users see class docblock for shape.
     */
    public function __construct($users)
    {
        $this->users = $users;
    }
    /**
     * @inheritdoc
     */
    public function authenticate($user, $password)
    {
        if (!isset($this->users[$user])) {
            return false;
        }
        $entry = $this->users[$user];
        if (is_string($entry)) {
            $entry = ['password' => $entry];
        }
        $expected = isset($entry['password']) ?
            (string) $entry['password'] : '';
        if (!hash_equals($expected, (string) $password)) {
            return false;
        }
        return [
            'user' => $user,
            'login_folder' => isset($entry['login_folder']) ?
                $entry['login_folder'] : '/',
            'read_only' => !empty($entry['read_only']),
        ];
    }
}
/**
 * Composite authenticator that tries a list of authenticators
 * in order and returns the first success. Useful for
 * combining anonymous access with a static user list -- a
 * common deployment shape where most visitors land in /pub
 * read-only but a small set of named users have write access
 * to their own subdirectories.
 *
 *      new CompositeAuthenticator([
 *          new StaticUserAuthenticator([...]),
 *          new AnonAuthenticator('/pub'),
 *      ]);
 */
class CompositeAuthenticator extends FtpAuthenticator
{
    /**
     * @var array of FtpAuthenticator
     */
    protected $authenticators;
    /**
     * @param array $authenticators list of FtpAuthenticator
     *      instances tried in order.
     */
    public function __construct($authenticators)
    {
        $this->authenticators = $authenticators;
    }
    /**
     * @inheritdoc
     */
    public function authenticate($user, $password)
    {
        foreach ($this->authenticators as $auth) {
            $result = $auth->authenticate($user, $password);
            if ($result !== false) {
                return $result;
            }
        }
        return false;
    }
}
/**
 * Abstract storage. The protocol layer never touches the
 * underlying filesystem (or whatever the backend is) -- it
 * delegates every read, write, list, and metadata query to
 * a concrete subclass. The path argument to every method is
 * an FTP-style path (forward slashes, leading slash means
 * the FTP root, no escape via "..") and the storage is
 * responsible for resolving it safely.
 *
 * Listing entries are associative arrays with these keys:
 *
 *   'name'  (string) basename of the entry
 *   'type'  (string) "file" or "dir" (others ignored)
 *   'size'  (int)    byte length, 0 for directories
 *   'mtime' (int)    Unix timestamp of last modification
 *   'mode'  (int)    POSIX mode bits, e.g. 0644 (best-effort
 *                    on platforms that do not have them)
 *
 * Methods that produce a stream return a PHP stream resource
 * the caller must fclose() when done. Methods that consume a
 * stream read it to EOF and close it themselves so the caller
 * does not need to track resource lifetime through error
 * paths.
 */
abstract class FtpStorage
{
    /**
     * Resolves a client-supplied path to a backend-specific
     * absolute identifier (e.g. an absolute filesystem path).
     * Returns false when the path tries to escape the root
     * via "..", absolute prefixes the backend rejects, or
     * any other security concern. The protocol layer treats
     * a false return as a 550 response.
     *
     * @param string $cwd the connection's current working
     *      directory, FTP-style ("/" rooted, forward slashes)
     * @param string $path the path supplied by the client,
     *      may be relative or absolute (FTP-style)
     * @return string|false backend-specific resolved path
     */
    abstract public function resolveSafe($cwd, $path);
    /**
     * Returns a list of entries inside a directory. Returns
     * false when the path does not exist or is not a
     * directory.
     *
     * @param string $resolved backend path from resolveSafe()
     * @return array|false list of entry-info arrays
     */
    abstract public function listing($resolved);
    /**
     * Returns metadata about a single entry, or false if it
     * does not exist. Same shape as listing entries.
     *
     * @param string $resolved
     * @return array|false
     */
    abstract public function statEntry($resolved);
    /**
     * Returns true if the path exists (file or directory).
     *
     * @param string $resolved
     * @return bool
     */
    abstract public function exists($resolved);
    /**
     * Returns true if the path exists and is a directory.
     *
     * @param string $resolved
     * @return bool
     */
    abstract public function isDir($resolved);
    /**
     * Opens the file for reading and returns a stream. The
     * caller is responsible for fclose() on the returned
     * resource. Returns false on error.
     *
     * @param string $resolved
     * @param int $offset bytes to seek past the start, used
     *      for REST-restarted transfers
     * @return resource|false
     */
    abstract public function openRead($resolved, $offset = 0);
    /**
     * Streams the contents of an open input stream into the
     * named path, replacing any existing content. The input
     * stream is read to EOF; the caller does not close it
     * (we do, even on error). Returns true on success.
     *
     * @param string $resolved
     * @param resource $input
     * @param bool $append if true, open for append rather
     *      than overwrite (used by APPE)
     * @return bool
     */
    abstract public function streamWrite($resolved, $input,
        $append = false);
    /**
     * Deletes a file. Returns true on success.
     *
     * @param string $resolved
     * @return bool
     */
    abstract public function deleteFile($resolved);
    /**
     * Creates a directory. Returns true on success. Does
     * not create parents.
     *
     * @param string $resolved
     * @return bool
     */
    abstract public function makeDir($resolved);
    /**
     * Removes an empty directory. Returns true on success.
     * Returns false if the directory is non-empty.
     *
     * @param string $resolved
     * @return bool
     */
    abstract public function removeDir($resolved);
    /**
     * Renames a path. Both arguments are resolved backend
     * paths. Returns true on success.
     *
     * @param string $from_resolved
     * @param string $to_resolved
     * @return bool
     */
    abstract public function renameEntry($from_resolved,
        $to_resolved);
}
/**
 * Filesystem-backed FtpStorage. All operations are confined
 * to the configured root directory; the resolveSafe()
 * implementation rejects any path that, after resolving "."
 * and ".." segments, would land outside the root.
 *
 * Symlinks pointing outside the root ARE followed by
 * realpath() and are rejected by the prefix check, which is
 * the correct behavior: a hostile symlink should not let a
 * client read /etc/passwd. Symlinks pointing to other places
 * within the root are followed normally.
 */
class FilesystemFtpStorage extends FtpStorage
{
    /**
     * @var string canonical absolute path to the FTP root
     *      (no trailing separator). All resolved paths must
     *      start with this prefix.
     */
    protected $root;
    /**
     * @param string $root absolute path to the FTP root.
     *      Must already exist; the constructor canonicalizes
     *      it via realpath() so symlink loops in the path
     *      itself do not confuse the prefix check later.
     */
    public function __construct($root)
    {
        $real = @realpath($root);
        if ($real === false) {
            $real = rtrim($root, "/\\");
        }
        $this->root = rtrim($real, "/\\");
    }
    /**
     * Returns the canonical absolute root, useful for
     * launchers and tests that need to render the path.
     *
     * @return string
     */
    public function rootDir()
    {
        return $this->root;
    }
    /**
     * @inheritdoc
     */
    public function resolveSafe($cwd, $path)
    {
        /*
            Combine cwd + path in FTP-space (forward slashes,
            leading slash = FTP root). An absolute path
            replaces cwd; a relative one is appended.
         */
        if ($path === '') {
            $combined = $cwd === '' ? '/' : $cwd;
        } else if ($path[0] === '/') {
            $combined = $path;
        } else {
            $combined = rtrim($cwd, '/') . '/' . $path;
        }
        /*
            Walk the components and apply "." (skip) and ".."
            (pop). After this the remaining segments are
            "below FTP root"; we then anchor at $this->root
            and join with the platform separator.
         */
        $segments = [];
        foreach (explode('/', $combined) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            /*
                Reject any segment that contains a NUL or
                a backslash. NUL would let an attacker
                truncate the path on backends that pass it
                to C-string APIs; backslash on Windows would
                act as a separator and bypass our segment-
                level vetting.
             */
            if (strpos($segment, "\0") !== false ||
                strpos($segment, "\\") !== false) {
                return false;
            }
            $segments[] = $segment;
        }
        $absolute = $this->root;
        if (!empty($segments)) {
            $absolute .= DIRECTORY_SEPARATOR .
                implode(DIRECTORY_SEPARATOR, $segments);
        }
        /*
            Final defense: if the path exists, realpath() it
            and confirm the canonical form still starts with
            the root prefix. This catches symlinks whose
            targets escape the root. If the path does not
            exist (e.g. STOR creating a new file), we accept
            the lexical resolution we already did, because
            there is no realpath() to consult.
         */
        $canonical = @realpath($absolute);
        if ($canonical !== false) {
            if ($canonical !== $this->root &&
                strpos($canonical,
                    $this->root . DIRECTORY_SEPARATOR) !== 0) {
                return false;
            }
            return $canonical;
        }
        /*
            Path does not exist yet. The parent must exist and
            be inside the root for any operation to make
            sense; check that.
         */
        $parent = dirname($absolute);
        $parent_canonical = @realpath($parent);
        if ($parent_canonical === false) {
            return false;
        }
        if ($parent_canonical !== $this->root &&
            strpos($parent_canonical,
                $this->root . DIRECTORY_SEPARATOR) !== 0) {
            return false;
        }
        return $parent_canonical . DIRECTORY_SEPARATOR .
            basename($absolute);
    }
    /**
     * @inheritdoc
     */
    public function listing($resolved)
    {
        if (!is_dir($resolved)) {
            return false;
        }
        $entries = @scandir($resolved);
        if ($entries === false) {
            return false;
        }
        $out = [];
        foreach ($entries as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $resolved . DIRECTORY_SEPARATOR . $name;
            $info = $this->describe($path, $name);
            if ($info !== false) {
                $out[] = $info;
            }
        }
        return $out;
    }
    /**
     * @inheritdoc
     */
    public function statEntry($resolved)
    {
        if (!file_exists($resolved)) {
            return false;
        }
        return $this->describe($resolved, basename($resolved));
    }
    /**
     * @inheritdoc
     */
    public function exists($resolved)
    {
        return file_exists($resolved);
    }
    /**
     * @inheritdoc
     */
    public function isDir($resolved)
    {
        return is_dir($resolved);
    }
    /**
     * @inheritdoc
     */
    public function openRead($resolved, $offset = 0)
    {
        if (!is_file($resolved)) {
            return false;
        }
        $stream = @fopen($resolved, 'rb');
        if ($stream === false) {
            return false;
        }
        if ($offset > 0) {
            if (@fseek($stream, $offset) !== 0) {
                fclose($stream);
                return false;
            }
        }
        return $stream;
    }
    /**
     * @inheritdoc
     */
    public function streamWrite($resolved, $input,
        $append = false)
    {
        $mode = $append ? 'ab' : 'wb';
        $out = @fopen($resolved, $mode);
        if ($out === false) {
            @fclose($input);
            return false;
        }
        while (!feof($input)) {
            $chunk = @fread($input, 65536);
            if ($chunk === false) {
                fclose($out);
                @fclose($input);
                return false;
            }
            if ($chunk === '') {
                /*
                    Non-blocking source with nothing to read
                    yet but not EOF; back off briefly. The
                    caller's data-channel loop fills the
                    buffer between iterations.
                 */
                usleep(10000);
                continue;
            }
            $written = 0;
            $length = strlen($chunk);
            while ($written < $length) {
                $n = @fwrite($out,
                    substr($chunk, $written));
                if ($n === false || $n === 0) {
                    fclose($out);
                    @fclose($input);
                    return false;
                }
                $written += $n;
            }
        }
        fclose($out);
        @fclose($input);
        return true;
    }
    /**
     * @inheritdoc
     */
    public function deleteFile($resolved)
    {
        return @unlink($resolved);
    }
    /**
     * @inheritdoc
     */
    public function makeDir($resolved)
    {
        return @mkdir($resolved, 0755, false);
    }
    /**
     * @inheritdoc
     */
    public function removeDir($resolved)
    {
        return @rmdir($resolved);
    }
    /**
     * @inheritdoc
     */
    public function renameEntry($from_resolved, $to_resolved)
    {
        return @rename($from_resolved, $to_resolved);
    }
    /**
     * Builds the metadata array for one filesystem entry.
     */
    protected function describe($path, $name)
    {
        $stat = @stat($path);
        if ($stat === false) {
            return false;
        }
        return [
            'name' => $name,
            'type' => is_dir($path) ? 'dir' : 'file',
            'size' => is_dir($path) ? 0 : (int) $stat['size'],
            'mtime' => (int) $stat['mtime'],
            'mode' => $stat['mode'] & 0777,
        ];
    }
}
/**
 * Per-connection state. One instance is created when a
 * client opens the control connection and lives until the
 * client disconnects or QUITs. Holds authentication state,
 * the current working directory in FTP-space, transfer-mode
 * flags (TYPE, MODE, STRU), the active passive-mode listener
 * (if any), the active active-mode peer address (if any),
 * a pending REST offset, and a pending RNFR target.
 */
class FtpConnection
{
    /**
     * @var resource control-channel stream socket
     */
    public $control;
    /**
     * @var string accumulated incoming bytes on the control
     *      channel, drained as full CRLF-terminated lines
     */
    public $buffer = "";
    /**
     * @var string remote peer's "ip:port" as reported by
     *      stream_socket_get_name; used in logs
     */
    public $peer = "";
    /**
     * @var bool true once the client has authenticated.
     */
    public $authed = false;
    /**
     * @var string username from USER, captured before PASS
     */
    public $pending_user = "";
    /**
     * @var array user-info from authenticate(), populated on
     *      successful PASS
     */
    public $user_info = [];
    /**
     * @var string current working directory in FTP-space,
     *      e.g. "/" or "/pub"
     */
    public $cwd = "/";
    /**
     * @var string TYPE: "I" for binary (default), "A" for
     *      ASCII. We accept both but treat both as binary
     *      because cross-OS line-ending translation is more
     *      trouble than it is worth in 2026.
     */
    public $type = "I";
    /**
     * @var resource|false passive-mode listener socket, or
     *      false when the next data transfer should use the
     *      active-mode address instead
     */
    public $pasv_listener = false;
    /**
     * @var int the port the passive listener is bound to,
     *      cached so we can repeat it in PASV / EPSV replies
     */
    public $pasv_port = 0;
    /**
     * @var array|false [host, port] for active-mode data
     *      connections, or false when in passive mode
     */
    public $active_addr = false;
    /**
     * @var int REST-supplied byte offset for the next
     *      transfer; reset to 0 after the transfer starts
     */
    public $rest_offset = 0;
    /**
     * @var string|false resolved path captured by RNFR,
     *      consumed by the next RNTO
     */
    public $pending_rename_from = false;
    /**
     * @var bool whether the control connection is wrapped
     *      in TLS (set by AUTH TLS path)
     */
    public $tls_active = false;
    /**
     * @var bool whether subsequent data channels should be
     *      TLS-protected. Set to true by PROT P, false by
     *      PROT C. RFC 4217 sec 9 says the default is C
     *      (cleartext data) until the client explicitly
     *      asks for protection, even after AUTH TLS.
     */
    public $prot_p = false;
    /**
     * @var int when the control channel was opened (Unix
     *      timestamp); used to time out idle connections
     */
    public $opened = 0;
    /**
     * @var int last activity time (Unix timestamp); used to
     *      decide whether the connection is idle
     */
    public $last_activity = 0;
}
/**
 * The FTP server. Binds the control port (and optionally an
 * implicit-FTPS port), accepts client connections, runs a
 * select loop that drains command lines, and dispatches each
 * command to a handler method named cmdXXX where XXX is the
 * uppercase verb.
 *
 * Configuration follows the chained-setter pattern of the
 * other atto servers:
 *
 *      $ftp = new FtpSite();
 *      $ftp->auth(new AnonAuthenticator('/pub'))
 *          ->root('/srv/ftp')
 *          ->banner('AttoFTP demo')
 *          ->serverName('ftp.example.test')
 *          ->loginFolder('/')
 *          ->passivePortRange(50000, 50100);
 *      $ftp->listen([
 *          'BIND' => '0.0.0.0',
 *          'FTP_PORT' => 2121,
 *          'FTPS_PORT' => 9990,
 *          'SERVER_CONTEXT' => ['ssl' => [...]],
 *      ]);
 *
 * Configuration keys recognized by listen():
 *
 *   BIND             interface, default 0.0.0.0
 *   FTP_PORT         control port, default 2121 (21 needs root)
 *   FTPS_PORT        implicit-FTPS port, default 9990 (990
 *                    is the well-known but privileged port);
 *                    only bound when SERVER_CONTEXT carries
 *                    an ssl block
 *   IDLE_TIMEOUT     seconds; close idle control channels
 *                    after this many seconds, default 300
 *   SERVER_CONTEXT   stream context, see above
 *
 * The reverse of the configuration setters is the demo's
 * usual file-listener pattern: the demo's index.php
 * configures the server, the demo's webui.php drives it
 * over a real socket.
 */
class FtpSite
{
    /* Greeting / banner code (RFC 959 sec 5.4). */
    const REPLY_READY = 220;
    const REPLY_GOODBYE = 221;
    const REPLY_TRANSFER_OK = 226;
    const REPLY_PASV_OK = 227;
    const REPLY_EPSV_OK = 229;
    const REPLY_USER_LOGGED_IN = 230;
    const REPLY_TLS_OK = 234;
    const REPLY_OK = 250;
    const REPLY_PATHNAME = 257;
    const REPLY_NEED_PASS = 331;
    const REPLY_NEED_RNTO = 350;
    const REPLY_OPENING = 150;
    const REPLY_CONN_CLOSED = 421;
    const REPLY_NO_DATA_CONN = 425;
    const REPLY_DATA_ABORTED = 426;
    const REPLY_FILE_BUSY = 450;
    const REPLY_LOCAL_ERROR = 451;
    const REPLY_SYNTAX_ERR = 500;
    const REPLY_PARAM_ERR = 501;
    const REPLY_NOT_IMPL = 502;
    const REPLY_BAD_SEQUENCE = 503;
    const REPLY_PARAM_NOT_IMPL = 504;
    const REPLY_NOT_LOGGED_IN = 530;
    const REPLY_FILE_UNAVAILABLE = 550;
    const REPLY_NEEDS_TLS = 534;
    const REPLY_FEAT = 211;
    const REPLY_STAT = 212;
    const REPLY_HELP = 214;
    const REPLY_SYST = 215;
    /**
     * @var FtpAuthenticator
     */
    protected $authenticator;
    /**
     * @var FtpStorage
     */
    protected $storage;
    /**
     * @var string greeting after the REPLY_READY code.
     */
    protected $banner = "AttoFTP ready.";
    /**
     * @var string what to report in SYST and in MLSD
     *      "system" facts. Pretend to be UNIX so naive
     *      clients that branch on this value treat us as a
     *      well-known shape.
     */
    protected $system = "UNIX Type: L8";
    /**
     * @var string the server identifier exposed to clients
     *      in the banner; also used in trace logging.
     */
    protected $server_name = "atto-ftp";
    /**
     * @var string default login folder for users whose auth
     *      result does not specify one.
     */
    protected $default_login_folder = "/";
    /**
     * @var int low end of the port range for PASV / EPSV
     *      listeners, inclusive.
     */
    protected $pasv_port_low = 50000;
    /**
     * @var int high end of the port range, inclusive.
     */
    protected $pasv_port_high = 50100;
    /**
     * @var string|false PASV-advertised public IP address
     *      for clients behind NAT. False means "use the IP
     *      the control connection arrived on", which is the
     *      right answer for non-NAT'd setups (most demos).
     */
    protected $pasv_advertise_ip = false;
    /**
     * @var array runtime config from listen()
     */
    protected $config = [];
    /**
     * @var array ssl options (the contents of
     *      SERVER_CONTEXT['ssl']) saved from listen() so the
     *      AUTH TLS path can apply them per-connection
     */
    protected $ssl_options = [];
    /**
     * @var array map of (int) stream resource id => FtpConnection
     */
    protected $connections = [];
    /**
     * Sets the authenticator. Returns $this for chaining.
     *
     * @param FtpAuthenticator $authenticator
     * @return $this
     */
    public function auth($authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
    /**
     * Sets the storage backend. Returns $this for chaining.
     *
     * @param FtpStorage $storage
     * @return $this
     */
    public function storage($storage)
    {
        $this->storage = $storage;
        return $this;
    }
    /**
     * Convenience setter for the common case of a
     * filesystem-rooted backend. Equivalent to passing a
     * pre-built FilesystemFtpStorage to storage().
     *
     * @param string $directory
     * @return $this
     */
    public function root($directory)
    {
        $this->storage = new FilesystemFtpStorage($directory);
        return $this;
    }
    /**
     * Sets the greeting banner (the text after the 220
     * code in the welcome reply).
     *
     * @param string $banner
     * @return $this
     */
    public function banner($banner)
    {
        $this->banner = $banner;
        return $this;
    }
    /**
     * Sets the server name (used in logging).
     *
     * @param string $name
     * @return $this
     */
    public function serverName($name)
    {
        $this->server_name = $name;
        return $this;
    }
    /**
     * Sets the default cwd for users whose authenticator
     * result does not include a login_folder.
     *
     * @param string $folder
     * @return $this
     */
    public function loginFolder($folder)
    {
        $this->default_login_folder = $folder;
        return $this;
    }
    /**
     * Sets the port range used for PASV / EPSV listeners.
     * The server picks a free port in this range for each
     * passive transfer; the range needs to be open if a
     * firewall sits between the client and us. The default
     * range (50000-50100) leaves room for ~100 concurrent
     * passive transfers, which is plenty for a demo.
     *
     * @param int $low
     * @param int $high
     * @return $this
     */
    public function passivePortRange($low, $high)
    {
        $this->pasv_port_low = (int) $low;
        $this->pasv_port_high = (int) $high;
        return $this;
    }
    /**
     * Sets the IP we advertise in PASV / EPSV responses for
     * clients behind NAT. If false (the default) we use the
     * IP the control connection arrived on, which is correct
     * for non-NAT deployments (localhost demos included).
     *
     * @param string|false $ip
     * @return $this
     */
    public function pasvAdvertiseIp($ip)
    {
        $this->pasv_advertise_ip = $ip;
        return $this;
    }
    /**
     * Binds the control port and (when configured) the
     * implicit-FTPS port and runs the select loop until
     * the process is killed.
     *
     * @param array $config see class docblock for keys
     * @return bool false on bind failure
     */
    public function listen($config = [])
    {
        $defaults = [
            'BIND' => '0.0.0.0',
            'FTP_PORT' => 2121,
            'FTPS_PORT' => 9990,
            'IDLE_TIMEOUT' => 300,
        ];
        $context_array = [];
        if (isset($config['SERVER_CONTEXT'])) {
            $context_array = $config['SERVER_CONTEXT'];
            unset($config['SERVER_CONTEXT']);
        }
        $this->config = array_merge($defaults, $config);
        if (!empty($context_array['ssl'])) {
            $this->ssl_options = $context_array['ssl'];
        }
        if ($this->authenticator === null) {
            echo "FtpSite: no authenticator configured; " .
                "rejecting all logins.\n";
        }
        if ($this->storage === null) {
            echo "FtpSite: no storage configured; " .
                "refusing to start.\n";
            return false;
        }
        $bind = $this->config['BIND'];
        $ctrl_addr = "tcp://$bind:" .
            $this->config['FTP_PORT'];
        $ctrl = @stream_socket_server($ctrl_addr,
            $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$ctrl) {
            echo "Failed to bind FTP $ctrl_addr: $errstr\n";
            return false;
        }
        stream_set_blocking($ctrl, 0);
        echo "atto-ftp listening: control at $ctrl_addr\n";
        $ftps = false;
        if (!empty($this->ssl_options)) {
            $ftps_addr = "tcp://$bind:" .
                $this->config['FTPS_PORT'];
            $ftps_context = stream_context_create(
                ['ssl' => $this->ssl_options]);
            $ftps = @stream_socket_server($ftps_addr,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
                $ftps_context);
            if ($ftps) {
                stream_set_blocking($ftps, 0);
                echo "atto-ftp listening: implicit FTPS at " .
                    "$ftps_addr\n";
            } else {
                echo "Warning: failed to bind FTPS " .
                    "$ftps_addr: $errstr\n";
                $ftps = false;
            }
        }
        while (true) {
            $reads = [$ctrl];
            if ($ftps !== false) {
                $reads[] = $ftps;
            }
            foreach ($this->connections as $c) {
                $reads[] = $c->control;
            }
            $writes = null;
            $excepts = null;
            $n = @stream_select($reads, $writes, $excepts, 5);
            if ($n === false || $n === 0) {
                $this->reapIdle();
                continue;
            }
            foreach ($reads as $stream) {
                if ($stream === $ctrl) {
                    $this->acceptControl($ctrl, false);
                    continue;
                }
                if ($ftps !== false && $stream === $ftps) {
                    $this->acceptControl($ftps, true);
                    continue;
                }
                $this->serviceClient($stream);
            }
            $this->reapIdle();
        }
    }
    /**
     * Accepts one control-connection client. For implicit
     * FTPS listeners we perform the TLS handshake here;
     * for explicit-FTPS (AUTH TLS) the upgrade happens
     * later inside cmdAUTH.
     */
    protected function acceptControl($listener, $is_implicit_tls)
    {
        $client = @stream_socket_accept($listener, 0, $peer);
        if (!$client) {
            return;
        }
        if ($is_implicit_tls && !$this->upgradeToTls($client)) {
            @fclose($client);
            return;
        }
        stream_set_blocking($client, 0);
        $conn = new FtpConnection();
        $conn->control = $client;
        $conn->peer = (string) $peer;
        $conn->tls_active = $is_implicit_tls;
        $conn->opened = time();
        $conn->last_activity = time();
        $this->connections[(int) $client] = $conn;
        $this->reply($conn, self::REPLY_READY,
            $this->banner);
    }
    /**
     * Drains pending bytes from one client, dispatches each
     * full command line, and closes the connection on EOF
     * or unrecoverable error.
     */
    protected function serviceClient($stream)
    {
        $key = (int) $stream;
        if (!isset($this->connections[$key])) {
            return;
        }
        $conn = $this->connections[$key];
        $chunk = @fread($stream, 8192);
        if ($chunk === false || $chunk === "") {
            $meta = stream_get_meta_data($stream);
            if (!empty($meta['eof']) ||
                !empty($meta['timed_out'])) {
                $this->closeConnection($conn);
            }
            return;
        }
        $conn->buffer .= $chunk;
        $conn->last_activity = time();
        /*
            Commands are CRLF-terminated. Some clients send
            bare LF; accept both. We loop because one read
            may have delivered multiple commands.
         */
        while (($eol = strpos($conn->buffer, "\n")) !== false) {
            $line = substr($conn->buffer, 0, $eol);
            $conn->buffer = substr($conn->buffer, $eol + 1);
            $line = rtrim($line, "\r");
            if ($line === '') {
                continue;
            }
            $this->dispatch($conn, $line);
            if (!isset($this->connections[$key])) {
                /* dispatch() called closeConnection() */
                return;
            }
        }
    }
    /**
     * Parses a command line into verb + argument and runs
     * the matching handler. Unknown verbs get 502.
     */
    protected function dispatch($conn, $line)
    {
        $sp = strpos($line, ' ');
        if ($sp === false) {
            $verb = strtoupper($line);
            $arg = '';
        } else {
            $verb = strtoupper(substr($line, 0, $sp));
            $arg = substr($line, $sp + 1);
        }
        $method = 'cmd' . $verb;
        if (!method_exists($this, $method)) {
            $this->reply($conn, self::REPLY_NOT_IMPL,
                "Command not implemented.");
            return;
        }
        $this->$method($conn, $arg);
    }
    /**
     * Closes a connection cleanly, including any open
     * passive listener.
     */
    protected function closeConnection($conn)
    {
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        @fclose($conn->control);
        unset($this->connections[(int) $conn->control]);
    }
    /**
     * Closes idle control connections that have not seen a
     * command in IDLE_TIMEOUT seconds.
     */
    protected function reapIdle()
    {
        $now = time();
        $limit = $now - (int) $this->config['IDLE_TIMEOUT'];
        foreach ($this->connections as $conn) {
            if ($conn->last_activity < $limit) {
                $this->reply($conn, self::REPLY_CONN_CLOSED,
                    "Idle timeout, closing.");
                $this->closeConnection($conn);
            }
        }
    }
    /**
     * Writes one reply line. Replies are always
     * CRLF-terminated; the textual part may be either a
     * scalar (single-line reply) or an array (multi-line
     * reply, all but the last line get a "-" between code
     * and text per RFC 959 sec 4.2).
     */
    protected function reply($conn, $code, $text)
    {
        $stream = $conn->control;
        if (is_array($text)) {
            $last = count($text) - 1;
            foreach ($text as $i => $line) {
                $sep = ($i === $last) ? ' ' : '-';
                @fwrite($stream, $code . $sep . $line . "\r\n");
            }
        } else {
            @fwrite($stream, $code . ' ' . $text . "\r\n");
        }
    }
    /**
     * Performs the server-side TLS handshake on a control
     * socket. Mirrors the pattern in DnsSite::upgradeToTls
     * and MailSite::upgradeToTls: bracket
     * stream_socket_enable_crypto with a scoped error
     * handler so a failure can be attributed to this exact
     * call. Returns true on success.
     */
    protected function upgradeToTls($stream)
    {
        if (empty($this->ssl_options)) {
            return false;
        }
        foreach ($this->ssl_options as $option_name =>
            $option_value) {
            stream_context_set_option($stream, 'ssl',
                $option_name, $option_value);
        }
        $error = null;
        set_error_handler(
            function ($errno, $errstr) use (&$error) {
                $error = $errstr;
                return true;
            });
        stream_set_blocking($stream, 1);
        $method = STREAM_CRYPTO_METHOD_TLS_SERVER;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
        }
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
        }
        $ok = @stream_socket_enable_crypto($stream, true,
            $method);
        stream_set_blocking($stream, 0);
        restore_error_handler();
        if ($ok === true) {
            return true;
        }
        if ($error !== null) {
            echo "FtpSite TLS handshake failed: $error\n";
        }
        return false;
    }
    /**
     * Opens the data connection for the next transfer. In
     * passive mode this means accepting on the listener the
     * client got when we replied to PASV / EPSV; in active
     * mode it means dialing the address the client gave us
     * via PORT / EPRT. Returns the data stream on success,
     * false on failure (after sending the appropriate error
     * reply).
     */
    protected function openDataChannel($conn)
    {
        $stream = false;
        if ($conn->pasv_listener !== false) {
            /*
                Wait briefly for the client to connect. The
                accept timeout is short because the client
                opens the data socket immediately after seeing
                our PASV reply; if 5 seconds is not enough,
                something is wrong with the network and we
                should fail rather than block.
             */
            $stream = @stream_socket_accept(
                $conn->pasv_listener, 5);
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
            $conn->pasv_port = 0;
            if (!$stream) {
                $this->reply($conn, self::REPLY_NO_DATA_CONN,
                    "Cannot open passive data connection.");
                return false;
            }
        } else if ($conn->active_addr !== false) {
            list($host, $port) = $conn->active_addr;
            $conn->active_addr = false;
            $stream = @stream_socket_client(
                "tcp://$host:$port", $errno, $errstr, 5);
            if (!$stream) {
                $this->reply($conn, self::REPLY_NO_DATA_CONN,
                    "Cannot open active data connection: " .
                    $errstr);
                return false;
            }
        } else {
            $this->reply($conn, self::REPLY_NO_DATA_CONN,
                "Use PASV or PORT before requesting a " .
                "transfer.");
            return false;
        }
        /*
            If the client requested PROT P, do the TLS
            handshake on the data socket before returning.
            The client wraps its end at the same time, so
            both sides are encrypted before any bytes flow.
         */
        if (!empty($conn->prot_p) &&
            !empty($this->ssl_options)) {
            if (!$this->upgradeToTls($stream)) {
                @fclose($stream);
                $this->reply($conn, self::REPLY_NO_DATA_CONN,
                    "TLS handshake on data channel failed.");
                return false;
            }
        }
        return $stream;
    }
    /**
     * Picks an unused port in the configured passive range
     * and binds a one-shot listener on it. Returns
     * [$listener_stream, $port] on success or [false, 0] on
     * failure.
     */
    protected function bindPassiveListener($conn)
    {
        $bind = $this->config['BIND'];
        $low = $this->pasv_port_low;
        $high = $this->pasv_port_high;
        /*
            Try ports in pseudo-random order so two
            simultaneous PASVs from the same client almost
            never collide on the first attempt. We give up
            after a bounded number of tries to avoid spinning
            forever if the whole range is full (which would
            indicate a leak or a denial-of-service attempt).
         */
        $tries = 0;
        $max_tries = max(8, ($high - $low + 1));
        while ($tries < $max_tries) {
            $port = random_int($low, $high);
            $addr = "tcp://$bind:$port";
            $listener = @stream_socket_server($addr,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
            if ($listener !== false) {
                stream_set_blocking($listener, 0);
                return [$listener, $port];
            }
            $tries++;
        }
        return [false, 0];
    }
    /**
     * Returns the IP we should advertise in PASV / EPSV
     * responses. Either the configured override (for NAT'd
     * deployments) or the address the control connection
     * arrived on (the right answer for non-NAT setups).
     */
    protected function advertiseIp($conn)
    {
        if ($this->pasv_advertise_ip !== false) {
            return $this->pasv_advertise_ip;
        }
        $local = stream_socket_get_name($conn->control,
            false);
        if ($local === false) {
            return '127.0.0.1';
        }
        $colon = strrpos($local, ':');
        if ($colon === false) {
            return '127.0.0.1';
        }
        $ip = substr($local, 0, $colon);
        $ip = trim($ip, "[]");
        return $ip;
    }
    /**
     * Convenience: most commands need to confirm the
     * connection is authenticated before proceeding.
     * Returns true and sends nothing on success; sends the
     * 530 reply and returns false on failure.
     */
    protected function requireAuth($conn)
    {
        if (!$conn->authed) {
            $this->reply($conn, self::REPLY_NOT_LOGGED_IN,
                "Please log in with USER and PASS.");
            return false;
        }
        return true;
    }
    /**
     * Convenience: read-only-aware guard used by mutating
     * commands. Returns true if the user can mutate; sends
     * 550 and returns false if not.
     */
    protected function requireWrite($conn)
    {
        if (!empty($conn->user_info['read_only'])) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Permission denied: read-only account.");
            return false;
        }
        return true;
    }
    /*
        Command handlers below. Each handler is named cmdXXX
        where XXX is the uppercase verb. Adding a new command
        is as simple as adding a new method; the dispatcher
        in dispatch() finds it via method_exists.

        Replies use the REPLY_* constants for clarity at the
        call site. Bodies are kept short on purpose: business
        logic lives in the storage class, not here.
     */
    protected function cmdUSER($conn, $arg)
    {
        if ($arg === '') {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "USER requires a username.");
            return;
        }
        $conn->pending_user = $arg;
        $conn->authed = false;
        $conn->user_info = [];
        $this->reply($conn, self::REPLY_NEED_PASS,
            "Password required for $arg.");
    }
    protected function cmdPASS($conn, $arg)
    {
        if ($conn->pending_user === '') {
            $this->reply($conn, self::REPLY_BAD_SEQUENCE,
                "Send USER first.");
            return;
        }
        if ($this->authenticator === null) {
            $this->reply($conn, self::REPLY_NOT_LOGGED_IN,
                "No authenticator configured.");
            return;
        }
        $info = $this->authenticator->authenticate(
            $conn->pending_user, $arg);
        if ($info === false) {
            $this->reply($conn, self::REPLY_NOT_LOGGED_IN,
                "Login incorrect.");
            return;
        }
        $conn->authed = true;
        $conn->user_info = $info;
        $conn->cwd = isset($info['login_folder']) ?
            $info['login_folder'] :
            $this->default_login_folder;
        $this->reply($conn, self::REPLY_USER_LOGGED_IN,
            "User " . $info['user'] . " logged in.");
    }
    protected function cmdQUIT($conn, $arg)
    {
        $this->reply($conn, self::REPLY_GOODBYE, "Goodbye.");
        $this->closeConnection($conn);
    }
    protected function cmdNOOP($conn, $arg)
    {
        $this->reply($conn, self::REPLY_OK, "OK.");
    }
    protected function cmdSYST($conn, $arg)
    {
        $this->reply($conn, self::REPLY_SYST,
            $this->system);
    }
    protected function cmdHELP($conn, $arg)
    {
        $this->reply($conn, self::REPLY_HELP, [
            "Commands supported:",
            "USER PASS QUIT NOOP SYST HELP STAT FEAT OPTS",
            "PWD CWD CDUP TYPE MODE STRU",
            "PASV EPSV PORT EPRT REST ABOR",
            "LIST NLST MLSD MLST SIZE MDTM",
            "RETR STOR APPE DELE",
            "MKD RMD RNFR RNTO",
            "AUTH PBSZ PROT",
            "End of help.",
        ]);
    }
    protected function cmdSTAT($conn, $arg)
    {
        if ($arg === '') {
            $this->reply($conn, self::REPLY_STAT, [
                "AttoFTP server status:",
                "Logged in as " .
                    ($conn->authed ?
                        $conn->user_info['user'] : "no one"),
                "Type: " . $conn->type,
                "TLS: " .
                    ($conn->tls_active ? "active" : "off"),
                "End of status.",
            ]);
            return;
        }
        /*
            STAT <path> requests an inline listing. We deliver
            it on the control channel inside the multi-line
            reply rather than opening a data connection.
         */
        if (!$this->requireAuth($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "File not found.");
            return;
        }
        if ($this->storage->isDir($resolved)) {
            $entries = $this->storage->listing($resolved);
            $lines = ["Status of $arg:"];
            foreach (($entries ?: []) as $e) {
                $lines[] = $this->formatListLine($e);
            }
            $lines[] = "End of status.";
            $this->reply($conn, self::REPLY_STAT, $lines);
            return;
        }
        $info = $this->storage->statEntry($resolved);
        $this->reply($conn, self::REPLY_STAT, [
            "Status of $arg:",
            $this->formatListLine($info),
            "End of status.",
        ]);
    }
    protected function cmdFEAT($conn, $arg)
    {
        $features = [
            "Features:",
            " UTF8",
            " MLST type*;size*;modify*;perm*;",
            " MLSD",
            " SIZE",
            " MDTM",
            " REST STREAM",
            " PASV",
            " EPSV",
            " EPRT",
        ];
        if (!empty($this->ssl_options)) {
            $features[] = " AUTH TLS";
            $features[] = " PBSZ";
            $features[] = " PROT";
        }
        $features[] = "End.";
        $this->reply($conn, self::REPLY_FEAT, $features);
    }
    protected function cmdOPTS($conn, $arg)
    {
        $upper = strtoupper(trim($arg));
        if (strpos($upper, 'UTF8') === 0) {
            $this->reply($conn, self::REPLY_OK, "UTF8 set.");
            return;
        }
        if (strpos($upper, 'MLST') === 0) {
            /*
                MLST OPTS lets the client toggle which facts
                appear in MLSD/MLST output. We accept and
                ignore; we always emit the same fact set.
             */
            $this->reply($conn, self::REPLY_OK,
                "MLST options set.");
            return;
        }
        $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
            "OPTS option not supported.");
    }
    /*
        --- Navigation ---
     */
    protected function cmdPWD($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $this->reply($conn, self::REPLY_PATHNAME,
            '"' . $conn->cwd . '" is the current directory.');
    }
    protected function cmdCWD($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        if ($arg === '') {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "CWD requires a path.");
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Cannot change to $arg.");
            return;
        }
        /*
            We track cwd in FTP-space (forward-slash, root-
            anchored) because that is what PWD reports.
            Combine the supplied arg with the current cwd in
            FTP-space, normalize, and store.
         */
        $conn->cwd = $this->normalizeFtpPath($conn->cwd, $arg);
        $this->reply($conn, self::REPLY_OK,
            "Directory changed to " . $conn->cwd . ".");
    }
    protected function cmdCDUP($conn, $arg)
    {
        $this->cmdCWD($conn, '..');
    }
    /**
     * Resolves an FTP-space path the same way resolveSafe
     * does for filesystem paths, but stays in FTP-space.
     * Used to keep $conn->cwd in canonical form after CWD.
     */
    protected function normalizeFtpPath($cwd, $arg)
    {
        if ($arg === '') {
            return $cwd;
        }
        if ($arg[0] === '/') {
            $combined = $arg;
        } else {
            $combined = rtrim($cwd, '/') . '/' . $arg;
        }
        $segments = [];
        foreach (explode('/', $combined) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }
        return '/' . implode('/', $segments);
    }
    /*
        --- Transfer mode ---
     */
    protected function cmdTYPE($conn, $arg)
    {
        $upper = strtoupper(trim($arg));
        if ($upper === 'I' || $upper === 'A' ||
            strpos($upper, 'I ') === 0 ||
            strpos($upper, 'A ') === 0) {
            $conn->type = $upper[0];
            $this->reply($conn, self::REPLY_OK,
                "Type set to " . $conn->type . ".");
            return;
        }
        $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
            "Only TYPE I (binary) and A (ASCII) supported.");
    }
    protected function cmdMODE($conn, $arg)
    {
        if (strtoupper(trim($arg)) === 'S') {
            $this->reply($conn, self::REPLY_OK,
                "Mode S (stream) set.");
            return;
        }
        $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
            "Only stream mode supported.");
    }
    protected function cmdSTRU($conn, $arg)
    {
        if (strtoupper(trim($arg)) === 'F') {
            $this->reply($conn, self::REPLY_OK,
                "File structure set.");
            return;
        }
        $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
            "Only file structure supported.");
    }
    /*
        --- Data-channel setup ---
     */
    protected function cmdPASV($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        list($listener, $port) =
            $this->bindPassiveListener($conn);
        if (!$listener) {
            $this->reply($conn, self::REPLY_LOCAL_ERROR,
                "Cannot allocate passive port.");
            return;
        }
        $conn->pasv_listener = $listener;
        $conn->pasv_port = $port;
        $conn->active_addr = false;
        /*
            PASV reply syntax (RFC 959 sec 3.2.1):
                227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            where h1-h4 are the four octets of the IPv4
            address and p1*256 + p2 = port. Some clients
            require commas inside the parens; some demand the
            literal phrase "Entering Passive Mode" -- both are
            included for maximum compatibility.
         */
        $ip = $this->advertiseIp($conn);
        $octets = explode('.', $ip);
        if (count($octets) !== 4) {
            $octets = ['127', '0', '0', '1'];
        }
        $p1 = ($port >> 8) & 0xFF;
        $p2 = $port & 0xFF;
        $tuple = implode(',', $octets) . ",$p1,$p2";
        $this->reply($conn, self::REPLY_PASV_OK,
            "Entering Passive Mode ($tuple).");
    }
    protected function cmdEPSV($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        list($listener, $port) =
            $this->bindPassiveListener($conn);
        if (!$listener) {
            $this->reply($conn, self::REPLY_LOCAL_ERROR,
                "Cannot allocate passive port.");
            return;
        }
        $conn->pasv_listener = $listener;
        $conn->pasv_port = $port;
        $conn->active_addr = false;
        /*
            EPSV reply (RFC 2428): the protocol family and IP
            are intentionally elided so the client uses the
            same address it already opened the control
            connection on. The format is:
                229 Entering Extended Passive Mode (|||port|)
            with three empty fields and the port between the
            outer pipes.
         */
        $this->reply($conn, self::REPLY_EPSV_OK,
            "Entering Extended Passive Mode (|||$port|).");
    }
    protected function cmdPORT($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $parts = explode(',', $arg);
        if (count($parts) !== 6) {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "PORT requires h1,h2,h3,h4,p1,p2.");
            return;
        }
        $host = $parts[0] . '.' . $parts[1] . '.' .
            $parts[2] . '.' . $parts[3];
        $port = ((int) $parts[4]) * 256 + (int) $parts[5];
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        $conn->active_addr = [$host, $port];
        $this->reply($conn, self::REPLY_OK,
            "PORT command successful.");
    }
    protected function cmdEPRT($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        /*
            EPRT format (RFC 2428):
                EPRT <d><net-prt><d><net-addr><d><tcp-port><d>
            Where <d> is a single delimiter character (usually
            "|") and net-prt is "1" for IPv4 or "2" for IPv6.
         */
        if (strlen($arg) < 7) {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "Bad EPRT format.");
            return;
        }
        $delim = $arg[0];
        $parts = explode($delim, $arg);
        if (count($parts) < 5) {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "Bad EPRT format.");
            return;
        }
        $host = $parts[2];
        $port = (int) $parts[3];
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        $conn->active_addr = [$host, $port];
        $this->reply($conn, self::REPLY_OK,
            "EPRT command successful.");
    }
    protected function cmdREST($conn, $arg)
    {
        $offset = (int) $arg;
        if ($offset < 0) {
            $this->reply($conn, self::REPLY_PARAM_ERR,
                "Bad REST offset.");
            return;
        }
        $conn->rest_offset = $offset;
        $this->reply($conn, self::REPLY_NEED_RNTO,
            "Restarting at $offset; send RETR or STOR.");
    }
    protected function cmdABOR($conn, $arg)
    {
        if ($conn->pasv_listener !== false) {
            @fclose($conn->pasv_listener);
            $conn->pasv_listener = false;
        }
        $this->reply($conn, self::REPLY_TRANSFER_OK,
            "Aborted.");
    }
    /*
        --- Listing ---
     */
    protected function cmdLIST($conn, $arg)
    {
        $this->doListing($conn, $arg, 'list');
    }
    protected function cmdNLST($conn, $arg)
    {
        $this->doListing($conn, $arg, 'nlst');
    }
    protected function cmdMLSD($conn, $arg)
    {
        $this->doListing($conn, $arg, 'mlsd');
    }
    protected function cmdMLST($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg !== '' ? $arg :
                $conn->cwd);
        if ($resolved === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Path not found.");
            return;
        }
        $info = $this->storage->statEntry($resolved);
        if ($info === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Path not found.");
            return;
        }
        /*
            MLST replies inline on the control channel with a
            single 250 multi-line reply: the first line is the
            "Listing" header, the middle lines (indented with
            a leading space per RFC 3659) are the facts, and
            the last line closes.
         */
        $facts = $this->formatMlstLine($info,
            $arg !== '' ? $arg : $conn->cwd);
        $this->reply($conn, self::REPLY_OK, [
            "Listing " . ($arg !== '' ? $arg : $conn->cwd),
            " " . $facts,
            "End of MLST.",
        ]);
    }
    /**
     * Shared body of LIST / NLST / MLSD: open the data
     * channel, write one line per entry in the appropriate
     * format, close.
     */
    protected function doListing($conn, $arg, $format)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $target = $arg !== '' ? $arg : $conn->cwd;
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $target);
        if ($resolved === false ||
            !$this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Cannot list $target.");
            return;
        }
        $entries = $this->storage->listing($resolved);
        if ($entries === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Cannot list $target.");
            return;
        }
        $this->reply($conn, self::REPLY_OPENING,
            "Opening data connection for listing.");
        $data = $this->openDataChannel($conn);
        if (!$data) {
            return;
        }
        foreach ($entries as $e) {
            if ($format === 'nlst') {
                $line = $e['name'];
            } else if ($format === 'mlsd') {
                $line = $this->formatMlstLine($e, $e['name']);
            } else {
                $line = $this->formatListLine($e);
            }
            @fwrite($data, $line . "\r\n");
        }
        @fclose($data);
        $this->reply($conn, self::REPLY_TRANSFER_OK,
            "Listing complete.");
    }
    /**
     * Formats one entry as an ls -l style line, the format
     * older clients expect from LIST. The owner / group
     * fields are constants because we do not surface
     * filesystem ownership through the storage layer (and
     * doing so cross-platform is more trouble than it is
     * worth for a demo).
     */
    protected function formatListLine($info)
    {
        $is_dir = ($info['type'] === 'dir');
        $perms = ($is_dir ? 'd' : '-') .
            $this->permString($info['mode']);
        $size = str_pad((string) $info['size'], 10,
            ' ', STR_PAD_LEFT);
        $when = date('M d H:i', $info['mtime']);
        return sprintf("%s 1 atto atto %s %s %s",
            $perms, $size, $when, $info['name']);
    }
    /**
     * Renders POSIX mode bits as the rwx string ls uses.
     */
    protected function permString($mode)
    {
        $out = '';
        for ($shift = 6; $shift >= 0; $shift -= 3) {
            $bits = ($mode >> $shift) & 0x7;
            $out .= ($bits & 0x4) ? 'r' : '-';
            $out .= ($bits & 0x2) ? 'w' : '-';
            $out .= ($bits & 0x1) ? 'x' : '-';
        }
        return $out;
    }
    /**
     * Formats one entry for MLSD/MLST: a semicolon-separated
     * list of fact=value pairs followed by a space and the
     * filename. RFC 3659 sec 7.5 defines the standard facts;
     * we emit type, size, modify, and perm.
     */
    protected function formatMlstLine($info, $name)
    {
        $type_value = ($info['type'] === 'dir') ?
            'dir' : 'file';
        $modify = gmdate('YmdHis', $info['mtime']);
        $perm = ($info['type'] === 'dir') ? 'el' : 'r';
        $facts = "type=$type_value;size=" . $info['size'] .
            ";modify=$modify;perm=$perm;";
        return $facts . ' ' . $name;
    }
    /*
        --- File transfer ---
     */
    protected function cmdRETR($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved) ||
            $this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "File not found.");
            $conn->rest_offset = 0;
            return;
        }
        $stream = $this->storage->openRead($resolved,
            $conn->rest_offset);
        if ($stream === false) {
            $this->reply($conn, self::REPLY_FILE_BUSY,
                "Cannot open file.");
            $conn->rest_offset = 0;
            return;
        }
        $this->reply($conn, self::REPLY_OPENING,
            "Opening data connection for $arg.");
        $data = $this->openDataChannel($conn);
        if (!$data) {
            fclose($stream);
            $conn->rest_offset = 0;
            return;
        }
        $conn->rest_offset = 0;
        while (!feof($stream)) {
            $chunk = @fread($stream, 65536);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $written = 0;
            $length = strlen($chunk);
            while ($written < $length) {
                $n = @fwrite($data,
                    substr($chunk, $written));
                if ($n === false || $n === 0) {
                    break 2;
                }
                $written += $n;
            }
        }
        fclose($stream);
        @fclose($data);
        $this->reply($conn, self::REPLY_TRANSFER_OK,
            "Transfer complete.");
    }
    protected function cmdSTOR($conn, $arg)
    {
        $this->doUpload($conn, $arg, false);
    }
    protected function cmdAPPE($conn, $arg)
    {
        $this->doUpload($conn, $arg, true);
    }
    /**
     * Shared body for STOR / APPE: open the data channel,
     * stream incoming bytes through to storage, close.
     */
    protected function doUpload($conn, $arg, $append)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Bad path.");
            return;
        }
        $this->reply($conn, self::REPLY_OPENING,
            "Opening data connection for upload.");
        $data = $this->openDataChannel($conn);
        if (!$data) {
            return;
        }
        $ok = $this->storage->streamWrite($resolved, $data,
            $append);
        if ($ok) {
            $this->reply($conn, self::REPLY_TRANSFER_OK,
                "Upload complete.");
        } else {
            $this->reply($conn, self::REPLY_LOCAL_ERROR,
                "Upload failed.");
        }
    }
    protected function cmdDELE($conn, $arg)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved) ||
            $this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "File not found.");
            return;
        }
        if ($this->storage->deleteFile($resolved)) {
            $this->reply($conn, self::REPLY_OK,
                "File deleted.");
        } else {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Delete failed.");
        }
    }
    protected function cmdMKD($conn, $arg)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Bad path.");
            return;
        }
        if ($this->storage->makeDir($resolved)) {
            $created = $this->normalizeFtpPath(
                $conn->cwd, $arg);
            $this->reply($conn, self::REPLY_PATHNAME,
                '"' . $created . '" directory created.');
        } else {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Cannot create directory.");
        }
    }
    protected function cmdRMD($conn, $arg)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Directory not found.");
            return;
        }
        if ($this->storage->removeDir($resolved)) {
            $this->reply($conn, self::REPLY_OK,
                "Directory removed.");
        } else {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Remove failed (directory non-empty?).");
        }
    }
    protected function cmdRNFR($conn, $arg)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Source not found.");
            return;
        }
        $conn->pending_rename_from = $resolved;
        $this->reply($conn, self::REPLY_NEED_RNTO,
            "Send RNTO to complete rename.");
    }
    protected function cmdRNTO($conn, $arg)
    {
        if (!$this->requireAuth($conn) ||
            !$this->requireWrite($conn)) {
            return;
        }
        if ($conn->pending_rename_from === false) {
            $this->reply($conn, self::REPLY_BAD_SEQUENCE,
                "Send RNFR first.");
            return;
        }
        $to = $this->storage->resolveSafe($conn->cwd, $arg);
        $from = $conn->pending_rename_from;
        $conn->pending_rename_from = false;
        if ($to === false) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Bad target path.");
            return;
        }
        if ($this->storage->renameEntry($from, $to)) {
            $this->reply($conn, self::REPLY_OK,
                "Rename successful.");
        } else {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "Rename failed.");
        }
    }
    protected function cmdSIZE($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved) ||
            $this->storage->isDir($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "File not found.");
            return;
        }
        $info = $this->storage->statEntry($resolved);
        $this->reply($conn, self::REPLY_FEAT,
            (string) $info['size']);
    }
    protected function cmdMDTM($conn, $arg)
    {
        if (!$this->requireAuth($conn)) {
            return;
        }
        $resolved = $this->storage->resolveSafe($conn->cwd,
            $arg);
        if ($resolved === false ||
            !$this->storage->exists($resolved)) {
            $this->reply($conn, self::REPLY_FILE_UNAVAILABLE,
                "File not found.");
            return;
        }
        $info = $this->storage->statEntry($resolved);
        $this->reply($conn, self::REPLY_FEAT,
            gmdate('YmdHis', $info['mtime']));
    }
    /*
        --- Accept-and-ignore commands. Some clients send
        these for backward compatibility; we acknowledge
        without doing anything.
     */
    protected function cmdALLO($conn, $arg)
    {
        $this->reply($conn, self::REPLY_OK,
            "ALLO accepted.");
    }
    protected function cmdACCT($conn, $arg)
    {
        $this->reply($conn, self::REPLY_OK, "ACCT accepted.");
    }
    protected function cmdSITE($conn, $arg)
    {
        $this->reply($conn, self::REPLY_OK, "SITE accepted.");
    }
    /*
        --- FTPS (RFC 4217) ---
     */
    protected function cmdAUTH($conn, $arg)
    {
        $upper = strtoupper(trim($arg));
        if ($upper !== 'TLS' && $upper !== 'SSL' &&
            $upper !== 'TLS-C') {
            $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
                "AUTH type not supported.");
            return;
        }
        if (empty($this->ssl_options)) {
            $this->reply($conn, self::REPLY_NEEDS_TLS,
                "TLS not configured on this server.");
            return;
        }
        if ($conn->tls_active) {
            $this->reply($conn, self::REPLY_BAD_SEQUENCE,
                "Already in TLS.");
            return;
        }
        $this->reply($conn, self::REPLY_TLS_OK,
            "AUTH $upper OK; starting TLS.");
        if ($this->upgradeToTls($conn->control)) {
            $conn->tls_active = true;
            /*
                Per RFC 4217 sec 4.3, after AUTH TLS the
                client must re-send USER/PASS, so wipe any
                pending login state we have.
             */
            $conn->authed = false;
            $conn->pending_user = '';
            $conn->user_info = [];
        } else {
            /*
                Handshake failed; the connection is unusable.
                Close it.
             */
            $this->closeConnection($conn);
        }
    }
    protected function cmdPBSZ($conn, $arg)
    {
        /*
            For TLS PBSZ must be 0 (RFC 4217 sec 9). We
            accept any value to be liberal but always echo 0
            in the reply text so clients that parse it see
            the right thing.
         */
        $this->reply($conn, self::REPLY_OK, "PBSZ=0");
    }
    protected function cmdPROT($conn, $arg)
    {
        $upper = strtoupper(trim($arg));
        if ($upper === 'C') {
            /*
                C = Clear (data channel not protected).
             */
            $conn->prot_p = false;
            $this->reply($conn, self::REPLY_OK,
                "Data channel will be unprotected.");
            return;
        }
        if ($upper === 'P') {
            /*
                P = Private (data channel TLS-protected).
                The actual TLS handshake on the data socket
                happens in openDataChannel, after the
                client connects (PASV) or we connect to
                the client (PORT), but before any bytes
                flow on the data channel.
             */
            $conn->prot_p = true;
            $this->reply($conn, self::REPLY_OK,
                "Data channel will be protected.");
            return;
        }
        $this->reply($conn, self::REPLY_PARAM_NOT_IMPL,
            "Only PROT C and PROT P supported.");
    }
}
