<?php
/**
 * seekquarry\atto\SshSite -- a single-file SSH server
 * implementing RFC 4250-4254 (transport, authentication,
 * connection layer) plus the SFTP subsystem
 * (draft-ietf-secsh-filexfer-02). The transport uses
 * curve25519-sha256 key exchange (RFC 8731), Ed25519 host
 * keys (RFC 8709), and the aes128-ctr cipher with hmac-
 * sha2-256-etm@openssh.com message authentication.
 *
 * Two channel applications are provided out of the box:
 * the SFTP subsystem (file transfer with handle-based
 * access), and a small built-in shell with a fixed set of
 * commands suitable for demos. Production deployments are
 * expected to use the SFTP subsystem; the shell is there
 * to illustrate the channel layer rather than to be a
 * real interactive login.
 *
 * Single-file philosophy: all crypto primitives are taken
 * from PHP's bundled extensions. Curve25519 scalar mult
 * and Ed25519 sign/verify come from ext-sodium; AES-CTR
 * and SHA-256 come from ext-openssl and ext-hash. There
 * are no Composer dependencies.
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
 * Abstract authenticator. Concrete subclasses validate
 * the credentials a client offers during the userauth
 * phase. Two methods cover SSH's two main credential
 * shapes:
 *
 *   checkPassword($username, $password)
 *       returns user-info array on success, false on
 *       failure
 *
 *   checkPublicKey($username, $algorithm, $blob,
 *                  $signature_or_null)
 *       called twice per pubkey attempt; first with
 *       $signature_or_null === null (the "would this key
 *       be acceptable" probe), then with a real signature
 *       to verify. Authenticators that don't trust the
 *       signature step would still implement verification
 *       of the signature blob using the public key blob;
 *       SshSite handles the signature verification itself
 *       and only calls checkPublicKey to decide whether
 *       this user is allowed to use this public key.
 *
 * The user-info array uses the same keys FtpAuthenticator
 * does, so a single user store can serve both servers:
 *
 *   'user'         (string) canonical username; required
 *   'login_folder' (string) for SFTP, the cwd to set on
 *                  open; defaults to "/"
 *   'read_only'    (bool)   if true, write operations
 *                  are rejected; defaults to false
 */
abstract class SshAuthenticator
{
    /**
     * Validates a username + password. Returns user info
     * array on success, or false on failure.
     *
     * @param string $username
     * @param string $password
     * @return array|false
     */
    abstract public function checkPassword($username,
        $password);
    /**
     * Validates a username + public-key offer. Called
     * twice per attempt: once to probe (with
     * $offer_only === true) and once for the signed
     * follow-up. The default implementation rejects all
     * pubkey offers; subclasses with a key store override.
     *
     * @param string $username
     * @param string $algorithm e.g. "ssh-ed25519"
     * @param string $key_blob raw SSH public-key blob
     * @param bool $offer_only true on the probe phase,
     *      false on the signed phase
     * @return array|false user info, or false to reject
     */
    public function checkPublicKey($username, $algorithm,
        $key_blob, $offer_only)
    {
        return false;
    }
}
/**
 * In-memory authenticator. Constructor takes a map of
 * username => password. Suitable for the demo and small
 * deployments; production servers would back this with a
 * database lookup. Public-key auth is not supported by
 * this authenticator; pair with AuthorizedKeysAuthenticator
 * in a CompositeAuthenticator if both are needed.
 */
class StaticSshAuthenticator extends SshAuthenticator
{
    /**
     * @var array map username => password (cleartext)
     */
    protected $users = [];
    /**
     * @var array map username => login_folder
     */
    protected $folders = [];
    /**
     * @var array map username => read_only flag
     */
    protected $read_only = [];
    /**
     * @param array $users
     *   either [username => password, ...] or
     *   [username => [
     *       'password' => string,
     *       'login_folder' => string (optional),
     *       'read_only' => bool (optional)],
     *    ...]
     */
    public function __construct($users)
    {
        foreach ($users as $name => $info) {
            if (is_string($info)) {
                $this->users[$name] = $info;
                $this->folders[$name] = '/';
                $this->read_only[$name] = false;
                continue;
            }
            $this->users[$name] = $info['password'] ?? '';
            $this->folders[$name] = $info['login_folder']
                ?? '/';
            $this->read_only[$name] = !empty(
                $info['read_only']);
        }
    }
    public function checkPassword($username, $password)
    {
        if (!isset($this->users[$username])) {
            return false;
        }
        if (!hash_equals($this->users[$username],
            $password)) {
            return false;
        }
        return [
            'user' => $username,
            'login_folder' => $this->folders[$username],
            'read_only' => $this->read_only[$username],
        ];
    }
}
/**
 * Public-key authenticator backed by an authorized_keys
 * file in the OpenSSH format -- one key per line, of the
 * form
 *
 *     <algorithm> <base64-blob> [comment]
 *
 * with optional leading options ignored. Supports
 * ssh-ed25519 and ssh-rsa (with rsa-sha2-256 and
 * rsa-sha2-512 signature algorithms) in this version.
 *
 * The constructor takes a map of username =>
 * authorized_keys_path so each user can have their own
 * file. A user with no entry in the map is rejected.
 */
class AuthorizedKeysAuthenticator extends SshAuthenticator
{
    /**
     * @var array map username => path to authorized_keys
     */
    protected $paths = [];
    /**
     * @var array map username => login_folder
     */
    protected $folders = [];
    /**
     * @var array map username => read_only flag
     */
    protected $read_only = [];
    /**
     * @param array $users
     *   [username => [
     *       'authorized_keys' => path,
     *       'login_folder' => string (optional),
     *       'read_only' => bool (optional)],
     *    ...]
     */
    public function __construct($users)
    {
        foreach ($users as $name => $info) {
            $this->paths[$name] = $info['authorized_keys']
                ?? '';
            $this->folders[$name] = $info['login_folder']
                ?? '/';
            $this->read_only[$name] = !empty(
                $info['read_only']);
        }
    }
    public function checkPassword($username, $password)
    {
        return false;
    }
    public function checkPublicKey($username, $algorithm,
        $key_blob, $offer_only)
    {
        if (!isset($this->paths[$username])) {
            return false;
        }
        $path = $this->paths[$username];
        if ($path === '' || !is_file($path)) {
            return false;
        }
        $lines = @file($path,
            FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return false;
        }
        foreach ($lines as $line) {
            $line = ltrim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $parts = preg_split('/\s+/', $line, 3);
            if (count($parts) < 2) {
                continue;
            }
            $alg = $parts[0];
            $b64 = $parts[1];
            $stored = base64_decode($b64, true);
            if ($stored === false) {
                continue;
            }
            /*
                For verification SshSite has already
                checked that the offered $algorithm matches
                what the public-key blob declares. Here we
                only need to confirm the blob bytes match
                what the user has on file.
             */
            if (hash_equals($stored, $key_blob)) {
                return [
                    'user' => $username,
                    'login_folder' => $this->folders[
                        $username],
                    'read_only' => $this->read_only[
                        $username],
                ];
            }
        }
        return false;
    }
}
/**
 * Tries a list of authenticators in order; the first one
 * that accepts the credential wins. Same shape as
 * FtpSite's CompositeAuthenticator.
 */
class CompositeSshAuthenticator extends SshAuthenticator
{
    /**
     * @var SshAuthenticator[]
     */
    protected $delegates = [];
    /**
     * @param SshAuthenticator[] $delegates
     */
    public function __construct($delegates)
    {
        $this->delegates = $delegates;
    }
    public function checkPassword($username, $password)
    {
        foreach ($this->delegates as $d) {
            $r = $d->checkPassword($username, $password);
            if ($r !== false) {
                return $r;
            }
        }
        return false;
    }
    public function checkPublicKey($username, $algorithm,
        $key_blob, $offer_only)
    {
        foreach ($this->delegates as $d) {
            $r = $d->checkPublicKey($username, $algorithm,
                $key_blob, $offer_only);
            if ($r !== false) {
                return $r;
            }
        }
        return false;
    }
}
/**
 * Per-connection state. One instance per accepted TCP
 * socket. Holds the raw socket, the read/write packet
 * sequence numbers, the negotiated encryption keys, and
 * any open channels on this connection.
 *
 * The state advances through phases: BANNER (waiting for
 * the client's "SSH-2.0-..." line), KEXINIT (waiting for
 * the client's KEXINIT or having sent ours), KEX_ECDH
 * (curve25519 in flight), NEWKEYS (waiting for the
 * client's NEWKEYS), AUTH (running userauth), and
 * CONNECTED (channels can now be opened).
 */
class SshConnection
{
    const PHASE_BANNER = 0;
    const PHASE_KEXINIT = 1;
    const PHASE_KEX_ECDH = 2;
    const PHASE_NEWKEYS = 3;
    const PHASE_AUTH = 4;
    const PHASE_CONNECTED = 5;
    /**
     * @var resource the TCP socket, set non-blocking
     */
    public $socket = null;
    /**
     * @var string client's address (for logging)
     */
    public $peer = "";
    /**
     * @var int one of the PHASE_ constants
     */
    public $phase = self::PHASE_BANNER;
    /**
     * @var string accumulated read buffer; raw bytes off
     *      the socket that have not yet been consumed by
     *      the protocol decoder
     */
    public $read_buf = "";
    /**
     * @var string accumulated write buffer; bytes the
     *      protocol layer has produced but that have not
     *      yet been flushed to the socket
     */
    public $write_buf = "";
    /**
     * @var string client's identification string from the
     *      banner exchange ("SSH-2.0-..."), without the
     *      trailing CRLF. Used in the exchange-hash KDF.
     */
    public $client_version = "";
    /**
     * @var string our identification string, sent at the
     *      start of the conversation
     */
    public $server_version = "";
    /**
     * @var string client's KEXINIT payload (excluding the
     *      packet framing -- just the algorithm name lists
     *      and the message-type byte). Saved for use in
     *      the exchange-hash computation.
     */
    public $client_kexinit = "";
    /**
     * @var string our KEXINIT payload, similarly saved
     */
    public $server_kexinit = "";
    /**
     * @var string ephemeral curve25519 secret key (32
     *      bytes), generated for this connection's KEX
     */
    public $kex_secret = "";
    /**
     * @var string ephemeral curve25519 public key (32
     *      bytes), sent to the client in the KEX_ECDH_REPLY
     */
    public $kex_public = "";
    /**
     * @var string the session ID -- the very first
     *      exchange-hash, frozen for the life of the
     *      connection. Used in pubkey-auth signatures.
     */
    public $session_id = "";
    /**
     * @var int outgoing packet sequence number; starts at
     *      0, increments after every packet sent
     */
    public $send_seq = 0;
    /**
     * @var int incoming packet sequence number; starts at
     *      0, increments after every packet received
     */
    public $recv_seq = 0;
    /**
     * @var bool true once we've sent NEWKEYS and so all
     *      future outgoing packets are encrypted
     */
    public $send_encrypted = false;
    /**
     * @var bool true once we've received NEWKEYS from the
     *      client and so all future incoming packets are
     *      expected to be encrypted
     */
    public $recv_encrypted = false;
    /**
     * @var string AES-128-CTR encryption key (server->
     *      client direction), 16 bytes
     */
    public $send_enc_key = "";
    /**
     * @var string AES-128-CTR initial counter (server->
     *      client direction), 16 bytes
     */
    public $send_enc_iv = "";
    /**
     * @var string HMAC-SHA-256 key (server->client), 32
     *      bytes
     */
    public $send_mac_key = "";
    /**
     * @var string AES-128-CTR encryption key (client->
     *      server direction)
     */
    public $recv_enc_key = "";
    /**
     * @var string AES-128-CTR initial counter (client->
     *      server direction)
     */
    public $recv_enc_iv = "";
    /**
     * @var string HMAC-SHA-256 key (client->server)
     */
    public $recv_mac_key = "";
    /**
     * @var string current AES-CTR counter state for
     *      send (rolls forward each block)
     */
    public $send_ctr = "";
    /**
     * @var string current AES-CTR counter state for recv
     */
    public $recv_ctr = "";
    /**
     * @var array authenticated user-info, set after a
     *      successful userauth. null until then.
     */
    public $user_info = null;
    /**
     * @var int number of failed auth attempts (RFC 4252
     *      sec 4 suggests disconnecting after some bound)
     */
    public $auth_failures = 0;
    /**
     * @var array open channels: server_channel_id => SshChannel
     */
    public $channels = [];
    /**
     * @var int next server-side channel id to hand out
     */
    public $next_channel_id = 0;
    /**
     * @var bool flag to tear this connection down on the
     *      next loop iteration
     */
    public $disconnect = false;
}
/**
 * Per-channel state. SSH multiplexes many independent
 * "channels" inside a single connection; each channel
 * has its own flow-control window and may be running a
 * shell, an exec, or a subsystem.
 */
class SshChannel
{
    const TYPE_SESSION = 'session';
    /**
     * @var int our (server-side) id for this channel
     */
    public $local_id = 0;
    /**
     * @var int the remote (client-side) id we use when
     *      sending channel messages back to the client
     */
    public $remote_id = 0;
    /**
     * @var int outgoing flow-control window: how many
     *      bytes the client says we may send before they
     *      need to send us a WINDOW_ADJUST. We decrement
     *      this on every CHANNEL_DATA we send.
     */
    public $remote_window = 0;
    /**
     * @var int incoming flow-control window: how many
     *      bytes we've told the client they may send.
     *      Decrement on every CHANNEL_DATA we receive;
     *      send WINDOW_ADJUST when it gets low.
     */
    public $local_window = 0;
    /**
     * @var int max packet size the client wants us to use
     */
    public $remote_max_packet = 0;
    /**
     * @var int max packet size we want from the client
     */
    public $local_max_packet = 0;
    /**
     * @var string channel type, e.g. "session"
     */
    public $type = "";
    /**
     * @var bool we have sent EOF
     */
    public $eof_sent = false;
    /**
     * @var bool the client has sent EOF
     */
    public $eof_received = false;
    /**
     * @var bool we have sent CLOSE
     */
    public $close_sent = false;
    /**
     * @var bool the client has sent CLOSE
     */
    public $close_received = false;
    /**
     * @var string subsystem name once a subsystem request
     *      has been accepted ("sftp", "shell", "exec")
     */
    public $app = "";
    /**
     * @var mixed application-level state. For SFTP this
     *      is an associative array of file/dir handles;
     *      for shell it's the line-edit buffer; etc.
     */
    public $app_state = null;
}
/*
    --- SSH wire-format primitives (RFC 4251 sec 5) ---

    SSH defines a small set of typed primitives that
    appear inside packet payloads:

        byte                one octet
        uint32              four octets, big-endian
        uint64              eight octets, big-endian
        string              uint32 length + that many
                            bytes (binary clean)
        name-list           string whose contents are
                            comma-separated tokens
        mpint               two's-complement signed
                            big-endian, encoded as a
                            string. Special rules:
                            positive numbers whose top
                            byte has the high bit set
                            must have a leading 0x00
                            byte added to keep them
                            positive; zero is encoded
                            as an empty string.

    These helpers (declared as a trait) are mixed into
    SshSite and into SftpSubsystem; the SFTP layer reuses
    the same string/uint32 encoding.
 */
trait SshWireFormat
{
    /**
     * Encodes an SSH "string": a uint32 length followed
     * by that many bytes.
     */
    protected function packString($s)
    {
        return pack('N', strlen($s)) . $s;
    }
    /**
     * Reads an SSH string. Returns [value, new_offset].
     * Returns [false, $off] on overrun.
     */
    protected function readString($buf, $off)
    {
        if ($off + 4 > strlen($buf)) {
            return [false, $off];
        }
        $u = unpack('Nlen', substr($buf, $off, 4));
        $len = $u['len'];
        if ($off + 4 + $len > strlen($buf)) {
            return [false, $off];
        }
        return [substr($buf, $off + 4, $len),
            $off + 4 + $len];
    }
    /**
     * Reads a single byte, returns [value, new_offset].
     */
    protected function readByte($buf, $off)
    {
        if ($off + 1 > strlen($buf)) {
            return [false, $off];
        }
        return [ord($buf[$off]), $off + 1];
    }
    /**
     * Reads a uint32, returns [value, new_offset].
     */
    protected function readUint32($buf, $off)
    {
        if ($off + 4 > strlen($buf)) {
            return [false, $off];
        }
        $u = unpack('Nv', substr($buf, $off, 4));
        return [$u['v'], $off + 4];
    }
    /**
     * Encodes an mpint from a big-endian unsigned binary
     * representation (arbitrary length). Strips redundant
     * leading zero bytes; adds one back if the high bit
     * of the resulting top byte is set, to keep the
     * two's-complement value positive.
     */
    protected function packMpint($be_unsigned)
    {
        /* strip leading zero bytes */
        $i = 0;
        while ($i < strlen($be_unsigned) - 1 &&
            $be_unsigned[$i] === "\x00") {
            $i++;
        }
        $b = substr($be_unsigned, $i);
        if ($b === "\x00") {
            return $this->packString("");
        }
        if (ord($b[0]) & 0x80) {
            $b = "\x00" . $b;
        }
        return $this->packString($b);
    }
    /**
     * Encodes an array of tokens as an SSH name-list
     * (RFC 4251 sec 5).
     */
    protected function packNameList($names)
    {
        return $this->packString(implode(',', $names));
    }
    /**
     * Reads an SSH name-list, returns [array, new_offset].
     */
    protected function readNameList($buf, $off)
    {
        list($s, $off2) = $this->readString($buf, $off);
        if ($s === false) {
            return [false, $off];
        }
        if ($s === '') {
            return [[], $off2];
        }
        return [explode(',', $s), $off2];
    }
}
/**
 * The SSH server. Configures via chained setters and
 * runs the protocol loop in listen().
 *
 *     $ssh = new SshSite();
 *     $ssh->auth(new StaticSshAuthenticator(['alice' =>
 *             'hunter2']))
 *         ->storage(new FilesystemFtpStorage('/srv/sftp'))
 *         ->hostKey('/etc/atto/ssh_host_ed25519')
 *         ->software('atto-ssh 1.0')
 *         ->enableSftp(true)
 *         ->enableShell(true);
 *     $ssh->listen(['BIND' => '::', 'SSH_PORT' => 12122]);
 */
class SshSite
{
    use SshWireFormat;
    /*
        --- SSH message-type bytes (RFC 4250 sec 4.1) ---
        Transport layer: 1-19 generic, 20-29 algorithm
        negotiation, 30-49 method-specific.
     */
    const MSG_DISCONNECT = 1;
    const MSG_IGNORE = 2;
    const MSG_UNIMPLEMENTED = 3;
    const MSG_DEBUG = 4;
    const MSG_SERVICE_REQUEST = 5;
    const MSG_SERVICE_ACCEPT = 6;
    const MSG_KEXINIT = 20;
    const MSG_NEWKEYS = 21;
    /*
        Curve25519 KEX shares wire numbers with classic
        ECDH KEX (RFC 5656 sec 7.1): 30 = ECDH_INIT
        (client -> server, contains client public Q_C),
        31 = ECDH_REPLY (server -> client, contains
        server's host key K_S, server's ephemeral public
        Q_S, and the signature of the exchange hash H).
     */
    const MSG_KEX_ECDH_INIT = 30;
    const MSG_KEX_ECDH_REPLY = 31;
    /*
        Userauth (RFC 4252).
     */
    const MSG_USERAUTH_REQUEST = 50;
    const MSG_USERAUTH_FAILURE = 51;
    const MSG_USERAUTH_SUCCESS = 52;
    const MSG_USERAUTH_BANNER = 53;
    /*
        Userauth method-specific. 60 is reused by several
        methods: with publickey it's PK_OK, with password
        it's PASSWD_CHANGEREQ, etc.
     */
    const MSG_USERAUTH_PK_OK = 60;
    /*
        Connection layer (RFC 4254).
     */
    const MSG_GLOBAL_REQUEST = 80;
    const MSG_REQUEST_SUCCESS = 81;
    const MSG_REQUEST_FAILURE = 82;
    const MSG_CHANNEL_OPEN = 90;
    const MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    const MSG_CHANNEL_OPEN_FAILURE = 92;
    const MSG_CHANNEL_WINDOW_ADJUST = 93;
    const MSG_CHANNEL_DATA = 94;
    const MSG_CHANNEL_EXTENDED_DATA = 95;
    const MSG_CHANNEL_EOF = 96;
    const MSG_CHANNEL_CLOSE = 97;
    const MSG_CHANNEL_REQUEST = 98;
    const MSG_CHANNEL_SUCCESS = 99;
    const MSG_CHANNEL_FAILURE = 100;
    /*
        Disconnect reason codes (RFC 4250 sec 4.2).
     */
    const DC_PROTOCOL_ERROR = 2;
    const DC_KEY_EXCHANGE_FAILED = 3;
    const DC_MAC_ERROR = 5;
    const DC_SERVICE_NOT_AVAILABLE = 7;
    const DC_BY_APPLICATION = 11;
    /*
        Channel-open failure codes (RFC 4254 sec 5.1).
     */
    const COF_ADMINISTRATIVELY_PROHIBITED = 1;
    const COF_CONNECT_FAILED = 2;
    const COF_UNKNOWN_CHANNEL_TYPE = 3;
    const COF_RESOURCE_SHORTAGE = 4;
    /*
        Initial flow-control window we advertise per
        channel. OpenSSH uses 2 MiB; we use the same.
     */
    const INITIAL_WINDOW = 2097152;
    const MAX_PACKET = 32768;
    /*
        Hard cap on auth attempts before we drop the
        connection (RFC 4252 sec 4 suggests something).
     */
    const MAX_AUTH_FAILURES = 6;
    /**
     * @var SshAuthenticator|null
     */
    protected $authenticator = null;
    /**
     * @var FtpStorage|null storage backend for SFTP. Reused
     *      directly from FtpSite -- the abstraction is the
     *      same.
     */
    protected $storage = null;
    /**
     * @var string path to the host-key file. If the file
     *      is missing on first listen() it is generated.
     */
    protected $host_key_path = '';
    /**
     * @var string SSH-2.0-... identification string (the
     *      part after "SSH-2.0-")
     */
    protected $software = 'atto-ssh_1.0';
    /**
     * @var bool whether to accept "subsystem sftp" channel
     *      requests
     */
    protected $enable_sftp = true;
    /**
     * @var bool whether to accept "shell" channel requests
     */
    protected $enable_shell = false;
    /**
     * @var bool whether to accept "exec" channel requests
     */
    protected $enable_exec = false;
    /**
     * @var array configuration from listen()
     */
    protected $config = [];
    /**
     * @var resource the TCP listener
     */
    protected $listener = null;
    /**
     * @var array open SshConnection objects, keyed by an
     *      integer id
     */
    protected $connections = [];
    /**
     * @var int next connection id
     */
    protected $next_conn_id = 0;
    /**
     * @var string Ed25519 secret key (64 bytes -- this is
     *      the libsodium "secret key" form which actually
     *      contains both the seed and the public key)
     */
    protected $host_secret = '';
    /**
     * @var string Ed25519 public key (32 bytes)
     */
    protected $host_public = '';
    /**
     * @var string the SSH-format public-key blob for the
     *      host key, used in KEX ("ssh-ed25519" string +
     *      32-byte public-key string)
     */
    protected $host_blob = '';
    public function auth($authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
    public function storage($storage)
    {
        $this->storage = $storage;
        return $this;
    }
    public function hostKey($path)
    {
        $this->host_key_path = $path;
        return $this;
    }
    public function software($s)
    {
        $this->software = $s;
        return $this;
    }
    public function enableSftp($flag)
    {
        $this->enable_sftp = (bool) $flag;
        return $this;
    }
    public function enableShell($flag)
    {
        $this->enable_shell = (bool) $flag;
        return $this;
    }
    public function enableExec($flag)
    {
        $this->enable_exec = (bool) $flag;
        return $this;
    }
    /*
        ============================================================
        --- Server lifecycle ---
        ============================================================
     */
    /**
     * Binds the TCP listener and runs the dispatch loop.
     * Returns when the loop exits.
     *
     * Recognized configuration keys:
     *
     *   BIND          (string) listener bind address.
     *                 Default "127.0.0.1".
     *   SSH_PORT      (int) TCP port. Default 22 (which
     *                 requires privilege; demos use a
     *                 high port).
     *   IDLE_TIMEOUT  (int) seconds of idleness before
     *                 a connection is closed. Default
     *                 600.
     */
    public function listen($config = [])
    {
        $defaults = [
            'BIND' => '127.0.0.1',
            'SSH_PORT' => 22,
            'IDLE_TIMEOUT' => 600,
        ];
        $this->config = array_merge($defaults, $config);
        if (!$this->loadOrCreateHostKey()) {
            echo "Failed to load or create host key at " .
                $this->host_key_path . "\n";
            return false;
        }
        $bind = $this->config['BIND'];
        $port = $this->config['SSH_PORT'];
        $addr = (strpos($bind, ':') !== false) ?
            "tcp://[$bind]:$port" : "tcp://$bind:$port";
        $errno = 0;
        $errstr = '';
        $listener = @stream_socket_server($addr, $errno,
            $errstr);
        if (!$listener) {
            echo "Failed to bind SSH $addr: $errstr\n";
            return false;
        }
        stream_set_blocking($listener, 0);
        $this->listener = $listener;
        echo "atto-ssh listening: $addr\n";
        $this->loop();
        return true;
    }
    /**
     * Loads the host key from $host_key_path, or generates
     * a fresh Ed25519 keypair if the file does not exist.
     *
     * Storage format (atto's own; not OpenSSH-compatible):
     *
     *     # atto ssh ed25519 host key
     *     <base64-encoded 64-byte sodium secret key>
     *
     * The libsodium secret-key form already contains the
     * public key, so one line is enough.
     */
    protected function loadOrCreateHostKey()
    {
        if ($this->host_key_path === '') {
            /*
                No path configured -- generate an ephemeral
                key. The connection will work but clients
                will see a different host key on every
                server restart, which is exactly the warning
                shape that tells operators to wire up
                hostKey() before going to production.
             */
            $kp = sodium_crypto_sign_keypair();
            $this->host_secret =
                sodium_crypto_sign_secretkey($kp);
            $this->host_public =
                sodium_crypto_sign_publickey($kp);
            $this->host_blob = $this->packString(
                'ssh-ed25519') . $this->packString(
                $this->host_public);
            return true;
        }
        if (is_file($this->host_key_path)) {
            $raw = @file_get_contents($this->host_key_path);
            if ($raw === false) {
                return false;
            }
            $b64 = '';
            foreach (explode("\n", $raw) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $b64 = $line;
                break;
            }
            $sk = base64_decode($b64, true);
            if ($sk === false || strlen($sk) !==
                SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                return false;
            }
            $this->host_secret = $sk;
            $this->host_public =
                sodium_crypto_sign_publickey_from_secretkey(
                $sk);
        } else {
            /*
                First run on this host; mint a fresh
                keypair and save it.
             */
            $kp = sodium_crypto_sign_keypair();
            $this->host_secret =
                sodium_crypto_sign_secretkey($kp);
            $this->host_public =
                sodium_crypto_sign_publickey($kp);
            $body = "# atto ssh ed25519 host key\n" .
                base64_encode($this->host_secret) . "\n";
            if (@file_put_contents($this->host_key_path,
                $body) === false) {
                return false;
            }
            @chmod($this->host_key_path, 0600);
        }
        $this->host_blob = $this->packString(
            'ssh-ed25519') . $this->packString(
            $this->host_public);
        return true;
    }
    /**
     * Main dispatch loop. select()s across the listener
     * and every active connection's socket; routes
     * readable events to onClientReadable and writable
     * events to flushing the per-connection write buffer.
     */
    protected function loop()
    {
        while (true) {
            $reads = [$this->listener];
            $writes = [];
            foreach ($this->connections as $conn) {
                $reads[] = $conn->socket;
                if ($conn->write_buf !== '') {
                    $writes[] = $conn->socket;
                }
            }
            $ex = null;
            $n = @stream_select($reads, $writes, $ex,
                1, 0);
            if ($n === false) {
                continue;
            }
            if ($n > 0) {
                foreach ($reads as $sock) {
                    if ($sock === $this->listener) {
                        $this->acceptConnection();
                    } else {
                        $this->onClientReadable($sock);
                    }
                }
                foreach ($writes as $sock) {
                    $this->flushConnection($sock);
                }
            }
            $this->reapDisconnected();
        }
    }
    /**
     * Accepts one queued TCP connection, sets non-blocking,
     * sends our identification banner, and registers the
     * connection in $this->connections.
     */
    protected function acceptConnection()
    {
        $peer = '';
        $sock = @stream_socket_accept($this->listener,
            0, $peer);
        if (!$sock) {
            return;
        }
        stream_set_blocking($sock, 0);
        $conn = new SshConnection();
        $conn->socket = $sock;
        $conn->peer = $peer;
        $conn->server_version = 'SSH-2.0-' .
            $this->software;
        /*
            RFC 4253 sec 4.2: the server's identification
            string is sent immediately on connect (well,
            after the optional pre-banner lines, which we
            don't use). The string is followed by CRLF;
            the version stored in $conn->server_version
            does NOT include the CRLF (it's used in the
            exchange-hash KDF without it).
         */
        $conn->write_buf = $conn->server_version . "\r\n";
        $id = $this->next_conn_id++;
        $this->connections[$id] = $conn;
    }
    /**
     * Reads available bytes from the connection's socket
     * into its read buffer, then drives the protocol
     * decoder. The decoder's job is to turn buffered
     * bytes into a sequence of well-defined events
     * (banner received, packet received) and dispatch
     * each to a handler.
     */
    protected function onClientReadable($sock)
    {
        $conn = $this->lookupConnection($sock);
        if ($conn === null) {
            return;
        }
        $buf = @fread($sock, 8192);
        if ($buf === false || $buf === '') {
            /*
                A zero-byte read on a non-blocking socket
                indicates the peer closed; mark the
                connection for teardown.
             */
            $meta = @stream_get_meta_data($sock);
            if (!empty($meta['eof'])) {
                $conn->disconnect = true;
            }
            return;
        }
        $conn->read_buf .= $buf;
        $this->driveProtocol($conn);
    }
    /**
     * Locates an SshConnection by its socket resource.
     */
    protected function lookupConnection($sock)
    {
        foreach ($this->connections as $conn) {
            if ($conn->socket === $sock) {
                return $conn;
            }
        }
        return null;
    }
    /**
     * Flushes as much of the connection's write buffer to
     * the socket as the kernel will accept right now.
     */
    protected function flushConnection($sock)
    {
        $conn = $this->lookupConnection($sock);
        if ($conn === null || $conn->write_buf === '') {
            return;
        }
        $n = @fwrite($sock, $conn->write_buf);
        if ($n === false) {
            $conn->disconnect = true;
            return;
        }
        if ($n > 0) {
            $conn->write_buf = substr($conn->write_buf, $n);
        }
    }
    /**
     * Removes connections that have been marked for
     * teardown.
     */
    protected function reapDisconnected()
    {
        foreach ($this->connections as $id => $conn) {
            if ($conn->disconnect && $conn->write_buf
                === '') {
                @fclose($conn->socket);
                unset($this->connections[$id]);
            }
        }
    }
    /**
     * Protocol decoder. Called every time bytes arrive on
     * a connection. Dispatches by phase: in BANNER phase
     * we look for the client's "SSH-2.0-..." line; in any
     * other phase we look for full SSH packets and route
     * them to handlers by message-type byte.
     *
     * The method consumes as much of the read buffer as
     * possible before returning, in case multiple packets
     * arrived in one TCP read.
     */
    protected function driveProtocol($conn)
    {
        if ($conn->phase === SshConnection::PHASE_BANNER) {
            if (!$this->consumeBanner($conn)) {
                return;
            }
            /*
                Banner consumed; immediately send our
                KEXINIT and advance to KEXINIT phase.
             */
            $this->sendKexInit($conn);
            $conn->phase = SshConnection::PHASE_KEXINIT;
        }
        while (true) {
            $packet = $this->readPacket($conn);
            if ($packet === null) {
                break;
            }
            if ($packet === false) {
                $conn->disconnect = true;
                return;
            }
            $this->handlePacket($conn, $packet);
            if ($conn->disconnect) {
                return;
            }
        }
    }
    /**
     * Consumes the client's identification banner (a line
     * ending in CRLF or LF, starting with "SSH-2.0-").
     * RFC 4253 sec 4.2 allows the server to send any
     * number of UTF-8 lines BEFORE its own identification
     * banner; we don't, but we tolerate the same on the
     * client side.
     *
     * Returns true if a banner was consumed and stored,
     * false if more bytes are needed.
     */
    protected function consumeBanner($conn)
    {
        while (true) {
            $eol = strpos($conn->read_buf, "\n");
            if ($eol === false) {
                if (strlen($conn->read_buf) > 8192) {
                    $conn->disconnect = true;
                }
                return false;
            }
            $line = substr($conn->read_buf, 0, $eol);
            if (substr($line, -1) === "\r") {
                $line = substr($line, 0, -1);
            }
            $conn->read_buf = substr($conn->read_buf,
                $eol + 1);
            if (substr($line, 0, 4) === 'SSH-') {
                $conn->client_version = $line;
                return true;
            }
            /*
                Pre-banner garbage; loop to try the next
                line.
             */
        }
    }
    /*
        ============================================================
        --- SSH binary packet protocol (RFC 4253 sec 6) ---
        ============================================================

        Wire layout of one packet:

            uint32   packet_length     (NOT including itself,
                                        NOT including mac)
            byte     padding_length    (4..255)
            byte[n]  payload           (n = packet_length
                                        - padding_length - 1)
            byte[p]  random_padding
            byte[m]  mac               (only when encryption
                                        is on; m = 32 for
                                        hmac-sha2-256)

        Total bytes of (packet_length || padding_length ||
        payload || padding) must be a multiple of the
        cipher block size (16 for AES) and at least 16.
        Padding must be between 4 and 255 bytes inclusive.

        We use hmac-sha2-256-etm@openssh.com once encryption
        is on. ETM = encrypt-then-MAC, so:

          - The length field is sent in CLEARTEXT (the
            receiver needs it to know how many ciphertext
            bytes to read before they can verify the MAC).
          - padding_length || payload || padding is
            encrypted with AES-128-CTR.
          - The MAC is computed over
            (seq_num || encrypted_length || ciphertext).

        Pre-encryption packets (the ones during version and
        KEX exchange, before NEWKEYS) have no MAC and no
        cipher: the whole packet is plaintext.
     */
    /**
     * Encodes a payload as a complete SSH packet ready to
     * append to the connection's write buffer. Picks a
     * pad-length that brings the total to a multiple of
     * the block size and meets the >=4 padding minimum.
     *
     * Returns the bytes to send.
     */
    protected function buildPacket($conn, $payload)
    {
        $block = $conn->send_encrypted ? 16 : 8;
        /*
            For ETM mode the length field is NOT encrypted,
            so the 4-byte length itself doesn't count
            toward the block-alignment constraint -- only
            (padding_length || payload || padding) needs
            to be a multiple of the block size. For the
            initial unencrypted phase RFC 4253 sec 6
            requires the WHOLE packet (including length
            field) to align, so we treat the minimum block
            size as 8 in cleartext mode and still count
            from packet_length.
         */
        if ($conn->send_encrypted) {
            $base = 1 + strlen($payload);
            $pad = $block - ($base % $block);
            if ($pad < 4) {
                $pad += $block;
            }
        } else {
            $base = 4 + 1 + strlen($payload);
            $pad = $block - ($base % $block);
            if ($pad < 4) {
                $pad += $block;
            }
        }
        $padding = random_bytes($pad);
        $packet_length = 1 + strlen($payload) + $pad;
        $clear = pack('N', $packet_length) . chr($pad) .
            $payload . $padding;
        if (!$conn->send_encrypted) {
            $conn->send_seq = ($conn->send_seq + 1) &
                0xFFFFFFFF;
            return $clear;
        }
        /*
            ETM: encrypt only the bytes after the 4-byte
            length, then MAC the whole thing.
         */
        $cipher_input = substr($clear, 4);
        $ciphertext = $this->aesCtrEncrypt($conn,
            $cipher_input, true);
        $on_wire = substr($clear, 0, 4) . $ciphertext;
        $mac_in = pack('N', $conn->send_seq) . $on_wire;
        $mac = hash_hmac('sha256', $mac_in,
            $conn->send_mac_key, true);
        $conn->send_seq = ($conn->send_seq + 1) &
            0xFFFFFFFF;
        return $on_wire . $mac;
    }
    /**
     * Encrypts $data with AES-128-CTR using $conn's send
     * key and counter. The counter advances by one block
     * (16 bytes) for each block of $data and is stored
     * back into $conn->send_ctr (or recv_ctr if
     * $is_send is false).
     *
     * Implementation note: PHP's openssl_encrypt with
     * AES-128-CTR takes an IV that is the counter for
     * the FIRST block of the ciphertext, then OpenSSL
     * advances internally. We track the counter ourselves
     * across calls so we can resume mid-stream.
     */
    protected function aesCtrEncrypt($conn, $data, $is_send)
    {
        $key = $is_send ? $conn->send_enc_key :
            $conn->recv_enc_key;
        $ctr = $is_send ? $conn->send_ctr :
            $conn->recv_ctr;
        $out = openssl_encrypt($data, 'aes-128-ctr', $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $ctr);
        if ($out === false) {
            return '';
        }
        $blocks = intdiv(strlen($data) + 15, 16);
        $new_ctr = $this->incrementCounter($ctr, $blocks);
        if ($is_send) {
            $conn->send_ctr = $new_ctr;
        } else {
            $conn->recv_ctr = $new_ctr;
        }
        return $out;
    }
    /**
     * Adds $n to a 16-byte big-endian counter, returning
     * the new counter as 16 bytes.
     */
    protected function incrementCounter($ctr, $n)
    {
        $bytes = array_values(unpack('C*', $ctr));
        for ($i = 15; $i >= 0 && $n > 0; $i--) {
            $sum = $bytes[$i] + ($n & 0xFF);
            $bytes[$i] = $sum & 0xFF;
            $carry = $sum >> 8;
            $n = ($n >> 8) + $carry;
        }
        $out = '';
        for ($i = 0; $i < 16; $i++) {
            $out .= chr($bytes[$i]);
        }
        return $out;
    }
    /**
     * Tries to decode one complete packet from $conn's
     * read buffer. Returns:
     *
     *   string  the payload (just the payload, with the
     *           padding stripped) on success
     *   null    not enough bytes yet; try again later
     *   false   protocol or MAC error; caller should
     *           tear down the connection
     */
    protected function readPacket($conn)
    {
        if (!$conn->recv_encrypted) {
            return $this->readPacketCleartext($conn);
        }
        return $this->readPacketEtm($conn);
    }
    /**
     * Cleartext-phase packet read. Used during banner +
     * KEX exchange before NEWKEYS.
     */
    protected function readPacketCleartext($conn)
    {
        if (strlen($conn->read_buf) < 4) {
            return null;
        }
        $u = unpack('Nlen', substr($conn->read_buf, 0, 4));
        $len = $u['len'];
        if ($len < 1 || $len > 35000) {
            return false;
        }
        if (strlen($conn->read_buf) < 4 + $len) {
            return null;
        }
        $packet = substr($conn->read_buf, 0, 4 + $len);
        $conn->read_buf = substr($conn->read_buf,
            4 + $len);
        $pad = ord($packet[4]);
        if ($pad < 4 || $pad > $len - 1) {
            return false;
        }
        $payload = substr($packet, 5, $len - 1 - $pad);
        $conn->recv_seq = ($conn->recv_seq + 1) &
            0xFFFFFFFF;
        return $payload;
    }
    /**
     * Encrypted-phase packet read with ETM MAC. Reads the
     * 4-byte cleartext length, then enough ciphertext +
     * mac bytes to decode and verify, then decrypts and
     * returns the payload.
     */
    protected function readPacketEtm($conn)
    {
        if (strlen($conn->read_buf) < 4) {
            return null;
        }
        $u = unpack('Nlen', substr($conn->read_buf, 0, 4));
        $len = $u['len'];
        if ($len < 1 || $len > 35000) {
            return false;
        }
        $mac_len = 32;
        $total = 4 + $len + $mac_len;
        if (strlen($conn->read_buf) < $total) {
            return null;
        }
        $on_wire = substr($conn->read_buf, 0, 4 + $len);
        $mac_recv = substr($conn->read_buf, 4 + $len,
            $mac_len);
        $mac_in = pack('N', $conn->recv_seq) . $on_wire;
        $mac_calc = hash_hmac('sha256', $mac_in,
            $conn->recv_mac_key, true);
        if (!hash_equals($mac_calc, $mac_recv)) {
            return false;
        }
        $ciphertext = substr($on_wire, 4);
        $clear = $this->aesCtrEncrypt($conn, $ciphertext,
            false);
        $pad = ord($clear[0]);
        if ($pad < 4 || $pad > strlen($clear) - 1) {
            return false;
        }
        $payload = substr($clear, 1, strlen($clear) - 1
            - $pad);
        $conn->read_buf = substr($conn->read_buf, $total);
        $conn->recv_seq = ($conn->recv_seq + 1) &
            0xFFFFFFFF;
        return $payload;
    }
    /**
     * Appends a packet to a connection's outgoing buffer.
     */
    protected function sendPacket($conn, $payload)
    {
        $conn->write_buf .= $this->buildPacket($conn,
            $payload);
    }
    /**
     * Sends a SSH_MSG_DISCONNECT and marks the connection
     * for teardown.
     */
    protected function sendDisconnect($conn, $reason,
        $description)
    {
        $payload = chr(self::MSG_DISCONNECT) .
            pack('N', $reason) .
            $this->packString($description) .
            $this->packString('en');
        $this->sendPacket($conn, $payload);
        $conn->disconnect = true;
    }
    /*
        ============================================================
        --- KEXINIT and algorithm negotiation (RFC 4253 sec 7) ---
        ============================================================

        The KEXINIT message is the first thing both sides
        send after the version banner. Its body is:

            byte         msg_type = 20 (SSH_MSG_KEXINIT)
            byte[16]     random cookie
            name-list    kex_algorithms
            name-list    server_host_key_algorithms
            name-list    encryption_algorithms_c2s
            name-list    encryption_algorithms_s2c
            name-list    mac_algorithms_c2s
            name-list    mac_algorithms_s2c
            name-list    compression_algorithms_c2s
            name-list    compression_algorithms_s2c
            name-list    languages_c2s
            name-list    languages_s2c
            boolean      first_kex_packet_follows
            uint32       reserved (always 0)

        Both sides compute the negotiated algorithms using
        a deterministic rule: walk the client's lists in
        order and pick the first one that the server
        also offers. That's the "client's preference wins"
        mode, which is the standard.

        We offer exactly one algorithm in each slot --
        because we only implement one each -- so the
        negotiation is trivial: it succeeds iff the client
        also offers our one choice.
     */
    /**
     * Sends our KEXINIT and stores the encoded payload
     * (without the message-type byte stripped, but as it
     * appears on the wire) for later use in the
     * exchange-hash computation.
     */
    protected function sendKexInit($conn)
    {
        $cookie = random_bytes(16);
        $kex = ['curve25519-sha256',
            'curve25519-sha256@libssh.org'];
        $hostkey = ['ssh-ed25519'];
        $enc = ['aes128-ctr'];
        $mac = ['hmac-sha2-256-etm@openssh.com'];
        $comp = ['none'];
        $body = chr(self::MSG_KEXINIT) . $cookie .
            $this->packNameList($kex) .
            $this->packNameList($hostkey) .
            $this->packNameList($enc) .
            $this->packNameList($enc) .
            $this->packNameList($mac) .
            $this->packNameList($mac) .
            $this->packNameList($comp) .
            $this->packNameList($comp) .
            $this->packNameList([]) .
            $this->packNameList([]) .
            chr(0) . pack('N', 0);
        $conn->server_kexinit = $body;
        $this->sendPacket($conn, $body);
    }
    /**
     * Parses an incoming KEXINIT and verifies that the
     * client offers each of the algorithms we require.
     * Stores the raw payload in $conn->client_kexinit
     * for the exchange-hash KDF.
     *
     * Returns true on success, false if any required
     * algorithm is missing.
     */
    protected function parseKexInit($conn, $payload)
    {
        $conn->client_kexinit = $payload;
        $off = 1 + 16; /* msg byte + cookie */
        $required = [
            ['curve25519-sha256',
                'curve25519-sha256@libssh.org'],
            ['ssh-ed25519'],
            ['aes128-ctr'],
            ['aes128-ctr'],
            ['hmac-sha2-256-etm@openssh.com'],
            ['hmac-sha2-256-etm@openssh.com'],
            ['none'],
            ['none'],
        ];
        $ok = true;
        foreach ($required as $slot) {
            list($lst, $off) = $this->readNameList($payload,
                $off);
            if ($lst === false) {
                return false;
            }
            $matched = false;
            foreach ($lst as $cand) {
                if (in_array($cand, $slot, true)) {
                    $matched = true;
                    break;
                }
            }
            if (!$matched) {
                $ok = false;
            }
        }
        /*
            Skip the two language name-lists, the
            first_kex_packet_follows boolean, and the
            reserved uint32. We don't validate them -- if
            the client guessed wrong on first_kex it will
            send an extra packet we ignore.
         */
        return $ok;
    }
    /*
        ============================================================
        --- KEX_ECDH (RFC 8731 / RFC 5656 sec 4) ---
        ============================================================

        Curve25519-SHA-256 KEX:

          1. Client sends KEX_ECDH_INIT containing Q_C
             (the client's ephemeral public point, 32
             bytes wrapped in an SSH "string").
          2. Server generates ephemeral keypair (q_s, Q_S),
             computes shared secret K = Curve25519(q_s,
             Q_C), interpreted as a big-endian unsigned
             number and packed as an mpint.
          3. Server computes exchange hash H over the
             concatenation:

               string V_C   (client identification, no CRLF)
               string V_S   (server identification)
               string I_C   (client KEXINIT payload)
               string I_S   (server KEXINIT payload)
               string K_S   (server host-key blob)
               string Q_C   (client ephemeral public, raw 32B
                             wrapped as string)
               string Q_S   (server ephemeral public, raw 32B
                             wrapped as string)
               mpint  K     (shared secret as bignum)

             The "string" framing for Q_C and Q_S is the
             length-prefixed bytes form, NOT mpint.

          4. Server signs H with its host key (Ed25519);
             the signature is wrapped in the SSH
             signature format
             "string algorithm string raw-signature".
          5. Server sends KEX_ECDH_REPLY containing K_S,
             Q_S, and the signature.
          6. Both sides derive six keys from K, H, and the
             session_id (which equals H on the first KEX).
     */
    /**
     * Handles a received KEX_ECDH_INIT, computes the
     * shared secret, the exchange hash, signs it with the
     * host key, and sends KEX_ECDH_REPLY.
     */
    protected function handleKexEcdhInit($conn, $payload)
    {
        list($qc, $off) = $this->readString($payload, 1);
        if ($qc === false || strlen($qc) !== 32) {
            $this->sendDisconnect($conn,
                self::DC_KEY_EXCHANGE_FAILED,
                'bad Q_C');
            return;
        }
        /*
            Generate ephemeral X25519 keypair. libsodium
            exposes Curve25519 scalar multiplication via
            sodium_crypto_scalarmult; the secret key is
            32 random bytes (well, almost -- it's clamped
            internally on use), and the public key is
            scalarmult(secret, base).
         */
        $secret = random_bytes(32);
        $public = sodium_crypto_scalarmult_base($secret);
        $conn->kex_secret = $secret;
        $conn->kex_public = $public;
        $shared = sodium_crypto_scalarmult($secret, $qc);
        /*
            Build the exchange hash inputs and compute H.
         */
        $h_input =
            $this->packString($conn->client_version) .
            $this->packString($conn->server_version) .
            $this->packString($conn->client_kexinit) .
            $this->packString($conn->server_kexinit) .
            $this->packString($this->host_blob) .
            $this->packString($qc) .
            $this->packString($public) .
            $this->packMpint($shared);
        $H = hash('sha256', $h_input, true);
        if ($conn->session_id === '') {
            $conn->session_id = $H;
        }
        /*
            Sign H with our Ed25519 host key. The result is
            64 bytes; wrap as
                string "ssh-ed25519"
                string raw-64-byte-signature
         */
        $sig_raw = sodium_crypto_sign_detached($H,
            $this->host_secret);
        $sig_blob = $this->packString('ssh-ed25519') .
            $this->packString($sig_raw);
        $reply = chr(self::MSG_KEX_ECDH_REPLY) .
            $this->packString($this->host_blob) .
            $this->packString($public) .
            $this->packString($sig_blob);
        $this->sendPacket($conn, $reply);
        /*
            Derive the six session keys from K and H.
            Per RFC 4253 sec 7.2:
                IV    c->s = HASH(K || H || "A" || sid)
                IV    s->c = HASH(K || H || "B" || sid)
                ENC   c->s = HASH(K || H || "C" || sid)
                ENC   s->c = HASH(K || H || "D" || sid)
                MAC   c->s = HASH(K || H || "E" || sid)
                MAC   s->c = HASH(K || H || "F" || sid)
         */
        $K_mp = $this->packMpint($shared);
        $sid = $conn->session_id;
        $conn->recv_enc_iv = $this->deriveKey($K_mp, $H,
            'A', $sid, 16);
        $conn->send_enc_iv = $this->deriveKey($K_mp, $H,
            'B', $sid, 16);
        $conn->recv_enc_key = $this->deriveKey($K_mp, $H,
            'C', $sid, 16);
        $conn->send_enc_key = $this->deriveKey($K_mp, $H,
            'D', $sid, 16);
        $conn->recv_mac_key = $this->deriveKey($K_mp, $H,
            'E', $sid, 32);
        $conn->send_mac_key = $this->deriveKey($K_mp, $H,
            'F', $sid, 32);
        $conn->send_ctr = $conn->send_enc_iv;
        $conn->recv_ctr = $conn->recv_enc_iv;
        /*
            Send our NEWKEYS. From this point on our
            outgoing packets must be encrypted; we set
            send_encrypted AFTER the NEWKEYS packet is
            built so the NEWKEYS itself goes out in
            cleartext.
         */
        $this->sendPacket($conn, chr(self::MSG_NEWKEYS));
        $conn->send_encrypted = true;
        /*
            We re-use send_seq as-is (NEWKEYS counted as
            seq N; the next packet will be N+1, encrypted).
            RFC 4253 sec 7.3 specifies the sequence number
            is NOT reset on key exchange.
         */
        $conn->phase = SshConnection::PHASE_NEWKEYS;
    }
    /**
     * Derives one session key per RFC 4253 sec 7.2. The
     * KDF is iterated SHA-256: K1 = H(K || H || letter ||
     * sid); K2 = H(K || H || K1); ...; concatenate until
     * we have at least $bytes of key material; truncate
     * to $bytes.
     */
    protected function deriveKey($K_mp, $H, $letter, $sid,
        $bytes)
    {
        $k = hash('sha256',
            $K_mp . $H . $letter . $sid, true);
        while (strlen($k) < $bytes) {
            $k .= hash('sha256',
                $K_mp . $H . $k, true);
        }
        return substr($k, 0, $bytes);
    }
    /**
     * Handles the client's NEWKEYS message: from this
     * point on incoming packets are encrypted.
     */
    protected function handleNewKeys($conn)
    {
        $conn->recv_encrypted = true;
        $conn->phase = SshConnection::PHASE_AUTH;
    }
    /*
        ============================================================
        --- Service request and packet dispatch ---
        ============================================================
     */
    /**
     * Top-level packet dispatch. The first byte of the
     * payload is the message type; we route to the right
     * handler and update phase state.
     */
    protected function handlePacket($conn, $payload)
    {
        if ($payload === '') {
            return;
        }
        $msg = ord($payload[0]);
        switch ($msg) {
            case self::MSG_DISCONNECT:
                $conn->disconnect = true;
                return;
            case self::MSG_IGNORE:
            case self::MSG_DEBUG:
                return;
            case self::MSG_KEXINIT:
                if (!$this->parseKexInit($conn, $payload)) {
                    $this->sendDisconnect($conn,
                        self::DC_KEY_EXCHANGE_FAILED,
                        'algorithm negotiation failed');
                    return;
                }
                $conn->phase =
                    SshConnection::PHASE_KEX_ECDH;
                return;
            case self::MSG_KEX_ECDH_INIT:
                $this->handleKexEcdhInit($conn, $payload);
                return;
            case self::MSG_NEWKEYS:
                $this->handleNewKeys($conn);
                return;
            case self::MSG_SERVICE_REQUEST:
                $this->handleServiceRequest($conn,
                    $payload);
                return;
            case self::MSG_USERAUTH_REQUEST:
                $this->handleUserauthRequest($conn,
                    $payload);
                return;
        }
        if ($msg >= self::MSG_GLOBAL_REQUEST &&
            $msg <= self::MSG_CHANNEL_FAILURE) {
            $this->handleConnectionMessage($conn, $payload);
            return;
        }
    }
    /**
     * Handles a SERVICE_REQUEST. The only service we
     * implement is "ssh-userauth"; anything else gets
     * a disconnect.
     */
    protected function handleServiceRequest($conn,
        $payload)
    {
        list($name, ) = $this->readString($payload, 1);
        if ($name !== 'ssh-userauth') {
            $this->sendDisconnect($conn,
                self::DC_SERVICE_NOT_AVAILABLE,
                'unknown service');
            return;
        }
        $reply = chr(self::MSG_SERVICE_ACCEPT) .
            $this->packString('ssh-userauth');
        $this->sendPacket($conn, $reply);
    }
    /**
     * Sends an SSH_MSG_USERAUTH_FAILURE listing the
     * authentication methods we accept. The "partial
     * success" flag is always 0 here.
     */
    protected function sendUserauthFailure($conn)
    {
        $methods = [];
        if ($this->authenticator !== null) {
            $methods[] = 'password';
            $methods[] = 'publickey';
        }
        $payload = chr(self::MSG_USERAUTH_FAILURE) .
            $this->packNameList($methods) . chr(0);
        $this->sendPacket($conn, $payload);
        $conn->auth_failures++;
        if ($conn->auth_failures >=
            self::MAX_AUTH_FAILURES) {
            $this->sendDisconnect($conn,
                self::DC_BY_APPLICATION,
                'too many failed auth attempts');
        }
    }
    /*
        ============================================================
        --- User authentication (RFC 4252) ---
        ============================================================

        After NEWKEYS the client requests the
        "ssh-userauth" service, then sends one or more
        USERAUTH_REQUEST packets. The packet body is:

            byte    msg_type = 50
            string  username
            string  service-name (always "ssh-connection")
            string  method ("none" / "password" / "publickey")
            ... method-specific fields ...

        For "password":
            boolean change_password (always 0 here)
            string  password

        For "publickey":
            boolean has_signature
            string  public-key-algorithm
            string  public-key-blob
            [ if has_signature ]
                string signature

        Successful auth: server sends USERAUTH_SUCCESS
        (msg_type 52, no body) and the connection enters
        the connection-protocol phase.

        Failed auth: server sends USERAUTH_FAILURE
        (sendUserauthFailure above) listing the methods
        the client may try next.
     */
    /**
     * Handles a USERAUTH_REQUEST packet. Dispatches by
     * method, calls the right authenticator method, and
     * sends SUCCESS or FAILURE.
     */
    protected function handleUserauthRequest($conn,
        $payload)
    {
        $off = 1;
        list($username, $off) = $this->readString($payload,
            $off);
        list($service, $off) = $this->readString($payload,
            $off);
        list($method, $off) = $this->readString($payload,
            $off);
        if ($username === false || $service === false ||
            $method === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        if ($service !== 'ssh-connection') {
            $this->sendUserauthFailure($conn);
            return;
        }
        if ($this->authenticator === null) {
            $this->sendUserauthFailure($conn);
            return;
        }
        switch ($method) {
            case 'none':
                /*
                    The "none" method is the universal
                    initial probe: clients use it to
                    discover the server's accepted methods.
                    We always reject; the FAILURE response
                    advertises the real methods.
                 */
                $this->sendUserauthFailure($conn);
                return;
            case 'password':
                $this->handleUserauthPassword($conn,
                    $username, $payload, $off);
                return;
            case 'publickey':
                $this->handleUserauthPubkey($conn,
                    $username, $payload, $off);
                return;
            default:
                $this->sendUserauthFailure($conn);
                return;
        }
    }
    /**
     * Handles a "password" USERAUTH_REQUEST.
     */
    protected function handleUserauthPassword($conn,
        $username, $payload, $off)
    {
        list($change, $off) = $this->readByte($payload,
            $off);
        list($password, $off) = $this->readString($payload,
            $off);
        if ($password === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        if (!empty($change)) {
            /*
                Password-change requests aren't supported.
             */
            $this->sendUserauthFailure($conn);
            return;
        }
        $info = $this->authenticator->checkPassword(
            $username, $password);
        if ($info === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        $conn->user_info = $info;
        $this->sendPacket($conn,
            chr(self::MSG_USERAUTH_SUCCESS));
        $conn->phase = SshConnection::PHASE_CONNECTED;
    }
    /**
     * Handles a "publickey" USERAUTH_REQUEST. Two phases:
     *   has_signature == false -- the client is asking
     *       "would you accept a sig from this key?"; we
     *       call the authenticator with $offer_only=true
     *       and reply USERAUTH_PK_OK if accepted.
     *   has_signature == true -- the client is sending
     *       a real signature. We verify it, then call
     *       the authenticator with $offer_only=false to
     *       map the user, then SUCCESS / FAILURE.
     */
    protected function handleUserauthPubkey($conn,
        $username, $payload, $off)
    {
        list($has_sig, $off) = $this->readByte($payload,
            $off);
        list($algo, $off) = $this->readString($payload,
            $off);
        list($key_blob, $off) = $this->readString($payload,
            $off);
        if ($algo === false || $key_blob === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        if (!$has_sig) {
            $info = $this->authenticator->checkPublicKey(
                $username, $algo, $key_blob, true);
            if ($info === false) {
                $this->sendUserauthFailure($conn);
                return;
            }
            $reply = chr(self::MSG_USERAUTH_PK_OK) .
                $this->packString($algo) .
                $this->packString($key_blob);
            $this->sendPacket($conn, $reply);
            return;
        }
        /*
            Signed phase. The signature is over the blob
            (RFC 4252 sec 7):
                string  session_id
                byte    SSH_MSG_USERAUTH_REQUEST (50)
                string  username
                string  "ssh-connection"
                string  "publickey"
                boolean true
                string  algorithm
                string  public-key-blob
         */
        list($sig_blob, ) = $this->readString($payload,
            $off);
        if ($sig_blob === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        $signed = $this->packString($conn->session_id) .
            chr(self::MSG_USERAUTH_REQUEST) .
            $this->packString($username) .
            $this->packString('ssh-connection') .
            $this->packString('publickey') . chr(1) .
            $this->packString($algo) .
            $this->packString($key_blob);
        if (!$this->verifyPubkeySignature($algo, $key_blob,
            $signed, $sig_blob)) {
            $this->sendUserauthFailure($conn);
            return;
        }
        $info = $this->authenticator->checkPublicKey(
            $username, $algo, $key_blob, false);
        if ($info === false) {
            $this->sendUserauthFailure($conn);
            return;
        }
        $conn->user_info = $info;
        $this->sendPacket($conn,
            chr(self::MSG_USERAUTH_SUCCESS));
        $conn->phase = SshConnection::PHASE_CONNECTED;
    }
    /**
     * Verifies that $sig_blob is a valid signature on
     * $signed under the public key $key_blob, using the
     * algorithm $algo. Supports ssh-ed25519 via libsodium
     * and rsa-sha2-256 / rsa-sha2-512 via openssl_verify.
     *
     * The $sig_blob is in SSH wire format ("string algo
     * || string raw_signature"); we unwrap before
     * verifying.
     */
    protected function verifyPubkeySignature($algo,
        $key_blob, $signed, $sig_blob)
    {
        list($sig_algo, $off) = $this->readString($sig_blob,
            0);
        list($sig_raw, ) = $this->readString($sig_blob,
            $off);
        if ($sig_algo === false || $sig_raw === false) {
            return false;
        }
        if ($algo === 'ssh-ed25519' &&
            $sig_algo === 'ssh-ed25519') {
            list($k_algo, $off2) = $this->readString(
                $key_blob, 0);
            list($pk, ) = $this->readString($key_blob,
                $off2);
            if ($k_algo !== 'ssh-ed25519' || $pk === false
                || strlen($pk) !== 32) {
                return false;
            }
            try {
                return sodium_crypto_sign_verify_detached(
                    $sig_raw, $signed, $pk);
            } catch (\Exception $e) {
                return false;
            }
        }
        if ($algo === 'ssh-rsa' && ($sig_algo
            === 'rsa-sha2-256' || $sig_algo
            === 'rsa-sha2-512')) {
            /*
                The ssh-rsa public-key blob is:
                    string  "ssh-rsa"
                    mpint   e
                    mpint   n
                We rebuild it as an RSA public key in PEM
                form so openssl_verify can use it.
             */
            $pem = $this->rsaSshBlobToPem($key_blob);
            if ($pem === false) {
                return false;
            }
            $alg = ($sig_algo === 'rsa-sha2-256') ?
                OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA512;
            $ok = @openssl_verify($signed, $sig_raw, $pem,
                $alg);
            return $ok === 1;
        }
        return false;
    }
    /**
     * Converts an SSH-format ssh-rsa public-key blob
     * (string "ssh-rsa" + mpint e + mpint n) into a PEM-
     * encoded RSA public key suitable for openssl_verify.
     *
     * The conversion builds an ASN.1 SubjectPublicKeyInfo
     * by hand. RSA's algorithm OID is
     * 1.2.840.113549.1.1.1 (rsaEncryption); the inner
     * RSAPublicKey is SEQUENCE { INTEGER n, INTEGER e }.
     */
    protected function rsaSshBlobToPem($blob)
    {
        list($algo, $off) = $this->readString($blob, 0);
        list($e_mp, $off) = $this->readString($blob, $off);
        list($n_mp, ) = $this->readString($blob, $off);
        if ($algo !== 'ssh-rsa' || $e_mp === false ||
            $n_mp === false) {
            return false;
        }
        $rsa_pubkey = $this->derSequence(
            $this->derInteger($n_mp) .
            $this->derInteger($e_mp));
        $alg_id = $this->derSequence(
            $this->derOid('1.2.840.113549.1.1.1') .
            "\x05\x00");
        $bit_string = "\x03" .
            $this->derLength(strlen($rsa_pubkey) + 1) .
            "\x00" . $rsa_pubkey;
        $spki = $this->derSequence($alg_id . $bit_string);
        $b64 = chunk_split(base64_encode($spki), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n" . $b64 .
            "-----END PUBLIC KEY-----\n";
    }
    /**
     * DER length encoding: short form for <128, long form
     * (0x80 | n) followed by n length bytes for >=128.
     */
    protected function derLength($n)
    {
        if ($n < 128) {
            return chr($n);
        }
        $bytes = '';
        while ($n > 0) {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
    /**
     * DER SEQUENCE (tag 0x30).
     */
    protected function derSequence($body)
    {
        return "\x30" . $this->derLength(strlen($body)) .
            $body;
    }
    /**
     * DER INTEGER (tag 0x02). Takes an SSH mpint payload
     * (which may have a leading 0x00 byte already if the
     * top bit was set) and reuses it directly -- mpint
     * and DER INTEGER agree on the leading-zero rule.
     */
    protected function derInteger($mp_payload)
    {
        return "\x02" . $this->derLength(strlen(
            $mp_payload)) . $mp_payload;
    }
    /**
     * DER OBJECT IDENTIFIER (tag 0x06). Encodes a dotted-
     * decimal OID per X.690. The first two arcs collapse
     * into one byte (40*A + B).
     */
    protected function derOid($dotted)
    {
        $arcs = explode('.', $dotted);
        $out = chr(40 * (int)$arcs[0] + (int)$arcs[1]);
        for ($i = 2; $i < count($arcs); $i++) {
            $a = (int)$arcs[$i];
            if ($a < 0x80) {
                $out .= chr($a);
                continue;
            }
            $bytes = '';
            while ($a > 0) {
                $bytes = chr(($a & 0x7F) |
                    (strlen($bytes) > 0 ? 0x80 : 0)) .
                    $bytes;
                $a >>= 7;
            }
            $out .= $bytes;
        }
        return "\x06" . $this->derLength(strlen($out)) .
            $out;
    }
    /*
        ============================================================
        --- Connection layer (RFC 4254) ---
        ============================================================

        After USERAUTH_SUCCESS the client opens "channels"
        which are independent byte streams multiplexed
        over the same encrypted connection. Each channel
        has flow-control windows in both directions:
        the receiver advertises how many bytes the sender
        may send before they must wait for a WINDOW_ADJUST.

        Channel lifecycle:

          1. Client sends CHANNEL_OPEN with its
             channel id, type ("session"), initial
             window, max packet, and type-specific data.
          2. Server replies CHANNEL_OPEN_CONFIRMATION
             with its own channel id, server's initial
             window, server's max packet (the same
             values flow back to the client). Or
             CHANNEL_OPEN_FAILURE on rejection.
          3. Client sends CHANNEL_REQUEST(s) on the
             channel: "pty-req", "env", "shell", "exec",
             "subsystem". Each request carries a
             want-reply boolean; if set, server replies
             CHANNEL_SUCCESS or CHANNEL_FAILURE.
          4. Once the application is running, both sides
             exchange CHANNEL_DATA (and optionally
             EXTENDED_DATA for stderr).
          5. EOF and CLOSE messages tear the channel down.
     */
    /**
     * Top-level connection-layer dispatch. Called for any
     * packet whose first byte identifies a connection-
     * layer message (90-100). Routes by message type.
     */
    protected function handleConnectionMessage($conn,
        $payload)
    {
        $msg = ord($payload[0]);
        switch ($msg) {
            case self::MSG_GLOBAL_REQUEST:
                $this->handleGlobalRequest($conn, $payload);
                return;
            case self::MSG_CHANNEL_OPEN:
                $this->handleChannelOpen($conn, $payload);
                return;
            case self::MSG_CHANNEL_DATA:
                $this->handleChannelData($conn, $payload);
                return;
            case self::MSG_CHANNEL_WINDOW_ADJUST:
                $this->handleChannelWindowAdjust($conn,
                    $payload);
                return;
            case self::MSG_CHANNEL_REQUEST:
                $this->handleChannelRequest($conn,
                    $payload);
                return;
            case self::MSG_CHANNEL_EOF:
                $this->handleChannelEof($conn, $payload);
                return;
            case self::MSG_CHANNEL_CLOSE:
                $this->handleChannelClose($conn, $payload);
                return;
        }
    }
    /**
     * Handles SSH_MSG_GLOBAL_REQUEST. The only common
     * one is "tcpip-forward" / "cancel-tcpip-forward",
     * which we don't support. If the client wants a reply
     * we send REQUEST_FAILURE.
     */
    protected function handleGlobalRequest($conn, $payload)
    {
        $off = 1;
        list($name, $off) = $this->readString($payload,
            $off);
        list($want, ) = $this->readByte($payload, $off);
        if (!empty($want)) {
            $this->sendPacket($conn,
                chr(self::MSG_REQUEST_FAILURE));
        }
    }
    /**
     * Handles SSH_MSG_CHANNEL_OPEN. Body:
     *     string   channel-type
     *     uint32   sender (client) channel id
     *     uint32   initial window
     *     uint32   max packet
     *     ...      type-specific data
     */
    protected function handleChannelOpen($conn, $payload)
    {
        $off = 1;
        list($type, $off) = $this->readString($payload,
            $off);
        list($remote_id, $off) = $this->readUint32(
            $payload, $off);
        list($remote_win, $off) = $this->readUint32(
            $payload, $off);
        list($remote_pkt, $off) = $this->readUint32(
            $payload, $off);
        if ($type !== SshChannel::TYPE_SESSION) {
            $this->sendChannelOpenFailure($conn,
                $remote_id,
                self::COF_UNKNOWN_CHANNEL_TYPE,
                'only session channels are supported');
            return;
        }
        $ch = new SshChannel();
        $ch->local_id = $conn->next_channel_id++;
        $ch->remote_id = $remote_id;
        $ch->remote_window = $remote_win;
        $ch->remote_max_packet = $remote_pkt;
        $ch->local_window = self::INITIAL_WINDOW;
        $ch->local_max_packet = self::MAX_PACKET;
        $ch->type = $type;
        $conn->channels[$ch->local_id] = $ch;
        $reply = chr(self::MSG_CHANNEL_OPEN_CONFIRMATION) .
            pack('N', $ch->remote_id) .
            pack('N', $ch->local_id) .
            pack('N', $ch->local_window) .
            pack('N', $ch->local_max_packet);
        $this->sendPacket($conn, $reply);
    }
    /**
     * Sends CHANNEL_OPEN_FAILURE for a channel-open we
     * have rejected.
     */
    protected function sendChannelOpenFailure($conn,
        $remote_id, $code, $reason)
    {
        $payload = chr(self::MSG_CHANNEL_OPEN_FAILURE) .
            pack('N', $remote_id) .
            pack('N', $code) .
            $this->packString($reason) .
            $this->packString('en');
        $this->sendPacket($conn, $payload);
    }
    /**
     * Handles a CHANNEL_REQUEST. Dispatches by request
     * type: "subsystem", "shell", "exec", "pty-req",
     * "env", and "window-change". Sends CHANNEL_SUCCESS
     * or CHANNEL_FAILURE if the client wanted a reply.
     */
    protected function handleChannelRequest($conn, $payload)
    {
        $off = 1;
        list($local_id, $off) = $this->readUint32(
            $payload, $off);
        list($req, $off) = $this->readString($payload,
            $off);
        list($want, $off) = $this->readByte($payload,
            $off);
        if (!isset($conn->channels[$local_id])) {
            return;
        }
        $ch = $conn->channels[$local_id];
        $ok = false;
        $kicker = null;
        switch ($req) {
            case 'pty-req':
            case 'env':
            case 'window-change':
                /*
                    PTY allocation, environment variables,
                    and window-resize. We accept-but-ignore
                    all three: the demo shell doesn't care
                    about terminal modes, and SFTP doesn't
                    use a PTY. RFC 4254 sec 6.2 allows
                    pty-req to fail, but accepting is
                    friendlier to clients that always send
                    one before "shell".
                 */
                $ok = true;
                break;
            case 'shell':
                if ($this->enable_shell &&
                    $this->storage !== null) {
                    $ok = true;
                    $kicker = function () use ($conn,
                        $ch) {
                        $this->startShell($conn, $ch);
                    };
                }
                break;
            case 'exec':
                if ($this->enable_exec &&
                    $this->storage !== null) {
                    $ok = true;
                    /*
                        Capture the command-line bytes now;
                        the local $payload variable goes
                        out of scope when handleChannelRequest
                        returns.
                     */
                    $exec_payload = $payload;
                    $exec_off = $off;
                    $kicker = function () use ($conn, $ch,
                        $exec_payload, $exec_off) {
                        $this->startExec($conn, $ch,
                            $exec_payload, $exec_off);
                    };
                }
                break;
            case 'subsystem':
                list($name, ) = $this->readString($payload,
                    $off);
                if ($name === 'sftp' &&
                    $this->enable_sftp &&
                    $this->storage !== null) {
                    $ok = true;
                    $kicker = function () use ($conn, $ch) {
                        $this->startSftp($conn, $ch);
                    };
                }
                break;
        }
        /*
            Send the SUCCESS / FAILURE reply BEFORE
            starting the application. RFC 4254 sec 5.4
            doesn't strictly require this order, but
            paramiko (and OpenSSH's clients in general)
            expect to see CHANNEL_SUCCESS before any
            CHANNEL_DATA, EXIT_STATUS, EOF, or CLOSE
            from us. If we run the application first
            and it finishes synchronously (the exec
            case is the obvious one), the client sees
            CLOSE before the SUCCESS that confirms its
            request and treats the channel as having
            failed.
         */
        if (!empty($want)) {
            $reply = chr($ok ? self::MSG_CHANNEL_SUCCESS :
                self::MSG_CHANNEL_FAILURE) .
                pack('N', $ch->remote_id);
            $this->sendPacket($conn, $reply);
        }
        if ($ok && $kicker !== null) {
            $kicker();
        }
    }
    /**
     * Handles CHANNEL_DATA. Body:
     *     uint32   recipient (server) channel
     *     string   data
     */
    protected function handleChannelData($conn, $payload)
    {
        $off = 1;
        list($local_id, $off) = $this->readUint32(
            $payload, $off);
        list($data, ) = $this->readString($payload, $off);
        if (!isset($conn->channels[$local_id]) ||
            $data === false) {
            return;
        }
        $ch = $conn->channels[$local_id];
        $ch->local_window -= strlen($data);
        $this->dispatchAppData($conn, $ch, $data);
        if ($ch->local_window < self::INITIAL_WINDOW / 2) {
            $delta = self::INITIAL_WINDOW -
                $ch->local_window;
            $ch->local_window += $delta;
            $adjust = chr(
                self::MSG_CHANNEL_WINDOW_ADJUST) .
                pack('N', $ch->remote_id) .
                pack('N', $delta);
            $this->sendPacket($conn, $adjust);
        }
    }
    /**
     * Handles CHANNEL_WINDOW_ADJUST. The client just
     * grew its receive window; we update the
     * corresponding remote_window on our channel state.
     */
    protected function handleChannelWindowAdjust($conn,
        $payload)
    {
        $off = 1;
        list($local_id, $off) = $this->readUint32(
            $payload, $off);
        list($delta, ) = $this->readUint32($payload, $off);
        if (!isset($conn->channels[$local_id])) {
            return;
        }
        $conn->channels[$local_id]->remote_window +=
            $delta;
    }
    /**
     * Handles CHANNEL_EOF. The client signals it will
     * send no more data. We mark the channel and let
     * the application decide what to do.
     */
    protected function handleChannelEof($conn, $payload)
    {
        $off = 1;
        list($local_id, ) = $this->readUint32($payload,
            $off);
        if (!isset($conn->channels[$local_id])) {
            return;
        }
        $conn->channels[$local_id]->eof_received = true;
    }
    /**
     * Handles CHANNEL_CLOSE. Per RFC 4254 sec 5.3 we
     * must reply with CHANNEL_CLOSE if we have not
     * already sent one, then both sides forget the
     * channel.
     */
    protected function handleChannelClose($conn, $payload)
    {
        $off = 1;
        list($local_id, ) = $this->readUint32($payload,
            $off);
        if (!isset($conn->channels[$local_id])) {
            return;
        }
        $ch = $conn->channels[$local_id];
        $ch->close_received = true;
        if (!$ch->close_sent) {
            $reply = chr(self::MSG_CHANNEL_CLOSE) .
                pack('N', $ch->remote_id);
            $this->sendPacket($conn, $reply);
            $ch->close_sent = true;
        }
        unset($conn->channels[$local_id]);
    }
    /**
     * Sends bytes on a channel as CHANNEL_DATA, splitting
     * across multiple packets if the data exceeds
     * remote_max_packet, and decrementing remote_window
     * accordingly. Returns the number of bytes accepted
     * (which may be less than strlen($data) if the window
     * is exhausted).
     */
    protected function sendChannelData($conn, $ch, $data)
    {
        $sent = 0;
        while (strlen($data) > 0) {
            $room = min($ch->remote_window,
                $ch->remote_max_packet);
            if ($room <= 0) {
                break;
            }
            $chunk = substr($data, 0, $room);
            $payload = chr(self::MSG_CHANNEL_DATA) .
                pack('N', $ch->remote_id) .
                $this->packString($chunk);
            $this->sendPacket($conn, $payload);
            $ch->remote_window -= strlen($chunk);
            $sent += strlen($chunk);
            $data = substr($data, strlen($chunk));
        }
        return $sent;
    }
    /**
     * Sends EXIT_STATUS as a channel request, then
     * CHANNEL_EOF and CHANNEL_CLOSE. Used by the shell
     * and exec apps when their command finishes.
     */
    protected function sendChannelExit($conn, $ch, $code)
    {
        $exit = chr(self::MSG_CHANNEL_REQUEST) .
            pack('N', $ch->remote_id) .
            $this->packString('exit-status') . chr(0) .
            pack('N', $code);
        $this->sendPacket($conn, $exit);
        if (!$ch->eof_sent) {
            $eof = chr(self::MSG_CHANNEL_EOF) .
                pack('N', $ch->remote_id);
            $this->sendPacket($conn, $eof);
            $ch->eof_sent = true;
        }
        if (!$ch->close_sent) {
            $close = chr(self::MSG_CHANNEL_CLOSE) .
                pack('N', $ch->remote_id);
            $this->sendPacket($conn, $close);
            $ch->close_sent = true;
        }
    }
    /**
     * Routes incoming channel data to the right
     * application handler based on $ch->app.
     */
    protected function dispatchAppData($conn, $ch, $data)
    {
        switch ($ch->app) {
            case 'sftp':
                $this->sftpOnData($conn, $ch, $data);
                return;
            case 'shell':
                $this->shellOnData($conn, $ch, $data);
                return;
            case 'exec':
                /* exec doesn't typically take input */
                return;
        }
    }
    /*
        ============================================================
        --- Application: interactive shell ---
        ============================================================

        The "shell" subsystem in atto is a tiny line-edited
        command interpreter. It is intentionally not a real
        shell -- it does not spawn /bin/sh, has no PTY, no
        job control, and no pipelines -- but it understands
        a useful subset of read-only filesystem commands so
        the demo has something to do once a user is logged
        in.

        Recognized commands:
            pwd                  print working directory
            ls [path]            list directory entries
            cd [path]            change directory; cd alone
                                 returns to the login folder
            cat path             print file contents
            echo args...         print args separated by spaces
            whoami               print authenticated username
            help                 show this list
            clear                clear the screen (ANSI)
            exit / logout        end the session

        Anything else gets a "command not found" message.
        Backspace edits the line buffer. Carriage return
        (the terminal sends \r when the user presses Enter)
        executes the line and resets the buffer.
     */
    /**
     * Initializes shell state on a session channel. Sends
     * the welcome banner and the first prompt; thereafter
     * the channel is fed by shellOnData.
     */
    protected function startShell($conn, $ch)
    {
        if ($this->storage === null) {
            return false;
        }
        $cwd = '/';
        if (is_array($conn->user_info) &&
            isset($conn->user_info['login_folder'])) {
            $cwd = $conn->user_info['login_folder'];
        }
        $ch->app = 'shell';
        $ch->app_state = [
            'cwd' => $cwd,
            'buf' => '',
        ];
        $user = is_array($conn->user_info) ?
            ($conn->user_info['user'] ?? '') : '';
        $banner = "atto-ssh demo shell. Type 'help' for " .
            "commands.\r\n";
        $this->sendChannelData($conn, $ch, $banner);
        $this->shellPrompt($conn, $ch);
        return true;
    }
    /**
     * Sends the prompt for the next command.
     */
    protected function shellPrompt($conn, $ch)
    {
        $cwd = $ch->app_state['cwd'];
        $user = is_array($conn->user_info) ?
            ($conn->user_info['user'] ?? '?') : '?';
        $this->sendChannelData($conn, $ch,
            "atto:$cwd $user> ");
    }
    /**
     * Handles raw bytes arriving on a shell channel. The
     * client is typically a real terminal in raw mode --
     * each keystroke arrives as a single-byte CHANNEL_DATA
     * message. We echo printable bytes back to the client
     * so they appear on the user's terminal, accumulate
     * them into a line buffer, and run a command on CR.
     */
    protected function shellOnData($conn, $ch, $data)
    {
        for ($i = 0; $i < strlen($data); $i++) {
            $c = $data[$i];
            $b = ord($c);
            if ($b === 0x0D || $b === 0x0A) {
                /* CR or LF: execute */
                $this->sendChannelData($conn, $ch,
                    "\r\n");
                $line = $ch->app_state['buf'];
                $ch->app_state['buf'] = '';
                $stop = $this->shellRunLine($conn, $ch,
                    $line);
                if ($stop) {
                    $this->sendChannelExit($conn, $ch, 0);
                    return;
                }
                $this->shellPrompt($conn, $ch);
                continue;
            }
            if ($b === 0x7F || $b === 0x08) {
                /* DEL (backspace key) or BS */
                if (strlen($ch->app_state['buf']) > 0) {
                    $ch->app_state['buf'] = substr(
                        $ch->app_state['buf'], 0, -1);
                    $this->sendChannelData($conn, $ch,
                        "\x08 \x08");
                }
                continue;
            }
            if ($b === 0x03) {
                /* Ctrl-C: clear the line, prompt fresh */
                $ch->app_state['buf'] = '';
                $this->sendChannelData($conn, $ch,
                    "^C\r\n");
                $this->shellPrompt($conn, $ch);
                continue;
            }
            if ($b === 0x04 &&
                $ch->app_state['buf'] === '') {
                /* Ctrl-D on an empty line: logout */
                $this->sendChannelData($conn, $ch,
                    "logout\r\n");
                $this->sendChannelExit($conn, $ch, 0);
                return;
            }
            if ($b < 0x20 || $b >= 0x7F) {
                /* skip other non-printable input */
                continue;
            }
            $ch->app_state['buf'] .= $c;
            $this->sendChannelData($conn, $ch, $c);
        }
    }
    /**
     * Runs one input line through the dispatch table.
     * Returns true if the session should end (after exit
     * / logout); false otherwise.
     */
    protected function shellRunLine($conn, $ch, $line)
    {
        $line = trim($line);
        if ($line === '') {
            return false;
        }
        $args = $this->shellSplitArgs($line);
        if (empty($args)) {
            return false;
        }
        $cmd = array_shift($args);
        switch ($cmd) {
            case 'exit':
            case 'logout':
            case 'quit':
                $this->sendChannelData($conn, $ch,
                    "bye\r\n");
                return true;
            case 'pwd':
                $this->sendChannelData($conn, $ch,
                    $ch->app_state['cwd'] . "\r\n");
                return false;
            case 'whoami':
                $u = is_array($conn->user_info) ?
                    ($conn->user_info['user'] ?? '?') : '?';
                $this->sendChannelData($conn, $ch,
                    "$u\r\n");
                return false;
            case 'echo':
                $this->sendChannelData($conn, $ch,
                    implode(' ', $args) . "\r\n");
                return false;
            case 'help':
                $this->sendChannelData($conn, $ch,
                    "commands: pwd, ls [path], cd [path], " .
                    "cat path, echo args..., whoami, " .
                    "clear, help, exit\r\n");
                return false;
            case 'clear':
                $this->sendChannelData($conn, $ch,
                    "\x1b[2J\x1b[H");
                return false;
            case 'ls':
                $this->shellLs($conn, $ch, $args);
                return false;
            case 'cd':
                $this->shellCd($conn, $ch, $args);
                return false;
            case 'cat':
                $this->shellCat($conn, $ch, $args);
                return false;
        }
        $this->sendChannelData($conn, $ch,
            "$cmd: command not found\r\n");
        return false;
    }
    /**
     * Splits a shell line into argv, honoring single and
     * double quotes. No backslash escapes -- the demo
     * shell does not pretend to be POSIX-compliant.
     */
    protected function shellSplitArgs($line)
    {
        $out = [];
        $cur = '';
        $quote = '';
        for ($i = 0; $i < strlen($line); $i++) {
            $c = $line[$i];
            if ($quote === '') {
                if ($c === ' ' || $c === "\t") {
                    if ($cur !== '') {
                        $out[] = $cur;
                        $cur = '';
                    }
                    continue;
                }
                if ($c === '"' || $c === "'") {
                    $quote = $c;
                    continue;
                }
                $cur .= $c;
                continue;
            }
            if ($c === $quote) {
                $quote = '';
                continue;
            }
            $cur .= $c;
        }
        if ($cur !== '') {
            $out[] = $cur;
        }
        return $out;
    }
    /**
     * "ls" implementation. Lists the named directory (or
     * the current directory if no argument given) using
     * the storage layer.
     */
    protected function shellLs($conn, $ch, $args)
    {
        $target = isset($args[0]) ? $args[0] : '.';
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $target);
        if ($resolved === false) {
            $this->sendChannelData($conn, $ch,
                "ls: $target: invalid path\r\n");
            return;
        }
        if (!$this->storage->isDir($resolved)) {
            $entry = $this->storage->statEntry($resolved);
            if ($entry === false) {
                $this->sendChannelData($conn, $ch,
                    "ls: $target: no such file\r\n");
                return;
            }
            $this->sendChannelData($conn, $ch,
                $entry['name'] . "\r\n");
            return;
        }
        $entries = $this->storage->listing($resolved);
        if ($entries === false) {
            $this->sendChannelData($conn, $ch,
                "ls: $target: cannot list\r\n");
            return;
        }
        $out = '';
        foreach ($entries as $e) {
            $marker = ($e['type'] === 'dir') ? '/' : '';
            $out .= sprintf("%s%-30s %10d  %s\r\n",
                ($e['type'] === 'dir') ? 'd' : '-',
                $e['name'] . $marker,
                $e['size'],
                date('Y-m-d H:i', $e['mtime']));
        }
        $this->sendChannelData($conn, $ch, $out);
    }
    /**
     * "cd" implementation. Updates the channel's cwd to
     * a new directory, after verifying it exists and is
     * a directory.
     */
    protected function shellCd($conn, $ch, $args)
    {
        if (empty($args)) {
            $login = '/';
            if (is_array($conn->user_info) &&
                isset($conn->user_info['login_folder'])) {
                $login = $conn->user_info['login_folder'];
            }
            $ch->app_state['cwd'] = $login;
            return;
        }
        $target = $args[0];
        /*
            Compute the FTP-space new cwd by resolving
            relative to the current one. We then ask the
            storage to confirm it exists and is a dir.
         */
        $cwd = $ch->app_state['cwd'];
        if (substr($target, 0, 1) === '/') {
            $new_cwd = $target;
        } else {
            $new_cwd = rtrim($cwd, '/') . '/' . $target;
        }
        $new_cwd = $this->normalizeFtpPath($new_cwd);
        if ($new_cwd === false) {
            $this->sendChannelData($conn, $ch,
                "cd: $target: invalid path\r\n");
            return;
        }
        $resolved = $this->storage->resolveSafe('/',
            $new_cwd);
        if ($resolved === false ||
            !$this->storage->isDir($resolved)) {
            $this->sendChannelData($conn, $ch,
                "cd: $target: no such directory\r\n");
            return;
        }
        $ch->app_state['cwd'] = $new_cwd;
    }
    /**
     * Collapses "." and ".." segments in an FTP-style
     * path. Refuses to ascend above "/" -- returns false
     * if too many ".." would. Returns the cleaned path.
     */
    protected function normalizeFtpPath($path)
    {
        $parts = explode('/', $path);
        $out = [];
        foreach ($parts as $p) {
            if ($p === '' || $p === '.') {
                continue;
            }
            if ($p === '..') {
                if (empty($out)) {
                    return false;
                }
                array_pop($out);
                continue;
            }
            $out[] = $p;
        }
        return '/' . implode('/', $out);
    }
    /**
     * "cat" implementation. Streams the contents of a
     * file to the client.
     */
    protected function shellCat($conn, $ch, $args)
    {
        if (empty($args)) {
            $this->sendChannelData($conn, $ch,
                "cat: missing path\r\n");
            return;
        }
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $args[0]);
        if ($resolved === false ||
            !$this->storage->exists($resolved) ||
            $this->storage->isDir($resolved)) {
            $this->sendChannelData($conn, $ch,
                "cat: " . $args[0] .
                ": no such file\r\n");
            return;
        }
        $stream = $this->storage->openRead($resolved);
        if ($stream === false) {
            $this->sendChannelData($conn, $ch,
                "cat: cannot read\r\n");
            return;
        }
        while (!feof($stream)) {
            $chunk = @fread($stream, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            /*
                Translate bare LFs to CRLFs so the output
                lines up cleanly on a terminal that
                expects CRLF line endings.
             */
            $chunk = preg_replace('/(?<!\r)\n/', "\r\n",
                $chunk);
            $this->sendChannelData($conn, $ch, $chunk);
        }
        @fclose($stream);
    }
    /*
        ============================================================
        --- Application: exec ---
        ============================================================

        "exec" runs one command and exits, no PTY. The
        client provides the full command line in the
        request's payload (after the channel id, request
        type, and want-reply byte). We dispatch through
        the same shellRunLine the interactive shell uses,
        then send EOF + exit-status + CLOSE.
     */
    /**
     * Initializes an exec session. The command line lives
     * in $payload starting at offset $off (pointing at the
     * SSH "string" that holds the command).
     */
    protected function startExec($conn, $ch, $payload, $off)
    {
        if ($this->storage === null) {
            return false;
        }
        list($command, ) = $this->readString($payload,
            $off);
        if ($command === false) {
            return false;
        }
        $cwd = '/';
        if (is_array($conn->user_info) &&
            isset($conn->user_info['login_folder'])) {
            $cwd = $conn->user_info['login_folder'];
        }
        $ch->app = 'exec';
        $ch->app_state = [
            'cwd' => $cwd,
            'buf' => '',
        ];
        /*
            Run the command synchronously inside this
            handler. shellRunLine writes its output via
            sendChannelData on the same channel, so the
            client sees the whole result in one logical
            transfer. After the command finishes we send
            exit-status / EOF / CLOSE.
         */
        $this->shellRunLine($conn, $ch, $command);
        $this->sendChannelExit($conn, $ch, 0);
        return true;
    }
    /*
        ============================================================
        --- Application: SFTP subsystem ---
        ============================================================

        Implements draft-ietf-secsh-filexfer-02, the version
        of the SFTP protocol OpenSSH and most clients (incl.
        paramiko, FileZilla, WinSCP) speak. The wire format
        inside the SSH channel is:

            uint32 packet_length
            byte   type
            uint32 request_id            (except INIT/VERSION)
            ... per-type body ...

        Multiple packets may be coalesced inside a single
        CHANNEL_DATA, and one packet may be split across
        several. We accumulate bytes in app_state['rxbuf']
        and pull off complete packets in a loop.

        Per-channel state:
            rxbuf        accumulated bytes
            handles      open handles -> info array
            next_handle  counter for new handle ids
            cwd          working dir, for REALPATH on a
                         relative path
            negotiated   set true once VERSION has been sent
    */
    /*
        SFTP message types (sec 3 of the draft).
     */
    const SFTP_INIT = 1;
    const SFTP_VERSION = 2;
    const SFTP_OPEN = 3;
    const SFTP_CLOSE = 4;
    const SFTP_READ = 5;
    const SFTP_WRITE = 6;
    const SFTP_LSTAT = 7;
    const SFTP_FSTAT = 8;
    const SFTP_SETSTAT = 9;
    const SFTP_FSETSTAT = 10;
    const SFTP_OPENDIR = 11;
    const SFTP_READDIR = 12;
    const SFTP_REMOVE = 13;
    const SFTP_MKDIR = 14;
    const SFTP_RMDIR = 15;
    const SFTP_REALPATH = 16;
    const SFTP_STAT = 17;
    const SFTP_RENAME = 18;
    const SFTP_READLINK = 19;
    const SFTP_SYMLINK = 20;
    const SFTP_STATUS = 101;
    const SFTP_HANDLE = 102;
    const SFTP_DATA = 103;
    const SFTP_NAME = 104;
    const SFTP_ATTRS = 105;
    /*
        SFTP status codes.
     */
    const SFTP_FX_OK = 0;
    const SFTP_FX_EOF = 1;
    const SFTP_FX_NO_SUCH_FILE = 2;
    const SFTP_FX_PERMISSION_DENIED = 3;
    const SFTP_FX_FAILURE = 4;
    const SFTP_FX_BAD_MESSAGE = 5;
    const SFTP_FX_OP_UNSUPPORTED = 8;
    /*
        ATTRS flags.
     */
    const SFTP_ATTR_SIZE = 0x00000001;
    const SFTP_ATTR_UIDGID = 0x00000002;
    const SFTP_ATTR_PERMISSIONS = 0x00000004;
    const SFTP_ATTR_ACMODTIME = 0x00000008;
    /*
        OPEN flags.
     */
    const SFTP_OPEN_READ = 0x00000001;
    const SFTP_OPEN_WRITE = 0x00000002;
    const SFTP_OPEN_APPEND = 0x00000004;
    const SFTP_OPEN_CREAT = 0x00000008;
    const SFTP_OPEN_TRUNC = 0x00000010;
    const SFTP_OPEN_EXCL = 0x00000020;
    /**
     * Initializes SFTP state on a session channel. The
     * client's first packet (INIT) is what triggers the
     * VERSION reply; this method just sets up the channel
     * to receive it.
     */
    protected function startSftp($conn, $ch)
    {
        if ($this->storage === null) {
            return false;
        }
        $cwd = '/';
        if (is_array($conn->user_info) &&
            isset($conn->user_info['login_folder'])) {
            $cwd = $conn->user_info['login_folder'];
        }
        $ch->app = 'sftp';
        $ch->app_state = [
            'rxbuf' => '',
            'handles' => [],
            'next_handle' => 1,
            'cwd' => $cwd,
            'negotiated' => false,
        ];
        return true;
    }
    /**
     * Handles incoming bytes for an SFTP channel. Buffers
     * until a complete length-prefixed packet is in hand,
     * then dispatches by message type. Loops in case the
     * input contains multiple packets.
     */
    protected function sftpOnData($conn, $ch, $data)
    {
        $ch->app_state['rxbuf'] .= $data;
        while (true) {
            $buf = $ch->app_state['rxbuf'];
            if (strlen($buf) < 4) {
                return;
            }
            $hdr = unpack('Nlen', substr($buf, 0, 4));
            $plen = $hdr['len'];
            if ($plen < 1 || $plen > 16 * 1024 * 1024) {
                /*
                    Unreasonable packet length; treat as
                    malformed and tear the channel down.
                 */
                $this->sendChannelExit($conn, $ch, 1);
                return;
            }
            if (strlen($buf) < 4 + $plen) {
                return;
            }
            $packet = substr($buf, 4, $plen);
            $ch->app_state['rxbuf'] = substr($buf,
                4 + $plen);
            $this->sftpDispatch($conn, $ch, $packet);
        }
    }
    /**
     * Dispatches a single SFTP packet (without the length
     * prefix) to its per-type handler.
     */
    protected function sftpDispatch($conn, $ch, $packet)
    {
        if (strlen($packet) < 1) {
            return;
        }
        $type = ord($packet[0]);
        if ($type === self::SFTP_INIT) {
            $this->sftpHandleInit($conn, $ch, $packet);
            return;
        }
        if (!$ch->app_state['negotiated']) {
            return;
        }
        if (strlen($packet) < 5) {
            return;
        }
        $rid = unpack('Nv', substr($packet, 1, 4))['v'];
        $body = substr($packet, 5);
        switch ($type) {
            case self::SFTP_OPEN:
                $this->sftpHandleOpen($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_CLOSE:
                $this->sftpHandleClose($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_READ:
                $this->sftpHandleRead($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_WRITE:
                $this->sftpHandleWrite($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_LSTAT:
            case self::SFTP_STAT:
                $this->sftpHandleStat($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_FSTAT:
                $this->sftpHandleFstat($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_SETSTAT:
            case self::SFTP_FSETSTAT:
                /*
                    The demo storage doesn't actually
                    track times or permissions beyond what
                    the underlying filesystem provides, so
                    we acknowledge SETSTAT/FSETSTAT as a
                    no-op success. Refusing them outright
                    causes some clients to abort an upload.
                 */
                $this->sftpSendStatus($conn, $ch, $rid,
                    self::SFTP_FX_OK, 'ok');
                return;
            case self::SFTP_OPENDIR:
                $this->sftpHandleOpendir($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_READDIR:
                $this->sftpHandleReaddir($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_REMOVE:
                $this->sftpHandleRemove($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_MKDIR:
                $this->sftpHandleMkdir($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_RMDIR:
                $this->sftpHandleRmdir($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_REALPATH:
                $this->sftpHandleRealpath($conn, $ch,
                    $rid, $body);
                return;
            case self::SFTP_RENAME:
                $this->sftpHandleRename($conn, $ch, $rid,
                    $body);
                return;
            case self::SFTP_READLINK:
            case self::SFTP_SYMLINK:
                $this->sftpSendStatus($conn, $ch, $rid,
                    self::SFTP_FX_OP_UNSUPPORTED,
                    'symlinks not supported');
                return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OP_UNSUPPORTED,
            'unknown sftp message');
    }
    /*
        --- SFTP packet helpers ---
     */
    /**
     * Wraps a body in the SFTP packet framing (uint32
     * length + payload) and writes it to the channel.
     */
    protected function sftpSendPacket($conn, $ch, $payload)
    {
        $framed = pack('N', strlen($payload)) . $payload;
        $this->sendChannelData($conn, $ch, $framed);
    }
    /**
     * Sends an SFTP STATUS packet.
     */
    protected function sftpSendStatus($conn, $ch, $rid,
        $code, $message)
    {
        $body = chr(self::SFTP_STATUS) . pack('N', $rid) .
            pack('N', $code) .
            $this->packString($message) .
            $this->packString('en');
        $this->sftpSendPacket($conn, $ch, $body);
    }
    /**
     * Sends an SFTP HANDLE packet.
     */
    protected function sftpSendHandle($conn, $ch, $rid,
        $handle)
    {
        $body = chr(self::SFTP_HANDLE) . pack('N', $rid) .
            $this->packString($handle);
        $this->sftpSendPacket($conn, $ch, $body);
    }
    /**
     * Sends an SFTP DATA packet.
     */
    protected function sftpSendData($conn, $ch, $rid,
        $data)
    {
        $body = chr(self::SFTP_DATA) . pack('N', $rid) .
            $this->packString($data);
        $this->sftpSendPacket($conn, $ch, $body);
    }
    /**
     * Sends an SFTP ATTRS packet.
     */
    protected function sftpSendAttrs($conn, $ch, $rid,
        $entry)
    {
        $body = chr(self::SFTP_ATTRS) . pack('N', $rid) .
            $this->encodeAttrs($entry);
        $this->sftpSendPacket($conn, $ch, $body);
    }
    /**
     * Encodes one entry-info array (the shape FtpStorage's
     * statEntry / listing returns) as an SFTP attributes
     * blob.
     */
    protected function encodeAttrs($entry)
    {
        if ($entry === false) {
            return pack('N', 0);
        }
        $flags = self::SFTP_ATTR_SIZE |
            self::SFTP_ATTR_PERMISSIONS |
            self::SFTP_ATTR_ACMODTIME;
        $perms = $entry['mode'];
        if ($entry['type'] === 'dir') {
            $perms |= 0x4000; /* S_IFDIR */
        } else {
            $perms |= 0x8000; /* S_IFREG */
        }
        $size = $entry['size'];
        $size_hi = ($size >> 32) & 0xFFFFFFFF;
        $size_lo = $size & 0xFFFFFFFF;
        return pack('N', $flags) .
            pack('NN', $size_hi, $size_lo) .
            pack('N', $perms) .
            pack('N', $entry['mtime']) .
            pack('N', $entry['mtime']);
    }
    /**
     * "ls -l"-style long name for a directory entry,
     * needed in NAME replies for READDIR.
     */
    protected function sftpLongName($entry)
    {
        $type = ($entry['type'] === 'dir') ? 'd' : '-';
        $perms = $entry['mode'];
        $perm_str = '';
        for ($shift = 6; $shift >= 0; $shift -= 3) {
            $bits = ($perms >> $shift) & 0x7;
            $perm_str .= ($bits & 0x4) ? 'r' : '-';
            $perm_str .= ($bits & 0x2) ? 'w' : '-';
            $perm_str .= ($bits & 0x1) ? 'x' : '-';
        }
        $when = date('M j H:i', $entry['mtime']);
        return sprintf("%s%s 1 atto atto %10d %s %s",
            $type, $perm_str, $entry['size'], $when,
            $entry['name']);
    }
    /**
     * Allocates a fresh handle string for a new file or
     * directory. Handles are short opaque ASCII strings
     * the client uses in subsequent operations.
     */
    protected function sftpAllocHandle($ch)
    {
        $id = $ch->app_state['next_handle']++;
        return 'h' . $id;
    }
    /*
        --- SFTP per-type handlers ---
     */
    /**
     * SSH_FXP_INIT. Body: uint32 client_version, plus
     * optional extensions we ignore. Server replies with
     * VERSION (we only speak version 3).
     */
    protected function sftpHandleInit($conn, $ch, $packet)
    {
        $ch->app_state['negotiated'] = true;
        $body = chr(self::SFTP_VERSION) . pack('N', 3);
        $this->sftpSendPacket($conn, $ch, $body);
    }
    /**
     * SSH_FXP_OPEN. Body: string filename, uint32 pflags,
     * ATTRS attrs.
     */
    protected function sftpHandleOpen($conn, $ch, $rid,
        $body)
    {
        $off = 0;
        list($filename, $off) = $this->readString($body,
            $off);
        list($pflags, $off) = $this->readUint32($body,
            $off);
        if ($filename === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_BAD_MESSAGE, 'bad open');
            return;
        }
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $filename);
        if ($resolved === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        $is_read = (bool) ($pflags &
            self::SFTP_OPEN_READ);
        $is_write = (bool) ($pflags &
            self::SFTP_OPEN_WRITE);
        if (!$is_read && !$is_write) {
            $is_read = true;
        }
        if ($is_write &&
            !empty($conn->user_info['read_only'])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'read-only user');
            return;
        }
        if ($is_read && !$is_write) {
            if (!$this->storage->exists($resolved) ||
                $this->storage->isDir($resolved)) {
                $this->sftpSendStatus($conn, $ch, $rid,
                    self::SFTP_FX_NO_SUCH_FILE,
                    'no such file');
                return;
            }
            $stream = $this->storage->openRead($resolved);
            if ($stream === false) {
                $this->sftpSendStatus($conn, $ch, $rid,
                    self::SFTP_FX_FAILURE, 'open failed');
                return;
            }
            $h = $this->sftpAllocHandle($ch);
            $ch->app_state['handles'][$h] = [
                'kind' => 'file',
                'mode' => 'r',
                'path' => $resolved,
                'stream' => $stream,
            ];
            $this->sftpSendHandle($conn, $ch, $rid, $h);
            return;
        }
        /*
            Write path. We can't open the file's underlying
            descriptor directly because FtpStorage's
            interface is "stream me an input source and I
            will persist it"; for SFTP we instead buffer
            writes into a temp file and flush via
            streamWrite() on CLOSE. This keeps the storage
            abstraction unchanged.
         */
        if (!$is_read && $is_write &&
            ($pflags & self::SFTP_OPEN_EXCL) &&
            $this->storage->exists($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'already exists');
            return;
        }
        $tmp = @tmpfile();
        if ($tmp === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE,
                'tmpfile creation failed');
            return;
        }
        $append = (bool) ($pflags &
            self::SFTP_OPEN_APPEND);
        $h = $this->sftpAllocHandle($ch);
        $ch->app_state['handles'][$h] = [
            'kind' => 'file',
            'mode' => 'w',
            'path' => $resolved,
            'stream' => $tmp,
            'append' => $append,
        ];
        $this->sftpSendHandle($conn, $ch, $rid, $h);
    }
    /**
     * SSH_FXP_CLOSE. Body: string handle.
     */
    protected function sftpHandleClose($conn, $ch, $rid,
        $body)
    {
        list($h, ) = $this->readString($body, 0);
        if (!isset($ch->app_state['handles'][$h])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'unknown handle');
            return;
        }
        $info = $ch->app_state['handles'][$h];
        unset($ch->app_state['handles'][$h]);
        if ($info['kind'] === 'dir') {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_OK, 'closed');
            return;
        }
        if ($info['mode'] === 'r') {
            @fclose($info['stream']);
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_OK, 'closed');
            return;
        }
        @rewind($info['stream']);
        $ok = $this->storage->streamWrite($info['path'],
            $info['stream'], !empty($info['append']));
        if (!$ok) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'write failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'written');
    }
    /**
     * SSH_FXP_READ. Body: string handle, uint64 offset,
     * uint32 length.
     */
    protected function sftpHandleRead($conn, $ch, $rid,
        $body)
    {
        $off = 0;
        list($h, $off) = $this->readString($body, $off);
        if (strlen($body) < $off + 12) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_BAD_MESSAGE, 'short read');
            return;
        }
        $hi = unpack('N', substr($body, $off, 4))[1];
        $lo = unpack('N', substr($body, $off + 4, 4))[1];
        $offset = ($hi << 32) | $lo;
        $length = unpack('N', substr($body, $off + 8,
            4))[1];
        if (!isset($ch->app_state['handles'][$h])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'unknown handle');
            return;
        }
        $info = $ch->app_state['handles'][$h];
        if ($info['kind'] !== 'file' ||
            $info['mode'] !== 'r') {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE,
                'handle not readable');
            return;
        }
        if (@fseek($info['stream'], $offset) < 0) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'seek failed');
            return;
        }
        $cap = min($length, 32768);
        $data = @fread($info['stream'], $cap);
        if ($data === false || $data === '') {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_EOF, 'eof');
            return;
        }
        $this->sftpSendData($conn, $ch, $rid, $data);
    }
    /**
     * SSH_FXP_WRITE. Body: string handle, uint64 offset,
     * string data.
     */
    protected function sftpHandleWrite($conn, $ch, $rid,
        $body)
    {
        $off = 0;
        list($h, $off) = $this->readString($body, $off);
        if (strlen($body) < $off + 8) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_BAD_MESSAGE, 'short write');
            return;
        }
        $hi = unpack('N', substr($body, $off, 4))[1];
        $lo = unpack('N', substr($body, $off + 4, 4))[1];
        $offset = ($hi << 32) | $lo;
        $off += 8;
        list($data, ) = $this->readString($body, $off);
        if ($data === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_BAD_MESSAGE, 'no data');
            return;
        }
        if (!isset($ch->app_state['handles'][$h])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'unknown handle');
            return;
        }
        $info = $ch->app_state['handles'][$h];
        if ($info['kind'] !== 'file' ||
            $info['mode'] !== 'w') {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE,
                'handle not writable');
            return;
        }
        if (@fseek($info['stream'], $offset) < 0) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'seek failed');
            return;
        }
        $written = @fwrite($info['stream'], $data);
        if ($written === false ||
            $written < strlen($data)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'write failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'written');
    }
    /**
     * SSH_FXP_STAT and SSH_FXP_LSTAT. Body: string path.
     * The demo storage has no symlinks, so we treat
     * these identically.
     */
    protected function sftpHandleStat($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $path);
        if ($resolved === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        $entry = $this->storage->statEntry($resolved);
        if ($entry === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_NO_SUCH_FILE,
                'no such file');
            return;
        }
        $this->sftpSendAttrs($conn, $ch, $rid, $entry);
    }
    /**
     * SSH_FXP_FSTAT. Body: string handle.
     */
    protected function sftpHandleFstat($conn, $ch, $rid,
        $body)
    {
        list($h, ) = $this->readString($body, 0);
        if (!isset($ch->app_state['handles'][$h])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'unknown handle');
            return;
        }
        $path = $ch->app_state['handles'][$h]['path'];
        $entry = $this->storage->statEntry($path);
        if ($entry === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'fstat failed');
            return;
        }
        $this->sftpSendAttrs($conn, $ch, $rid, $entry);
    }
    /**
     * SSH_FXP_OPENDIR. Body: string path. Captures the
     * directory listing into the handle for serial
     * READDIR pagination.
     */
    protected function sftpHandleOpendir($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $path);
        if ($resolved === false ||
            !$this->storage->isDir($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_NO_SUCH_FILE,
                'not a directory');
            return;
        }
        $entries = $this->storage->listing($resolved);
        if ($entries === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'list failed');
            return;
        }
        $h = $this->sftpAllocHandle($ch);
        $ch->app_state['handles'][$h] = [
            'kind' => 'dir',
            'path' => $resolved,
            'entries' => $entries,
            'pos' => 0,
        ];
        $this->sftpSendHandle($conn, $ch, $rid, $h);
    }
    /**
     * SSH_FXP_READDIR. Body: string handle. Iterates
     * the directory listing in chunks; replies with
     * STATUS=EOF when exhausted.
     */
    protected function sftpHandleReaddir($conn, $ch, $rid,
        $body)
    {
        list($h, ) = $this->readString($body, 0);
        if (!isset($ch->app_state['handles'][$h]) ||
            $ch->app_state['handles'][$h]['kind']
            !== 'dir') {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'unknown handle');
            return;
        }
        $info = &$ch->app_state['handles'][$h];
        $remaining = array_slice($info['entries'],
            $info['pos']);
        if (empty($remaining)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_EOF, 'eof');
            return;
        }
        $chunk = array_slice($remaining, 0, 64);
        $info['pos'] += count($chunk);
        $payload = chr(self::SFTP_NAME) .
            pack('N', $rid) . pack('N', count($chunk));
        foreach ($chunk as $entry) {
            $payload .= $this->packString($entry['name']) .
                $this->packString(
                $this->sftpLongName($entry)) .
                $this->encodeAttrs($entry);
        }
        $this->sftpSendPacket($conn, $ch, $payload);
    }
    /**
     * SSH_FXP_REMOVE. Body: string path.
     */
    protected function sftpHandleRemove($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        if (!empty($conn->user_info['read_only'])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'read-only user');
            return;
        }
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $path);
        if ($resolved === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        if (!$this->storage->exists($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_NO_SUCH_FILE, 'no such');
            return;
        }
        if (!$this->storage->deleteFile($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'remove failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'removed');
    }
    /**
     * SSH_FXP_MKDIR. Body: string path, ATTRS attrs.
     */
    protected function sftpHandleMkdir($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        if (!empty($conn->user_info['read_only'])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'read-only user');
            return;
        }
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $path);
        if ($resolved === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        if (!$this->storage->makeDir($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'mkdir failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'created');
    }
    /**
     * SSH_FXP_RMDIR. Body: string path.
     */
    protected function sftpHandleRmdir($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        if (!empty($conn->user_info['read_only'])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'read-only user');
            return;
        }
        $resolved = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $path);
        if ($resolved === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        if (!$this->storage->removeDir($resolved)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'rmdir failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'removed');
    }
    /**
     * SSH_FXP_REALPATH. Body: string path. Returns the
     * canonicalized version of the path as a single
     * NAME entry. Most clients call this once at startup
     * with "." to discover the working directory.
     */
    protected function sftpHandleRealpath($conn, $ch, $rid,
        $body)
    {
        list($path, ) = $this->readString($body, 0);
        if ($path === '' || $path === '.') {
            $resolved_ftp = $ch->app_state['cwd'];
        } else if (substr($path, 0, 1) === '/') {
            $resolved_ftp = $path;
        } else {
            $resolved_ftp = rtrim($ch->app_state['cwd'],
                '/') . '/' . $path;
        }
        $resolved_ftp = $this->normalizeFtpPath(
            $resolved_ftp);
        if ($resolved_ftp === false) {
            $resolved_ftp = '/';
        }
        $entry = ['name' => $resolved_ftp,
            'type' => 'dir',
            'size' => 0,
            'mtime' => time(),
            'mode' => 0755];
        $payload = chr(self::SFTP_NAME) .
            pack('N', $rid) . pack('N', 1) .
            $this->packString($resolved_ftp) .
            $this->packString(
            $this->sftpLongName($entry)) .
            $this->encodeAttrs($entry);
        $this->sftpSendPacket($conn, $ch, $payload);
    }
    /**
     * SSH_FXP_RENAME. Body: string oldpath, string newpath.
     */
    protected function sftpHandleRename($conn, $ch, $rid,
        $body)
    {
        $off = 0;
        list($from, $off) = $this->readString($body,
            $off);
        list($to, ) = $this->readString($body, $off);
        if (!empty($conn->user_info['read_only'])) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'read-only user');
            return;
        }
        $r_from = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $from);
        $r_to = $this->storage->resolveSafe(
            $ch->app_state['cwd'], $to);
        if ($r_from === false || $r_to === false) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_PERMISSION_DENIED,
                'invalid path');
            return;
        }
        if (!$this->storage->renameEntry($r_from,
            $r_to)) {
            $this->sftpSendStatus($conn, $ch, $rid,
                self::SFTP_FX_FAILURE, 'rename failed');
            return;
        }
        $this->sftpSendStatus($conn, $ch, $rid,
            self::SFTP_FX_OK, 'renamed');
    }

}

