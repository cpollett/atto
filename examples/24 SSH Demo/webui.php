<?php
/**
 * AttoSSH demo webui. Companion UI to index.php; see that
 * file for the demo's "how to run" docs and the full
 * configuration. This script is itself an atto WebSite
 * application that uses an embedded minimal SSH client
 * (the SshDemoClient class below) to exercise the running
 * SSH server. Three tabs:
 *
 *   1. Scenarios -- click-through canned exchanges. Each
 *      scenario opens a new SSH connection, runs through
 *      a sequence of operations, and renders the wire
 *      transcript.
 *   2. Raw command box -- pick a username (and a
 *      password or one of the bundled keys), type any
 *      "exec" command, see the output and transcript.
 *   3. File browser -- a server-side view of the storage
 *      root, with download / upload / rename / delete
 *      driven by real SFTP commands against the running
 *      server.
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 * License: GPL-3.0-or-later
 * @author Chris Pollett chris@pollett.org
 * @copyright 2017-2026
 * @filesource
 */
require '../../src/WebSite.php';
use seekquarry\atto\WebSite;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$site = new WebSite(".");
$cfg = [
    'host' => '127.0.0.1',
    'port' => 12222,
    'bind_file' => __DIR__ . DIRECTORY_SEPARATOR .
        'bind.txt',
    'bind_choices' => [
        '127.0.0.1' => 'IPv4 loopback (127.0.0.1)',
        '::1' => 'IPv6 loopback (::1)',
        '0.0.0.0' => 'IPv4 all interfaces (0.0.0.0)',
        '::' => 'IPv6 / dual-stack all interfaces (::)',
    ],
    'demo_users' => [
        ['user' => 'alice', 'pass' => 'hunter2'],
        ['user' => 'bob', 'pass' => 'sekret'],
        ['user' => 'guest', 'pass' => 'guest'],
    ],
    'demo_keys' => [
        'alice' => __DIR__ . DIRECTORY_SEPARATOR .
            'keys' . DIRECTORY_SEPARATOR .
            'alice_demo_key',
    ],
    'root' => __DIR__ . DIRECTORY_SEPARATOR . 'root',
];
$cfg['host'] = sshHostFromBind(
    is_file($cfg['bind_file']) ?
    trim((string) file_get_contents($cfg['bind_file'])) :
    '127.0.0.1');
function sshHostFromBind($bind)
{
    if ($bind === '::1' || $bind === '::') {
        return '::1';
    }
    return '127.0.0.1';
}
function sshDialUrl($host, $port)
{
    if (strpos($host, ':') !== false) {
        return "tcp://[$host]:$port";
    }
    return "tcp://$host:$port";
}
/**
 * Minimal SSH client used by the demo's webui. Speaks the
 * exact same algorithm suite the SshSite server speaks --
 * curve25519-sha256, ssh-ed25519 host key, AES-128-CTR
 * encryption with hmac-sha2-256-etm@openssh.com (server
 * side) plus hmac-sha2-256 (etm) on this client side too.
 *
 * Only the operations the webui needs are implemented:
 * banner exchange, KEXINIT, Curve25519 ECDH, NEWKEYS,
 * userauth password OR ed25519-publickey, one channel
 * for exec OR subsystem sftp, plus a small SFTP client
 * supporting OPEN/READ/CLOSE, OPEN/WRITE/CLOSE,
 * OPENDIR/READDIR/CLOSE, STAT, REALPATH, REMOVE, MKDIR,
 * RMDIR, RENAME.
 *
 * The client emits a structured transcript (text lines)
 * documenting each protocol step so the webui can render
 * it for educational display.
 */
class SshDemoClient
{
    /*
        SSH message types -- subset, only what the client
        uses.
     */
    const MSG_DISCONNECT = 1;
    const MSG_IGNORE = 2;
    const MSG_UNIMPLEMENTED = 3;
    const MSG_DEBUG = 4;
    const MSG_SERVICE_REQUEST = 5;
    const MSG_SERVICE_ACCEPT = 6;
    const MSG_KEXINIT = 20;
    const MSG_NEWKEYS = 21;
    const MSG_KEX_ECDH_INIT = 30;
    const MSG_KEX_ECDH_REPLY = 31;
    const MSG_USERAUTH_REQUEST = 50;
    const MSG_USERAUTH_FAILURE = 51;
    const MSG_USERAUTH_SUCCESS = 52;
    const MSG_USERAUTH_BANNER = 53;
    const MSG_USERAUTH_PK_OK = 60;
    const MSG_GLOBAL_REQUEST = 80;
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
        SFTP message types -- subset.
     */
    const SFTP_INIT = 1;
    const SFTP_VERSION = 2;
    const SFTP_OPEN = 3;
    const SFTP_CLOSE = 4;
    const SFTP_READ = 5;
    const SFTP_WRITE = 6;
    const SFTP_LSTAT = 7;
    const SFTP_OPENDIR = 11;
    const SFTP_READDIR = 12;
    const SFTP_REMOVE = 13;
    const SFTP_MKDIR = 14;
    const SFTP_RMDIR = 15;
    const SFTP_REALPATH = 16;
    const SFTP_STAT = 17;
    const SFTP_RENAME = 18;
    const SFTP_STATUS = 101;
    const SFTP_HANDLE = 102;
    const SFTP_DATA = 103;
    const SFTP_NAME = 104;
    const SFTP_ATTRS = 105;
    const SFTP_FX_OK = 0;
    const SFTP_FX_EOF = 1;
    const SFTP_OPEN_READ = 0x00000001;
    const SFTP_OPEN_WRITE = 0x00000002;
    const SFTP_OPEN_CREAT = 0x00000008;
    const SFTP_OPEN_TRUNC = 0x00000010;
    /**
     * @var resource TCP socket
     */
    protected $sock = null;
    /**
     * @var string client identification string we send
     */
    public $client_version = "SSH-2.0-atto-demo-client_1.0";
    /**
     * @var string server's "SSH-2.0-..." string, captured
     */
    public $server_version = "";
    /**
     * @var string our KEXINIT payload (saved for the
     *      exchange-hash computation)
     */
    protected $client_kexinit = "";
    /**
     * @var string server's KEXINIT payload (same)
     */
    protected $server_kexinit = "";
    /**
     * @var string ephemeral curve25519 secret key
     */
    protected $kex_secret = "";
    /**
     * @var string ephemeral curve25519 public key
     */
    protected $kex_public = "";
    /**
     * @var string the session ID -- frozen first
     *      exchange-hash, used in pubkey-auth signatures
     */
    public $session_id = "";
    /**
     * @var string server's host-key blob (ssh-ed25519
     *      formatted), captured for fingerprint display
     */
    public $host_key_blob = "";
    /**
     * @var int outgoing packet sequence number
     */
    protected $send_seq = 0;
    /**
     * @var int incoming packet sequence number
     */
    protected $recv_seq = 0;
    /**
     * @var bool true once we've sent NEWKEYS
     */
    protected $send_encrypted = false;
    /**
     * @var bool true once we've received NEWKEYS
     */
    protected $recv_encrypted = false;
    /**
     * @var string AES-128-CTR keys, IVs, and HMAC keys
     *      (post-KEX). Names mirror SshSite's naming
     *      from the server side: send_* are bytes we
     *      transmit, recv_* are bytes we receive.
     */
    protected $send_enc_key = "";
    protected $send_enc_iv = "";
    protected $send_mac_key = "";
    protected $recv_enc_key = "";
    protected $recv_enc_iv = "";
    protected $recv_mac_key = "";
    /**
     * @var string current AES-CTR counter for send
     */
    protected $send_ctr = "";
    /**
     * @var string current AES-CTR counter for recv
     */
    protected $recv_ctr = "";
    /**
     * @var string accumulated incoming bytes
     */
    protected $rxbuf = "";
    /**
     * @var array transcript lines collected during the
     *      session for educational rendering
     */
    protected $transcript = [];
    /**
     * @param string $url e.g. "tcp://127.0.0.1:12222"
     * @param string $client_version banner suffix to send
     */
    public function __construct($url, $client_version = '')
    {
        if ($client_version !== '') {
            $this->client_version = $client_version;
        }
        $errno = 0;
        $errstr = '';
        $this->sock = @stream_socket_client($url, $errno,
            $errstr, 4);
        if ($this->sock === false) {
            $this->log("! connect failed: $errstr");
            return;
        }
        stream_set_timeout($this->sock, 5);
        $this->log("> connected to $url");
    }
    /**
     * Returns true if the underlying socket is open.
     */
    public function isOpen()
    {
        return $this->sock !== null && $this->sock !== false;
    }
    /**
     * Returns the transcript collected so far.
     */
    public function transcript()
    {
        return $this->transcript;
    }
    /**
     * Logs one line into the transcript.
     */
    protected function log($line)
    {
        $this->transcript[] = $line;
    }
    /**
     * Closes the socket.
     */
    public function close()
    {
        if ($this->sock !== null) {
            @fclose($this->sock);
            $this->sock = null;
        }
    }
    /*
        ============================================================
        --- Wire-format helpers (RFC 4251 sec 5) ---
        ============================================================
     */
    protected function packString($s)
    {
        return pack('N', strlen($s)) . $s;
    }
    protected function readString($buf, $off)
    {
        if (strlen($buf) < $off + 4) {
            return [false, $off];
        }
        $len = unpack('N', substr($buf, $off, 4))[1];
        if ($len < 0 || strlen($buf) < $off + 4 + $len) {
            return [false, $off];
        }
        return [substr($buf, $off + 4, $len),
            $off + 4 + $len];
    }
    protected function readByte($buf, $off)
    {
        if (strlen($buf) < $off + 1) {
            return [0, $off];
        }
        return [ord($buf[$off]), $off + 1];
    }
    protected function readUint32($buf, $off)
    {
        if (strlen($buf) < $off + 4) {
            return [0, $off];
        }
        return [unpack('N', substr($buf, $off, 4))[1],
            $off + 4];
    }
    /**
     * Encodes an SSH "mpint" -- a two's-complement signed
     * big-endian integer wrapped in a length-prefixed
     * string. We only ever encode unsigned positive
     * values (the shared secret K and the curve25519
     * public keys); the "high bit set means add a leading
     * zero" rule still applies.
     */
    protected function packMpint($be_unsigned)
    {
        $b = ltrim($be_unsigned, "\x00");
        if ($b === '') {
            return $this->packString('');
        }
        if (ord($b[0]) >= 0x80) {
            $b = "\x00" . $b;
        }
        return $this->packString($b);
    }
    protected function packNameList($names)
    {
        return $this->packString(implode(',', $names));
    }
    /*
        ============================================================
        --- Banner + packet I/O ---
        ============================================================
     */
    /**
     * Sends our SSH banner and reads the server's. SSH
     * banners are CRLF-terminated, may be preceded by
     * other lines we ignore.
     */
    public function exchangeBanner()
    {
        if (!$this->isOpen()) {
            return false;
        }
        @fwrite($this->sock,
            $this->client_version . "\r\n");
        $this->log("> " . $this->client_version);
        /*
            Read lines until we see one starting with
            "SSH-"; that is the server's identification
            string.
         */
        $deadline = microtime(true) + 5;
        $line = '';
        while (microtime(true) < $deadline) {
            $c = @fgetc($this->sock);
            if ($c === false || $c === '') {
                usleep(20000);
                continue;
            }
            $line .= $c;
            if (str_ends_with($line, "\r\n")) {
                $trimmed = rtrim($line, "\r\n");
                if (substr($trimmed, 0, 4) === 'SSH-') {
                    $this->server_version = $trimmed;
                    $this->log("< " . $trimmed);
                    return true;
                }
                /* Pre-banner line; ignore and keep going */
                $this->log("< (pre-banner) " . $trimmed);
                $line = '';
            }
        }
        $this->log("! banner timeout");
        return false;
    }
    /**
     * Sends one SSH packet. Pre-NEWKEYS the format is
     * cleartext (length || padlen || payload || pad). Post-
     * NEWKEYS we use the etm (encrypt-then-MAC) flavor of
     * hmac-sha2-256: encrypt length+payload+pad with AES-
     * CTR, MAC the encrypted bytes plus the seq number.
     */
    public function sendPacket($payload)
    {
        if (!$this->isOpen()) {
            return false;
        }
        $blocksize = $this->send_encrypted ? 16 : 8;
        /*
            Total length = 1 (padlen byte) + payload + pad.
            pad must satisfy: total + 4 (len field, only
            in non-etm) % blocksize === 0, with minimum 4
            bytes of pad. With etm the length field is
            cleartext, so only payload+pad+1 must be
            multiple of blocksize.
         */
        if ($this->send_encrypted) {
            $rem = (1 + strlen($payload)) % $blocksize;
            $pad = $blocksize - $rem;
            if ($pad < 4) {
                $pad += $blocksize;
            }
        } else {
            $rem = (4 + 1 + strlen($payload)) % $blocksize;
            $pad = $blocksize - $rem;
            if ($pad < 4) {
                $pad += $blocksize;
            }
        }
        $padding = random_bytes($pad);
        $packet_len = 1 + strlen($payload) + $pad;
        $framed = pack('N', $packet_len) . chr($pad) .
            $payload . $padding;
        if (!$this->send_encrypted) {
            @fwrite($this->sock, $framed);
            $this->send_seq++;
            return true;
        }
        /*
            etm: MAC over (seqnum || cleartext-length-field
            || ciphertext-of-the-rest). Length stays in
            cleartext on the wire; everything after it is
            encrypted.
         */
        $len_bytes = substr($framed, 0, 4);
        $rest = substr($framed, 4);
        $cipher = $this->aesCtrEncrypt($rest, true);
        $mac = hash_hmac('sha256',
            pack('N', $this->send_seq) . $len_bytes .
            $cipher, $this->send_mac_key, true);
        @fwrite($this->sock, $len_bytes . $cipher . $mac);
        $this->send_seq++;
        return true;
    }
    /**
     * AES-128-CTR. We carry the counter forward between
     * packets so consecutive packets continue the keystream.
     * $is_send picks which counter and key to use.
     */
    protected function aesCtrEncrypt($data, $is_send)
    {
        if ($is_send) {
            $key = $this->send_enc_key;
            $ctr = $this->send_ctr;
        } else {
            $key = $this->recv_enc_key;
            $ctr = $this->recv_ctr;
        }
        $blocks = intdiv(strlen($data), 16);
        if (strlen($data) % 16) {
            $blocks++;
        }
        $out = @openssl_encrypt($data, 'aes-128-ctr',
            $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            $ctr);
        $ctr = $this->incrementCounter($ctr, $blocks);
        if ($is_send) {
            $this->send_ctr = $ctr;
        } else {
            $this->recv_ctr = $ctr;
        }
        return $out;
    }
    /**
     * Adds $n to a 16-byte big-endian counter. Used to
     * advance the AES-CTR state between blocks.
     */
    protected function incrementCounter($ctr, $n)
    {
        $bytes = unpack('C16', $ctr);
        for ($i = 16; $i >= 1 && $n > 0; $i--) {
            $sum = $bytes[$i] + ($n & 0xFF);
            $bytes[$i] = $sum & 0xFF;
            $n = ($n >> 8) + ($sum >> 8);
        }
        return pack('C16', $bytes[1], $bytes[2], $bytes[3],
            $bytes[4], $bytes[5], $bytes[6], $bytes[7],
            $bytes[8], $bytes[9], $bytes[10], $bytes[11],
            $bytes[12], $bytes[13], $bytes[14], $bytes[15],
            $bytes[16]);
    }
    /**
     * Reads one SSH packet. Pre-NEWKEYS we read the 4-byte
     * length field and pull the rest cleartext. Post-
     * NEWKEYS (etm) we read the cleartext length, the
     * ciphertext body, the MAC, verify, and decrypt.
     */
    public function readPacket()
    {
        if (!$this->isOpen()) {
            return false;
        }
        if (!$this->fillBuf(4)) {
            return false;
        }
        if (!$this->recv_encrypted) {
            $packet_len = unpack('N',
                substr($this->rxbuf, 0, 4))[1];
            if (!$this->fillBuf(4 + $packet_len)) {
                return false;
            }
            $framed = substr($this->rxbuf, 0,
                4 + $packet_len);
            $this->rxbuf = substr($this->rxbuf,
                4 + $packet_len);
            $padlen = ord($framed[4]);
            $payload = substr($framed, 5,
                $packet_len - $padlen - 1);
            $this->recv_seq++;
            return $payload;
        }
        /*
            etm: 4-byte length is cleartext; ciphertext is
            $packet_len bytes; then 32-byte SHA-256 MAC.
         */
        $packet_len = unpack('N',
            substr($this->rxbuf, 0, 4))[1];
        $needed = 4 + $packet_len + 32;
        if (!$this->fillBuf($needed)) {
            return false;
        }
        $len_bytes = substr($this->rxbuf, 0, 4);
        $cipher = substr($this->rxbuf, 4, $packet_len);
        $mac_in = substr($this->rxbuf, 4 + $packet_len,
            32);
        $this->rxbuf = substr($this->rxbuf, $needed);
        $mac_calc = hash_hmac('sha256',
            pack('N', $this->recv_seq) . $len_bytes .
            $cipher, $this->recv_mac_key, true);
        if (!hash_equals($mac_calc, $mac_in)) {
            $this->log("! MAC mismatch on incoming packet");
            return false;
        }
        $body = $this->aesCtrEncrypt($cipher, false);
        $padlen = ord($body[0]);
        $payload = substr($body, 1,
            $packet_len - $padlen - 1);
        $this->recv_seq++;
        return $payload;
    }
    /**
     * Fills $rxbuf until it has at least $n bytes.
     * Returns false on socket error / timeout.
     */
    protected function fillBuf($n)
    {
        $deadline = microtime(true) + 5;
        while (strlen($this->rxbuf) < $n) {
            if (microtime(true) > $deadline) {
                return false;
            }
            $chunk = @fread($this->sock,
                $n - strlen($this->rxbuf));
            if ($chunk === false || $chunk === '') {
                $info = stream_get_meta_data($this->sock);
                if (!empty($info['eof'])) {
                    return false;
                }
                usleep(10000);
                continue;
            }
            $this->rxbuf .= $chunk;
        }
        return true;
    }
    /*
        ============================================================
        --- Key exchange ---
        ============================================================

        The KEX dance the demo performs:

            1. Both sides send KEXINIT (algorithm offers)
            2. We send KEX_ECDH_INIT with our ephemeral
               curve25519 public Q_C
            3. Server sends KEX_ECDH_REPLY with K_S (host
               key blob), Q_S, and a signature over the
               exchange hash H
            4. We compute the shared secret K = X25519(
               our_secret, Q_S), and the exchange hash H
               from V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K
            5. We verify that the signature is valid Ed25519
               under the public key inside K_S
            6. We derive 6 keys (enc/iv/mac per direction)
               via the SHA-256 KDF
            7. Both sides exchange NEWKEYS; thereafter all
               packets are encrypted
     */
    /**
     * Sends our KEXINIT, receives the server's, then runs
     * the Curve25519 ECDH and NEWKEYS exchange. Returns
     * true on success (post-NEWKEYS state). The server's
     * host-key blob is stored in $this->host_key_blob
     * for the caller to inspect / pin.
     */
    public function performKex($pinned_host_key_blob = null)
    {
        if (!$this->sendClientKexInit()) {
            return false;
        }
        if (!$this->readServerKexInit()) {
            return false;
        }
        if (!$this->sendKexEcdhInit()) {
            return false;
        }
        if (!$this->readKexEcdhReply($pinned_host_key_blob))
        {
            return false;
        }
        if (!$this->exchangeNewKeys()) {
            return false;
        }
        return true;
    }
    /**
     * Builds and sends our KEXINIT. We offer the same
     * algorithms SshSite supports, plus a couple of common
     * fallbacks; the server picks the first mutually
     * supported algorithm in our list.
     */
    protected function sendClientKexInit()
    {
        $cookie = random_bytes(16);
        $kex = ['curve25519-sha256',
            'curve25519-sha256@libssh.org'];
        $hostkey = ['ssh-ed25519'];
        $cipher = ['aes128-ctr'];
        $mac = ['hmac-sha2-256-etm@openssh.com',
            'hmac-sha2-256'];
        $compress = ['none'];
        $lang = [''];
        $body = chr(self::MSG_KEXINIT) . $cookie .
            $this->packNameList($kex) .
            $this->packNameList($hostkey) .
            $this->packNameList($cipher) .
            $this->packNameList($cipher) .
            $this->packNameList($mac) .
            $this->packNameList($mac) .
            $this->packNameList($compress) .
            $this->packNameList($compress) .
            $this->packNameList($lang) .
            $this->packNameList($lang) .
            chr(0) . pack('N', 0);
        $this->client_kexinit = $body;
        $this->log("> KEXINIT (offering curve25519-sha256," .
            " ssh-ed25519, aes128-ctr, hmac-sha2-256-etm)");
        return $this->sendPacket($body);
    }
    /**
     * Reads the server's KEXINIT and saves it for the
     * exchange-hash computation. We don't need to inspect
     * the algorithms in detail because we only offer
     * algorithms we know SshSite supports.
     */
    protected function readServerKexInit()
    {
        $payload = $this->readPacket();
        if ($payload === false || strlen($payload) < 1 ||
            ord($payload[0]) !== self::MSG_KEXINIT) {
            $this->log("! expected KEXINIT");
            return false;
        }
        $this->server_kexinit = $payload;
        $this->log("< KEXINIT");
        return true;
    }
    /**
     * Generates an ephemeral curve25519 keypair via
     * sodium and sends the public half as KEX_ECDH_INIT.
     */
    protected function sendKexEcdhInit()
    {
        /*
            sodium_crypto_kx_keypair returns a 64-byte
            blob: 32-byte secret followed by 32-byte
            public, which is exactly the form Curve25519
            expects for X25519.
         */
        $kp = sodium_crypto_kx_keypair();
        $this->kex_secret =
            sodium_crypto_kx_secretkey($kp);
        $this->kex_public =
            sodium_crypto_kx_publickey($kp);
        $body = chr(self::MSG_KEX_ECDH_INIT) .
            $this->packString($this->kex_public);
        $this->log("> KEX_ECDH_INIT (sending Q_C, " .
            "32 bytes)");
        return $this->sendPacket($body);
    }
    /**
     * Reads KEX_ECDH_REPLY, verifies the signature on
     * the exchange hash, computes K and H, and sets up
     * key-derivation state. If $pinned is non-null, the
     * server's host-key blob is required to match it.
     */
    protected function readKexEcdhReply($pinned)
    {
        $payload = $this->readPacket();
        if ($payload === false || strlen($payload) < 1 ||
            ord($payload[0]) !== self::MSG_KEX_ECDH_REPLY) {
            $this->log("! expected KEX_ECDH_REPLY");
            return false;
        }
        $off = 1;
        list($K_S, $off) = $this->readString($payload,
            $off);
        list($Q_S, $off) = $this->readString($payload,
            $off);
        list($sig_blob, $off) = $this->readString($payload,
            $off);
        if ($K_S === false || $Q_S === false ||
            $sig_blob === false) {
            $this->log("! malformed KEX_ECDH_REPLY");
            return false;
        }
        $this->host_key_blob = $K_S;
        $fp = 'SHA256:' . rtrim(strtr(base64_encode(
            hash('sha256', $K_S, true)), '+/', '-_'),
            '=');
        $this->log("< KEX_ECDH_REPLY (host key " . $fp .
            ")");
        if ($pinned !== null && $K_S !== $pinned) {
            $this->log("! host-key mismatch (pinned " .
                "fingerprint did not match)");
            return false;
        }
        /*
            Compute K = X25519(our_secret, Q_S). Sodium's
            scalarmult is the X25519 primitive.
         */
        $K = sodium_crypto_scalarmult($this->kex_secret,
            $Q_S);
        if (strlen($K) !== 32) {
            $this->log("! scalarmult failed");
            return false;
        }
        /*
            Compute H = sha256(V_C || V_S || I_C || I_S ||
            K_S || Q_C || Q_S || K), where each || is the
            "string" or "mpint" encoding (length-prefixed).
            The KEXINIT payloads are encoded as strings.
         */
        $H_input = $this->packString($this->client_version) .
            $this->packString($this->server_version) .
            $this->packString($this->client_kexinit) .
            $this->packString($this->server_kexinit) .
            $this->packString($K_S) .
            $this->packString($this->kex_public) .
            $this->packString($Q_S) .
            $this->packMpint($K);
        $H = hash('sha256', $H_input, true);
        if ($this->session_id === '') {
            $this->session_id = $H;
        }
        /*
            Verify the signature on H against the public
            key inside K_S. K_S is itself an SSH "string"
            of "ssh-ed25519" + a "string" of the 32-byte
            public key. The signature blob is "ssh-ed25519"
            + a "string" of the 64-byte Ed25519 signature.
         */
        $kso = 0;
        list($host_alg, $kso) = $this->readString($K_S,
            $kso);
        list($host_pub, $kso) = $this->readString($K_S,
            $kso);
        $sgo = 0;
        list($sig_alg, $sgo) = $this->readString($sig_blob,
            $sgo);
        list($sig_bytes, $sgo) = $this->readString(
            $sig_blob, $sgo);
        if ($host_alg !== 'ssh-ed25519' ||
            $sig_alg !== 'ssh-ed25519' ||
            strlen($host_pub) !== 32 ||
            strlen($sig_bytes) !== 64) {
            $this->log("! unexpected host-key / sig types");
            return false;
        }
        $valid = sodium_crypto_sign_verify_detached(
            $sig_bytes, $H, $host_pub);
        if (!$valid) {
            $this->log("! host-key signature did not " .
                "verify");
            return false;
        }
        $this->log("  Ed25519 host-key signature verified");
        $this->K_mp = $this->packMpint($K);
        $this->H = $H;
        return true;
    }
    /**
     * Sends our NEWKEYS and reads the server's, derives
     * the six session keys, and switches both directions
     * into encrypted mode.
     */
    protected function exchangeNewKeys()
    {
        $this->sendPacket(chr(self::MSG_NEWKEYS));
        $this->log("> NEWKEYS");
        /*
            Per RFC 4253 sec 7.3, the KDF is:
              K1 = HASH(K || H || letter || session_id)
              K2 = HASH(K || H || K1)
              ...
            and we slice the resulting bytes for each key.
            For aes128-ctr we need 16 bytes of key+IV;
            for hmac-sha2-256 we need 32 bytes of mac key.
        */
        $this->send_enc_key = $this->deriveKey('C', 16);
        $this->recv_enc_key = $this->deriveKey('D', 16);
        $this->send_enc_iv = $this->deriveKey('A', 16);
        $this->recv_enc_iv = $this->deriveKey('B', 16);
        $this->send_mac_key = $this->deriveKey('E', 32);
        $this->recv_mac_key = $this->deriveKey('F', 32);
        $this->send_ctr = $this->send_enc_iv;
        $this->recv_ctr = $this->recv_enc_iv;
        $payload = $this->readPacket();
        if ($payload === false || strlen($payload) < 1 ||
            ord($payload[0]) !== self::MSG_NEWKEYS) {
            $this->log("! expected NEWKEYS");
            return false;
        }
        $this->log("< NEWKEYS");
        $this->send_encrypted = true;
        $this->recv_encrypted = true;
        $this->log("  transport encrypted: aes128-ctr + " .
            "hmac-sha2-256-etm");
        return true;
    }
    /**
     * RFC 4253 sec 7.2 KDF letter table: A=client-to-
     * server IV, B=server-to-client IV, C=c2s key, D=s2c
     * key, E=c2s integrity, F=s2c integrity. We are the
     * client, so "send" is c2s and "recv" is s2c.
     */
    protected function deriveKey($letter, $want_bytes)
    {
        $K_mp = $this->K_mp;
        $H = $this->H;
        $sid = $this->session_id;
        $out = hash('sha256',
            $K_mp . $H . $letter . $sid, true);
        while (strlen($out) < $want_bytes) {
            $out .= hash('sha256', $K_mp . $H . $out,
                true);
        }
        return substr($out, 0, $want_bytes);
    }
    /**
     * Holds the encoded mpint(K) and exchange hash H
     * across exchangeNewKeys, where they are needed to
     * derive the six session keys.
     */
    protected $K_mp = "";
    protected $H = "";
    /*
        ============================================================
        --- Userauth (RFC 4252) ---
        ============================================================
     */
    /**
     * Requests the "ssh-userauth" service, then attempts
     * password auth. Returns true on success.
     */
    public function authPassword($username, $password)
    {
        if (!$this->beginUserauthService()) {
            return false;
        }
        $body = chr(self::MSG_USERAUTH_REQUEST) .
            $this->packString($username) .
            $this->packString('ssh-connection') .
            $this->packString('password') .
            chr(0) .
            $this->packString($password);
        $this->log("> USERAUTH_REQUEST (password) for " .
            $username);
        $this->sendPacket($body);
        return $this->readUserauthResult();
    }
    /**
     * Requests the "ssh-userauth" service, then attempts
     * Ed25519 publickey auth. The keyfile path must point
     * at a sodium secret key (raw 64 bytes) accompanied by
     * its public key (32 bytes); for the demo we accept
     * the OpenSSH-format file we shipped under keys/.
     */
    public function authPublicKey($username, $keyfile_path)
    {
        $loaded = $this->loadEd25519Key($keyfile_path);
        if ($loaded === false) {
            $this->log("! failed to load key from " .
                $keyfile_path);
            return false;
        }
        list($priv64, $pub32) = $loaded;
        if (!$this->beginUserauthService()) {
            return false;
        }
        $key_blob = $this->packString('ssh-ed25519') .
            $this->packString($pub32);
        /*
            First send a "query" form (no signature) to
            check whether the server will accept a
            signature for this key. RFC 4252 sec 7. The
            server replies PK_OK or USERAUTH_FAILURE.
         */
        $query = chr(self::MSG_USERAUTH_REQUEST) .
            $this->packString($username) .
            $this->packString('ssh-connection') .
            $this->packString('publickey') .
            chr(0) .
            $this->packString('ssh-ed25519') .
            $this->packString($key_blob);
        $this->log("> USERAUTH_REQUEST (publickey query) " .
            "for " . $username);
        $this->sendPacket($query);
        $reply = $this->readPacket();
        if ($reply === false || strlen($reply) < 1) {
            $this->log("! no reply to pubkey query");
            return false;
        }
        $type = ord($reply[0]);
        if ($type !== self::MSG_USERAUTH_PK_OK) {
            $this->log("< pubkey query refused (type " .
                $type . ")");
            return false;
        }
        $this->log("< USERAUTH_PK_OK");
        /*
            Build the signature blob. RFC 4252 sec 7
            specifies:
              signed = string(session_id) || byte(50) ||
                       string(user) || string(svc) ||
                       string("publickey") || bool(true) ||
                       string(alg) || string(key_blob)
         */
        $signed = $this->packString($this->session_id) .
            chr(self::MSG_USERAUTH_REQUEST) .
            $this->packString($username) .
            $this->packString('ssh-connection') .
            $this->packString('publickey') .
            chr(1) .
            $this->packString('ssh-ed25519') .
            $this->packString($key_blob);
        $sig = sodium_crypto_sign_detached($signed,
            $priv64);
        $sig_blob = $this->packString('ssh-ed25519') .
            $this->packString($sig);
        $req = chr(self::MSG_USERAUTH_REQUEST) .
            $this->packString($username) .
            $this->packString('ssh-connection') .
            $this->packString('publickey') .
            chr(1) .
            $this->packString('ssh-ed25519') .
            $this->packString($key_blob) .
            $this->packString($sig_blob);
        $this->log("> USERAUTH_REQUEST (publickey signed)");
        $this->sendPacket($req);
        return $this->readUserauthResult();
    }
    /**
     * Sends SERVICE_REQUEST for "ssh-userauth" and reads
     * the SERVICE_ACCEPT.
     */
    protected function beginUserauthService()
    {
        $body = chr(self::MSG_SERVICE_REQUEST) .
            $this->packString('ssh-userauth');
        $this->log("> SERVICE_REQUEST ssh-userauth");
        $this->sendPacket($body);
        $r = $this->readPacket();
        if ($r === false || strlen($r) < 1 ||
            ord($r[0]) !== self::MSG_SERVICE_ACCEPT) {
            $this->log("! expected SERVICE_ACCEPT");
            return false;
        }
        $this->log("< SERVICE_ACCEPT ssh-userauth");
        return true;
    }
    /**
     * Reads the next packet expecting either USERAUTH_
     * SUCCESS or USERAUTH_FAILURE. Returns true on
     * success.
     */
    protected function readUserauthResult()
    {
        for ($i = 0; $i < 4; $i++) {
            $r = $this->readPacket();
            if ($r === false || strlen($r) < 1) {
                $this->log("! no userauth reply");
                return false;
            }
            $type = ord($r[0]);
            if ($type === self::MSG_USERAUTH_SUCCESS) {
                $this->log("< USERAUTH_SUCCESS");
                return true;
            }
            if ($type === self::MSG_USERAUTH_FAILURE) {
                list($methods, ) = $this->readString($r,
                    1);
                $this->log("< USERAUTH_FAILURE (methods " .
                    "still available: " . $methods . ")");
                return false;
            }
            if ($type === self::MSG_USERAUTH_BANNER) {
                /* skip and continue waiting */
                continue;
            }
            $this->log("< unexpected userauth packet " .
                "(type " . $type . ")");
            return false;
        }
        return false;
    }
    /**
     * Reads an OpenSSH-format Ed25519 private key file
     * and returns [secret_64, public_32]. Returns false on
     * any parse error. Only unencrypted (cipher "none")
     * files are supported -- the demo's bundled key has
     * no passphrase.
     */
    protected function loadEd25519Key($path)
    {
        $pem = @file_get_contents($path);
        if ($pem === false) {
            return false;
        }
        $body = preg_replace(
            '/-----BEGIN OPENSSH PRIVATE KEY-----|' .
            '-----END OPENSSH PRIVATE KEY-----|\s+/',
            '', $pem);
        $raw = base64_decode($body, true);
        if ($raw === false) {
            return false;
        }
        if (substr($raw, 0, 15) !==
            "openssh-key-v1\x00") {
            return false;
        }
        $off = 15;
        list($cipher, $off) = $this->readString($raw,
            $off);
        if ($cipher !== 'none') {
            return false;
        }
        list($kdf, $off) = $this->readString($raw, $off);
        list($kdfopts, $off) = $this->readString($raw,
            $off);
        list($nkeys, $off) = $this->readUint32($raw, $off);
        if ($nkeys !== 1) {
            return false;
        }
        list($pub_blob, $off) = $this->readString($raw,
            $off);
        list($priv_section, $off) = $this->readString($raw,
            $off);
        $po = 0;
        $po += 8; /* skip checkints */
        list($alg, $po) = $this->readString($priv_section,
            $po);
        if ($alg !== 'ssh-ed25519') {
            return false;
        }
        list($pub32, $po) = $this->readString(
            $priv_section, $po);
        list($priv64, $po) = $this->readString(
            $priv_section, $po);
        if (strlen($pub32) !== 32 ||
            strlen($priv64) !== 64) {
            return false;
        }
        return [$priv64, $pub32];
    }
    /*
        ============================================================
        --- Channel layer ---
        ============================================================
     */
    /**
     * Opens a session channel and waits for the
     * confirmation. Returns the [local_id, remote_id,
     * remote_window, remote_max_packet] tuple on success.
     */
    public function openSession()
    {
        $local_id = 0;
        $body = chr(self::MSG_CHANNEL_OPEN) .
            $this->packString('session') .
            pack('N', $local_id) .
            pack('N', 1048576) .
            pack('N', 32768);
        $this->log("> CHANNEL_OPEN session");
        $this->sendPacket($body);
        $r = $this->readPacket();
        if ($r === false || strlen($r) < 1 ||
            ord($r[0]) !==
            self::MSG_CHANNEL_OPEN_CONFIRMATION) {
            $this->log("! channel open failed");
            return false;
        }
        $this->log("< CHANNEL_OPEN_CONFIRMATION");
        $off = 1;
        list($local_echo, $off) = $this->readUint32($r,
            $off);
        list($remote_id, $off) = $this->readUint32($r,
            $off);
        list($remote_window, $off) = $this->readUint32($r,
            $off);
        list($remote_max_packet, $off) =
            $this->readUint32($r, $off);
        return [$local_id, $remote_id, $remote_window,
            $remote_max_packet];
    }
    /**
     * Sends a CHANNEL_REQUEST of type "exec" with the
     * given command. Returns true if the server replies
     * CHANNEL_SUCCESS.
     */
    public function execRequest($remote_id, $command)
    {
        $body = chr(self::MSG_CHANNEL_REQUEST) .
            pack('N', $remote_id) .
            $this->packString('exec') .
            chr(1) .
            $this->packString($command);
        $this->log("> CHANNEL_REQUEST exec " .
            json_encode($command));
        $this->sendPacket($body);
        return $this->awaitChannelSuccess();
    }
    /**
     * Sends a CHANNEL_REQUEST of type "subsystem" with
     * name "sftp". Returns true on CHANNEL_SUCCESS.
     */
    public function subsystemRequest($remote_id, $name)
    {
        $body = chr(self::MSG_CHANNEL_REQUEST) .
            pack('N', $remote_id) .
            $this->packString('subsystem') .
            chr(1) .
            $this->packString($name);
        $this->log("> CHANNEL_REQUEST subsystem " . $name);
        $this->sendPacket($body);
        return $this->awaitChannelSuccess();
    }
    /**
     * Pumps incoming packets until we see a
     * CHANNEL_SUCCESS or CHANNEL_FAILURE for the request
     * we just made. Other messages (window adjust, debug)
     * are absorbed and ignored.
     */
    protected function awaitChannelSuccess()
    {
        for ($i = 0; $i < 8; $i++) {
            $r = $this->readPacket();
            if ($r === false || strlen($r) < 1) {
                return false;
            }
            $type = ord($r[0]);
            if ($type === self::MSG_CHANNEL_SUCCESS) {
                $this->log("< CHANNEL_SUCCESS");
                return true;
            }
            if ($type === self::MSG_CHANNEL_FAILURE) {
                $this->log("< CHANNEL_FAILURE");
                return false;
            }
            if ($type === self::MSG_GLOBAL_REQUEST ||
                $type === self::MSG_DEBUG ||
                $type === self::MSG_IGNORE ||
                $type === self::MSG_CHANNEL_WINDOW_ADJUST) {
                continue;
            }
            /*
                Unexpected packet (often DATA arriving
                before SUCCESS for a quick exec). Push
                back and let the caller handle it via
                drainChannel.
             */
            $this->pending[] = $r;
        }
        return false;
    }
    /**
     * @var array deferred packets waiting to be consumed
     *      by drainChannel
     */
    protected $pending = [];
    /**
     * Sends CHANNEL_DATA with the given bytes.
     */
    public function sendChannelData($remote_id, $data)
    {
        $body = chr(self::MSG_CHANNEL_DATA) .
            pack('N', $remote_id) .
            $this->packString($data);
        $this->sendPacket($body);
    }
    /**
     * Reads packets until either EOF / CLOSE or a
     * CHANNEL_DATA chunk. Returns ['data' => string,
     * 'eof' => bool, 'close' => bool, 'exit_status' =>
     * int|null].
     *
     * The caller invokes this in a loop, accumulating
     * data and watching for close, the way an interactive
     * shell or exec session is consumed.
     */
    public function readChannelStep()
    {
        if (!empty($this->pending)) {
            $r = array_shift($this->pending);
        } else {
            $r = $this->readPacket();
        }
        if ($r === false || strlen($r) < 1) {
            return ['data' => '', 'eof' => true,
                'close' => true, 'exit_status' => null];
        }
        $type = ord($r[0]);
        if ($type === self::MSG_CHANNEL_DATA) {
            list(, $off) = $this->readUint32($r, 1);
            list($data, ) = $this->readString($r, $off);
            return ['data' => $data, 'eof' => false,
                'close' => false, 'exit_status' => null];
        }
        if ($type === self::MSG_CHANNEL_EXTENDED_DATA) {
            list(, $off) = $this->readUint32($r, 1);
            list(, $off) = $this->readUint32($r, $off);
            list($data, ) = $this->readString($r, $off);
            /*
                Extended data is stderr; we collapse it
                onto the same stream for the demo
                transcript.
             */
            return ['data' => $data, 'eof' => false,
                'close' => false, 'exit_status' => null];
        }
        if ($type === self::MSG_CHANNEL_REQUEST) {
            $off = 1;
            list(, $off) = $this->readUint32($r, $off);
            list($req, $off) = $this->readString($r, $off);
            list($want, $off) = $this->readByte($r, $off);
            if ($req === 'exit-status') {
                list($status, ) = $this->readUint32($r,
                    $off);
                $this->log("< exit-status = " . $status);
                return ['data' => '', 'eof' => false,
                    'close' => false,
                    'exit_status' => $status];
            }
            return ['data' => '', 'eof' => false,
                'close' => false, 'exit_status' => null];
        }
        if ($type === self::MSG_CHANNEL_EOF) {
            $this->log("< CHANNEL_EOF");
            return ['data' => '', 'eof' => true,
                'close' => false, 'exit_status' => null];
        }
        if ($type === self::MSG_CHANNEL_CLOSE) {
            $this->log("< CHANNEL_CLOSE");
            return ['data' => '', 'eof' => true,
                'close' => true, 'exit_status' => null];
        }
        if ($type === self::MSG_CHANNEL_WINDOW_ADJUST ||
            $type === self::MSG_GLOBAL_REQUEST ||
            $type === self::MSG_DEBUG ||
            $type === self::MSG_IGNORE) {
            return ['data' => '', 'eof' => false,
                'close' => false, 'exit_status' => null];
        }
        return ['data' => '', 'eof' => false,
            'close' => false, 'exit_status' => null];
    }
    /**
     * Reads bytes from the channel into a buffer until
     * the channel is closed; returns the accumulated
     * stdout plus the exit status (if any).
     */
    public function drainChannel($remote_id)
    {
        $out = '';
        $exit = null;
        $closed = false;
        for ($i = 0; $i < 200 && !$closed; $i++) {
            $step = $this->readChannelStep();
            if ($step['data'] !== '') {
                $out .= $step['data'];
            }
            if ($step['exit_status'] !== null) {
                $exit = $step['exit_status'];
            }
            if ($step['close']) {
                $closed = true;
            }
        }
        return ['stdout' => $out, 'exit_status' => $exit];
    }
    /**
     * Sends CHANNEL_CLOSE and waits briefly for the
     * server's confirmation.
     */
    public function closeChannel($remote_id)
    {
        $body = chr(self::MSG_CHANNEL_CLOSE) .
            pack('N', $remote_id);
        $this->sendPacket($body);
        for ($i = 0; $i < 4; $i++) {
            $r = $this->readPacket();
            if ($r === false) {
                return;
            }
            if (strlen($r) > 0 && ord($r[0]) ===
                self::MSG_CHANNEL_CLOSE) {
                return;
            }
        }
    }
    /**
     * Sends DISCONNECT and closes the socket.
     */
    public function disconnect()
    {
        if ($this->sock === null) {
            return;
        }
        $body = chr(self::MSG_DISCONNECT) .
            pack('N', 11) .
            $this->packString('demo done') .
            $this->packString('en');
        @$this->sendPacket($body);
        $this->close();
    }
    /*
        ============================================================
        --- SFTP client ---
        ============================================================

        Speaks SFTP version 3 over a previously-opened
        channel that has had subsystemRequest('sftp')
        called on it. The channel id is passed into each
        method so multiple SFTP sessions could share a
        client (the demo only ever opens one).

        Each SFTP request increments $sftp_rid; replies
        echo the same id and we use that to demultiplex
        if needed -- but since we operate strictly
        synchronously in this client (one outstanding
        request at a time) the id is just a sanity check.
     */
    /**
     * @var int next SFTP request id
     */
    protected $sftp_rid = 1;
    /**
     * @var string accumulator for SFTP packet framing
     *      coming back from the server
     */
    protected $sftp_rxbuf = '';
    /**
     * Sends SFTP_INIT and reads SFTP_VERSION. Returns
     * true on success.
     */
    public function sftpInit($remote_id)
    {
        $body = chr(self::SFTP_INIT) . pack('N', 3);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_INIT version=3");
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false || strlen($reply) < 5 ||
            ord($reply[0]) !== self::SFTP_VERSION) {
            $this->log("! expected SFTP_VERSION");
            return false;
        }
        $ver = unpack('N', substr($reply, 1, 4))[1];
        $this->log("< SFTP_VERSION " . $ver);
        return true;
    }
    /**
     * Sends one SFTP packet (with the uint32-length
     * framing) over the channel.
     */
    protected function sftpSendPacket($remote_id, $body)
    {
        $framed = pack('N', strlen($body)) . $body;
        $this->sendChannelData($remote_id, $framed);
    }
    /**
     * Reads one full SFTP packet from the channel data
     * stream. Returns the packet body (without the
     * length prefix) or false on end-of-channel.
     */
    protected function sftpReadPacket($remote_id)
    {
        while (true) {
            if (strlen($this->sftp_rxbuf) >= 4) {
                $plen = unpack('N',
                    substr($this->sftp_rxbuf, 0, 4))[1];
                if (strlen($this->sftp_rxbuf) >=
                    4 + $plen) {
                    $packet = substr($this->sftp_rxbuf, 4,
                        $plen);
                    $this->sftp_rxbuf = substr(
                        $this->sftp_rxbuf, 4 + $plen);
                    return $packet;
                }
            }
            $step = $this->readChannelStep();
            if ($step['close'] ||
                ($step['data'] === '' && $step['eof'])) {
                return false;
            }
            if ($step['data'] !== '') {
                $this->sftp_rxbuf .= $step['data'];
            }
        }
    }
    /**
     * SFTP REALPATH. Returns the canonicalized path or
     * false on error.
     */
    public function sftpRealpath($remote_id, $path)
    {
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_REALPATH) .
            pack('N', $rid) . $this->packString($path);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_REALPATH " . $path);
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false) {
            return false;
        }
        $type = ord($reply[0]);
        if ($type !== self::SFTP_NAME) {
            return false;
        }
        $off = 5;
        list($count, $off) = $this->readUint32($reply,
            $off);
        if ($count < 1) {
            return false;
        }
        list($name, ) = $this->readString($reply, $off);
        $this->log("< SFTP_NAME " . $name);
        return $name;
    }
    /**
     * SFTP STAT or LSTAT. Returns an attributes array
     * [size, mtime, type] or false. type is 'dir' if the
     * permission bits show S_IFDIR, else 'file'.
     */
    public function sftpStat($remote_id, $path)
    {
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_STAT) . pack('N', $rid) .
            $this->packString($path);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_STAT " . $path);
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false) {
            return false;
        }
        $type = ord($reply[0]);
        if ($type !== self::SFTP_ATTRS) {
            $this->log("< SFTP_STATUS (no such or " .
                "denied)");
            return false;
        }
        return $this->parseAttrs($reply, 5);
    }
    /**
     * Parses the ATTRS structure starting at offset $off
     * in $buf. Returns ['size', 'mtime', 'type', 'mode'].
     */
    protected function parseAttrs($buf, $off)
    {
        list($flags, $off) = $this->readUint32($buf, $off);
        $info = ['flags' => $flags, 'size' => 0,
            'mtime' => 0, 'mode' => 0,
            'type' => 'file'];
        if ($flags & 0x00000001) {
            $hi = unpack('N',
                substr($buf, $off, 4))[1];
            $lo = unpack('N',
                substr($buf, $off + 4, 4))[1];
            $info['size'] = ($hi << 32) | $lo;
            $off += 8;
        }
        if ($flags & 0x00000002) {
            $off += 8;
        }
        if ($flags & 0x00000004) {
            list($mode, $off) = $this->readUint32($buf,
                $off);
            $info['mode'] = $mode;
            $info['type'] = ($mode & 0x4000) ? 'dir' :
                'file';
        }
        if ($flags & 0x00000008) {
            list($atime, $off) = $this->readUint32($buf,
                $off);
            list($mtime, $off) = $this->readUint32($buf,
                $off);
            $info['mtime'] = $mtime;
        }
        return $info;
    }
    /**
     * SFTP OPENDIR + READDIR loop + CLOSE. Returns an
     * array of entry-info arrays or false on error.
     */
    public function sftpListDir($remote_id, $path)
    {
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_OPENDIR) .
            pack('N', $rid) . $this->packString($path);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_OPENDIR " . $path);
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false || ord($reply[0]) !==
            self::SFTP_HANDLE) {
            $this->log("! opendir failed");
            return false;
        }
        list($handle, ) = $this->readString($reply, 5);
        $entries = [];
        for ($i = 0; $i < 100; $i++) {
            $rid = $this->sftp_rid++;
            $body = chr(self::SFTP_READDIR) .
                pack('N', $rid) .
                $this->packString($handle);
            $this->sftpSendPacket($remote_id, $body);
            $reply = $this->sftpReadPacket($remote_id);
            if ($reply === false) {
                break;
            }
            $type = ord($reply[0]);
            if ($type === self::SFTP_STATUS) {
                break;
            }
            if ($type !== self::SFTP_NAME) {
                break;
            }
            $off = 5;
            list($count, $off) = $this->readUint32($reply,
                $off);
            for ($j = 0; $j < $count; $j++) {
                list($name, $off) = $this->readString(
                    $reply, $off);
                list($longname, $off) = $this->readString(
                    $reply, $off);
                $attrs = $this->parseAttrs($reply, $off);
                /*
                    Advance past the parsed attrs by
                    re-running its decode. Cheaper to do
                    a tiny re-walk than refactor parseAttrs
                    to return the new offset.
                 */
                list($flags, $off) = $this->readUint32(
                    $reply, $off);
                if ($flags & 0x00000001) {
                    $off += 8;
                }
                if ($flags & 0x00000002) {
                    $off += 8;
                }
                if ($flags & 0x00000004) {
                    $off += 4;
                }
                if ($flags & 0x00000008) {
                    $off += 8;
                }
                $entries[] = ['name' => $name,
                    'longname' => $longname,
                    'size' => $attrs['size'],
                    'mtime' => $attrs['mtime'],
                    'type' => $attrs['type']];
            }
        }
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_CLOSE) . pack('N', $rid) .
            $this->packString($handle);
        $this->sftpSendPacket($remote_id, $body);
        $this->sftpReadPacket($remote_id);
        $this->log("< " . count($entries) . " entries");
        return $entries;
    }
    /**
     * SFTP OPEN + READ loop + CLOSE for a small file.
     * Returns the file contents or false.
     */
    public function sftpReadFile($remote_id, $path)
    {
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_OPEN) . pack('N', $rid) .
            $this->packString($path) .
            pack('N', self::SFTP_OPEN_READ) .
            pack('N', 0);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_OPEN " . $path . " (read)");
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false || ord($reply[0]) !==
            self::SFTP_HANDLE) {
            $this->log("! open failed");
            return false;
        }
        list($handle, ) = $this->readString($reply, 5);
        $out = '';
        $offset = 0;
        for ($i = 0; $i < 1000; $i++) {
            $rid = $this->sftp_rid++;
            $body = chr(self::SFTP_READ) .
                pack('N', $rid) .
                $this->packString($handle) .
                pack('NN', 0, $offset) .
                pack('N', 32768);
            $this->sftpSendPacket($remote_id, $body);
            $reply = $this->sftpReadPacket($remote_id);
            if ($reply === false) {
                break;
            }
            $type = ord($reply[0]);
            if ($type === self::SFTP_STATUS) {
                /* status with EOF means we are done */
                break;
            }
            if ($type !== self::SFTP_DATA) {
                break;
            }
            list($chunk, ) = $this->readString($reply, 5);
            $out .= $chunk;
            $offset += strlen($chunk);
            if (strlen($chunk) < 32768) {
                /* last chunk */
                break;
            }
        }
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_CLOSE) . pack('N', $rid) .
            $this->packString($handle);
        $this->sftpSendPacket($remote_id, $body);
        $this->sftpReadPacket($remote_id);
        $this->log("< read " . strlen($out) . " bytes");
        return $out;
    }
    /**
     * SFTP OPEN(write) + WRITE + CLOSE for a small file.
     * Returns true on success.
     */
    public function sftpWriteFile($remote_id, $path,
        $data)
    {
        $rid = $this->sftp_rid++;
        $flags = self::SFTP_OPEN_WRITE |
            self::SFTP_OPEN_CREAT | self::SFTP_OPEN_TRUNC;
        $body = chr(self::SFTP_OPEN) . pack('N', $rid) .
            $this->packString($path) .
            pack('N', $flags) . pack('N', 0);
        $this->sftpSendPacket($remote_id, $body);
        $this->log("> SFTP_OPEN " . $path . " (write)");
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false || ord($reply[0]) !==
            self::SFTP_HANDLE) {
            $this->log("! open(write) failed");
            return false;
        }
        list($handle, ) = $this->readString($reply, 5);
        $offset = 0;
        $remaining = $data;
        while (strlen($remaining) > 0) {
            $chunk = substr($remaining, 0, 16384);
            $remaining = substr($remaining,
                strlen($chunk));
            $rid = $this->sftp_rid++;
            $body = chr(self::SFTP_WRITE) .
                pack('N', $rid) .
                $this->packString($handle) .
                pack('NN', 0, $offset) .
                $this->packString($chunk);
            $this->sftpSendPacket($remote_id, $body);
            $reply = $this->sftpReadPacket($remote_id);
            if ($reply === false ||
                ord($reply[0]) !== self::SFTP_STATUS) {
                $this->log("! write failed");
                return false;
            }
            $code = unpack('N', substr($reply, 5, 4))[1];
            if ($code !== self::SFTP_FX_OK) {
                $this->log("! write status " . $code);
                return false;
            }
            $offset += strlen($chunk);
        }
        $rid = $this->sftp_rid++;
        $body = chr(self::SFTP_CLOSE) . pack('N', $rid) .
            $this->packString($handle);
        $this->sftpSendPacket($remote_id, $body);
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false ||
            ord($reply[0]) !== self::SFTP_STATUS) {
            return false;
        }
        $code = unpack('N', substr($reply, 5, 4))[1];
        $this->log("< close status " . $code);
        return $code === self::SFTP_FX_OK;
    }
    /**
     * SFTP REMOVE / MKDIR / RMDIR / RENAME (one-shot
     * status replies). Returns true on STATUS=OK.
     */
    public function sftpStatusOp($remote_id, $type, $path,
        $second = null)
    {
        $rid = $this->sftp_rid++;
        $body = chr($type) . pack('N', $rid) .
            $this->packString($path);
        if ($second !== null) {
            $body .= $this->packString($second);
        }
        $this->sftpSendPacket($remote_id, $body);
        $name = ['', '', 'INIT', '', '', '', '', '', '',
            '', '', '', '', 'REMOVE', 'MKDIR', 'RMDIR',
            'REALPATH', 'STAT', 'RENAME'][$type] ?? '';
        $this->log("> SFTP_" . $name . " " . $path .
            ($second !== null ? " -> " . $second : ""));
        $reply = $this->sftpReadPacket($remote_id);
        if ($reply === false ||
            ord($reply[0]) !== self::SFTP_STATUS) {
            return false;
        }
        $code = unpack('N', substr($reply, 5, 4))[1];
        $this->log("< STATUS " . $code);
        return $code === self::SFTP_FX_OK;
    }
}
/*
    ============================================================
    --- Stylesheet ---
    ============================================================
    Same palette and row-based layout the other atto demos
    use (#06c blue, #b33 close, #f6f6f6 cards, #1e1e1e
    transcript). The Run -> Running... -> X toggle is the
    same shape as ex22/ex23/ex25.
 */
$site->get('/style.css', function () use ($site) {
    $site->header("Content-Type: text/css");
    echo <<<'CSS'
body { font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, sans-serif;
    max-width: 940px; margin: 1.5em auto; padding: 0 1em;
    color: #222; }
h1 { margin-bottom: 0.1em; }
.meta { color: #666; font-size: 0.9em;
    margin-bottom: 1.5em; }
h2 { font-size: 1.05em; margin-top: 1.6em;
    padding-bottom: 0.2em; border-bottom: 1px solid #ddd; }
.note { color: #555; font-size: 0.88em; }
code { background: #eee; padding: 0.1em 0.3em;
    border-radius: 3px; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
nav.tabs { display: flex; gap: 4px; margin: 0.5em 0 1em;
    border-bottom: 1px solid #ddd; }
nav.tabs a { padding: 0.5em 1em; text-decoration: none;
    color: #444; border: 1px solid transparent;
    border-bottom: none; border-radius: 4px 4px 0 0; }
nav.tabs a.active { background: #f6f6f6; border-color: #ddd;
    color: #111; font-weight: 600; }
.bind-bar { display: flex; align-items: center; gap: 1em;
    margin: 0 0 1.5em; padding: 0.7em 0.9em;
    background: #ecf3ff; border: 1px solid #b8c8e8;
    border-radius: 4px; }
.bind-bar label { font-size: 0.9em; color: #234;
    font-weight: 600; }
.bind-bar select { font: inherit; padding: 0.3em 0.5em;
    border-radius: 4px; border: 1px solid #b8c8e8;
    background: #fff; }
.bind-bar .bind-status { color: #555; font-size: 0.9em;
    flex: 1; }
.scenario { margin: 0.6em 0; padding: 0.7em 0.9em;
    background: #f6f6f6; border-radius: 4px; }
.scenario .row { display: flex; align-items: center;
    justify-content: space-between; gap: 1em; }
.scenario .label { font-weight: 600; }
.scenario .desc { color: #555; font-size: 0.92em;
    margin-top: 0.25em; }
.scenario button { font: inherit; padding: 0.35em 0.9em;
    background: #06c; color: white; border: 0;
    border-radius: 4px; cursor: pointer; flex-shrink: 0;
    min-width: 4.5em; text-align: center; }
.scenario button:disabled { background: #888;
    cursor: default; }
.scenario button.close { background: #b33; }
.scenario button.close:hover { background: #c44; }
.scenario .transcript { display: none; margin-top: 0.7em;
    background: #1e1e1e; color: #ddd; padding: 0.8em;
    border-radius: 4px; white-space: pre-wrap;
    font-size: 0.85em; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; max-height: 380px;
    overflow: auto; }
.scenario .transcript.visible { display: block; }
.scenario .note-hint { display: none; margin-top: 0.6em;
    padding: 0.55em 0.8em; background: #fff8e1;
    border-left: 3px solid #f0b400; color: #5a4400;
    font-size: 0.88em; line-height: 1.45;
    border-radius: 0 3px 3px 0; }
.scenario .note-hint.visible { display: block; }
form.raw { background: #f6f6f6; padding: 0.9em;
    border-radius: 4px; margin: 0.6em 0; }
form.raw label { display: block; font-size: 0.85em;
    color: #555; margin-bottom: 0.2em; }
form.raw .row { display: flex; gap: 1em;
    margin-bottom: 0.7em; align-items: end; flex-wrap: wrap;}
form.raw .row > div { flex: 1; min-width: 180px; }
form.raw select, form.raw input[type=text] { font: inherit;
    padding: 0.35em 0.5em; border: 1px solid #bbb;
    border-radius: 3px; width: 100%; }
form.raw button { font: inherit; padding: 0.4em 1em;
    background: #06c; color: white; border: 0;
    border-radius: 4px; cursor: pointer; margin-top: 0.5em; }
form.raw button:hover { background: #0050a0; }
#rawResult { margin-top: 0.7em; }
pre.transcript-static { background: #1e1e1e; color: #ddd;
    padding: 0.8em; border-radius: 4px; white-space: pre-wrap;
    font-size: 0.85em; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; max-height: 380px;
    overflow: auto; margin: 0; }
.banner { background: #ecf3ff; color: #234;
    border: 1px solid #b8c8e8; padding: 0.7em 0.9em;
    border-radius: 4px; font-size: 0.9em;
    margin-bottom: 1em; line-height: 1.4; }
.banner code { background: rgba(0,0,0,0.06); }
.browse-table { width: 100%; border-collapse: collapse;
    background: #fff; border: 1px solid #ddd;
    border-radius: 3px; margin-top: 0.6em; }
.browse-table th, .browse-table td { text-align: left;
    padding: 0.45em 0.7em; border-bottom: 1px solid #eee;
    font-size: 0.92em; vertical-align: middle; }
.browse-table th { background: #f4f4f4; font-weight: 600;
    font-size: 0.85em; }
.browse-table .actions { white-space: nowrap; }
.browse-table .actions a { color: #06c; text-decoration:
    none; margin-right: 0.6em; font-size: 0.88em; }
.browse-table .actions a:hover { text-decoration:
    underline; }
.browse-table .actions a.danger { color: #b33; }
.crumbs { font-size: 0.9em; margin: 0.6em 0; color: #555; }
.crumbs a { color: #06c; text-decoration: none; }
.crumbs a:hover { text-decoration: underline; }
.upload-bar { margin: 0.8em 0; padding: 0.7em 0.9em;
    background: #f6f6f6; border-radius: 4px; }
.user-switcher { margin: 0.6em 0 0; padding: 0.55em 0.8em;
    background: #fffbe9; border: 1px solid #f0e0a8;
    border-radius: 4px; display: flex; align-items: center;
    gap: 0.6em; flex-wrap: wrap; font-size: 0.9em;
    color: #4a3c00; }
.user-switcher select { font: inherit; padding: 0.2em
    0.4em; border-radius: 3px; border: 1px solid #d8c890;
    background: #fff; }
.user-switcher .reset-btn { font: inherit; padding: 0.3em
    0.8em; background: #b33; color: white; border: 0;
    border-radius: 4px; cursor: pointer; margin-left: auto; }
.user-switcher .reset-btn:disabled { background: #888;
    cursor: default; }
.user-switcher .reset-btn:hover { background: #c44; }
.browse-table .entry-icon { width: 1.6em; text-align:
    center; font-size: 1.05em; padding-right: 0; }
CSS;
});
/*
    ============================================================
    --- Page renderer ---
    ============================================================
 */
function sshRenderPage($which, $cfg, $body_fn)
{
    $tabs = [
        'scenarios' => ['/', 'Scenarios'],
        'raw' => ['/raw', 'Raw command box'],
        'browser' => ['/browser', 'File browser'],
    ];
    echo "<!DOCTYPE html><html lang=\"en\"><head>";
    echo "<meta charset=\"utf-8\">";
    echo "<meta name=\"viewport\" content=\"width=" .
        "device-width, initial-scale=1\">";
    echo "<title>AttoSSH Demo</title>";
    echo "<link rel=\"stylesheet\" href=\"/style.css\">";
    echo "</head><body>";
    echo "<h1>AttoSSH Demo</h1>";
    $display_host = (strpos($cfg['host'], ':') !== false) ?
        '[' . $cfg['host'] . ']' : $cfg['host'];
    echo "<div class=\"meta\">SSH listener on tcp://" .
        htmlspecialchars($display_host) . ":" .
        (int) $cfg['port'] . " &middot; demo creds " .
        "<code>alice / hunter2</code>, " .
        "<code>bob / sekret</code>, " .
        "<code>guest / guest</code> (read-only). Companion " .
        "UI to <code>index.php</code>; every transcript on " .
        "this page comes from a real SSH session driven by " .
        "an embedded client.</div>";
    $current_bind = is_file($cfg['bind_file']) ?
        trim((string) file_get_contents(
        $cfg['bind_file'])) : '127.0.0.1';
    if (!isset($cfg['bind_choices'][$current_bind])) {
        $current_bind = '127.0.0.1';
    }
    echo "<div class=\"bind-bar\">";
    echo "<label for=\"bind-select\">Bind:</label>";
    echo "<select id=\"bind-select\">";
    foreach ($cfg['bind_choices'] as $key => $label) {
        $sel = ($key === $current_bind) ? ' selected' : '';
        echo "<option value=\"" . htmlspecialchars($key) .
            "\"$sel>" . htmlspecialchars($label) .
            "</option>";
    }
    echo "</select>";
    echo "<span class=\"bind-status\" id=\"bind-status\">";
    echo "Switching the bind stops the server. Relaunch " .
        "<code>php index.php</code> in your terminal " .
        "after the switch to see the demo on the new " .
        "family.";
    echo "</span></div>";
    echo "<nav class=\"tabs\">";
    foreach ($tabs as $key => $info) {
        list($url, $label) = $info;
        $cls = ($key === $which) ? ' class="active"' : '';
        echo "<a href=\"$url\"$cls>" .
            htmlspecialchars($label) . "</a>";
    }
    echo "</nav>";
    $body_fn();
    echo "<script>" . sshBindScript() . "</script>";
    echo "</body></html>";
}
function sshBindScript()
{
    return <<<'JS'
(function () {
    var sel = document.getElementById('bind-select');
    if (!sel) return;
    var current = sel.value;
    sel.addEventListener('change', function () {
        if (sel.value === current) return;
        if (!window.confirm(
            'Switch the listener bind to "' + sel.value +
            '"?\n\nThe server will stop after this ' +
            'request. You will need to run "php ' +
            'index.php" again in the terminal to see the ' +
            'example with the new bind.')) {
            sel.value = current;
            return;
        }
        sel.disabled = true;
        var fd = new FormData();
        fd.append('bind', sel.value);
        fetch('/bind', { method: 'POST', body: fd })
            .then(function (r) { return r.text(); })
            .then(function (msg) {
                document.body.innerHTML =
                    '<h1>Bind switched</h1>' +
                    '<p>The server has been asked to ' +
                    'shut down. Once it exits in your ' +
                    'terminal, run:</p>' +
                    '<pre style="background:#1e1e1e;' +
                    'color:#ddd;padding:1em;' +
                    'border-radius:4px;">php index.php' +
                    '</pre>' +
                    '<p>and reload this page to see ' +
                    'the demo on <code>' +
                    sel.value.replace(/[<>&]/g, '') +
                    '</code>.</p>';
            })
            .catch(function (err) {
                sel.value = current;
                sel.disabled = false;
            });
    });
})();
JS;
}
/*
    ============================================================
    --- Scenarios ---
    ============================================================

    Each scenario opens a fresh SSH connection against the
    running server, runs through a sequence of operations,
    and returns a transcript. The transcript is the same
    line-by-line trace SshDemoClient logs internally.
 */
/**
 * Builds a fresh SshDemoClient and walks it through the
 * common prefix: banner, kex. Returns the client (post-
 * NEWKEYS) or false. Caller is responsible for disconnect.
 */
function sshConnect($cfg)
{
    $url = sshDialUrl($cfg['host'], $cfg['port']);
    $c = new SshDemoClient($url);
    if (!$c->isOpen()) {
        return $c;
    }
    if (!$c->exchangeBanner()) {
        return $c;
    }
    if (!$c->performKex()) {
        return $c;
    }
    return $c;
}
/**
 * Returns the static scenario list. Each entry has:
 *   title -- one-line headline shown on the card
 *   desc  -- a sentence or two of context
 *   run   -- callable that takes ($cfg) and returns
 *            ['transcript' => text, 'note' => string|null]
 */
function sshScenarioList($cfg)
{
    return [
        'banner-and-kex' => [
            'title' => 'Banner exchange and Curve25519 KEX',
            'desc' => 'TCP connect, swap "SSH-2.0-..." ' .
                'banners, send KEXINIT, run Curve25519 ' .
                'ECDH, verify the Ed25519 host-key ' .
                'signature on the exchange hash, and ' .
                'switch to encrypted mode. No userauth ' .
                'after that -- we disconnect immediately.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->disconnect();
                $fp = '';
                if ($c->host_key_blob !== '') {
                    $fp = 'SHA256:' .
                        rtrim(strtr(base64_encode(hash(
                        'sha256', $c->host_key_blob, true)),
                        '+/', '-_'), '=');
                }
                return [
                    'transcript' =>
                        implode("\n", $c->transcript()),
                    'note' => 'Host-key fingerprint: ' . $fp .
                        '. The Ed25519 signature on H is ' .
                        'how the client knows it is talking ' .
                        'to the legitimate server.',
                ];
            },
        ],
        'password-auth' => [
            'title' => 'Password authentication for alice',
            'desc' => 'After KEX, request the ssh-' .
                'userauth service and authenticate alice ' .
                'with the password "hunter2". The userauth ' .
                'request runs over the encrypted transport ' .
                'set up in the previous scenario.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                $c->disconnect();
                return [
                    'transcript' =>
                        implode("\n", $c->transcript()),
                    'note' => null,
                ];
            },
        ],
        'pubkey-auth' => [
            'title' => 'Ed25519 publickey authentication',
            'desc' => 'Same userauth flow but with ' .
                'publickey method. The client sends an ' .
                'unsigned query first; if the server ' .
                'replies USERAUTH_PK_OK, the client ' .
                'follows up with a real Ed25519 signature ' .
                'over the session ID and request blob.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $key = $cfg['demo_keys']['alice'];
                $c->authPublicKey('alice', $key);
                $c->disconnect();
                return [
                    'transcript' =>
                        implode("\n", $c->transcript()),
                    'note' => 'The two-phase dance is the ' .
                        'point: the cheap query lets the ' .
                        'client try several keys in turn ' .
                        'without having to compute a ' .
                        'signature for each.',
                ];
            },
        ],
        'wrong-password' => [
            'title' => 'Wrong password is rejected',
            'desc' => 'Same flow as password-auth, but ' .
                'with the wrong password. The server ' .
                'replies USERAUTH_FAILURE and lists the ' .
                'methods still available for retry.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'WRONG');
                $c->disconnect();
                return [
                    'transcript' =>
                        implode("\n", $c->transcript()),
                    'note' => null,
                ];
            },
        ],
        'exec-pwd' => [
            'title' => 'Open a session, exec "pwd"',
            'desc' => 'After auth, open a session ' .
                'channel, send a CHANNEL_REQUEST of type ' .
                'exec for the command "pwd", read back ' .
                'the output and exit-status. The "pwd" ' .
                'command in the demo shell prints the ' .
                'channel\'s working directory in the ' .
                'storage tree.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                $session = $c->openSession();
                if ($session === false) {
                    $c->disconnect();
                    return [
                        'transcript' =>
                            implode("\n", $c->transcript()),
                        'note' => null,
                    ];
                }
                list(, $rid) = $session;
                $c->execRequest($rid, 'pwd');
                $r = $c->drainChannel($rid);
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- stdout ---\n" .
                    $r['stdout'] .
                    "\n--- exit-status: " .
                    var_export($r['exit_status'], true);
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => null];
            },
        ],
        'exec-ls' => [
            'title' => 'Exec "ls" on the storage root',
            'desc' => 'Same machinery as exec-pwd but the ' .
                'command is "ls /". Output is multi-line; ' .
                'each entry is on its own line in the ' .
                'demo shell\'s output format.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                list(, $rid) = $c->openSession();
                $c->execRequest($rid, 'ls /');
                $r = $c->drainChannel($rid);
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- stdout ---\n" .
                    $r['stdout'] .
                    "\n--- exit-status: " .
                    var_export($r['exit_status'], true);
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => null];
            },
        ],
        'exec-cat' => [
            'title' => 'Exec "cat /pub/welcome.txt"',
            'desc' => 'Reads a file from the storage root ' .
                'via the toy shell\'s "cat" command. The ' .
                'output flows back over CHANNEL_DATA ' .
                'messages, gets buffered by the client, ' .
                'and is returned as one logical chunk.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                list(, $rid) = $c->openSession();
                $c->execRequest($rid,
                    'cat /pub/welcome.txt');
                $r = $c->drainChannel($rid);
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- stdout ---\n" .
                    $r['stdout'];
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => null];
            },
        ],
        'sftp-list' => [
            'title' => 'SFTP: list the root directory',
            'desc' => 'Open a session, request the "sftp" ' .
                'subsystem, send SFTP_INIT, then OPENDIR ' .
                '+ READDIR + CLOSE on /. Same FtpStorage ' .
                'backend the toy shell uses; SFTP just ' .
                'speaks a different wire protocol on top ' .
                'of it.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                list(, $rid) = $c->openSession();
                $c->subsystemRequest($rid, 'sftp');
                $c->sftpInit($rid);
                $entries = $c->sftpListDir($rid, '/');
                $body = "";
                foreach ((array) $entries as $e) {
                    $body .= sprintf(
                        "%s  %10d  %s\n",
                        $e['type'] === 'dir' ? 'd' : '-',
                        $e['size'], $e['name']);
                }
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- listdir / ---\n" . $body;
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => null];
            },
        ],
        'sftp-upload' => [
            'title' => 'SFTP: upload then re-read',
            'desc' => 'Demonstrates a write path: OPEN ' .
                'with WRITE+CREAT+TRUNC, WRITE chunks, ' .
                'CLOSE. The demo client then OPENs the ' .
                'same path for read and confirms the ' .
                'content round-tripped through the ' .
                'storage layer.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('alice', 'hunter2');
                list(, $rid) = $c->openSession();
                $c->subsystemRequest($rid, 'sftp');
                $c->sftpInit($rid);
                $payload = "uploaded by demo at " .
                    date('c') . "\n";
                $c->sftpWriteFile($rid,
                    '/users/alice/uploaded.txt',
                    $payload);
                $back = $c->sftpReadFile($rid,
                    '/users/alice/uploaded.txt');
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- round-trip ---\n" .
                    "wrote: " . json_encode($payload) .
                    "\nread:  " . json_encode($back);
                /* Clean up so the scenario is repeatable */
                $c->sftpStatusOp($rid,
                    SshDemoClient::SFTP_REMOVE,
                    '/users/alice/uploaded.txt');
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => 'The uploaded file was ' .
                        'cleaned up at the end so this ' .
                        'scenario stays repeatable. ' .
                        'Real uploads stick around -- ' .
                        'try the file browser tab.'];
            },
        ],
        'guest-readonly' => [
            'title' => 'Read-only user cannot upload',
            'desc' => 'Logs in as the "guest" user (a ' .
                'read-only account in the static-creds ' .
                'config). Listing and reading work; an ' .
                'attempted write returns SFTP_FX_' .
                'PERMISSION_DENIED. This is the per-user ' .
                'read_only flag in action.',
            'run' => function ($cfg) {
                $c = sshConnect($cfg);
                $c->authPassword('guest', 'guest');
                list(, $rid) = $c->openSession();
                $c->subsystemRequest($rid, 'sftp');
                $c->sftpInit($rid);
                $entries = $c->sftpListDir($rid, '/');
                $body = "";
                foreach ((array) $entries as $e) {
                    $body .= "  " . $e['name'] . "\n";
                }
                $ok = $c->sftpWriteFile($rid,
                    '/forbidden.txt', "should fail\n");
                $tx = implode("\n", $c->transcript()) .
                    "\n\n--- as guest ---\n" .
                    "listdir / ok:\n" . $body .
                    "\nwrite /forbidden.txt -> " .
                    ($ok ? "(unexpected) ok" : "denied");
                $c->disconnect();
                return ['transcript' => $tx,
                    'note' => null];
            },
        ],
    ];
}
/*
    ============================================================
    --- Recent transcripts ring buffer ---
    ============================================================
 */
const SSH_LOG_FILE = 'recent.json';
const SSH_LOG_MAX = 25;
function sshLogPath()
{
    return __DIR__ . DIRECTORY_SEPARATOR . SSH_LOG_FILE;
}
function sshLogRead()
{
    $p = sshLogPath();
    if (!is_file($p)) {
        return [];
    }
    $raw = @file_get_contents($p);
    $data = @json_decode($raw, true);
    return is_array($data) ? $data : [];
}
function sshLogAppend($entry)
{
    $log = sshLogRead();
    $log[] = $entry;
    if (count($log) > SSH_LOG_MAX) {
        $log = array_slice($log, -SSH_LOG_MAX);
    }
    @file_put_contents(sshLogPath(),
        json_encode($log, JSON_PRETTY_PRINT));
}
/*
    ============================================================
    --- Tab body renderers ---
    ============================================================
 */
function sshRenderScenarios($cfg)
{
    echo '<div class="banner">';
    echo 'Each scenario opens a fresh SSH connection ' .
        'against the running server, runs through a real ' .
        'session, and shows the on-wire transcript. ' .
        'Click <strong>Run</strong> on any card to expand.';
    echo '</div>';
    echo '<h2>Click-through scenarios</h2>';
    foreach (sshScenarioList($cfg) as $key => $info) {
        $btn_id = 'btn-' . htmlspecialchars($key);
        $box_id = 'box-' . htmlspecialchars($key);
        $note_id = 'note-' . htmlspecialchars($key);
        echo '<div class="scenario" data-key="' .
            htmlspecialchars($key) . '">';
        echo '<div class="row">';
        echo '<div>';
        echo '<div class="label">' .
            htmlspecialchars($info['title']) . '</div>';
        echo '<div class="desc">' .
            htmlspecialchars($info['desc']) . '</div>';
        echo '</div>';
        echo '<button id="' . $btn_id .
            '" class="run">Run</button>';
        echo '</div>';
        echo '<pre class="transcript" id="' . $box_id .
            '"></pre>';
        echo '<div class="note-hint" id="' . $note_id .
            '"></div>';
        echo '</div>';
    }
    echo '<script>' . sshClientScript() . '</script>';
}
function sshClientScript()
{
    return <<<'JS'
(function () {
    document.querySelectorAll('.scenario').forEach(
    function (card) {
        var key = card.getAttribute('data-key');
        if (!key) return;
        var btn = document.getElementById('btn-' + key);
        var box = document.getElementById('box-' + key);
        var note = document.getElementById('note-' + key);
        var state = 'idle';
        function reset() {
            btn.textContent = 'Run';
            btn.disabled = false;
            btn.classList.remove('close');
            box.textContent = '';
            box.classList.remove('visible');
            note.textContent = '';
            note.classList.remove('visible');
            state = 'idle';
        }
        function run() {
            btn.disabled = true;
            btn.textContent = 'Running...';
            box.textContent = '';
            box.classList.add('visible');
            note.textContent = '';
            note.classList.remove('visible');
            var fd = new FormData();
            fd.append('scenario', key);
            fetch('/scenario', {
                method: 'POST', body: fd,
            }).then(function (r) {
                return r.json();
            }).then(function (j) {
                box.textContent = j.transcript || '';
                if (j.note) {
                    note.textContent = j.note;
                    note.classList.add('visible');
                }
                btn.disabled = false;
                btn.textContent = '\u2715';
                btn.classList.add('close');
                state = 'open';
            }).catch(function (err) {
                box.textContent = 'ERROR: ' + err;
                btn.disabled = false;
                btn.textContent = '\u2715';
                btn.classList.add('close');
                state = 'open';
            });
        }
        btn.addEventListener('click', function () {
            if (state === 'idle') run();
            else reset();
        });
    });
})();
JS;
}
function sshRenderRaw($cfg)
{
    echo '<div class="banner">';
    echo 'Run an arbitrary <code>exec</code> command ' .
        'against the server. The toy shell understands ' .
        '<code>pwd</code>, <code>ls [path]</code>, ' .
        '<code>cd [path]</code>, <code>cat path</code>, ' .
        '<code>echo args...</code>, <code>whoami</code>, ' .
        '<code>help</code>, and <code>exit</code>. ' .
        'Pick a user; password is filled from the demo ' .
        'creds, but you can switch to publickey auth ' .
        'with the bundled Ed25519 key.';
    echo '</div>';
    echo '<h2>Raw exec command</h2>';
    echo '<form class="raw" id="rawForm">';
    echo '<div class="row">';
    echo '<div><label for="rawUser">User</label>';
    echo '<select id="rawUser" name="user">';
    foreach ($cfg['demo_users'] as $u) {
        echo '<option value="' .
            htmlspecialchars($u['user']) . '">' .
            htmlspecialchars($u['user']) . ' / ' .
            htmlspecialchars($u['pass']) . '</option>';
    }
    echo '</select></div>';
    echo '<div><label for="rawAuth">Authentication</label>';
    echo '<select id="rawAuth" name="auth">';
    echo '<option value="password">password</option>';
    echo '<option value="publickey">publickey ' .
        '(alice only)</option>';
    echo '</select></div>';
    echo '</div>';
    echo '<div class="row">';
    echo '<div><label for="rawCmd">Command</label>';
    echo '<input type="text" id="rawCmd" name="cmd" ' .
        'value="ls /pub" placeholder="ls /"></div>';
    echo '</div>';
    echo '<button type="button" id="rawSend">Run</button>';
    echo '</form>';
    echo '<div id="rawResult"></div>';
    echo '<script>' . sshRawScript() . '</script>';
}
function sshRawScript()
{
    return <<<'JS'
(function () {
    var btn = document.getElementById('rawSend');
    var result = document.getElementById('rawResult');
    if (!btn) return;
    btn.addEventListener('click', function () {
        btn.disabled = true;
        btn.textContent = 'Running...';
        result.innerHTML = '';
        var form = document.getElementById('rawForm');
        var fd = new FormData(form);
        fetch('/raw', {
            method: 'POST', body: fd,
        }).then(function (r) {
            return r.json();
        }).then(function (j) {
            var pre = document.createElement('pre');
            pre.className = 'transcript-static';
            pre.textContent = j.transcript || '(no reply)';
            result.appendChild(pre);
            btn.disabled = false;
            btn.textContent = 'Run';
        }).catch(function (err) {
            result.textContent = 'ERROR: ' + err;
            btn.disabled = false;
            btn.textContent = 'Run';
        });
    });
})();
JS;
}
/**
 * Builds a URL with a path query parameter that survives
 * atto's WebSite request-URI parser. The upstream parser
 * urldecodes the request URI before chopping off the
 * query string by the (still-encoded) QUERY_STRING length,
 * so a "%2F" inside the query string makes the chop math
 * undercount and the route is mis-identified as 404.
 *
 * Workaround: emit slashes literally inside the value of
 * the path parameter (browsers accept that fine), and
 * still escape every other character that has special
 * meaning in a query string. This is essentially urlencode
 * with "/" added to the safe set.
 */
function sshEncPath($value)
{
    return str_replace('%2F', '/', urlencode($value));
}
/**
 * Builds a "/browser?path=...&who=..." URL preserving the
 * current who selection across navigation.
 */
function sshBrowserUrl($path, $who)
{
    $url = '/browser?path=' . sshEncPath($path);
    if ($who !== '') {
        $url .= '&who=' . urlencode($who);
    }
    return $url;
}
function sshRenderBrowser($cfg)
{
    $path = $_GET['path'] ?? '/';
    if (!is_string($path) || $path === '') {
        $path = '/';
    }
    /*
        Sanity check: the path is FTP-space ("/foo/bar"),
        not a filesystem path. We resolve it server-side
        through SFTP listdir below, so any traversal
        attempt is bounded by the storage abstraction.
     */
    if (strpos($path, '..') !== false) {
        $path = '/';
    }
    /*
        The "who" query parameter chooses which demo user
        the browser tab logs in as. Different users see
        different parts of the tree (alice and bob are
        chrooted to their home folders; guest sees the
        whole tree but read-only). Defaults to alice.
     */
    $who = $_GET['who'] ?? 'alice';
    $valid_users = array_column($cfg['demo_users'],
        'user');
    if (!in_array($who, $valid_users, true)) {
        $who = 'alice';
    }
    $pass = '';
    foreach ($cfg['demo_users'] as $u) {
        if ($u['user'] === $who) {
            $pass = $u['pass'];
            break;
        }
    }
    $entries = sshBrowserListing($cfg, $path, $who, $pass);
    echo '<div class="banner">';
    echo 'Server-side view of the storage tree, driven by ' .
        'real SFTP commands against the running server. ' .
        'Pick a user from the switcher; alice and bob ' .
        'land in their per-user home folder, guest sees ' .
        'the whole tree read-only.';
    echo '</div>';
    /* User switcher + reset button row */
    echo '<form class="user-switcher" method="get" ' .
        'action="/browser">';
    echo '<input type="hidden" name="path" value="' .
        htmlspecialchars($path) . '">';
    echo '<label for="who-select">Logged in as:</label> ';
    echo '<select id="who-select" name="who" ' .
        'onchange="this.form.submit()">';
    foreach ($cfg['demo_users'] as $u) {
        $sel = ($u['user'] === $who) ? ' selected' : '';
        $tag = '';
        if (!empty($u['user']) && $u['user'] === 'guest') {
            $tag = ' (read-only)';
        }
        echo '<option value="' .
            htmlspecialchars($u['user']) . '"' . $sel .
            '>' . htmlspecialchars($u['user']) . $tag .
            '</option>';
    }
    echo '</select>';
    echo ' <button type="button" id="resetBtn" ' .
        'class="reset-btn">Reset root to pristine ' .
        'state</button>';
    echo '</form>';
    echo '<h2>Storage at ' .
        htmlspecialchars($path) . '</h2>';
    /* breadcrumbs */
    echo '<div class="crumbs">';
    $parts = array_filter(explode('/', $path),
        fn($p) => $p !== '');
    $accum = '';
    echo '<a href="' . sshBrowserUrl('/', $who) .
        '">/</a>';
    foreach ($parts as $i => $p) {
        $accum .= '/' . $p;
        if ($i < count($parts) - 1) {
            echo ' / <a href="' .
                sshBrowserUrl($accum, $who) . '">' .
                htmlspecialchars($p) . '</a>';
        } else {
            echo ' / ' . htmlspecialchars($p);
        }
    }
    echo '</div>';
    if ($entries === false) {
        echo '<p class="note">Could not list this path. ' .
            '(The selected user may not have access, or ' .
            'the path may not exist.)</p>';
        echo '<script>' . sshBrowserScript($who) .
            '</script>';
        return;
    }
    /* Upload form (POST multipart/form-data) */
    echo '<form class="upload-bar" method="post" ' .
        'action="/browser/upload" ' .
        'enctype="multipart/form-data">';
    echo '<input type="hidden" name="path" value="' .
        htmlspecialchars($path) . '">';
    echo '<input type="hidden" name="who" value="' .
        htmlspecialchars($who) . '">';
    echo '<label for="upfile">Upload to ' .
        htmlspecialchars($path) . ': </label>';
    echo '<input type="file" name="file" id="upfile" ' .
        'required>';
    echo ' <button type="submit">Upload</button>';
    echo '</form>';
    echo '<table class="browse-table">';
    echo '<thead><tr><th></th><th>Name</th><th>Size</th>' .
        '<th>Modified</th><th>Actions</th></tr></thead>';
    echo '<tbody>';
    /* Show parent link if we are below root */
    if ($path !== '/') {
        $parent = dirname(rtrim($path, '/'));
        if ($parent === '' || $parent === '.') {
            $parent = '/';
        }
        echo '<tr><td>&#x2934;</td>';
        echo '<td><a href="' .
            sshBrowserUrl($parent, $who) . '">..</a></td>';
        echo '<td>--</td><td>--</td><td></td></tr>';
    }
    foreach ($entries as $e) {
        $name = $e['name'];
        $is_dir = $e['type'] === 'dir';
        $child_path = rtrim($path, '/') . '/' . $name;
        $icon = $is_dir ? '&#x1F4C1;' : '&#x1F4C4;';
        echo '<tr>';
        echo '<td class="entry-icon">' . $icon . '</td>';
        echo '<td>';
        if ($is_dir) {
            echo '<a href="' .
                sshBrowserUrl($child_path, $who) . '">' .
                htmlspecialchars($name) . '/</a>';
        } else {
            echo htmlspecialchars($name);
        }
        echo '</td>';
        echo '<td>' . ($is_dir ? '--' :
            number_format($e['size'])) . '</td>';
        echo '<td>' . ($e['mtime'] ?
            date('Y-m-d H:i', $e['mtime']) : '--') .
            '</td>';
        echo '<td class="actions">';
        if (!$is_dir) {
            echo '<a href="/browser/download?path=' .
                sshEncPath($child_path) . '&who=' .
                urlencode($who) . '">download</a>';
        }
        echo ' <a class="danger" href="#" ' .
            'data-action="delete" data-path="' .
            htmlspecialchars($child_path) . '" ' .
            'data-isdir="' . ($is_dir ? '1' : '0') .
            '">delete</a>';
        echo '</td></tr>';
    }
    echo '</tbody></table>';
    echo '<script>' . sshBrowserScript($who) . '</script>';
}
function sshBrowserScript($who)
{
    $who_js = json_encode($who);
    return <<<JS
(function () {
    document.querySelectorAll('a[data-action="delete"]')
    .forEach(function (a) {
        a.addEventListener('click', function (ev) {
            ev.preventDefault();
            if (!window.confirm(
                'Delete ' + a.getAttribute('data-path') +
                '?')) return;
            var fd = new FormData();
            fd.append('path', a.getAttribute('data-path'));
            fd.append('isdir',
                a.getAttribute('data-isdir'));
            fd.append('who', $who_js);
            fetch('/browser/delete', {
                method: 'POST', body: fd,
            }).then(function () {
                window.location.reload();
            });
        });
    });
    var resetBtn = document.getElementById('resetBtn');
    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            if (!window.confirm(
                'Reset the storage root? This deletes ' +
                'every file currently in root/ and ' +
                'replaces them with the contents of ' +
                'original-root/.')) return;
            resetBtn.disabled = true;
            resetBtn.textContent = 'Resetting...';
            var fd = new FormData();
            fetch('/browser/reset', {
                method: 'POST', body: fd,
            }).then(function (r) {
                return r.text();
            }).then(function (msg) {
                window.location.href = '/browser?path=/' +
                    '&who=' + encodeURIComponent($who_js);
            }).catch(function (err) {
                resetBtn.disabled = false;
                resetBtn.textContent = 'Reset failed';
            });
        });
    }
})();
JS;
}
/**
 * Lists a directory via SFTP. Returns the entries array
 * or false on error. Used by the file-browser tab.
 */
function sshBrowserListing($cfg, $path, $who, $pass)
{
    $c = sshConnect($cfg);
    if (!$c->isOpen()) {
        return false;
    }
    if (!$c->authPassword($who, $pass)) {
        $c->disconnect();
        return false;
    }
    list(, $rid) = $c->openSession();
    if (!$c->subsystemRequest($rid, 'sftp') ||
        !$c->sftpInit($rid)) {
        $c->disconnect();
        return false;
    }
    $entries = $c->sftpListDir($rid, $path);
    $c->disconnect();
    if (!is_array($entries)) {
        return false;
    }
    /* Keep the listing tidy */
    usort($entries, function ($a, $b) {
        if ($a['type'] !== $b['type']) {
            return $a['type'] === 'dir' ? -1 : 1;
        }
        return strcmp($a['name'], $b['name']);
    });
    return $entries;
}
/*
    ============================================================
    --- Routes ---
    ============================================================
 */
$site->get('/', function () use ($site, $cfg) {
    sshRenderPage('scenarios', $cfg, function () use
        ($cfg) {
        sshRenderScenarios($cfg);
    });
});
$site->get('/raw', function () use ($site, $cfg) {
    sshRenderPage('raw', $cfg, function () use ($cfg) {
        sshRenderRaw($cfg);
    });
});
$site->get('/browser', function () use ($site, $cfg) {
    sshRenderPage('browser', $cfg, function () use
        ($cfg) {
        sshRenderBrowser($cfg);
    });
});
$site->post('/scenario', function () use ($site, $cfg) {
    $site->header('Content-Type: application/json');
    $key = $_POST['scenario'] ?? '';
    $list = sshScenarioList($cfg);
    if (!isset($list[$key])) {
        echo json_encode([
            'transcript' => "! unknown scenario: $key",
            'note' => null]);
        return;
    }
    $info = $list[$key];
    $result = ($info['run'])($cfg);
    sshLogAppend([
        'ts' => time(),
        'scenario' => $key,
        'title' => $info['title'],
        'transcript' => $result['transcript'],
        'note' => $result['note'] ?? null,
    ]);
    echo json_encode($result);
});
$site->post('/raw', function () use ($site, $cfg) {
    $site->header('Content-Type: application/json');
    $user = $_POST['user'] ?? 'alice';
    $auth = $_POST['auth'] ?? 'password';
    $cmd = $_POST['cmd'] ?? 'pwd';
    $pass = '';
    foreach ($cfg['demo_users'] as $u) {
        if ($u['user'] === $user) {
            $pass = $u['pass'];
            break;
        }
    }
    $c = sshConnect($cfg);
    if (!$c->isOpen()) {
        echo json_encode(['transcript' =>
            implode("\n", $c->transcript())]);
        return;
    }
    if ($auth === 'publickey' && isset(
        $cfg['demo_keys'][$user])) {
        $authed = $c->authPublicKey($user,
            $cfg['demo_keys'][$user]);
    } else {
        $authed = $c->authPassword($user, $pass);
    }
    if (!$authed) {
        $c->disconnect();
        echo json_encode(['transcript' =>
            implode("\n", $c->transcript())]);
        return;
    }
    $session = $c->openSession();
    if ($session === false) {
        $c->disconnect();
        echo json_encode(['transcript' =>
            implode("\n", $c->transcript())]);
        return;
    }
    list(, $rid) = $session;
    $c->execRequest($rid, $cmd);
    $r = $c->drainChannel($rid);
    $tx = implode("\n", $c->transcript()) .
        "\n\n--- stdout ---\n" . $r['stdout'] .
        "\n--- exit-status: " .
        var_export($r['exit_status'], true);
    $c->disconnect();
    sshLogAppend([
        'ts' => time(),
        'scenario' => 'raw',
        'title' => "raw: $user $auth $cmd",
        'transcript' => $tx,
        'note' => null,
    ]);
    echo json_encode(['transcript' => $tx]);
});
/**
 * Looks up the password for one of the configured demo
 * users, or returns false if the name is unknown. Used
 * by the file-browser routes to honor the "who" parameter.
 */
function sshLookupCreds($cfg, $who)
{
    foreach ($cfg['demo_users'] as $u) {
        if ($u['user'] === $who) {
            return $u['pass'];
        }
    }
    return false;
}
$site->get('/browser/download', function () use ($site,
    $cfg) {
    $path = $_GET['path'] ?? '';
    $who = $_GET['who'] ?? 'alice';
    if ($path === '' || strpos($path, '..') !== false) {
        $site->header('HTTP/1.1 400 Bad Request');
        echo 'bad path';
        return;
    }
    $pass = sshLookupCreds($cfg, $who);
    if ($pass === false) {
        $site->header('HTTP/1.1 400 Bad Request');
        echo 'bad user';
        return;
    }
    $c = sshConnect($cfg);
    if (!$c->isOpen() ||
        !$c->authPassword($who, $pass)) {
        $site->header('HTTP/1.1 500 Internal Error');
        echo 'cannot connect';
        return;
    }
    list(, $rid) = $c->openSession();
    if (!$c->subsystemRequest($rid, 'sftp') ||
        !$c->sftpInit($rid)) {
        $c->disconnect();
        $site->header('HTTP/1.1 500 Internal Error');
        echo 'sftp failed';
        return;
    }
    $bytes = $c->sftpReadFile($rid, $path);
    $c->disconnect();
    if ($bytes === false) {
        $site->header('HTTP/1.1 404 Not Found');
        echo 'not found';
        return;
    }
    $name = basename($path);
    $site->header('Content-Type: application/' .
        'octet-stream');
    $site->header('Content-Disposition: attachment; ' .
        'filename="' . str_replace('"', '', $name) . '"');
    echo $bytes;
});
$site->post('/browser/upload', function () use ($site,
    $cfg) {
    $path = $_POST['path'] ?? '/';
    $who = $_POST['who'] ?? 'alice';
    if (strpos($path, '..') !== false) {
        $path = '/';
    }
    $pass = sshLookupCreds($cfg, $who);
    $back = '/browser?path=' . sshEncPath($path) .
        '&who=' . urlencode($who);
    if ($pass === false) {
        $site->header('Location: ' . $back);
        return;
    }
    /*
        atto's cli-mode multipart parser populates $_FILES
        with a synthetic 'tmp_name' (no real file on disk)
        and the actual bytes under 'data'. Real CGI mode
        uses 'tmp_name' as a path. Read whichever is
        present.
     */
    if (empty($_FILES['file']['name'])) {
        $site->header('Location: ' . $back);
        return;
    }
    $name = basename($_FILES['file']['name']);
    $bytes = '';
    if (!empty($_FILES['file']['data'])) {
        $bytes = $_FILES['file']['data'];
    } else if (!empty($_FILES['file']['tmp_name']) &&
        is_uploaded_file($_FILES['file']['tmp_name'])) {
        $bytes = (string) @file_get_contents(
            $_FILES['file']['tmp_name']);
    } else {
        $site->header('Location: ' . $back);
        return;
    }
    $target = rtrim($path, '/') . '/' . $name;
    $c = sshConnect($cfg);
    if ($c->isOpen() &&
        $c->authPassword($who, $pass)) {
        list(, $rid) = $c->openSession();
        if ($c->subsystemRequest($rid, 'sftp') &&
            $c->sftpInit($rid)) {
            $c->sftpWriteFile($rid, $target, $bytes);
        }
    }
    $c->disconnect();
    $site->header('Location: ' . $back);
});
$site->post('/browser/delete', function () use ($site,
    $cfg) {
    $path = $_POST['path'] ?? '';
    $who = $_POST['who'] ?? 'alice';
    $isdir = !empty($_POST['isdir']);
    if ($path === '' || strpos($path, '..') !== false) {
        echo 'bad';
        return;
    }
    $pass = sshLookupCreds($cfg, $who);
    if ($pass === false) {
        echo 'bad user';
        return;
    }
    $c = sshConnect($cfg);
    if ($c->isOpen() &&
        $c->authPassword($who, $pass)) {
        list(, $rid) = $c->openSession();
        if ($c->subsystemRequest($rid, 'sftp') &&
            $c->sftpInit($rid)) {
            $c->sftpStatusOp($rid,
                $isdir ? SshDemoClient::SFTP_RMDIR :
                SshDemoClient::SFTP_REMOVE,
                $path);
        }
    }
    $c->disconnect();
    echo 'ok';
});
$site->post('/browser/reset', function () use ($site,
    $cfg) {
    /*
        Resets the storage tree by deleting the live root/
        and replacing it with a fresh copy of original-
        root/. Same self-repair logic the launcher runs at
        startup, but on demand. Both paths come from the
        webui's $cfg.
     */
    $site->header('Content-Type: text/plain');
    $root = rtrim($cfg['root'], DIRECTORY_SEPARATOR);
    $here = dirname($cfg['root']);
    $pristine = $here . DIRECTORY_SEPARATOR .
        'original-root';
    if (!is_dir($pristine)) {
        echo 'no pristine copy';
        return;
    }
    sshRmTree($root);
    @mkdir($root, 0777, true);
    foreach ((array) @scandir($pristine) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        sshCopyTree($pristine . DIRECTORY_SEPARATOR .
            $entry, $root . DIRECTORY_SEPARATOR . $entry);
    }
    echo 'reset ok';
});
/**
 * Recursive directory removal -- used by the reset route.
 */
function sshRmTree($path)
{
    if (!is_dir($path)) {
        if (is_file($path)) {
            @unlink($path);
        }
        return;
    }
    foreach ((array) @scandir($path) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $child = $path . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($child)) {
            sshRmTree($child);
        } else {
            @unlink($child);
        }
    }
    @rmdir($path);
}
/**
 * Recursive copy used by the reset route. Mirrors the
 * copyTree() helper in index.php.
 */
function sshCopyTree($src, $dst)
{
    if (is_dir($src)) {
        @mkdir($dst);
        foreach ((array) @scandir($src) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            sshCopyTree($src . DIRECTORY_SEPARATOR .
                $entry,
                $dst . DIRECTORY_SEPARATOR . $entry);
        }
    } else {
        @copy($src, $dst);
    }
}
$site->post('/bind', function () use ($site, $cfg) {
    $site->header('Content-Type: text/plain');
    $val = $_POST['bind'] ?? '';
    if (!isset($cfg['bind_choices'][$val])) {
        echo 'invalid bind';
        return;
    }
    @file_put_contents($cfg['bind_file'], $val);
    echo 'bind written; shutting down';
    $server_pid = (int) (getenv('ATTOSSH_SERVER_PID')
        ?: 0);
    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    }
    if (!strstr(PHP_OS, 'WIN')) {
        if ($server_pid > 0) {
            @posix_kill($server_pid, 15);
        }
        @posix_kill(getmypid(), 15);
    } else {
        if ($server_pid > 0) {
            @exec("taskkill /F /PID $server_pid");
        }
        @exec("taskkill /F /PID " . getmypid());
    }
});
$site->listen(8080);
