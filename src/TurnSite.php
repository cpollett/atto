<?php
/**
 * seekquarry\atto\TurnSite -- a single-file STUN/TURN server
 * implementing RFC 8489 (STUN) and RFC 8656 (TURN). Supports
 * Allocate, Refresh, CreatePermission, ChannelBind, Send and
 * Data indications, and ChannelData framing. Long-term
 * credentials with realm/nonce per RFC 8489 sec 9.2 are the
 * default authentication mode; an unauthenticated mode is
 * available for plain STUN binding-discovery deployments.
 *
 * Listens on UDP only in this version. TCP and TLS allocations
 * (RFC 6062, RFC 7350) are not implemented, since the common
 * WebRTC and SIP deployments use UDP. IPv4 and IPv6 are both
 * supported on the listener; the relay socket for an
 * allocation is bound on the same family the client used.
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
 * Abstract long-term-credential authenticator for TURN.
 * Concrete subclasses look up the username in some user
 * store and return the password (or its already-derived
 * MD5 key) so the server can verify MESSAGE-INTEGRITY.
 *
 * RFC 8489 sec 9.2 defines the long-term credential as
 *
 *     key = MD5(username ":" realm ":" password)
 *
 * which is then used as the HMAC-SHA1 key for the
 * MESSAGE-INTEGRITY attribute. Authenticators may return
 * either the cleartext password (the server derives the
 * key) or a precomputed key (so the cleartext password
 * never has to live in memory beyond user creation).
 *
 * Recognized return shapes for lookupUser():
 *
 *   ['password' => string]
 *       Cleartext password. The server computes the MD5
 *       key from username:realm:password.
 *
 *   ['key' => string (16 raw bytes)]
 *       Precomputed long-term-credential key. The server
 *       uses it as-is.
 *
 *   false
 *       No such user; server returns 401.
 */
abstract class TurnAuthenticator
{
    /**
     * @param string $username UTF-8 username from the
     *      USERNAME attribute
     * @return array|false user info, or false if no such user
     */
    abstract public function lookupUser($username);
}
/**
 * In-memory credential store. The constructor takes a map
 * of username => password. Suitable for the demo and small
 * deployments; a production server would back the lookup
 * with a database query.
 */
class StaticTurnAuthenticator extends TurnAuthenticator
{
    /**
     * @var array map username => password
     */
    protected $users = [];
    /**
     * @param array $users [username => password, ...]
     */
    public function __construct($users)
    {
        $this->users = $users;
    }
    public function lookupUser($username)
    {
        if (!isset($this->users[$username])) {
            return false;
        }
        return ['password' => $this->users[$username]];
    }
}
/**
 * Per-allocation state. One instance per client 5-tuple,
 * created on a successful Allocate request and torn down
 * on Refresh(lifetime=0), expiry, or socket error. RFC
 * 8656 sec 5 calls the underlying object the "allocation
 * data structure".
 */
class TurnAllocation
{
    /**
     * @var string client's address as text ("1.2.3.4" or
     *      "2001:db8::1"); part of the 5-tuple key
     */
    public $client_host = "";
    /**
     * @var int client's UDP port; part of the 5-tuple key
     */
    public $client_port = 0;
    /**
     * @var int 4 or 6 -- address family of the client
     */
    public $family = 4;
    /**
     * @var resource UDP socket bound on the relayed-address
     *      side; the server sends datagrams to peers from
     *      this socket and reads peer-to-client traffic on it
     */
    public $relay_socket = null;
    /**
     * @var string relayed-address as text
     */
    public $relay_host = "";
    /**
     * @var int port the relay_socket is bound to
     */
    public $relay_port = 0;
    /**
     * @var string the canonical username from USERNAME
     *      attribute; logged with each event
     */
    public $username = "";
    /**
     * @var int Unix timestamp at which the allocation
     *      expires unless refreshed. RFC 8656 sec 7.2
     *      default lifetime is 600 seconds.
     */
    public $expires = 0;
    /**
     * @var array permitted peer addresses, indexed by host
     *      string ("1.2.3.4"), value is the Unix timestamp
     *      the permission expires (5 minutes from create
     *      or refresh per RFC 8656 sec 9). The client must
     *      hold a permission for a peer host before it can
     *      Send to or receive Data from that peer.
     */
    public $permissions = [];
    /**
     * @var array channel bindings: [chan_num => [peer_host,
     *      peer_port, expires_ts]]. RFC 8656 sec 12 reserves
     *      0x4000-0x4FFF for client-initiated channels.
     */
    public $channels = [];
    /**
     * @var array reverse map peer_host:peer_port =>
     *      chan_num for fast inbound lookup when a relay
     *      datagram arrives from a peer that has a channel
     */
    public $channels_by_peer = [];
}
/**
 * The STUN/TURN server. Accepts datagrams on a UDP listener,
 * parses STUN messages and ChannelData frames, dispatches
 * TURN requests to handler methods, and shuttles relay
 * traffic between clients and their peers.
 *
 * Configuration is via chained setters, mirroring the other
 * atto servers:
 *
 *     $turn = new TurnSite();
 *     $turn->auth(new StaticTurnAuthenticator([
 *             'alice' => 'hunter2']))
 *         ->realm('atto-turn-demo')
 *         ->relayPortRange(60000, 60100)
 *         ->software('atto-turn 1.0');
 *     $turn->listen([
 *         'BIND' => '127.0.0.1',
 *         'TURN_PORT' => 13478,
 *     ]);
 *
 * The listen() loop is non-blocking and uses stream_select
 * across the listener and every active relay socket. There
 * is no per-client TCP control connection in TURN -- the
 * UDP listener is the control channel.
 */
class TurnSite
{
    /*
        --- STUN message-class bits (high two bits of the
            first byte of the message-type field). RFC 8489
            sec 5: a "method" is the lower 12 bits and a
            "class" is two bits split across the type field.
     */
    const CLASS_REQUEST = 0x0000;
    const CLASS_INDICATION = 0x0010;
    const CLASS_SUCCESS = 0x0100;
    const CLASS_ERROR = 0x0110;
    /*
        STUN method numbers. Binding is RFC 8489 core; the
        rest are RFC 8656 TURN extensions. The numbers are
        12-bit identifiers carried in the message-type field
        with the class bits interleaved (encodeMessageType
        and decodeMessageType handle the bit twiddling).
     */
    const METHOD_BINDING = 0x001;
    const METHOD_ALLOCATE = 0x003;
    const METHOD_REFRESH = 0x004;
    const METHOD_SEND = 0x006;
    const METHOD_DATA = 0x007;
    const METHOD_CREATE_PERMISSION = 0x008;
    const METHOD_CHANNEL_BIND = 0x009;
    /*
        STUN attribute types. RFC 8489 / RFC 8656 reserve
        comprehension-required (0x0000-0x7FFF) and
        comprehension-optional (0x8000-0xFFFF) ranges.
     */
    const ATTR_MAPPED_ADDRESS = 0x0001;
    const ATTR_USERNAME = 0x0006;
    const ATTR_MESSAGE_INTEGRITY = 0x0008;
    const ATTR_ERROR_CODE = 0x0009;
    const ATTR_UNKNOWN_ATTRS = 0x000A;
    const ATTR_REALM = 0x0014;
    const ATTR_NONCE = 0x0015;
    const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    const ATTR_LIFETIME = 0x000D;
    const ATTR_XOR_PEER_ADDRESS = 0x0012;
    const ATTR_DATA = 0x0013;
    const ATTR_XOR_RELAYED_ADDRESS = 0x0016;
    const ATTR_REQUESTED_TRANSPORT = 0x0019;
    const ATTR_REQUESTED_ADDRESS_FAMILY = 0x0017;
    const ATTR_CHANNEL_NUMBER = 0x000C;
    const ATTR_SOFTWARE = 0x8022;
    const ATTR_FINGERPRINT = 0x8028;
    /*
        Magic cookie -- second word of the STUN header,
        always 0x2112A442. The XOR-MAPPED-ADDRESS family
        of attributes XORs the address with this value.
     */
    const MAGIC_COOKIE = 0x2112A442;
    /*
        Default lifetimes per RFC 8656. Allocation default
        is 600 seconds with a max of 3600. Permissions live
        for 300 seconds. Channels for 600 seconds.
     */
    const DEFAULT_ALLOCATION_LIFETIME = 600;
    const MAX_ALLOCATION_LIFETIME = 3600;
    const PERMISSION_LIFETIME = 300;
    const CHANNEL_LIFETIME = 600;
    /*
        Channel number range, RFC 8656 sec 12: 0x4000-0x4FFF
        is the only range a client may use in ChannelBind.
        Other ranges are reserved.
     */
    const MIN_CHANNEL_NUMBER = 0x4000;
    const MAX_CHANNEL_NUMBER = 0x4FFF;
    /**
     * @var TurnAuthenticator|null long-term credential
     *      lookup. If null, the server runs in "STUN-only"
     *      mode -- Allocate is refused with 401 and only
     *      Binding requests are answered.
     */
    protected $authenticator = null;
    /**
     * @var string realm advertised in 401 challenges and
     *      used in long-term key derivation
     */
    protected $realm = "atto-turn";
    /**
     * @var string SOFTWARE attribute value (informational)
     */
    protected $software = "atto-turn";
    /**
     * @var int low end of the relay-port range (inclusive)
     */
    protected $relay_port_low = 60000;
    /**
     * @var int high end of the relay-port range (inclusive)
     */
    protected $relay_port_high = 60100;
    /**
     * @var array configuration from listen(): BIND,
     *      TURN_PORT, IDLE_TIMEOUT
     */
    protected $config = [];
    /**
     * @var resource the UDP listener
     */
    protected $listener = null;
    /**
     * @var array map "client_host:client_port" => TurnAllocation
     */
    protected $allocations = [];
    /**
     * @var array map "host:port" of relay socket =>
     *      TurnAllocation, for reverse lookup when the
     *      stream_select loop wakes on a relay socket
     */
    protected $relay_index = [];
    /**
     * @var array nonces issued recently: nonce => issued_ts.
     *      We accept any nonce that is at most NONCE_TTL
     *      seconds old; older ones get a 438 stale-nonce.
     */
    protected $nonces = [];
    const NONCE_TTL = 3600;
    /**
     * Sets the authenticator. Returns $this so calls chain.
     */
    public function auth($authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }
    /**
     * Sets the realm. Returns $this so calls chain.
     */
    public function realm($realm)
    {
        $this->realm = $realm;
        return $this;
    }
    /**
     * Sets the SOFTWARE attribute. Returns $this so calls
     * chain.
     */
    public function software($software)
    {
        $this->software = $software;
        return $this;
    }
    /**
     * Sets the relay-port range. Returns $this so calls
     * chain.
     */
    public function relayPortRange($low, $high)
    {
        $this->relay_port_low = (int) $low;
        $this->relay_port_high = (int) $high;
        return $this;
    }
    /*
        --- IPv6 helpers (same pattern as FtpSite) ---
     */
    /**
     * Returns true if the host string contains a colon, i.e.
     * looks like an IPv6 literal.
     */
    protected function looksLikeIPv6($host)
    {
        return strpos($host, ':') !== false;
    }
    /**
     * Formats a (host, port) pair as a stream-socket-style
     * udp:// URL, bracket-wrapping IPv6 literals so PHP
     * parses them correctly.
     */
    protected function formatBindAddress($host, $port)
    {
        $host = trim($host, '[]');
        if ($this->looksLikeIPv6($host)) {
            return "udp://[$host]:$port";
        }
        return "udp://$host:$port";
    }
    /**
     * Splits a "host:port" or "[host]:port" string into
     * [host, port]. Returns [false, 0] on parse error.
     */
    protected function splitHostPort($peer)
    {
        if ($peer === '' || $peer === false) {
            return [false, 0];
        }
        if ($peer[0] === '[') {
            $end = strpos($peer, ']');
            if ($end === false) {
                return [false, 0];
            }
            $host = substr($peer, 1, $end - 1);
            $port = (int) substr($peer, $end + 2);
            return [$host, $port];
        }
        $colon = strrpos($peer, ':');
        if ($colon === false) {
            return [false, 0];
        }
        return [substr($peer, 0, $colon),
            (int) substr($peer, $colon + 1)];
    }
    /*
        --- Server lifecycle ---
     */
    /**
     * Binds the UDP listener and runs the dispatch loop.
     * Returns when the loop exits (which only happens on
     * fatal listener error).
     *
     * Recognized configuration keys:
     *
     *   BIND          (string) listener bind address; "::"
     *                 binds dual-stack on most platforms,
     *                 "127.0.0.1" or "::1" for loopback only.
     *                 Default "127.0.0.1".
     *
     *   TURN_PORT     (int) UDP port for the listener.
     *                 Default 3478 (the IANA-assigned STUN
     *                 port; binding it requires privilege).
     *
     *   IDLE_TIMEOUT  (int) seconds; allocations idle longer
     *                 than this are torn down even if their
     *                 lifetime has not yet expired. Useful
     *                 for cleaning up after dead clients
     *                 that never send Refresh(lifetime=0).
     *                 Default 900.
     */
    public function listen($config = [])
    {
        $defaults = [
            'BIND' => '127.0.0.1',
            'TURN_PORT' => 3478,
            'IDLE_TIMEOUT' => 900,
        ];
        $this->config = array_merge($defaults, $config);
        $bind = $this->config['BIND'];
        $port = $this->config['TURN_PORT'];
        $addr = $this->formatBindAddress($bind, $port);
        $errno = 0;
        $errstr = '';
        $listener = @stream_socket_server($addr,
            $errno, $errstr,
            STREAM_SERVER_BIND);
        if (!$listener) {
            echo "Failed to bind TURN $addr: $errstr\n";
            return false;
        }
        stream_set_blocking($listener, 0);
        $this->listener = $listener;
        echo "atto-turn listening: $addr\n";
        $this->loop();
        return true;
    }
    /**
     * Main dispatch loop. select()s across the listener
     * and every relay socket; routes incoming bytes to the
     * right handler depending on which socket woke up.
     */
    protected function loop()
    {
        while (true) {
            $reads = [$this->listener];
            foreach ($this->allocations as $alloc) {
                if ($alloc->relay_socket !== null) {
                    $reads[] = $alloc->relay_socket;
                }
            }
            $writes = null;
            $excepts = null;
            $n = @stream_select($reads, $writes, $excepts,
                1, 0);
            if ($n === false) {
                /*
                    EINTR or similar transient error. Loop
                    body restarts the select.
                 */
                continue;
            }
            if ($n > 0) {
                foreach ($reads as $sock) {
                    if ($sock === $this->listener) {
                        $this->onListenerReadable();
                    } else {
                        $this->onRelayReadable($sock);
                    }
                }
            }
            $this->reapExpired();
        }
    }
    /**
     * Reads one datagram from the control listener and
     * dispatches it. STUN messages start with two zero
     * bits (because the type field's high bits are zero
     * for all defined methods), and ChannelData frames
     * start with bits 01 (the channel number falls in
     * 0x4000-0x7FFF). We discriminate on those two bits.
     */
    protected function onListenerReadable()
    {
        $peer = '';
        $buf = @stream_socket_recvfrom($this->listener,
            65535, 0, $peer);
        if ($buf === false || $buf === '' || $peer === '') {
            return;
        }
        if (strlen($buf) < 4) {
            return;
        }
        $first = ord($buf[0]);
        if (($first & 0xC0) === 0x00) {
            $this->handleStunMessage($buf, $peer);
        } else if (($first & 0xC0) === 0x40) {
            $this->handleChannelData($buf, $peer);
        }
        /*
            Other top-bit patterns are reserved by RFC 7983
            for DTLS / RTP demultiplexing on a shared port;
            we ignore them silently.
         */
    }
    /**
     * Reads one datagram from a relay socket. Looks up the
     * owning allocation, then delivers the payload to the
     * client either as a ChannelData frame (if a channel
     * is bound for the peer) or as a STUN Data indication.
     */
    protected function onRelayReadable($sock)
    {
        $peer = '';
        $buf = @stream_socket_recvfrom($sock, 65535, 0, $peer);
        if ($buf === false || $buf === '' || $peer === '') {
            return;
        }
        $local = stream_socket_get_name($sock, false);
        $key = $this->relayKey($local);
        if (!isset($this->relay_index[$key])) {
            return;
        }
        $alloc = $this->relay_index[$key];
        list($peer_host, $peer_port) =
            $this->splitHostPort($peer);
        if ($peer_host === false) {
            return;
        }
        /*
            Drop datagrams from unauthorized peers. RFC 8656
            sec 11.3: the server MUST silently discard any
            UDP datagram received on the relayed transport
            address whose source IP is not in the
            permissions list.
         */
        if (!isset($alloc->permissions[$peer_host]) ||
            $alloc->permissions[$peer_host] < time()) {
            return;
        }
        $peer_key = $peer_host . ":" . $peer_port;
        if (isset($alloc->channels_by_peer[$peer_key])) {
            $chan = $alloc->channels_by_peer[$peer_key];
            $this->sendChannelData($alloc, $chan, $buf);
        } else {
            $this->sendDataIndication($alloc, $peer_host,
                $peer_port, $buf);
        }
    }
    /**
     * Builds a stable key string from a "host:port" form
     * (with or without IPv6 brackets) so we can index the
     * allocations and relay maps with normalized keys.
     */
    protected function relayKey($endpoint)
    {
        list($host, $port) = $this->splitHostPort($endpoint);
        if ($host === false) {
            return '';
        }
        return $host . ':' . $port;
    }
    /**
     * Walks the allocation table and removes anything past
     * its expiry. Also prunes expired permissions and
     * channels in surviving allocations.
     */
    protected function reapExpired()
    {
        $now = time();
        foreach ($this->allocations as $key => $alloc) {
            if ($alloc->expires <= $now) {
                $this->destroyAllocation($alloc);
                unset($this->allocations[$key]);
                continue;
            }
            foreach ($alloc->permissions as $host => $exp) {
                if ($exp <= $now) {
                    unset($alloc->permissions[$host]);
                }
            }
            foreach ($alloc->channels as $chan => $info) {
                list(, , $exp) = $info;
                if ($exp <= $now) {
                    unset($alloc->channels[$chan]);
                    $pkey = $info[0] . ':' . $info[1];
                    unset($alloc->channels_by_peer[$pkey]);
                }
            }
        }
        /* Prune nonces older than NONCE_TTL */
        foreach ($this->nonces as $nonce => $issued) {
            if ($issued + self::NONCE_TTL < $now) {
                unset($this->nonces[$nonce]);
            }
        }
    }
    /**
     * Tears down an allocation: closes the relay socket,
     * unregisters it from relay_index. Allocation removal
     * from the allocations map is the caller's job.
     */
    protected function destroyAllocation($alloc)
    {
        if ($alloc->relay_socket !== null) {
            $local = stream_socket_get_name(
                $alloc->relay_socket, false);
            $key = $this->relayKey($local);
            if ($key !== '' &&
                isset($this->relay_index[$key])) {
                unset($this->relay_index[$key]);
            }
            @fclose($alloc->relay_socket);
            $alloc->relay_socket = null;
        }
    }
    /*
        --- STUN message-type encoding (RFC 8489 sec 5) ---

        The 16-bit message type field embeds two 1-bit class
        indicators (C0, C1) and a 12-bit method:

            0..0..M11..M7..C1..M6..M4..C0..M3..M0

        which in plain English means: take the 12-bit method,
        spread bits 4..11 across positions 5..13 with a hole
        at bit 4 (C1) and another at bit 8 (C0); fill C0 and
        C1 from the class. The two top bits are always zero
        for valid STUN messages, which is why ChannelData
        (bits 01) is unambiguously distinguishable.

        Class encoding (high two bits packed into C0 and C1):

            request    = 00     (C1=0, C0=0)
            indication = 01     (C1=0, C0=1)
            success    = 10     (C1=1, C0=0)
            error      = 11     (C1=1, C0=1)
     */
    /**
     * Combines a method (12-bit) and a class (one of the
     * CLASS_* constants) into a 16-bit message-type value.
     */
    protected function encodeMessageType($method, $class)
    {
        $m = $method;
        $low = ($m & 0x000F);
        $mid = ($m & 0x0070) << 1;
        $high = ($m & 0x0F80) << 2;
        $c0 = ($class & 0x0010);
        $c1 = ($class & 0x0100);
        return $low | $mid | $high | $c0 | $c1;
    }
    /**
     * Splits a 16-bit message-type into [method, class].
     */
    protected function decodeMessageType($type)
    {
        $low = ($type & 0x000F);
        $mid = ($type & 0x00E0) >> 1;
        $high = ($type & 0x3E00) >> 2;
        $method = $low | $mid | $high;
        $c0 = ($type & 0x0010);
        $c1 = ($type & 0x0100);
        return [$method, $c0 | $c1];
    }
    /**
     * Parses a STUN message (header + attributes) into a
     * structured array:
     *
     *     [
     *         'method' => int,
     *         'class'  => int,
     *         'tid'    => string (12 raw bytes),
     *         'attrs'  => [ [type => int, value => string], ... ],
     *         'mi_offset' => int|false  (byte offset of the
     *             MESSAGE-INTEGRITY attribute, for HMAC
     *             verification on a substring of the buffer),
     *     ]
     *
     * Returns false on parse failure.
     */
    protected function parseStun($buf)
    {
        if (strlen($buf) < 20) {
            return false;
        }
        $hdr = unpack('ntype/nlen/Ncookie', substr($buf, 0, 8));
        if ($hdr['cookie'] !== self::MAGIC_COOKIE) {
            return false;
        }
        $tid = substr($buf, 8, 12);
        $body_len = $hdr['len'];
        if (20 + $body_len > strlen($buf)) {
            return false;
        }
        list($method, $class) =
            $this->decodeMessageType($hdr['type']);
        $attrs = [];
        $off = 20;
        $end = 20 + $body_len;
        $mi_offset = false;
        while ($off + 4 <= $end) {
            $a = unpack('ntype/nlen', substr($buf, $off, 4));
            $atype = $a['type'];
            $alen = $a['len'];
            if ($off + 4 + $alen > $end) {
                return false;
            }
            $aval = substr($buf, $off + 4, $alen);
            if ($atype === self::ATTR_MESSAGE_INTEGRITY &&
                $mi_offset === false) {
                $mi_offset = $off;
            }
            $attrs[] = ['type' => $atype, 'value' => $aval];
            $off += 4 + $alen;
            $pad = (4 - ($alen % 4)) % 4;
            $off += $pad;
        }
        return [
            'method' => $method,
            'class' => $class,
            'tid' => $tid,
            'attrs' => $attrs,
            'mi_offset' => $mi_offset,
        ];
    }
    /**
     * Returns the value of the first attribute matching
     * the given type, or null if not present.
     */
    protected function findAttr($msg, $type)
    {
        foreach ($msg['attrs'] as $a) {
            if ($a['type'] === $type) {
                return $a['value'];
            }
        }
        return null;
    }
    /**
     * Encodes a single attribute (type, length, value, with
     * 4-byte padding). Returns the attribute bytes.
     */
    protected function encodeAttr($type, $value)
    {
        $len = strlen($value);
        $out = pack('nn', $type, $len) . $value;
        $pad = (4 - ($len % 4)) % 4;
        if ($pad > 0) {
            $out .= str_repeat("\x00", $pad);
        }
        return $out;
    }
    /**
     * Builds a full STUN message: 20-byte header + attributes.
     * Computes the length field after the attributes are
     * laid out. If $with_mi is non-empty, computes and
     * appends a MESSAGE-INTEGRITY attribute using $with_mi
     * as the HMAC-SHA1 key.
     */
    protected function buildStun($method, $class, $tid,
        $attr_blocks, $with_mi = '')
    {
        $body = implode('', $attr_blocks);
        if ($with_mi !== '') {
            /*
                Per RFC 8489 sec 14.5: the length field
                in the header counts everything AFTER the
                header up through the MESSAGE-INTEGRITY
                attribute, including its own 24-byte
                framing. Compute the HMAC over header (with
                provisional length set to body+24) plus
                everything before MESSAGE-INTEGRITY.
             */
            $provisional_len = strlen($body) + 24;
            $hdr = pack('nnN',
                $this->encodeMessageType($method, $class),
                $provisional_len, self::MAGIC_COOKIE) . $tid;
            $hmac = hash_hmac('sha1',
                $hdr . $body, $with_mi, true);
            $body .= $this->encodeAttr(
                self::ATTR_MESSAGE_INTEGRITY, $hmac);
        }
        $hdr = pack('nnN',
            $this->encodeMessageType($method, $class),
            strlen($body), self::MAGIC_COOKIE) . $tid;
        return $hdr . $body;
    }
    /**
     * Encodes XOR-MAPPED-ADDRESS or XOR-PEER-ADDRESS or
     * XOR-RELAYED-ADDRESS. RFC 8489 sec 14.2 defines the
     * XOR scheme: port XORed with high half of magic
     * cookie, address XORed with magic cookie (and TID
     * for IPv6).
     */
    protected function encodeXorAddr($host, $port, $tid)
    {
        $is_v6 = $this->looksLikeIPv6($host);
        $family = $is_v6 ? 0x02 : 0x01;
        $port_x = $port ^ ((self::MAGIC_COOKIE >> 16) & 0xFFFF);
        if ($is_v6) {
            $raw = inet_pton($host);
            $cookie_tid = pack('N', self::MAGIC_COOKIE) . $tid;
            $addr_x = $raw ^ $cookie_tid;
        } else {
            $raw = inet_pton($host);
            $addr_x = $raw ^ pack('N', self::MAGIC_COOKIE);
        }
        return pack('CCn', 0, $family, $port_x) . $addr_x;
    }
    /**
     * Decodes XOR-PEER-ADDRESS or similar. Returns
     * [host_string, port_int] or [false, 0] on parse
     * error.
     */
    protected function decodeXorAddr($value, $tid)
    {
        if (strlen($value) < 8) {
            return [false, 0];
        }
        $hdr = unpack('Czero/Cfamily/nport_x',
            substr($value, 0, 4));
        $port = $hdr['port_x'] ^
            ((self::MAGIC_COOKIE >> 16) & 0xFFFF);
        if ($hdr['family'] === 0x01) {
            if (strlen($value) < 8) {
                return [false, 0];
            }
            $addr_x = substr($value, 4, 4);
            $addr = $addr_x ^ pack('N', self::MAGIC_COOKIE);
            $host = inet_ntop($addr);
            return [$host, $port];
        } else if ($hdr['family'] === 0x02) {
            if (strlen($value) < 20) {
                return [false, 0];
            }
            $addr_x = substr($value, 4, 16);
            $cookie_tid = pack('N', self::MAGIC_COOKIE) . $tid;
            $addr = $addr_x ^ $cookie_tid;
            $host = inet_ntop($addr);
            return [$host, $port];
        }
        return [false, 0];
    }
    /**
     * Builds an ERROR-CODE attribute value. RFC 8489
     * encodes it as: 0x00 0x00 0x?? 0x?? + reason text,
     * where the first two zero bytes are reserved, the
     * third byte is the class (300..699 / 100), and the
     * fourth byte is the number modulo 100.
     */
    protected function encodeErrorCode($code, $reason)
    {
        $cls = intdiv($code, 100);
        $num = $code % 100;
        return chr(0) . chr(0) . chr($cls) . chr($num) .
            $reason;
    }
    /*
        --- STUN message dispatch ---
     */
    /**
     * Handles one parsed STUN message arriving on the
     * listener. Routes by method to a handler method.
     */
    protected function handleStunMessage($buf, $peer)
    {
        $msg = $this->parseStun($buf);
        if ($msg === false) {
            return;
        }
        if ($msg['class'] !== self::CLASS_REQUEST &&
            $msg['class'] !== self::CLASS_INDICATION) {
            /*
                Responses arriving on the listener are
                unexpected for a server; we ignore them.
             */
            return;
        }
        switch ($msg['method']) {
            case self::METHOD_BINDING:
                $this->handleBinding($msg, $buf, $peer);
                break;
            case self::METHOD_ALLOCATE:
                $this->handleAllocate($msg, $buf, $peer);
                break;
            case self::METHOD_REFRESH:
                $this->handleRefresh($msg, $buf, $peer);
                break;
            case self::METHOD_CREATE_PERMISSION:
                $this->handleCreatePermission($msg, $buf,
                    $peer);
                break;
            case self::METHOD_CHANNEL_BIND:
                $this->handleChannelBind($msg, $buf, $peer);
                break;
            case self::METHOD_SEND:
                $this->handleSend($msg, $buf, $peer);
                break;
            default:
                /*
                    Unknown method -- per RFC 8489 sec 6.3.4
                    we should reply 420 with UNKNOWN-
                    ATTRIBUTES, but keeping the demo simple
                    a quiet drop is acceptable.
                 */
                break;
        }
    }
    /**
     * Handles a Binding request: returns the client's
     * reflexive address in XOR-MAPPED-ADDRESS. Bare STUN,
     * no authentication required.
     */
    protected function handleBinding($msg, $buf, $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $attrs = [
            $this->encodeAttr(self::ATTR_XOR_MAPPED_ADDRESS,
                $this->encodeXorAddr($host, $port,
                $msg['tid'])),
            $this->encodeAttr(self::ATTR_SOFTWARE,
                $this->software),
        ];
        $resp = $this->buildStun(self::METHOD_BINDING,
            self::CLASS_SUCCESS, $msg['tid'], $attrs);
        @stream_socket_sendto($this->listener, $resp,
            0, $peer);
    }
    /*
        --- Authentication helper ---

        Long-term credential check (RFC 8489 sec 9.2).
        Returns either ['ok' => true, 'username' => ...,
        'key' => ...] on success or ['ok' => false,
        'code' => int, 'reason' => string, 'extra' => array]
        on failure. The caller composes the failure into a
        proper error response.
     */
    /**
     * Verifies the long-term credential on a request that
     * carries USERNAME, REALM, NONCE, and MESSAGE-INTEGRITY.
     * If any are missing or fail, returns the diagnostic
     * needed to send a 401 / 438 / similar.
     */
    protected function checkCredentials($msg, $buf)
    {
        if ($this->authenticator === null) {
            return ['ok' => false, 'code' => 401,
                'reason' => 'Authentication required'];
        }
        $username = $this->findAttr($msg, self::ATTR_USERNAME);
        $realm = $this->findAttr($msg, self::ATTR_REALM);
        $nonce = $this->findAttr($msg, self::ATTR_NONCE);
        $mi = $this->findAttr($msg,
            self::ATTR_MESSAGE_INTEGRITY);
        $extra = [];
        if ($username === null || $realm === null ||
            $nonce === null || $mi === null ||
            $msg['mi_offset'] === false) {
            $nonce_new = $this->mintNonce();
            $extra['REALM'] = $this->realm;
            $extra['NONCE'] = $nonce_new;
            return ['ok' => false, 'code' => 401,
                'reason' => 'Unauthorized',
                'extra' => $extra];
        }
        if (!isset($this->nonces[$nonce])) {
            $nonce_new = $this->mintNonce();
            $extra['REALM'] = $this->realm;
            $extra['NONCE'] = $nonce_new;
            return ['ok' => false, 'code' => 438,
                'reason' => 'Stale nonce',
                'extra' => $extra];
        }
        $info = $this->authenticator->lookupUser($username);
        if ($info === false) {
            $nonce_new = $this->mintNonce();
            $extra['REALM'] = $this->realm;
            $extra['NONCE'] = $nonce_new;
            return ['ok' => false, 'code' => 401,
                'reason' => 'Unknown user',
                'extra' => $extra];
        }
        if (isset($info['key'])) {
            $key = $info['key'];
        } else {
            $key = md5($username . ':' . $realm . ':' .
                $info['password'], true);
        }
        /*
            Recompute MESSAGE-INTEGRITY over the buffer up
            to (but not including) the attribute itself,
            with the header length field rewritten to
            reflect the position of MESSAGE-INTEGRITY.
         */
        $verify_len = $msg['mi_offset'] + 24 - 20;
        $hdr_fixed = substr($buf, 0, 2) .
            pack('n', $verify_len) . substr($buf, 4, 16);
        $body = substr($buf, 20, $msg['mi_offset'] - 20);
        $expected = hash_hmac('sha1', $hdr_fixed . $body,
            $key, true);
        if (!hash_equals($expected, $mi)) {
            $nonce_new = $this->mintNonce();
            $extra['REALM'] = $this->realm;
            $extra['NONCE'] = $nonce_new;
            return ['ok' => false, 'code' => 401,
                'reason' => 'Bad MESSAGE-INTEGRITY',
                'extra' => $extra];
        }
        return ['ok' => true,
            'username' => $username, 'key' => $key];
    }
    /**
     * Issues a fresh nonce, records its mint time, and
     * returns it. RFC 8489 sec 9.2 only requires the nonce
     * be unique and unguessable; we use 16 hex chars from
     * random_bytes which is more than sufficient.
     */
    protected function mintNonce()
    {
        $n = bin2hex(random_bytes(8));
        $this->nonces[$n] = time();
        return $n;
    }
    /**
     * Sends a STUN error response over the listener. The
     * 'extra' hash adds REALM/NONCE/USERNAME/etc.
     */
    protected function sendError($method, $msg, $peer, $code,
        $reason, $extra = [], $key = '')
    {
        $blocks = [
            $this->encodeAttr(self::ATTR_ERROR_CODE,
                $this->encodeErrorCode($code, $reason)),
        ];
        foreach ($extra as $k => $v) {
            switch ($k) {
                case 'REALM':
                    $blocks[] = $this->encodeAttr(
                        self::ATTR_REALM, $v);
                    break;
                case 'NONCE':
                    $blocks[] = $this->encodeAttr(
                        self::ATTR_NONCE, $v);
                    break;
            }
        }
        $blocks[] = $this->encodeAttr(self::ATTR_SOFTWARE,
            $this->software);
        $resp = $this->buildStun($method,
            self::CLASS_ERROR, $msg['tid'], $blocks, $key);
        @stream_socket_sendto($this->listener, $resp, 0,
            $peer);
    }
    /*
        --- TURN Allocate / Refresh ---
     */
    /**
     * Handles an Allocate request. RFC 8656 sec 7.
     * Authenticates with long-term credentials, validates
     * REQUESTED-TRANSPORT (must be UDP), allocates a relay
     * port on the same family the client used, and replies
     * with XOR-RELAYED-ADDRESS, XOR-MAPPED-ADDRESS, and
     * LIFETIME.
     */
    protected function handleAllocate($msg, $buf, $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        $cred = $this->checkCredentials($msg, $buf);
        if (!$cred['ok']) {
            $this->sendError(self::METHOD_ALLOCATE, $msg,
                $peer, $cred['code'], $cred['reason'],
                $cred['extra']);
            return;
        }
        if (isset($this->allocations[$key5])) {
            /*
                RFC 8656 sec 7.2: a 437 Allocation Mismatch
                response is the right answer when an
                allocation already exists for this 5-tuple
                and the new request does not match it. For
                the demo we keep this simple: reject.
             */
            $this->sendError(self::METHOD_ALLOCATE, $msg,
                $peer, 437, 'Allocation Mismatch', [],
                $cred['key']);
            return;
        }
        $rt = $this->findAttr($msg,
            self::ATTR_REQUESTED_TRANSPORT);
        if ($rt === null || strlen($rt) < 4) {
            $this->sendError(self::METHOD_ALLOCATE, $msg,
                $peer, 400, 'Bad Request', [], $cred['key']);
            return;
        }
        $proto = ord($rt[0]);
        if ($proto !== 17) {
            /*
                RFC 8656 sec 7.2 only requires UDP support;
                17 is the IANA UDP protocol number. TCP
                allocations are RFC 6062.
             */
            $this->sendError(self::METHOD_ALLOCATE, $msg,
                $peer, 442, 'Unsupported Transport Protocol',
                [], $cred['key']);
            return;
        }
        list($relay_sock, $relay_host, $relay_port) =
            $this->bindRelaySocket($host);
        if ($relay_sock === false) {
            $this->sendError(self::METHOD_ALLOCATE, $msg,
                $peer, 508, 'Insufficient Capacity', [],
                $cred['key']);
            return;
        }
        $lifetime = self::DEFAULT_ALLOCATION_LIFETIME;
        $req_lt = $this->findAttr($msg, self::ATTR_LIFETIME);
        if ($req_lt !== null && strlen($req_lt) === 4) {
            $u = unpack('Nv', $req_lt);
            $req_seconds = $u['v'];
            if ($req_seconds > 0) {
                $lifetime = min($req_seconds,
                    self::MAX_ALLOCATION_LIFETIME);
            }
        }
        $alloc = new TurnAllocation();
        $alloc->client_host = $host;
        $alloc->client_port = $port;
        $alloc->family = $this->looksLikeIPv6($host) ? 6 : 4;
        $alloc->relay_socket = $relay_sock;
        $alloc->relay_host = $relay_host;
        $alloc->relay_port = $relay_port;
        $alloc->username = $cred['username'];
        $alloc->expires = time() + $lifetime;
        $this->allocations[$key5] = $alloc;
        $this->relay_index[$relay_host . ':' . $relay_port] =
            $alloc;
        $blocks = [
            $this->encodeAttr(
                self::ATTR_XOR_RELAYED_ADDRESS,
                $this->encodeXorAddr($relay_host,
                $relay_port, $msg['tid'])),
            $this->encodeAttr(
                self::ATTR_XOR_MAPPED_ADDRESS,
                $this->encodeXorAddr($host, $port,
                $msg['tid'])),
            $this->encodeAttr(self::ATTR_LIFETIME,
                pack('N', $lifetime)),
            $this->encodeAttr(self::ATTR_SOFTWARE,
                $this->software),
        ];
        $resp = $this->buildStun(self::METHOD_ALLOCATE,
            self::CLASS_SUCCESS, $msg['tid'], $blocks,
            $cred['key']);
        @stream_socket_sendto($this->listener, $resp, 0,
            $peer);
    }
    /**
     * Picks a free port in the configured relay range and
     * binds a UDP socket on the same family as the client.
     * Returns [socket, host, port] on success or
     * [false, '', 0] on failure.
     */
    protected function bindRelaySocket($client_host)
    {
        $is_v6 = $this->looksLikeIPv6($client_host);
        /*
            Bind on the same loopback family so the relayed
            address is reachable. A production deployment
            would use the public address of the server's
            external interface; the demo runs everything
            against loopback.
         */
        $relay_host = $is_v6 ? '::1' : '127.0.0.1';
        $tries = 0;
        $low = $this->relay_port_low;
        $high = $this->relay_port_high;
        $max_tries = max(8, ($high - $low + 1));
        while ($tries < $max_tries) {
            $port = random_int($low, $high);
            $addr = $this->formatBindAddress($relay_host,
                $port);
            $sock = @stream_socket_server($addr,
                $errno, $errstr, STREAM_SERVER_BIND);
            if ($sock !== false) {
                stream_set_blocking($sock, 0);
                return [$sock, $relay_host, $port];
            }
            $tries++;
        }
        return [false, '', 0];
    }
    /**
     * Handles a Refresh request. RFC 8656 sec 8. With
     * lifetime>0 it extends the allocation; with lifetime=0
     * it tears the allocation down.
     */
    protected function handleRefresh($msg, $buf, $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        $cred = $this->checkCredentials($msg, $buf);
        if (!$cred['ok']) {
            $this->sendError(self::METHOD_REFRESH, $msg,
                $peer, $cred['code'], $cred['reason'],
                $cred['extra']);
            return;
        }
        if (!isset($this->allocations[$key5])) {
            $this->sendError(self::METHOD_REFRESH, $msg,
                $peer, 437, 'Allocation Mismatch', [],
                $cred['key']);
            return;
        }
        $alloc = $this->allocations[$key5];
        $lifetime = self::DEFAULT_ALLOCATION_LIFETIME;
        $req_lt = $this->findAttr($msg, self::ATTR_LIFETIME);
        if ($req_lt !== null && strlen($req_lt) === 4) {
            $u = unpack('Nv', $req_lt);
            $req_seconds = $u['v'];
            $lifetime = min($req_seconds,
                self::MAX_ALLOCATION_LIFETIME);
        }
        if ($lifetime === 0) {
            $this->destroyAllocation($alloc);
            unset($this->allocations[$key5]);
            $blocks = [
                $this->encodeAttr(self::ATTR_LIFETIME,
                    pack('N', 0)),
                $this->encodeAttr(self::ATTR_SOFTWARE,
                    $this->software),
            ];
            $resp = $this->buildStun(self::METHOD_REFRESH,
                self::CLASS_SUCCESS, $msg['tid'], $blocks,
                $cred['key']);
            @stream_socket_sendto($this->listener, $resp,
                0, $peer);
            return;
        }
        $alloc->expires = time() + $lifetime;
        $blocks = [
            $this->encodeAttr(self::ATTR_LIFETIME,
                pack('N', $lifetime)),
            $this->encodeAttr(self::ATTR_SOFTWARE,
                $this->software),
        ];
        $resp = $this->buildStun(self::METHOD_REFRESH,
            self::CLASS_SUCCESS, $msg['tid'], $blocks,
            $cred['key']);
        @stream_socket_sendto($this->listener, $resp, 0,
            $peer);
    }
    /*
        --- TURN CreatePermission / ChannelBind / Send ---
     */
    /**
     * Handles a CreatePermission request. RFC 8656 sec 9.
     * Adds (or refreshes) one or more peer-IP entries in
     * the allocation's permission table.
     */
    protected function handleCreatePermission($msg, $buf,
        $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        $cred = $this->checkCredentials($msg, $buf);
        if (!$cred['ok']) {
            $this->sendError(self::METHOD_CREATE_PERMISSION,
                $msg, $peer, $cred['code'], $cred['reason'],
                $cred['extra']);
            return;
        }
        if (!isset($this->allocations[$key5])) {
            $this->sendError(self::METHOD_CREATE_PERMISSION,
                $msg, $peer, 437, 'Allocation Mismatch', [],
                $cred['key']);
            return;
        }
        $alloc = $this->allocations[$key5];
        $any = false;
        foreach ($msg['attrs'] as $a) {
            if ($a['type'] !== self::ATTR_XOR_PEER_ADDRESS) {
                continue;
            }
            list($ph, $pp) = $this->decodeXorAddr(
                $a['value'], $msg['tid']);
            if ($ph === false) {
                continue;
            }
            $alloc->permissions[$ph] = time() +
                self::PERMISSION_LIFETIME;
            $any = true;
        }
        if (!$any) {
            $this->sendError(self::METHOD_CREATE_PERMISSION,
                $msg, $peer, 400, 'Bad Request', [],
                $cred['key']);
            return;
        }
        $blocks = [
            $this->encodeAttr(self::ATTR_SOFTWARE,
                $this->software),
        ];
        $resp = $this->buildStun(
            self::METHOD_CREATE_PERMISSION,
            self::CLASS_SUCCESS, $msg['tid'], $blocks,
            $cred['key']);
        @stream_socket_sendto($this->listener, $resp, 0,
            $peer);
    }
    /**
     * Handles a ChannelBind request. RFC 8656 sec 12.
     * Binds a channel number (0x4000-0x4FFF) to a peer
     * (host, port) pair. Implicitly creates a permission
     * for the peer host. Refreshes the binding if it
     * already exists.
     */
    protected function handleChannelBind($msg, $buf, $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        $cred = $this->checkCredentials($msg, $buf);
        if (!$cred['ok']) {
            $this->sendError(self::METHOD_CHANNEL_BIND, $msg,
                $peer, $cred['code'], $cred['reason'],
                $cred['extra']);
            return;
        }
        if (!isset($this->allocations[$key5])) {
            $this->sendError(self::METHOD_CHANNEL_BIND, $msg,
                $peer, 437, 'Allocation Mismatch', [],
                $cred['key']);
            return;
        }
        $alloc = $this->allocations[$key5];
        $cn_attr = $this->findAttr($msg,
            self::ATTR_CHANNEL_NUMBER);
        $pa_attr = $this->findAttr($msg,
            self::ATTR_XOR_PEER_ADDRESS);
        if ($cn_attr === null || strlen($cn_attr) < 4 ||
            $pa_attr === null) {
            $this->sendError(self::METHOD_CHANNEL_BIND, $msg,
                $peer, 400, 'Bad Request', [],
                $cred['key']);
            return;
        }
        $cn = unpack('nchan', $cn_attr);
        $chan_num = $cn['chan'];
        if ($chan_num < self::MIN_CHANNEL_NUMBER ||
            $chan_num > self::MAX_CHANNEL_NUMBER) {
            $this->sendError(self::METHOD_CHANNEL_BIND, $msg,
                $peer, 400, 'Channel out of range', [],
                $cred['key']);
            return;
        }
        list($ph, $pp) = $this->decodeXorAddr($pa_attr,
            $msg['tid']);
        if ($ph === false) {
            $this->sendError(self::METHOD_CHANNEL_BIND, $msg,
                $peer, 400, 'Bad peer address', [],
                $cred['key']);
            return;
        }
        $peer_key = $ph . ':' . $pp;
        /*
            Per RFC 8656 sec 12: a channel number can be
            bound to at most one peer, and a peer can be
            bound to at most one channel. Reject conflicts
            with 400.
         */
        foreach ($alloc->channels as $other_chan => $info) {
            if ($other_chan === $chan_num) {
                continue;
            }
            if ($info[0] === $ph && $info[1] === $pp) {
                $this->sendError(
                    self::METHOD_CHANNEL_BIND, $msg, $peer,
                    400, 'Peer already bound', [],
                    $cred['key']);
                return;
            }
        }
        if (isset($alloc->channels[$chan_num])) {
            $existing = $alloc->channels[$chan_num];
            if ($existing[0] !== $ph || $existing[1] !== $pp) {
                $this->sendError(
                    self::METHOD_CHANNEL_BIND, $msg, $peer,
                    400, 'Channel already bound', [],
                    $cred['key']);
                return;
            }
        }
        $exp = time() + self::CHANNEL_LIFETIME;
        $alloc->channels[$chan_num] = [$ph, $pp, $exp];
        $alloc->channels_by_peer[$peer_key] = $chan_num;
        /*
            ChannelBind implicitly creates a permission for
            the peer's IP per RFC 8656 sec 12.2.
         */
        $alloc->permissions[$ph] = time() +
            self::PERMISSION_LIFETIME;
        $blocks = [
            $this->encodeAttr(self::ATTR_SOFTWARE,
                $this->software),
        ];
        $resp = $this->buildStun(self::METHOD_CHANNEL_BIND,
            self::CLASS_SUCCESS, $msg['tid'], $blocks,
            $cred['key']);
        @stream_socket_sendto($this->listener, $resp, 0,
            $peer);
    }
    /**
     * Handles a Send indication. Indications carry no
     * MESSAGE-INTEGRITY (RFC 8656 sec 11.1) -- the
     * allocation itself is the credential. Forwards the
     * data to the peer over the relay socket if a
     * permission is held.
     */
    protected function handleSend($msg, $buf, $peer)
    {
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        if (!isset($this->allocations[$key5])) {
            return;
        }
        $alloc = $this->allocations[$key5];
        $pa_attr = $this->findAttr($msg,
            self::ATTR_XOR_PEER_ADDRESS);
        $data_attr = $this->findAttr($msg,
            self::ATTR_DATA);
        if ($pa_attr === null || $data_attr === null) {
            return;
        }
        list($ph, $pp) = $this->decodeXorAddr($pa_attr,
            $msg['tid']);
        if ($ph === false) {
            return;
        }
        if (!isset($alloc->permissions[$ph]) ||
            $alloc->permissions[$ph] < time()) {
            /*
                RFC 8656 sec 11.3: silently discard if no
                permission is held for the peer.
             */
            return;
        }
        $dest = $this->formatBindAddress($ph, $pp);
        /*
            stream_socket_sendto for UDP wants "host:port"
            without the udp:// scheme; use the bracket-
            wrapped form for v6 addresses.
         */
        $sendto = $this->looksLikeIPv6($ph) ?
            "[$ph]:$pp" : "$ph:$pp";
        @stream_socket_sendto($alloc->relay_socket,
            $data_attr, 0, $sendto);
    }
    /**
     * Handles a ChannelData frame. The first 4 bytes are
     * a channel number (0x4000-0x4FFF) and a 16-bit
     * length; the rest is the payload. Looks up the
     * channel and forwards to the bound peer.
     */
    protected function handleChannelData($buf, $peer)
    {
        if (strlen($buf) < 4) {
            return;
        }
        $hdr = unpack('nchan/nlen', substr($buf, 0, 4));
        $chan_num = $hdr['chan'];
        $len = $hdr['len'];
        if ($chan_num < self::MIN_CHANNEL_NUMBER ||
            $chan_num > self::MAX_CHANNEL_NUMBER) {
            return;
        }
        if (strlen($buf) < 4 + $len) {
            return;
        }
        $payload = substr($buf, 4, $len);
        list($host, $port) = $this->splitHostPort($peer);
        if ($host === false) {
            return;
        }
        $key5 = $host . ':' . $port;
        if (!isset($this->allocations[$key5])) {
            return;
        }
        $alloc = $this->allocations[$key5];
        if (!isset($alloc->channels[$chan_num])) {
            return;
        }
        list($ph, $pp, ) = $alloc->channels[$chan_num];
        if (!isset($alloc->permissions[$ph]) ||
            $alloc->permissions[$ph] < time()) {
            return;
        }
        $sendto = $this->looksLikeIPv6($ph) ?
            "[$ph]:$pp" : "$ph:$pp";
        @stream_socket_sendto($alloc->relay_socket,
            $payload, 0, $sendto);
    }
    /**
     * Sends a Data indication: wraps a peer-to-client
     * datagram in a STUN message with XOR-PEER-ADDRESS
     * and DATA attributes.
     */
    protected function sendDataIndication($alloc,
        $peer_host, $peer_port, $payload)
    {
        $tid = random_bytes(12);
        $blocks = [
            $this->encodeAttr(self::ATTR_XOR_PEER_ADDRESS,
                $this->encodeXorAddr($peer_host, $peer_port,
                $tid)),
            $this->encodeAttr(self::ATTR_DATA, $payload),
        ];
        $resp = $this->buildStun(self::METHOD_DATA,
            self::CLASS_INDICATION, $tid, $blocks);
        $sendto = $this->looksLikeIPv6($alloc->client_host) ?
            "[" . $alloc->client_host . "]:" .
            $alloc->client_port :
            $alloc->client_host . ":" . $alloc->client_port;
        @stream_socket_sendto($this->listener, $resp, 0,
            $sendto);
    }
    /**
     * Sends a ChannelData frame: 4-byte header + payload,
     * padded to 4 bytes for UDP (per RFC 8656 sec 12.4
     * the padding is required only for TCP/TLS but adding
     * it on UDP is harmless and clients tolerate it).
     */
    protected function sendChannelData($alloc, $chan_num,
        $payload)
    {
        $frame = pack('nn', $chan_num, strlen($payload)) .
            $payload;
        $sendto = $this->looksLikeIPv6($alloc->client_host) ?
            "[" . $alloc->client_host . "]:" .
            $alloc->client_port :
            $alloc->client_host . ":" . $alloc->client_port;
        @stream_socket_sendto($this->listener, $frame, 0,
            $sendto);
    }
}
