<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * HTTP/3 (QUIC) listener support via cloudflare/quiche libquiche.
 *
 * This file is loaded only when the user's listen() spec includes
 * 'protocol' => 'h3' on at least one listener. Atto stays a single-
 * file framework for the H1/H2 case; H3 is opt-in and brings in
 * this sibling file plus a runtime libquiche shared library.
 *
 * Three classes live here:
 *   H3FFI         - thin FFI wrapper around libquiche; encapsulates
 *                   library discovery, cdef registration, and the
 *                   subset of quiche_* functions Atto calls
 *   H3Connection  - extends Connection, holds a quiche_conn* pointer
 *                   plus the connection-id used to demux UDP packets
 *   H3Listener    - extends Listener, owns a UDP socket and the
 *                   per-listener quiche_config*; accept() reads one
 *                   datagram and routes it to a new or existing
 *                   H3Connection
 *
 * The actual H3 frame parsing (HEADERS, DATA, QPACK headers) and
 * request dispatch live in the companion H3Transport class, loaded
 * alongside this file.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */

namespace seekquarry\atto;

/**
 * Thin FFI wrapper around the cloudflare/quiche shared library.
 *
 * The class is constructed once per WebSite instance and shared
 * across all H3Listener / H3Connection / H3Transport instances. It
 * holds the FFI handle and exposes only the subset of quiche_*
 * functions Atto actually uses; this keeps the C ABI surface area
 * small and the cdef short.
 *
 * H3FFI::isAvailable() is the static graceful-degradation check.
 * It returns false if the FFI extension isn't loaded or libquiche
 * cannot be located, and listen() uses that to silently fall back
 * to H1/H2 only (with a notice). Callers MUST consult isAvailable
 * before constructing an H3FFI instance.
 *
 * Library discovery walks a list of conventional paths in order
 * of platform: Linux's /usr/local/lib first (matches the
 * cloudflare/quiche cargo-build install location), Homebrew on
 * macOS, /usr/lib system locations, and on Windows the working
 * directory and PATH. The first dlopen-able candidate wins.
 */
class H3FFI
{
    /**
     * QUIC protocol version. Mirror of QUICHE_PROTOCOL_VERSION
     * from quiche.h. Used in quiche_config_new and version
     * negotiation. Kept as a PHP class constant rather than in
     * the cdef because PHP FFI tries to resolve every named
     * declaration in cdef as a runtime library symbol; const
     * ints in C headers are compile-time-only and would fail
     * that lookup.
     */
    const QUICHE_PROTOCOL_VERSION = 0x00000001;
    /**
     * Maximum length of a QUIC connection ID in bytes. Mirror
     * of QUICHE_MAX_CONN_ID_LEN; see QUICHE_PROTOCOL_VERSION
     * for why this is a PHP constant rather than in the cdef.
     */
    const QUICHE_MAX_CONN_ID_LEN = 20;
    /**
     * Minimum length of an Initial packet sent by a client.
     * Mirror of QUICHE_MIN_CLIENT_INITIAL_LEN.
     */
    const QUICHE_MIN_CLIENT_INITIAL_LEN = 1200;
    /**
     * No more work to do. Mirror of QUICHE_ERR_DONE; the most
     * common non-error return from quiche_conn_send and
     * quiche_conn_stream_recv when the queue is empty.
     */
    const QUICHE_ERR_DONE = -1;
    /**
     * Provided buffer too short. Mirror of QUICHE_ERR_BUFFER_TOO_SHORT.
     */
    const QUICHE_ERR_BUFFER_TOO_SHORT = -2;
    /**
     * Packet's QUIC version is unrecognized; the server should
     * write a version negotiation packet via quiche_negotiate_version.
     * Mirror of QUICHE_ERR_UNKNOWN_VERSION.
     */
    const QUICHE_ERR_UNKNOWN_VERSION = -3;
    /**
     * The cdef passed to FFI::cdef. Restricted to a curated subset
     * of quiche.h; see https://github.com/cloudflare/quiche/blob/
     * master/quiche/include/quiche.h for the full surface. Adding
     * a new function here is a one-line append once we need it.
     * Kept as a class constant for cheap reuse on construction.
     *
     * Numeric C constants are NOT in this cdef because PHP FFI
     * tries to resolve every declared name as a runtime library
     * symbol; const ints from C headers are compile-time and
     * would fail that lookup. Mirror them as PHP class constants
     * above instead.
     * @var string
     */
    const CDEF = '
        typedef struct quiche_config quiche_config;
        typedef struct quiche_conn quiche_conn;
        typedef struct {
            void *from;
            unsigned int from_len;
            void *to;
            unsigned int to_len;
        } quiche_recv_info;
        typedef struct {
            char from[128];
            unsigned int from_len;
            char to[128];
            unsigned int to_len;
            char at[16];
        } quiche_send_info;
        const char *quiche_version(void);
        quiche_config *quiche_config_new(uint32_t version);
        int quiche_config_load_cert_chain_from_pem_file(
            quiche_config *config, const char *path);
        int quiche_config_load_priv_key_from_pem_file(
            quiche_config *config, const char *path);
        void quiche_config_verify_peer(quiche_config *config, bool v);
        int quiche_config_set_application_protos(
            quiche_config *config, const uint8_t *protos,
            size_t protos_len);
        void quiche_config_set_max_idle_timeout(
            quiche_config *config, uint64_t v);
        void quiche_config_set_max_recv_udp_payload_size(
            quiche_config *config, size_t v);
        void quiche_config_set_max_send_udp_payload_size(
            quiche_config *config, size_t v);
        void quiche_config_set_initial_max_data(
            quiche_config *config, uint64_t v);
        void quiche_config_set_initial_max_stream_data_bidi_local(
            quiche_config *config, uint64_t v);
        void quiche_config_set_initial_max_stream_data_bidi_remote(
            quiche_config *config, uint64_t v);
        void quiche_config_set_initial_max_stream_data_uni(
            quiche_config *config, uint64_t v);
        void quiche_config_set_initial_max_streams_bidi(
            quiche_config *config, uint64_t v);
        void quiche_config_set_initial_max_streams_uni(
            quiche_config *config, uint64_t v);
        void quiche_config_set_disable_active_migration(
            quiche_config *config, bool v);
        void quiche_config_free(quiche_config *config);
        int quiche_header_info(const uint8_t *buf, size_t buf_len,
            size_t dcil, uint32_t *version, uint8_t *type,
            uint8_t *scid, size_t *scid_len,
            uint8_t *dcid, size_t *dcid_len,
            uint8_t *token, size_t *token_len);
        bool quiche_version_is_supported(uint32_t version);
        ssize_t quiche_negotiate_version(
            const uint8_t *scid, size_t scid_len,
            const uint8_t *dcid, size_t dcid_len,
            uint8_t *out, size_t out_len);
        ssize_t quiche_retry(
            const uint8_t *scid, size_t scid_len,
            const uint8_t *dcid, size_t dcid_len,
            const uint8_t *new_scid, size_t new_scid_len,
            const uint8_t *token, size_t token_len,
            uint32_t version, uint8_t *out, size_t out_len);
        quiche_conn *quiche_accept(
            const uint8_t *scid, size_t scid_len,
            const uint8_t *odcid, size_t odcid_len,
            const void *local, unsigned int local_len,
            const void *peer, unsigned int peer_len,
            quiche_config *config);
        ssize_t quiche_conn_recv(quiche_conn *conn,
            uint8_t *buf, size_t buf_len,
            const quiche_recv_info *info);
        ssize_t quiche_conn_send(quiche_conn *conn,
            uint8_t *out, size_t out_len,
            quiche_send_info *out_info);
        bool quiche_conn_is_established(const quiche_conn *conn);
        bool quiche_conn_is_closed(const quiche_conn *conn);
        bool quiche_conn_is_draining(const quiche_conn *conn);
        bool quiche_conn_is_timed_out(const quiche_conn *conn);
        uint64_t quiche_conn_timeout_as_millis(const quiche_conn *conn);
        void quiche_conn_on_timeout(quiche_conn *conn);
        int quiche_conn_close(quiche_conn *conn, bool app,
            uint64_t err, const uint8_t *reason, size_t reason_len);
        ssize_t quiche_conn_stream_send(quiche_conn *conn,
            uint64_t stream_id, const uint8_t *buf, size_t buf_len,
            bool fin, uint64_t *out_error_code);
        ssize_t quiche_conn_stream_recv(quiche_conn *conn,
            uint64_t stream_id, uint8_t *out, size_t buf_len,
            bool *fin, uint64_t *out_error_code);
        int64_t quiche_conn_stream_readable_next(quiche_conn *conn);
        bool quiche_conn_stream_finished(const quiche_conn *conn,
            uint64_t stream_id);
        void quiche_conn_free(quiche_conn *conn);
    ';
    /**
     * Library names tried during dlopen, in priority order. Linux
     * conventions first, then macOS Homebrew, then a Windows DLL
     * name. The list is permissive: a single match is enough.
     * @var array
     */
    public static $library_candidates = [
        'libquiche.so.0',
        'libquiche.so',
        '/usr/local/lib/libquiche.so',
        '/usr/local/lib/libquiche.dylib',
        '/opt/homebrew/lib/libquiche.dylib',
        '/opt/homebrew/lib/libquiche.0.dylib',
        '/usr/lib/x86_64-linux-gnu/libquiche.so',
        'libquiche.dylib',
        'quiche.dll',
    ];
    /**
     * The FFI handle, created on first construction. Calls into
     * quiche go through $this->ffi->quiche_xxx().
     * @var \FFI
     */
    public $ffi;
    /**
     * Path of the library that was successfully loaded, kept for
     * diagnostic logging. Empty if H3FFI was constructed without a
     * successful library load (only happens via tests).
     * @var string
     */
    public $library_path = '';
    /**
     * Memoized result of isAvailable so probes from multiple call
     * sites within a single PHP process don't repeatedly try to
     * dlopen libquiche. Cleared by clearAvailabilityCache for
     * test scenarios that reload between availability checks.
     * @var bool|null
     */
    protected static $available_cache = null;
    /**
     * Returns true if the FFI extension is loaded and libquiche can
     * be opened on this system. This is the gate every call site
     * MUST consult before instantiating H3FFI; returning false
     * signals graceful fallback to H1/H2-only operation.
     *
     * The probe is cheap on first call and free thereafter (the
     * result is memoized in self::$available_cache).
     *
     * @return bool whether H3 can be supported in this process
     */
    public static function isAvailable()
    {
        if (self::$available_cache !== null) {
            return self::$available_cache;
        }
        if (!extension_loaded('FFI')) {
            self::$available_cache = false;
            return false;
        }
        $minimal_cdef = 'const char *quiche_version(void);';
        foreach (self::$library_candidates as $candidate) {
            try {
                $probe = \FFI::cdef($minimal_cdef, $candidate);
                /*
                    Calling quiche_version validates that the
                    symbol resolves and the library is the right
                    ABI; some systems have stale or incompatible
                    libquiche shims that cdef accepts but trip on
                    first call.
                 */
                $probe->quiche_version();
                self::$available_cache = true;
                return true;
            } catch (\FFI\Exception $e) {
                continue;
            } catch (\Throwable $e) {
                continue;
            }
        }
        self::$available_cache = false;
        return false;
    }
    /**
     * Resets the memoized isAvailable result. Used by test code
     * that wants to verify graceful-degradation paths without
     * spawning a new process.
     */
    public static function clearAvailabilityCache()
    {
        self::$available_cache = null;
    }
    /**
     * Constructs an H3FFI by walking the library candidates list
     * and returning on the first successful FFI::cdef. Throws if
     * no candidate works; callers should consult isAvailable
     * first to avoid the exception.
     *
     * @throws \RuntimeException if libquiche cannot be loaded
     */
    public function __construct()
    {
        if (!extension_loaded('FFI')) {
            throw new \RuntimeException(
                "PHP FFI extension is not loaded; H3 unavailable");
        }
        $last_error = '';
        foreach (self::$library_candidates as $candidate) {
            try {
                $this->ffi = \FFI::cdef(self::CDEF, $candidate);
                $this->library_path = $candidate;
                return;
            } catch (\FFI\Exception $e) {
                $last_error = $e->getMessage();
                continue;
            } catch (\Throwable $e) {
                $last_error = $e->getMessage();
                continue;
            }
        }
        throw new \RuntimeException(
            "Failed to load libquiche from any candidate path: "
            . $last_error);
    }
    /**
     * Returns the libquiche version string as reported by
     * quiche_version. Useful in startup banners so the operator
     * can confirm which build of quiche is in use.
     *
     * @return string version string from libquiche
     */
    public function version()
    {
        if ($this->ffi === null) {
            return 'unknown';
        }
        return \FFI::string($this->ffi->quiche_version());
    }
}
/**
 * H3 connection: extends Connection with a quiche_conn pointer and
 * the source connection ID used to demultiplex UDP packets at the
 * H3Listener level.
 *
 * Unlike H1/H2 connections (which are backed by a single TCP stream
 * pair from stream_socket_accept), an H3Connection has no PHP
 * stream resource of its own. The "resource" field of the parent
 * Connection class is set to null; I/O happens via quiche_conn_recv
 * on inbound UDP datagrams from the H3Listener's UDP socket and
 * quiche_conn_send for outbound. The per-connection event-loop
 * registration in WebSite::$in_streams uses the H3Listener's UDP
 * socket as a shared readable; the route from "UDP datagram
 * arrived" to "this connection should process it" goes through the
 * Connection ID lookup table in H3Listener.
 *
 * Because there is no PHP stream resource, processRequestStreams'
 * (int)$resource keying does not apply here. H3 connections are
 * keyed by their source CID hex string in WebSite::$connections,
 * with a single entry shared with H3Listener's CID map.
 */
class H3Connection extends Connection
{
    /**
     * The cdata pointer to the underlying quiche_conn. Owned by
     * this class; freed in close() via quiche_conn_free. Never
     * null between construction and close.
     * @var \FFI\CData
     */
    public $quiche_conn;
    /**
     * The local source connection ID, hex-encoded for use as a
     * map key. Set at construction time and immutable thereafter.
     * @var string
     */
    public $scid_hex = '';
    /**
     * The peer address as a packed sockaddr buffer (sockaddr_in
     * for IPv4, sockaddr_in6 for IPv6). Kept around so quiche_conn_send
     * can be told where to deliver the egress UDP datagram. Updated
     * if the connection's path migrates.
     * @var \FFI\CData|null
     */
    public $peer_sockaddr;
    /**
     * Length in bytes of the packed peer_sockaddr buffer.
     * @var int
     */
    public $peer_sockaddr_len = 0;
    /**
     * Reference to the H3FFI instance that owns the libquiche
     * handle. Held so close() can call quiche_conn_free without
     * a back-reference dance through WebSite.
     * @var H3FFI
     */
    public $ffi;
    /**
     * Constructs an H3Connection wrapping an already-created
     * quiche_conn. The resource argument from the parent class
     * is set to null because H3 connections do not have a PHP
     * stream resource — the UDP socket lives on H3Listener and
     * is shared across all connections.
     *
     * @param H3FFI $ffi the libquiche FFI wrapper
     * @param \FFI\CData $quiche_conn the quiche_conn pointer
     * @param string $scid_hex hex-encoded source connection id
     */
    public function __construct($ffi, $quiche_conn, $scid_hex)
    {
        parent::__construct(null, true);
        $this->protocol = 'h3';
        $this->ffi = $ffi;
        $this->quiche_conn = $quiche_conn;
        $this->scid_hex = $scid_hex;
    }
    /**
     * Returns true if the QUIC handshake has completed. Until
     * this returns true the H3Transport should not attempt H3
     * frame parsing, only continue feeding inbound packets and
     * draining outbound ones.
     *
     * @return bool whether the handshake is complete
     */
    public function isEstablished()
    {
        return (bool) $this->ffi->ffi
            ->quiche_conn_is_established($this->quiche_conn);
    }
    /**
     * Returns true if the connection is closed (peer closed,
     * idle-timed-out, or local close has been processed).
     * H3Listener's accept loop reaps these.
     *
     * @return bool whether the connection is closed
     */
    public function isClosed()
    {
        return (bool) $this->ffi->ffi
            ->quiche_conn_is_closed($this->quiche_conn);
    }
    /**
     * Releases the underlying quiche_conn. After close the
     * H3Connection is unusable; the H3Listener removes it from
     * its CID map.
     */
    public function close()
    {
        if ($this->quiche_conn !== null && $this->ffi !== null) {
            $this->ffi->ffi->quiche_conn_free($this->quiche_conn);
            $this->quiche_conn = null;
        }
    }
}
/**
 * H3 listener: a UDP socket plus a per-listener quiche_config,
 * accepting QUIC connections by demultiplexing inbound datagrams
 * to a connection map keyed by source connection ID.
 *
 * Unlike a TCP Listener whose accept() returns one Connection per
 * call, H3Listener::accept reads one UDP datagram per call and
 * either creates a new H3Connection (if the datagram is an
 * Initial packet establishing a new connection) or routes the
 * datagram to an existing H3Connection by Connection ID. This
 * means a single readable event on the UDP socket may produce
 * "no new connection but progress was made on existing ones" —
 * the return value reflects only NEW connections; ongoing-
 * connection traffic is handled internally.
 *
 * H3Listener owns the quiche_config, the UDP socket resource,
 * and the connection table. Configuration (cert path, ALPN,
 * idle timeout, flow-control limits) is applied at tryOpen
 * time and stays for the listener's lifetime.
 */
class H3Listener extends Listener
{
    /**
     * The H3FFI instance shared across all H3 listeners and
     * connections in this process. Held so accept() can call
     * quiche_accept and the connection objects can call into
     * libquiche for I/O.
     * @var H3FFI
     */
    public $ffi;
    /**
     * The quiche_config pointer for this listener. Owned by this
     * object; freed in close() via quiche_config_free.
     * @var \FFI\CData
     */
    public $quiche_config;
    /**
     * Map from source connection ID (hex-encoded) to H3Connection.
     * H3 connections do not have stream resources; they live in
     * this map keyed by CID. accept() consults the map on every
     * inbound datagram to route the packet.
     * @var array<string, H3Connection>
     */
    public $connections = [];
    /**
     * Path to the TLS certificate chain PEM file. Stored for
     * diagnostic and lifetime reasons.
     * @var string
     */
    public $cert_path = '';
    /**
     * Path to the TLS private key PEM file.
     * @var string
     */
    public $key_path = '';
    /**
     * Constructs an H3Listener. Most callers should use
     * H3Listener::tryOpen() which handles config setup and
     * applies sensible defaults; the constructor itself just
     * binds fields together.
     *
     * @param resource $server the UDP server socket
     * @param string $address human-readable bind address
     * @param array $globals per-listener server globals
     * @param H3FFI $ffi the libquiche FFI wrapper
     * @param \FFI\CData $quiche_config the quiche_config pointer
     */
    public function __construct($server, $address, $globals,
        $ffi, $quiche_config)
    {
        parent::__construct($server, $address, true, $globals);
        $this->ffi = $ffi;
        $this->quiche_config = $quiche_config;
    }
    /**
     * Opens an H3 listener: binds a UDP socket and constructs the
     * quiche_config from the supplied SSL settings. Returns null
     * if libquiche is not available or the bind fails; the caller
     * (WebSite::openListener) reports a friendly notice and falls
     * back to H1/H2 only.
     *
     * Expected $context shape mirrors the TLS H1/H2 path:
     *   ['ssl' => [
     *       'local_cert' => 'path/to/cert.pem',
     *       'local_pk'   => 'path/to/key.pem',
     *       // optional: 'verify_peer' => false,
     *   ]]
     *
     * The UDP socket is bound non-blocking. The libquiche config
     * advertises 'h3' as the only ALPN since this listener is
     * H3-only — peers that want H1/H2 should connect to a
     * separate TCP listener.
     *
     * @param string $bind_address tcp://host:port style address
     *      (we will rewrite to udp:// internally)
     * @param array $context stream context options; uses 'ssl'
     *      keys 'local_cert' and 'local_pk'
     * @param array $globals per-listener server globals to stamp
     *      onto accepted connections (SERVER_NAME, SERVER_PORT)
     * @return H3Listener|null the new listener, or null on any
     *      failure (FFI unavailable, bind failed, cert load
     *      failed); errors are echoed to stderr
     */
    public static function tryOpen($bind_address, $context, $globals)
    {
        if (!H3FFI::isAvailable()) {
            echo "H3 listener requested for $bind_address but "
                . "libquiche/FFI not available; skipping\n";
            return null;
        }
        $ssl = $context['ssl'] ?? [];
        $cert_path = $ssl['local_cert'] ?? '';
        $key_path = $ssl['local_pk'] ?? '';
        if (empty($cert_path) || empty($key_path)) {
            echo "H3 listener for $bind_address missing "
                . "ssl.local_cert / ssl.local_pk; skipping\n";
            return null;
        }
        if (!is_file($cert_path) || !is_file($key_path)) {
            echo "H3 listener for $bind_address: cert or key "
                . "file does not exist; skipping\n";
            return null;
        }
        /*
            The user passes tcp://host:port to keep the listen()
            spec uniform with the H1/H2 listeners; we rewrite to
            udp:// for the actual bind. UDP sockets do not have
            backlog the same way TCP does, so we do not set a
            socket-backlog context option.
         */
        $udp_address = preg_replace('/^tcp:\/\//', 'udp://',
            $bind_address);
        if ($udp_address === $bind_address
            && strpos($bind_address, '://') === false) {
            $udp_address = 'udp://' . $bind_address;
        }
        $server = stream_socket_server($udp_address, $errno, $errstr,
            STREAM_SERVER_BIND);
        if (!$server) {
            echo "H3 listener failed to bind $udp_address: $errstr "
                . "(errno $errno)\n";
            return null;
        }
        stream_set_blocking($server, false);
        try {
            $ffi = new H3FFI();
        } catch (\Throwable $e) {
            echo "H3 listener for $bind_address: FFI init failed: "
                . $e->getMessage() . "\n";
            @fclose($server);
            return null;
        }
        $config = self::buildConfig($ffi, $cert_path, $key_path);
        if ($config === null) {
            @fclose($server);
            return null;
        }
        $listener = new H3Listener($server, $bind_address, $globals,
            $ffi, $config);
        $listener->cert_path = $cert_path;
        $listener->key_path = $key_path;
        return $listener;
    }
    /**
     * Builds and returns a quiche_config* configured with the
     * given cert/key, h3 ALPN, and reasonable transport defaults.
     * Returns null if any libquiche call fails; the caller
     * reports the error.
     *
     * Defaults chosen for a general-purpose web server:
     *   max_idle_timeout: 30s
     *   max_recv_udp_payload_size: 1350 (matches the IETF default)
     *   max_send_udp_payload_size: 1350
     *   initial_max_data: 10 MiB connection-wide
     *   initial_max_stream_data_bidi_local: 1 MiB
     *   initial_max_stream_data_bidi_remote: 1 MiB
     *   initial_max_stream_data_uni: 1 MiB
     *   initial_max_streams_bidi: 100
     *   initial_max_streams_uni: 100
     *   disable_active_migration: true
     *
     * Operators with non-default needs can extend H3Listener and
     * override buildConfig.
     *
     * @param H3FFI $ffi the libquiche wrapper
     * @param string $cert_path path to PEM cert chain
     * @param string $key_path path to PEM private key
     * @return \FFI\CData|null the quiche_config, or null on error
     */
    protected static function buildConfig($ffi, $cert_path, $key_path)
    {
        $q = $ffi->ffi;
        $config = $q->quiche_config_new(H3FFI::QUICHE_PROTOCOL_VERSION);
        if (\FFI::isNull($config)) {
            echo "H3: quiche_config_new returned NULL\n";
            return null;
        }
        $rc = $q->quiche_config_load_cert_chain_from_pem_file(
            $config, $cert_path);
        if ($rc < 0) {
            echo "H3: load_cert_chain_from_pem_file failed "
                . "(rc=$rc, path=$cert_path)\n";
            $q->quiche_config_free($config);
            return null;
        }
        $rc = $q->quiche_config_load_priv_key_from_pem_file(
            $config, $key_path);
        if ($rc < 0) {
            echo "H3: load_priv_key_from_pem_file failed "
                . "(rc=$rc, path=$key_path)\n";
            $q->quiche_config_free($config);
            return null;
        }
        /*
            ALPN tokens are length-prefixed: one byte length,
            then the token bytes. "h3" is two bytes, so the
            wire form is "\x02h3" (3 bytes total). Using the
            same canonical form quiche.h documents.
         */
        $alpn = "\x02h3";
        $alpn_buf = self::stringToCData($ffi, $alpn);
        $rc = $q->quiche_config_set_application_protos(
            $config, $alpn_buf, strlen($alpn));
        if ($rc < 0) {
            echo "H3: set_application_protos failed (rc=$rc)\n";
            $q->quiche_config_free($config);
            return null;
        }
        $q->quiche_config_set_max_idle_timeout($config, 30000);
        $q->quiche_config_set_max_recv_udp_payload_size($config, 1350);
        $q->quiche_config_set_max_send_udp_payload_size($config, 1350);
        $q->quiche_config_set_initial_max_data($config, 10485760);
        $q->quiche_config_set_initial_max_stream_data_bidi_local(
            $config, 1048576);
        $q->quiche_config_set_initial_max_stream_data_bidi_remote(
            $config, 1048576);
        $q->quiche_config_set_initial_max_stream_data_uni(
            $config, 1048576);
        $q->quiche_config_set_initial_max_streams_bidi($config, 100);
        $q->quiche_config_set_initial_max_streams_uni($config, 100);
        $q->quiche_config_set_disable_active_migration($config, true);
        $q->quiche_config_verify_peer($config, false);
        return $config;
    }
    /**
     * Allocates a uint8_t* CData buffer holding the given PHP
     * string and returns it. The returned buffer is owned by
     * the caller; it stays alive only as long as the PHP-side
     * variable referencing it.
     *
     * @param H3FFI $ffi the libquiche wrapper
     * @param string $s the bytes to copy
     * @return \FFI\CData a uint8_t array holding $s
     */
    public static function stringToCData($ffi, $s)
    {
        $len = strlen($s);
        if ($len === 0) {
            return null;
        }
        $buf = \FFI::new("uint8_t[$len]", false);
        \FFI::memcpy($buf, $s, $len);
        return $buf;
    }
    /**
     * Reads available bytes from the buffer into a PHP string.
     * Useful in the dispatch path where libquiche fills a
     * uint8_t* and we need to hand the bytes back to PHP code.
     *
     * @param \FFI\CData $cdata source buffer
     * @param int $len number of bytes to copy
     * @return string the bytes as a PHP string
     */
    public static function cdataToString($cdata, $len)
    {
        if ($len <= 0) {
            return '';
        }
        return \FFI::string($cdata, $len);
    }
    /**
     * Closes the listener. Frees the quiche_config and the UDP
     * socket; H3Connections are not closed here because they may
     * still be draining (the WebSite shutdown path closes them).
     */
    public function close()
    {
        if ($this->quiche_config !== null && $this->ffi !== null) {
            $this->ffi->ffi->quiche_config_free($this->quiche_config);
            $this->quiche_config = null;
        }
        parent::close();
    }
    /**
     * Reads one UDP datagram from the server socket and either
     * returns a freshly-created H3Connection (for a new Initial
     * packet matching no existing CID) or routes the datagram to
     * an existing H3Connection's quiche_conn_recv. Returns
     * [null, null] if no datagram is available.
     *
     * @param ConnectionAcceptor $acceptor unused for H3; the
     *      TCP-accept-and-TLS-handshake helper has no analogue
     *      in the QUIC datagram path
     * @param float $timeout maximum seconds to block (unused
     *      since the UDP socket is non-blocking)
     * @return array [H3Connection|null, array|null]
     */
    public function accept($acceptor, $timeout)
    {
        $peer = '';
        $buf = stream_socket_recvfrom($this->server, 65535, 0, $peer);
        if ($buf === false || $buf === '') {
            return [null, null];
        }
        /*
            Connection creation via quiche_accept and per-CID
            datagram routing land alongside H3Transport. Until
            then this listener silently absorbs incoming datagrams
            so the UDP port behaves as a no-op.
         */
        return [null, null];
    }
}
