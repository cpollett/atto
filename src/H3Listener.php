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
     * H3 event types from the quiche_h3_event enum, returned by
     * quiche_h3_event_type. HEADERS arrives once per request when
     * the headers have been decoded; DATA arrives 0+ times as
     * request body chunks accumulate; FINISHED arrives once when
     * the peer closes its half of the stream. RESET means the
     * peer aborted; GOAWAY means the peer is shutting down the
     * connection.
     */
    const QUICHE_H3_EVENT_HEADERS = 0;
    const QUICHE_H3_EVENT_DATA = 1;
    const QUICHE_H3_EVENT_FINISHED = 2;
    const QUICHE_H3_EVENT_GOAWAY = 3;
    const QUICHE_H3_EVENT_RESET = 4;
    const QUICHE_H3_EVENT_PRIORITY_UPDATE = 5;
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
            char opaque[320];
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
        typedef struct quiche_h3_config quiche_h3_config;
        typedef struct quiche_h3_conn quiche_h3_conn;
        typedef struct quiche_h3_event quiche_h3_event;
        typedef struct {
            const uint8_t *name;
            size_t name_len;
            const uint8_t *value;
            size_t value_len;
        } quiche_h3_header;
        quiche_h3_config *quiche_h3_config_new(void);
        void quiche_h3_config_free(quiche_h3_config *config);
        quiche_h3_conn *quiche_h3_conn_new_with_transport(
            quiche_conn *conn, quiche_h3_config *config);
        void quiche_h3_conn_free(quiche_h3_conn *conn);
        int64_t quiche_h3_conn_poll(quiche_h3_conn *h3,
            quiche_conn *quic_conn, quiche_h3_event **ev);
        int quiche_h3_event_type(quiche_h3_event *ev);
        typedef int (*quiche_h3_header_cb)(uint8_t *name,
            size_t name_len, uint8_t *value, size_t value_len,
            void *argp);
        int quiche_h3_event_for_each_header(quiche_h3_event *ev,
            quiche_h3_header_cb cb, void *argp);
        void quiche_h3_event_free(quiche_h3_event *ev);
        ssize_t quiche_h3_send_response(quiche_h3_conn *h3,
            quiche_conn *quic_conn, uint64_t stream_id,
            quiche_h3_header *headers, size_t headers_len,
            bool fin);
        ssize_t quiche_h3_send_body(quiche_h3_conn *h3,
            quiche_conn *quic_conn, uint64_t stream_id,
            const uint8_t *body, size_t body_len, bool fin);
        ssize_t quiche_h3_recv_body(quiche_h3_conn *h3,
            quiche_conn *quic_conn, uint64_t stream_id,
            uint8_t *out, size_t out_len);
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
        $ret = $this->ffi->quiche_version();
        /*
            Some PHP FFI builds auto-marshal const char* return
            values to PHP strings while others return CData.
            Handle both.
         */
        if (is_string($ret)) {
            return $ret;
        }
        return \FFI::string($ret);
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
     * The cdata pointer to the underlying quiche_h3_conn. Created
     * lazily once isEstablished() returns true (the H3 protocol
     * layer can only attach to a QUIC connection that has
     * completed its TLS handshake). Owned by this class; freed
     * in close() via quiche_h3_conn_free.
     * @var \FFI\CData|null
     */
    public $h3_conn;
    /**
     * Per-stream request state, keyed by stream_id. Each entry is
     * an array with shape:
     *   'method'    => 'GET' | 'POST' | ...
     *   'path'      => '/some/path'
     *   'authority' => 'example.com:8443'
     *   'scheme'    => 'https'
     *   'headers'   => ['name' => 'value', ...]
     *   'body'      => '' (accumulated from DATA events)
     *   'fin'       => bool (FIN was seen)
     *   'dispatched'=> bool (already passed to process())
     * Cleared per stream once the response is sent.
     * @var array
     */
    public $streams = [];
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
     * The peer address as the original "host:port" string from
     * stream_socket_recvfrom. Kept around so the outbound
     * stream_socket_sendto call can address the packet.
     * @var string
     */
    public $peer_address = '';
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
        $this->h3_conn = null;
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
     * Releases the underlying quiche_conn and any attached
     * quiche_h3_conn. After close the H3Connection is unusable;
     * the H3Listener removes it from its CID map.
     */
    public function close()
    {
        if ($this->ffi !== null) {
            if ($this->h3_conn !== null) {
                $this->ffi->ffi->quiche_h3_conn_free($this->h3_conn);
                $this->h3_conn = null;
            }
            if ($this->quiche_conn !== null) {
                $this->ffi->ffi->quiche_conn_free($this->quiche_conn);
                $this->quiche_conn = null;
            }
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
     * Back-reference to the WebSite that opened this listener.
     * Set by listen() right after tryOpen returns. Held so
     * accept() can reach the H3Transport in
     * $site->transports['h3'] for event polling and dispatch
     * after each inbound packet.
     * @var WebSite|null
     */
    public $site;
    /**
     * Cached packed sockaddr buffer for this listener's local
     * address. Allocated once in tryOpen rather than on every
     * inbound packet. The local address never changes for a
     * bound socket so the buffer is reused for the lifetime of
     * the listener.
     * @var \FFI\CData|null
     */
    public $local_sockaddr;
    /**
     * Length in bytes of $local_sockaddr.
     * @var int
     */
    public $local_sockaddr_len = 0;
    /**
     * Reusable 1500-byte output buffer for drainConnection's
     * quiche_conn_send call. Allocated once per listener so the
     * inner loop does not pay an FFI::new cost per packet on a
     * 1+ MiB body which packetizes to 700+ datagrams.
     * @var \FFI\CData|null
     */
    public $send_buf;
    /**
     * Reusable quiche_send_info struct paired with $send_buf.
     * @var \FFI\CData|null
     */
    public $send_info;
    /**
     * Reusable quiche_recv_info struct for feedPacket. Same
     * lifetime hygiene as $send_info: allocate once per
     * listener, repopulate on every call.
     * @var \FFI\CData|null
     */
    public $recv_info;
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
        self::tuneSocketBuffers($server);
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
        /*
            Pre-allocate packet buffers and FFI structs reused
            on every drain and feed call. Allocating these per
            call dominates per-packet PHP overhead on large
            responses; hoisting to the listener turns a hot
            path allocation into a stable pointer.
         */
        $local_addr = @stream_socket_get_name($server, false);
        if ($local_addr !== false && $local_addr !== '') {
            $local_len = 0;
            $local_buf = self::peerToSockaddr($ffi, $local_addr,
                $local_len);
            if ($local_buf !== null) {
                $listener->local_sockaddr = $local_buf;
                $listener->local_sockaddr_len = $local_len;
            }
        }
        $listener->send_buf = $ffi->ffi->new('uint8_t[1500]');
        $listener->send_info = $ffi->ffi->new('quiche_send_info');
        $listener->recv_info = $ffi->ffi->new('quiche_recv_info');
        return $listener;
    }
    /**
     * Bumps the UDP socket's SO_SNDBUF and SO_RCVBUF where the
     * runtime allows. The default kernel UDP buffer sizes
     * (commonly ~256 KiB on Linux) are sized for chatty small-
     * datagram traffic; H3 servers regularly want bursts of
     * outbound packets and bursts of inbound ACKs that fit in
     * a single socket read. A 4 MiB buffer comfortably holds
     * a 1 MiB body's packets and the corresponding ACK flood.
     *
     * Best-effort: requires the sockets extension AND
     * socket_import_stream (POSIX-only in PHP). On Windows or
     * builds without sockets, the call is silently skipped and
     * the listener works at default buffer sizes — this is also
     * why drainConnection caps per-call emissions defensively.
     *
     * The kernel may clamp the requested size to its sysctl
     * (net.core.rmem_max / wmem_max on Linux). If the operator
     * needs larger buffers than the system allows they should
     * raise those sysctls.
     *
     * @param resource $server the UDP server stream
     */
    protected static function tuneSocketBuffers($server)
    {
        if (!function_exists('socket_import_stream')
            || !function_exists('socket_set_option')) {
            return;
        }
        $sock = @socket_import_stream($server);
        if ($sock === false || $sock === null) {
            return;
        }
        $size = 4194304; /* 4 MiB */
        @socket_set_option($sock, SOL_SOCKET, SO_RCVBUF, $size);
        @socket_set_option($sock, SOL_SOCKET, SO_SNDBUF, $size);
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
        /*
            Connection-level send window. 256 MiB is high enough
            that no realistic single response (file, JSON blob,
            HTML page) will trip it on localhost, while still
            being far below typical RAM. Per-stream window is
            16 MiB which gives big-body responses room to fill
            before the client has to send a window update; this
            avoids round-trip stalls during 1+ MiB bodies. The
            previous 1 MiB stream window was off-by-the-DATA-
            frame-header for exactly-1-MiB bodies and produced
            visible hangs in the bench /big case.
         */
        $q->quiche_config_set_initial_max_data($config, 268435456);
        $q->quiche_config_set_initial_max_stream_data_bidi_local(
            $config, 16777216);
        $q->quiche_config_set_initial_max_stream_data_bidi_remote(
            $config, 16777216);
        $q->quiche_config_set_initial_max_stream_data_uni(
            $config, 16777216);
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
        $buf = $ffi->ffi->new("uint8_t[$len]");
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
     * Drains all pending UDP datagrams from the server socket
     * in one event-loop pass. Each datagram is dispatched via
     * processDatagram, which routes to an existing H3Connection
     * by DCID or creates a new one for an Initial packet. The
     * first new connection created during the drain is surfaced
     * to the caller so processServerRequest can register it;
     * any subsequent new connections during the same drain stay
     * in the listener's CID-keyed map and surface on the next
     * event-loop pass via their existing-connection branch.
     *
     * Without this drain loop, atto would round-trip through
     * stream_select once per inbound datagram. For a 1 MiB
     * download that triggers tens of ACKs in quick succession,
     * that adds up to noticeable latency since congestion
     * control can only open the window when ACKs are processed
     * and the kernel UDP recv buffer fills before we read it
     * fast enough, causing drops and retransmits. Draining all
     * pending datagrams in one pass lets the QUIC stack see
     * them as a batch and respond with the next outbound burst
     * in the same accept call.
     *
     * @param ConnectionAcceptor $acceptor unused for H3; the
     *      TCP-accept-and-TLS-handshake helper has no analogue
     *      in the QUIC datagram path
     * @param float $timeout maximum seconds to block (unused
     *      since the UDP socket is non-blocking)
     * @return array [H3Connection|null, array|null] the first
     *      new connection created during the drain, or null/null
     *      if all datagrams were for existing connections (or
     *      none were available)
     */
    public function accept($acceptor, $timeout)
    {
        $first_new = null;
        $first_context = null;
        /*
            Safety bound on datagrams per drain. A 1 MiB body
            triggers tens of ACKs in burst; 4096 gives generous
            headroom while preventing a pathologically chatty
            client from monopolizing the event loop.
         */
        $max = 4096;
        while ($max-- > 0) {
            $peer = '';
            $buf = @stream_socket_recvfrom($this->server, 65535, 0,
                $peer);
            if ($buf === false || $buf === '') {
                break;
            }
            list($conn, $context) = $this->processDatagram($buf,
                $peer);
            if ($conn !== null && $first_new === null) {
                $first_new = $conn;
                $first_context = $context;
            }
        }
        if ($first_new !== null) {
            return [$first_new, $first_context];
        }
        return [null, null];
    }
    /**
     * Processes a single UDP datagram by parsing its QUIC header,
     * routing it to an existing H3Connection if the DCID matches
     * or creating a new H3Connection if the packet is an Initial
     * for an unknown CID. Returns the new connection (and its
     * context array) on the new-connection path; returns
     * [null, null] for existing-connection traffic and for
     * dropped or malformed datagrams.
     *
     * @param string $buf packet bytes
     * @param string $peer peer "host:port" from recvfrom
     * @return array [H3Connection|null, array|null]
     */
    protected function processDatagram($buf, $peer)
    {
        $q = $this->ffi->ffi;
        $buf_len = strlen($buf);
        $buf_cdata = self::stringToCData($this->ffi, $buf);
        /*
            Parse the QUIC header to extract version, packet type,
            and DCID/SCID. quiche_header_info needs PHP-side
            buffers for each output.
         */
        $version_ptr = $q->new('uint32_t');
        $type_ptr = $q->new('uint8_t');
        $scid_buf = $q->new('uint8_t[' . H3FFI::QUICHE_MAX_CONN_ID_LEN
            . ']');
        $scid_len_ptr = $q->new('size_t');
        $scid_len_ptr->cdata = H3FFI::QUICHE_MAX_CONN_ID_LEN;
        $dcid_buf = $q->new('uint8_t[' . H3FFI::QUICHE_MAX_CONN_ID_LEN
            . ']');
        $dcid_len_ptr = $q->new('size_t');
        $dcid_len_ptr->cdata = H3FFI::QUICHE_MAX_CONN_ID_LEN;
        $token_buf = $q->new('uint8_t[256]');
        $token_len_ptr = $q->new('size_t');
        $token_len_ptr->cdata = 256;
        $rc = $q->quiche_header_info($buf_cdata, $buf_len,
            H3FFI::QUICHE_MAX_CONN_ID_LEN,
            \FFI::addr($version_ptr), \FFI::addr($type_ptr),
            $scid_buf, \FFI::addr($scid_len_ptr),
            $dcid_buf, \FFI::addr($dcid_len_ptr),
            $token_buf, \FFI::addr($token_len_ptr));
        if ($rc < 0) {
            /* Malformed packet; drop it. */
            return [null, null];
        }
        $dcid_hex = bin2hex(self::cdataToString($dcid_buf,
            $dcid_len_ptr->cdata));
        $scid_hex = bin2hex(self::cdataToString($scid_buf,
            $scid_len_ptr->cdata));
        $version = $version_ptr->cdata;
        /*
            Existing connection: feed packet, drive H3 events,
            then drain outbound.
         */
        if (isset($this->connections[$dcid_hex])) {
            $conn = $this->connections[$dcid_hex];
            $this->feedPacket($conn, $buf_cdata, $buf_len, $peer);
            $this->driveH3($conn);
            $this->drainConnection($conn);
            $this->reapIfClosed($conn);
            return [null, null];
        }
        /*
            Unsupported version: send a Version Negotiation packet
            and drop the inbound packet.
         */
        if (!$q->quiche_version_is_supported($version)) {
            $this->sendVersionNegotiation($scid_buf,
                $scid_len_ptr->cdata,
                $dcid_buf, $dcid_len_ptr->cdata, $peer);
            return [null, null];
        }
        /*
            New connection: mint a fresh local SCID, call
            quiche_accept, register the connection, feed the first
            packet, then drain outbound.
         */
        $local_scid = random_bytes(H3FFI::QUICHE_MAX_CONN_ID_LEN);
        $local_scid_hex = bin2hex($local_scid);
        $local_scid_buf = self::stringToCData($this->ffi, $local_scid);
        $peer_sock = self::peerToSockaddr($this->ffi, $peer,
            $peer_len);
        if ($peer_sock === null
            || $this->local_sockaddr === null) {
            return [null, null];
        }
        $quiche_conn = $q->quiche_accept($local_scid_buf,
            H3FFI::QUICHE_MAX_CONN_ID_LEN, null, 0,
            $this->local_sockaddr, $this->local_sockaddr_len,
            $peer_sock, $peer_len, $this->quiche_config);
        if (\FFI::isNull($quiche_conn)) {
            return [null, null];
        }
        $h3_conn = new H3Connection($this->ffi, $quiche_conn,
            $local_scid_hex);
        $h3_conn->peer_address = $peer;
        $h3_conn->peer_sockaddr = $peer_sock;
        $h3_conn->peer_sockaddr_len = $peer_len;
        $this->connections[$local_scid_hex] = $h3_conn;
        $this->feedPacket($h3_conn, $buf_cdata, $buf_len, $peer);
        $this->driveH3($h3_conn);
        $this->drainConnection($h3_conn);
        $this->reapIfClosed($h3_conn);
        return [$h3_conn, ['protocol' => 'h3']];
    }
    /**
     * Hands the connection to H3Transport so any newly-decoded H3
     * events get polled and dispatched. Looks up the transport on
     * the back-referenced WebSite. No-op if the transport is not
     * registered (e.g. a misconfigured site missing H3Transport).
     *
     * @param H3Connection $conn the connection to drive
     */
    protected function driveH3($conn)
    {
        if ($this->site === null) {
            return;
        }
        $transport = $this->site->transports['h3'] ?? null;
        if ($transport === null) {
            return;
        }
        $transport->driveConnection($this, $conn);
    }
    /**
     * Feeds an inbound UDP datagram to a specific H3Connection
     * via quiche_conn_recv. Builds the quiche_recv_info struct
     * with the peer/local socket addresses libquiche needs for
     * path validation. Caller is expected to have already routed
     * the packet to the right connection by DCID.
     *
     * @param H3Connection $conn target connection
     * @param \FFI\CData $buf_cdata packet bytes as uint8_t*
     * @param int $buf_len packet length
     * @param string $peer peer "host:port" from recvfrom
     */
    protected function feedPacket($conn, $buf_cdata, $buf_len, $peer)
    {
        $q = $this->ffi->ffi;
        /*
            Use the connection's cached peer sockaddr (set when
            the connection was created) and the listener's cached
            local sockaddr (set in tryOpen). Allocating fresh
            sockaddr buffers per inbound packet was a measurable
            cost during 1+ MiB responses where a burst of ACKs
            triggers many feedPacket calls in quick succession.
            Falls back to the slow path (re-pack from $peer) if
            the connection somehow lacks a cached peer sockaddr.
         */
        if ($conn->peer_sockaddr === null
            || $this->local_sockaddr === null) {
            $peer_sock = self::peerToSockaddr($this->ffi, $peer,
                $peer_len);
            if ($peer_sock === null
                || $this->local_sockaddr === null) {
                return;
            }
            $peer_buf = $peer_sock;
            $peer_buf_len = $peer_len;
        } else {
            $peer_buf = $conn->peer_sockaddr;
            $peer_buf_len = $conn->peer_sockaddr_len;
        }
        $info = $this->recv_info;
        $info->from = $q->cast('void*', \FFI::addr($peer_buf[0]));
        $info->from_len = $peer_buf_len;
        $info->to = $q->cast('void*',
            \FFI::addr($this->local_sockaddr[0]));
        $info->to_len = $this->local_sockaddr_len;
        $q->quiche_conn_recv($conn->quiche_conn, $buf_cdata,
            $buf_len, \FFI::addr($info));
    }
    /**
     * Drains pending outbound packets from a connection by
     * calling quiche_conn_send in a loop and writing each
     * resulting datagram to the UDP socket via
     * stream_socket_sendto. Stops when libquiche reports
     * QUICHE_ERR_DONE (no more packets to send), when sendto
     * indicates the kernel UDP send buffer is full, or when
     * the per-call packet bound is reached.
     *
     * The packet bound matters: a single drain that floods
     * packets faster than the kernel can drain them to the wire
     * causes silent drops. quiche thinks those packets are in
     * flight, awaits ACKs that never come (because the client
     * never received them), and the connection stalls until
     * quiche's RTO fires. Capping per-drain emissions at a
     * value comfortably below the kernel UDP send buffer
     * (typically 256 KiB ~ 190 packets) lets the kernel push
     * what we wrote to the wire before the next drain queues
     * more.
     *
     * Subsequent drains, triggered by inbound ACKs, pick up
     * where this one left off because quiche keeps the body in
     * its internal stream buffer until the peer acknowledges.
     *
     * @param H3Connection $conn connection whose egress queue
     *      to drain
     */
    public function drainConnection($conn)
    {
        $q = $this->ffi->ffi;
        $out = $this->send_buf;
        $send_info = $this->send_info;
        /*
            64 packets per drain (~86 KiB) is conservative
            relative to the kernel UDP send buffer (which
            tryOpen bumps to 4 MiB) and gives the kernel time
            to push what we wrote to the wire before the next
            drain queues more. The sendto short-write check
            below catches any kernel buffer pressure regardless
            of cap. Empirically larger caps (we tried 2048) do
            not improve big-body throughput on this codepath:
            quiche's cwnd is the natural throttle long before
            the application-level cap matters.
         */
        $max = 64;
        while ($max-- > 0) {
            $written = $q->quiche_conn_send($conn->quiche_conn,
                $out, 1500, \FFI::addr($send_info));
            if ($written === H3FFI::QUICHE_ERR_DONE
                || $written <= 0) {
                break;
            }
            $bytes = \FFI::string($out, $written);
            $sent = @stream_socket_sendto($this->server, $bytes, 0,
                $conn->peer_address);
            if ($sent === false || $sent < $written) {
                /*
                    Kernel UDP send buffer is full or the route
                    is unreachable. Stop draining and let the
                    next ACK-triggered drain pick up where we
                    left off; quiche keeps the unsent body in
                    its internal buffer until the peer ACKs the
                    packets that did make it out.
                 */
                break;
            }
        }
    }
    /**
     * Removes a connection from the listener's CID map and frees
     * its libquiche resources if the connection has reached the
     * closed state. Called after every recv/drain cycle so
     * idle-timed-out and peer-closed connections don't leak.
     *
     * @param H3Connection $conn connection to check and reap
     */
    protected function reapIfClosed($conn)
    {
        if (!$conn->isClosed()) {
            return;
        }
        unset($this->connections[$conn->scid_hex]);
        $conn->close();
    }
    /**
     * Sends a Version Negotiation packet to the peer when an
     * inbound packet uses an unsupported QUIC version. The peer
     * will retry with one of the listed versions or give up.
     *
     * @param \FFI\CData $scid_buf the inbound packet's SCID
     * @param int $scid_len SCID length in bytes
     * @param \FFI\CData $dcid_buf the inbound packet's DCID
     * @param int $dcid_len DCID length in bytes
     * @param string $peer peer "host:port" to send the response to
     */
    protected function sendVersionNegotiation($scid_buf, $scid_len,
        $dcid_buf, $dcid_len, $peer)
    {
        $q = $this->ffi->ffi;
        $out = $q->new('uint8_t[1500]');
        $written = $q->quiche_negotiate_version($scid_buf, $scid_len,
            $dcid_buf, $dcid_len, $out, 1500);
        if ($written <= 0) {
            return;
        }
        $bytes = \FFI::string($out, $written);
        @stream_socket_sendto($this->server, $bytes, 0, $peer);
    }
    /**
     * Packs a "host:port" address string into a sockaddr_in or
     * sockaddr_in6 byte buffer suitable for passing to libquiche
     * as a `const struct sockaddr *`. $out_len is set by-reference
     * to the buffer length so the caller can pass it as the
     * accompanying socklen_t. Returns null on parse failure.
     *
     * The returned buffer is an FFI uint8_t[] CData. Owned by
     * the caller; lives only as long as the PHP variable holding
     * it.
     *
     * @param H3FFI $ffi the libquiche wrapper
     * @param string $address "host:port" or "[ipv6]:port"
     * @param int $out_len output: byte length of the buffer
     * @return \FFI\CData|null packed sockaddr buffer
     */
    public static function peerToSockaddr($ffi, $address, &$out_len)
    {
        if (strpos($address, '[') === 0) {
            $end = strpos($address, ']');
            if ($end === false) {
                return null;
            }
            $host = substr($address, 1, $end - 1);
            $rest = substr($address, $end + 1);
            if (strlen($rest) < 2 || $rest[0] !== ':') {
                return null;
            }
            $port = (int) substr($rest, 1);
            $is_v6 = true;
        } else {
            $colon = strrpos($address, ':');
            if ($colon === false) {
                return null;
            }
            $host = substr($address, 0, $colon);
            $port = (int) substr($address, $colon + 1);
            $is_v6 = strpos($host, ':') !== false;
        }
        $is_mac = strtolower(substr(PHP_OS, 0, 6)) === 'darwin';
        if ($is_v6) {
            /*
                sockaddr_in6: family(2)+port(2)+flowinfo(4)+
                addr(16)+scope_id(4) = 28 bytes. macOS prefixes
                a 1-byte length and uses 1 byte for family.
             */
            $packed_addr = @inet_pton($host);
            if ($packed_addr === false || strlen($packed_addr) !== 16) {
                return null;
            }
            if ($is_mac) {
                $bytes = chr(28) . chr(30) /* AF_INET6 macOS */
                    . pack('n', $port) . pack('N', 0)
                    . $packed_addr . pack('N', 0);
            } else {
                $bytes = pack('S', 10) /* AF_INET6 linux */
                    . pack('n', $port) . pack('N', 0)
                    . $packed_addr . pack('N', 0);
            }
            $out_len = 28;
        } else {
            /*
                sockaddr_in: family(2)+port(2)+addr(4)+pad(8) =
                16 bytes. macOS prefixes a 1-byte length and
                uses 1 byte for family.
             */
            $packed_addr = @inet_pton($host);
            if ($packed_addr === false || strlen($packed_addr) !== 4) {
                return null;
            }
            if ($is_mac) {
                $bytes = chr(16) . chr(2) /* AF_INET macOS */
                    . pack('n', $port) . $packed_addr
                    . str_repeat("\0", 8);
            } else {
                $bytes = pack('S', 2) /* AF_INET linux */
                    . pack('n', $port) . $packed_addr
                    . str_repeat("\0", 8);
            }
            $out_len = 16;
        }
        $len = strlen($bytes);
        $buf = $ffi->ffi->new("uint8_t[$len]");
        \FFI::memcpy($buf, $bytes, $len);
        return $buf;
    }
}
/**
 * H3 transport: drives the HTTP/3 layer on top of an established
 * QUIC connection. Held by WebSite under transports['h3'] but
 * driven manually by H3Listener::accept rather than through the
 * normal stream_select path, because all H3 traffic enters via
 * the listener's UDP socket and there are no per-connection
 * stream resources for the event loop to select on.
 *
 * The driveConnection method is the entry point: H3Listener calls
 * it after every successful inbound packet, and it polls
 * quiche_h3_conn_poll for any HEADERS/DATA/FINISHED events that
 * libquiche has parsed off the QUIC streams. Complete requests
 * are dispatched through WebSite::process and the response is
 * written via quiche_h3_send_response and quiche_h3_send_body.
 */
class H3Transport extends Transport
{
    /**
     * The shared quiche_h3_config used for every H3 connection
     * spun up by this transport. Allocated lazily on first use.
     * @var \FFI\CData|null
     */
    protected $h3_config;
    /**
     * Reference to the H3FFI instance, captured from the first
     * H3Listener that activates this transport. Held so we can
     * call libquiche functions without threading the FFI handle
     * through every method.
     * @var H3FFI|null
     */
    protected $ffi;
    /**
     * onReadable is unused for H3 because the event loop never
     * routes a per-connection readable to this transport — H3
     * connections share the listener's UDP socket. driveConnection
     * is the real entry point, called by H3Listener::accept after
     * each inbound packet.
     */
    public function onReadable($key, $conn, $in_stream, $too_long)
    {
        /* H3 traffic is driven by H3Listener::accept; nothing to do here. */
    }
    /**
     * Drives the HTTP/3 protocol layer on a freshly fed QUIC
     * connection. If the QUIC handshake just completed, attaches
     * a quiche_h3_conn. Then polls for H3 events and processes
     * each one: HEADERS captures pseudo-headers and regular
     * headers, FINISHED dispatches the request and writes the
     * response. Errors (poll returns < 0 with !ERR_DONE) tear
     * down the connection.
     *
     * @param H3Listener $listener the H3 listener owning $conn
     * @param H3Connection $conn the connection to drive
     */
    public function driveConnection($listener, $conn)
    {
        if ($this->ffi === null) {
            $this->ffi = $listener->ffi;
        }
        $q = $this->ffi->ffi;
        if (!$conn->isEstablished()) {
            return;
        }
        if ($conn->h3_conn === null) {
            if ($this->h3_config === null) {
                $this->h3_config = $q->quiche_h3_config_new();
            }
            if (\FFI::isNull($this->h3_config)) {
                return;
            }
            $conn->h3_conn = $q->quiche_h3_conn_new_with_transport(
                $conn->quiche_conn, $this->h3_config);
            if (\FFI::isNull($conn->h3_conn)) {
                $conn->h3_conn = null;
                return;
            }
        }
        $event_ptr = $this->ffi->ffi->new('quiche_h3_event*');
        $max_events = 64; /* safety bound per drive call */
        while ($max_events-- > 0) {
            $stream_id = $q->quiche_h3_conn_poll($conn->h3_conn,
                $conn->quiche_conn, \FFI::addr($event_ptr));
            if ($stream_id < 0) {
                break;
            }
            $type = $q->quiche_h3_event_type($event_ptr);
            $this->handleEvent($listener, $conn, $stream_id,
                $event_ptr, $type);
            $q->quiche_h3_event_free($event_ptr);
        }
        /*
            Resume any partial body sends that are waiting on
            flow-control credit. Each ACK from the peer opens
            the window; on the next inbound packet driveH3 fires
            again and we get to push more here.
         */
        $this->flushAllPendingBodies($conn);
    }
    /**
     * Dispatches an individual H3 event by type. HEADERS captures
     * the request line and headers; FINISHED dispatches the
     * request and queues the response. DATA is read via
     * quiche_h3_recv_body. RESET and GOAWAY clean up state.
     *
     * @param H3Listener $listener owning listener (for outbound drain)
     * @param H3Connection $conn connection the event arrived on
     * @param int $stream_id stream the event applies to
     * @param \FFI\CData $ev the event handle
     * @param int $type H3FFI::QUICHE_H3_EVENT_*
     */
    protected function handleEvent($listener, $conn, $stream_id,
        $ev, $type)
    {
        switch ($type) {
            case H3FFI::QUICHE_H3_EVENT_HEADERS:
                $this->captureHeaders($conn, $stream_id, $ev);
                break;
            case H3FFI::QUICHE_H3_EVENT_DATA:
                $this->captureData($conn, $stream_id);
                break;
            case H3FFI::QUICHE_H3_EVENT_FINISHED:
                if (!isset($conn->streams[$stream_id])) {
                    break;
                }
                $conn->streams[$stream_id]['fin'] = true;
                $this->dispatchRequest($listener, $conn, $stream_id);
                break;
            case H3FFI::QUICHE_H3_EVENT_RESET:
            case H3FFI::QUICHE_H3_EVENT_GOAWAY:
                unset($conn->streams[$stream_id]);
                break;
        }
    }
    /**
     * Captures the headers attached to an H3 HEADERS event. The
     * libquiche API delivers them via a callback (function-pointer
     * type declared in CDEF); the closure stores each name/value
     * pair into the connection's per-stream state. Pseudo-headers
     * (:method, :path, :authority, :scheme) are pulled out into
     * dedicated fields; regular headers go into a 'headers' map.
     *
     * @param H3Connection $conn connection the event arrived on
     * @param int $stream_id stream id the headers belong to
     * @param \FFI\CData $ev the event handle
     */
    protected function captureHeaders($conn, $stream_id, $ev)
    {
        $q = $this->ffi->ffi;
        if (!isset($conn->streams[$stream_id])) {
            $conn->streams[$stream_id] = [
                'method' => 'GET', 'path' => '/', 'authority' => '',
                'scheme' => 'https', 'headers' => [], 'body' => '',
                'fin' => false, 'dispatched' => false,
                'pending_body' => '',
            ];
        }
        $stream = &$conn->streams[$stream_id];
        $cb = function ($name, $name_len, $value, $value_len,
            $argp) use (&$stream) {
            $n = \FFI::string($name, $name_len);
            $v = \FFI::string($value, $value_len);
            switch ($n) {
                case ':method':
                    $stream['method'] = $v;
                    break;
                case ':path':
                    $stream['path'] = $v;
                    break;
                case ':authority':
                    $stream['authority'] = $v;
                    break;
                case ':scheme':
                    $stream['scheme'] = $v;
                    break;
                default:
                    $stream['headers'][$n] = $v;
            }
            return 0;
        };
        $q->quiche_h3_event_for_each_header($ev, $cb, null);
    }
    /**
     * Reads any available request-body bytes off the given stream
     * and appends them to the per-stream body buffer. Called when
     * a DATA event fires.
     *
     * @param H3Connection $conn the connection
     * @param int $stream_id the stream that has new body data
     */
    protected function captureData($conn, $stream_id)
    {
        if (!isset($conn->streams[$stream_id])) {
            return;
        }
        $q = $this->ffi->ffi;
        $buf = $q->new('uint8_t[16384]');
        while (true) {
            $n = $q->quiche_h3_recv_body($conn->h3_conn,
                $conn->quiche_conn, $stream_id, $buf, 16384);
            if ($n <= 0) {
                break;
            }
            $conn->streams[$stream_id]['body']
                .= \FFI::string($buf, $n);
        }
    }
    /**
     * Dispatches a complete request through WebSite::process and
     * sends the response back via H3 frames. Builds an H1/H2-style
     * context array from the captured pseudo-headers, calls the
     * site's setGlobals + getResponseData pair (matching how the
     * H2 dispatch path drives it), parses the resulting
     * header_data string for status + response headers, then
     * writes the response with quiche_h3_send_response and
     * quiche_h3_send_body.
     *
     * @param H3Listener $listener the listener (for drain after send)
     * @param H3Connection $conn connection the request arrived on
     * @param int $stream_id stream the request lives on
     */
    protected function dispatchRequest($listener, $conn, $stream_id)
    {
        if (!isset($conn->streams[$stream_id])) {
            return;
        }
        $stream = $conn->streams[$stream_id];
        if (!empty($stream['dispatched'])) {
            return;
        }
        $conn->streams[$stream_id]['dispatched'] = true;
        $context = $this->buildContext($listener, $conn, $stream);
        $this->site->setGlobals($context, $conn);
        try {
            $body = $this->site->getResponseData(false);
        } catch (\Throwable $e) {
            $this->sendErrorResponse($listener, $conn, $stream_id,
                500);
            unset($conn->streams[$stream_id]);
            return;
        }
        $status = 200;
        if (preg_match('/HTTP\/[\d.]+ (\d+)/',
                $this->site->header_data, $m)) {
            $status = (int) $m[1];
        }
        $headers = [];
        $lines = explode("\r\n", $this->site->header_data);
        array_shift($lines);
        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }
            $headers[] = $line;
        }
        $this->sendResponse($listener, $conn, $stream_id, $status,
            $headers, $body);
        /*
            Stream cleanup is conditional. sendResponse stashes
            any unsent body tail into pending_body when
            quiche_h3_send_body cannot accept the full body in
            one call (which is normal for any response larger
            than the initial congestion window: ~14 KiB). That
            tail is drained over subsequent ACK-triggered drive
            cycles by flushAllPendingBodies, which iterates
            $conn->streams looking for non-empty pending_body.
            If we removed the stream here while pending_body was
            still non-empty, the tail would be discarded and the
            client would hang forever waiting for body data that
            is never sent.

            For responses that fit in one quiche_h3_send_body
            call (small bodies, zero-byte bodies), pending_body
            is already empty by the time sendResponse returns,
            so we can clean up immediately. The same cleanup
            also happens in flushPendingBody once a long-running
            response finally drains.
         */
        if (isset($conn->streams[$stream_id])
            && ($conn->streams[$stream_id]['pending_body'] ?? '')
                === '') {
            unset($conn->streams[$stream_id]);
        }
    }
    /**
     * Builds an H1/H2-style $context array from the captured H3
     * request state. setGlobals then overlays this onto $_SERVER.
     *
     * @param H3Listener $listener the listener for SERVER_NAME/PORT
     * @param H3Connection $conn the connection
     * @param array $stream captured request state for the stream
     * @return array context array suitable for setGlobals
     */
    protected function buildContext($listener, $conn, $stream)
    {
        $path_only = $stream['path'];
        $query = '';
        $qpos = strpos($stream['path'], '?');
        if ($qpos !== false) {
            $path_only = substr($stream['path'], 0, $qpos);
            $query = substr($stream['path'], $qpos + 1);
        }
        $remote_addr = '';
        $remote_port = '';
        if ($conn->peer_address !== '') {
            $colon = strrpos($conn->peer_address, ':');
            if ($colon !== false) {
                $remote_addr = trim(substr(
                    $conn->peer_address, 0, $colon), '[]');
                $remote_port = substr(
                    $conn->peer_address, $colon + 1);
            }
        }
        /*
            Resolve the request authority. Priority mirrors the
            H2 path in WebSite::parseH2Request: prefer :authority
            when it is syntactically a valid URL host; fall back
            to the Host header if a client sent one (RFC 9114
            sec 4.3.1 permits Host alongside :authority); fall
            back to 'localhost' otherwise. The validation step
            wraps the candidate in "http://" so FILTER_VALIDATE_URL
            checks both the host and any port suffix. Atto does
            not match the authority against SERVER_NAME or any
            cert SAN; that mirrors the H1/H2 paths which are also
            permissive about Host. Apps that need strict virtual-
            host routing should check $_SERVER['HTTP_HOST'] in
            their own dispatcher.
         */
        $authority = 'localhost';
        $candidate = trim($stream['authority'] ?? '');
        if ($candidate === ''
            && isset($stream['headers']['host'])) {
            $candidate = trim($stream['headers']['host']);
        }
        if ($candidate !== '' && filter_var(
                "http://$candidate", FILTER_VALIDATE_URL)) {
            $authority = $candidate;
        }
        $context = [
            'REQUEST_METHOD' => $stream['method'],
            'REQUEST_URI' => $stream['path'],
            'QUERY_STRING' => $query,
            'PATH_INFO' => $path_only,
            'SCRIPT_NAME' => '',
            'HTTP_HOST' => $authority,
            'SERVER_PROTOCOL' => 'HTTP/3',
            'SERVER_NAME' => $listener->globals['SERVER_NAME'] ?? '',
            'SERVER_PORT' => $listener->globals['SERVER_PORT'] ?? '',
            'REMOTE_ADDR' => $remote_addr,
            'REMOTE_PORT' => $remote_port,
            'HTTPS' => 'on',
            'CONTENT' => $stream['body'],
        ];
        foreach ($stream['headers'] as $name => $value) {
            /*
                Skip 'host': it was already considered above when
                resolving $authority. Letting it through would
                clobber HTTP_HOST with the unvalidated raw value
                whenever the request includes a Host header
                alongside :authority, defeating the validation
                step.
             */
            if ($name === 'host') {
                continue;
            }
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
            $context[$key] = $value;
        }
        if (isset($stream['headers']['content-type'])) {
            $context['CONTENT_TYPE'] = $stream['headers'][
                'content-type'];
        }
        if (isset($stream['headers']['content-length'])) {
            $context['CONTENT_LENGTH'] = $stream['headers'][
                'content-length'];
        }
        return $context;
    }
    /**
     * Writes the response on the given stream as one HEADERS frame
     * followed by zero or more DATA frames terminated by a FIN.
     *
     * @param H3Listener $listener the listener (drain target)
     * @param H3Connection $conn the connection
     * @param int $stream_id stream the response goes on
     * @param int $status HTTP status code
     * @param array $headers response headers as ['Name: value', ...]
     * @param string $body response body
     */
    protected function sendResponse($listener, $conn, $stream_id,
        $status, $headers, $body)
    {
        $q = $this->ffi->ffi;
        $h3_headers = [
            [':status', (string) $status],
        ];
        foreach ($headers as $h) {
            $colon = strpos($h, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($h, 0, $colon)));
            $value = trim(substr($h, $colon + 1));
            /*
                Reject pseudo-headers and connection-specific
                headers per RFC 9114; their presence is a protocol
                violation that quiche will reject.
             */
            if ($name === '' || $name[0] === ':'
                || $name === 'connection'
                || $name === 'transfer-encoding'
                || $name === 'keep-alive'
                || $name === 'upgrade') {
                continue;
            }
            $h3_headers[] = [$name, $value];
        }
        $count = count($h3_headers);
        $arr = $q->new("quiche_h3_header[$count]");
        $name_bufs = [];
        $value_bufs = [];
        foreach ($h3_headers as $i => $pair) {
            list($n, $v) = $pair;
            $n_buf = H3Listener::stringToCData($this->ffi, $n);
            $v_buf = H3Listener::stringToCData($this->ffi, $v);
            $name_bufs[] = $n_buf;
            $value_bufs[] = $v_buf;
            $arr[$i]->name = $q->cast('uint8_t*',
                \FFI::addr($n_buf[0]));
            $arr[$i]->name_len = strlen($n);
            $arr[$i]->value = $q->cast('uint8_t*',
                \FFI::addr($v_buf[0]));
            $arr[$i]->value_len = strlen($v);
        }
        $body_len = strlen($body);
        $fin_with_headers = ($body_len === 0);
        $q->quiche_h3_send_response($conn->h3_conn,
            $conn->quiche_conn, $stream_id, $arr, $count,
            $fin_with_headers);
        if ($body_len > 0) {
            /*
                Stash the full body as pending and try to push it.
                quiche_h3_send_body returns the number of bytes
                accepted, which may be smaller than what we asked
                to send if the stream's flow-control window is
                exhausted. The unaccepted tail stays in
                pending_body and is retried by flushPendingBodies
                on every drive cycle as the peer sends ACKs and
                grants more credit.
             */
            if (!isset($conn->streams[$stream_id])) {
                $conn->streams[$stream_id] = [];
            }
            $conn->streams[$stream_id]['pending_body'] = $body;
            $this->flushPendingBody($conn, $stream_id);
        }
        $listener->drainConnection($conn);
    }
    /**
     * Pushes as many bytes as libquiche will accept from the
     * stream's pending_body buffer onto the QUIC stream, marking
     * FIN once all bytes are accepted. If quiche_h3_send_body
     * returns fewer bytes than offered, the remainder stays in
     * pending_body for the next attempt; the QUIC stack will
     * have to receive ACKs from the peer (which open the
     * flow-control window) before more bytes can be accepted.
     *
     * @param H3Connection $conn the connection
     * @param int $stream_id stream id whose pending_body to push
     * @return bool true if anything was written, false otherwise
     */
    protected function flushPendingBody($conn, $stream_id)
    {
        if (!isset($conn->streams[$stream_id])) {
            return false;
        }
        $pending = $conn->streams[$stream_id]['pending_body'] ?? '';
        if ($pending === '') {
            return false;
        }
        $q = $this->ffi->ffi;
        $len = strlen($pending);
        $body_buf = H3Listener::stringToCData($this->ffi, $pending);
        $written = $q->quiche_h3_send_body($conn->h3_conn,
            $conn->quiche_conn, $stream_id, $body_buf, $len, true);
        if ($written <= 0) {
            /*
                QUICHE_H3_ERR_DONE / QUICHE_ERR_DONE means the
                stream is currently flow-control-blocked. Keep
                pending_body intact and retry later; a fatal
                error (anything else negative) means the stream
                is gone, so drop the remainder and clean up the
                stream entry.
             */
            if ($written !== H3FFI::QUICHE_ERR_DONE) {
                unset($conn->streams[$stream_id]);
            }
            return false;
        }
        if ($written >= $len) {
            /*
                Full body accepted. Stream is done from atto's
                perspective: quiche owns the in-flight bytes
                and any retransmission. Remove the entry so
                $conn->streams does not grow without bound on
                long-lived connections handling many requests.
             */
            unset($conn->streams[$stream_id]);
            return true;
        }
        $conn->streams[$stream_id]['pending_body']
            = substr($pending, $written);
        return true;
    }
    /**
     * Re-attempts the pending_body push on every stream of a
     * connection. Called from the drive cycle so progress
     * resumes whenever the peer ACKs and grants more
     * flow-control credit. No-op for streams without a backlog.
     *
     * @param H3Connection $conn the connection
     * @return bool true if any stream made progress
     */
    public function flushAllPendingBodies($conn)
    {
        $progress = false;
        foreach ($conn->streams as $sid => $stream) {
            if (($stream['pending_body'] ?? '') !== '') {
                if ($this->flushPendingBody($conn, $sid)) {
                    $progress = true;
                }
            }
        }
        return $progress;
    }
    /**
     * Sends a bare-bones error response when request dispatch
     * threw an exception. Used to keep the connection from
     * hanging silently on internal errors.
     *
     * @param H3Listener $listener the listener (drain target)
     * @param H3Connection $conn the connection
     * @param int $stream_id stream id
     * @param int $status HTTP status code (typically 500)
     */
    protected function sendErrorResponse($listener, $conn,
        $stream_id, $status)
    {
        $this->sendResponse($listener, $conn, $stream_id, $status,
            ['Content-Type: text/plain'],
            "Server error\n");
    }
}
