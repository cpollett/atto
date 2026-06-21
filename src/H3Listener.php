<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Pure-PHP HTTP/3 (QUIC) listener. Sibling to the libquiche-FFI
 * backed H3QuicheListener.php; this file implements TLS 1.3,
 * QUIC v1, and HTTP/3 entirely in PHP using the standard openssl
 * + sodium extensions (plus gmp for RSA certs). No FFI, no
 * native deps, no Composer. WebSite.php loads this file lazily
 * on a listen() spec with 'protocol' => 'h3'; the FFI version is
 * 'protocol' => 'h3-quiche'.
 *
 * Implements: RFC 8446 TLS 1.3 server-side (no resumption, no
 * 0-RTT, no PSK; suites TLS_AES_128_GCM_SHA256 and
 * TLS_CHACHA20_POLY1305_SHA256; ecdsa_secp256r1_sha256 always
 * and rsa_pss_rsae_sha256 when ext-gmp is loaded; x25519 key
 * share). RFC 9000 QUIC v1 -- Initial / Handshake / 1-RTT
 * spaces, AEAD, header protection, varint, the full frame set,
 * idle timeout, graceful CONNECTION_CLOSE, RFC 9002 NewReno
 * loss detection and congestion control. RFC 9001 QUIC+TLS
 * mapping. RFC 9114 HTTP/3 and RFC 9204 QPACK with static-
 * table-only encoding (no server push, no priorities, no
 * dynamic QPACK table).
 *
 * Realistic per-connection throughput is a few MB/sec because
 * every byte goes through PHP-level packet decode, AEAD, and
 * frame parsing. Use the FFI sibling for ten-megabit-plus
 * sustained streams.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * TLS 1.3 server-side handshake engine. Self-contained: ext-
 * openssl, ext-sodium, ext-hash. Used by H3Listener and
 * usable in isolation against any byte-stream transport.
 *
 * Lifecycle: new Tls13Engine($cert_pem, $key_pem, $alpn_list,
 * $quic_transport_params); feedClientHello($bytes);
 * buildServerFlight(); feedClientFinished($bytes);
 * trafficSecrets() returns ['c_hs', 's_hs', 'c_ap', 's_ap']
 * with each entry the 32-byte SHA-256 secret QUIC will key
 * its packet protection from per RFC 9001 sec 5. The engine
 * never reads or writes a socket directly.
 */
class Tls13Engine
{
    /*
        TLS 1.3 record-layer constants (RFC 8446 sec 5).
     */
    const TLS_RECORD_HANDSHAKE = 22;
    const TLS_RECORD_APPLICATION_DATA = 23;
    const TLS_RECORD_ALERT = 21;
    const TLS_RECORD_CCS = 20;
    const TLS_VERSION_LEGACY = 0x0303;  /* TLS 1.2 (record-layer) */
    const TLS_VERSION_1_3 = 0x0304;     /* real version, in
                                           supported_versions */
    /*
        Handshake message types (RFC 8446 sec 4).
     */
    const HS_CLIENT_HELLO = 1;
    const HS_SERVER_HELLO = 2;
    const HS_NEW_SESSION_TICKET = 4;
    const HS_END_OF_EARLY_DATA = 5;
    const HS_ENCRYPTED_EXTENSIONS = 8;
    const HS_CERTIFICATE = 11;
    const HS_CERTIFICATE_REQUEST = 13;
    const HS_CERTIFICATE_VERIFY = 15;
    const HS_FINISHED = 20;
    const HS_KEY_UPDATE = 24;
    const HS_MESSAGE_HASH = 254;
    /*
        Extension type codes (RFC 8446 sec 4.2).
     */
    const EXT_SERVER_NAME = 0;
    const EXT_SUPPORTED_GROUPS = 10;
    const EXT_SIGNATURE_ALGORITHMS = 13;
    const EXT_ALPN = 16;
    const EXT_PRE_SHARED_KEY = 41;
    const EXT_EARLY_DATA = 42;
    const EXT_SUPPORTED_VERSIONS = 43;
    const EXT_PSK_KEY_EXCHANGE_MODES = 45;
    const EXT_KEY_SHARE = 51;
    /*
        QUIC transport parameters (RFC 9001 sec 8.2).
        Encoded as a TLS extension in ClientHello and
        EncryptedExtensions; we just round-trip the peer's
        bytes here in Phase 1. The QUIC layer in later
        phases will parse them.
     */
    const EXT_QUIC_TRANSPORT_PARAMETERS = 0x39;
    /*
        Cipher suites we support (RFC 8446 sec B.4).
     */
    const CIPHER_AES_128_GCM_SHA256 = 0x1301;
    const CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303;
    /*
        Named groups for key share (RFC 8446 sec 4.2.7).
     */
    const GROUP_X25519 = 0x001D;
    const GROUP_SECP256R1 = 0x0017;
    /*
        Signature schemes (RFC 8446 sec 4.2.3).
        Atto offers two: ecdsa_secp256r1_sha256 always,
        rsa_pss_rsae_sha256 only when ext-gmp is loaded
        (because PHP's openssl_sign cannot produce PSS
        signatures and we hand-roll the primitive via gmp).
     */
    const SIG_RSA_PKCS1_SHA256 = 0x0401; /* parsed only, never sent */
    const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
    const SIG_RSA_PSS_RSAE_SHA256 = 0x0804;
    /*
        Alert codes (RFC 8446 sec 6).
     */
    const ALERT_LEVEL_FATAL = 2;
    const ALERT_HANDSHAKE_FAILURE = 40;
    const ALERT_BAD_CERTIFICATE = 42;
    const ALERT_DECODE_ERROR = 50;
    const ALERT_PROTOCOL_VERSION = 70;
    const ALERT_INTERNAL_ERROR = 80;
    /*
        Engine state machine.
     */
    const ST_AWAIT_CLIENT_HELLO = 0;
    const ST_SENT_SERVER_FLIGHT = 1;
    const ST_AWAIT_CLIENT_FINISHED = 2;
    const ST_HANDSHAKE_COMPLETE = 3;
    /*
        Inserted in Phase 6.x: ClientHello has been fully
        parsed and validated, server flight has not yet been
        built. The QuicConnection driver checks this before
        calling buildServerFlight() so it doesn't try to
        build a flight when the CH straddles two QUIC
        Initial packets and only the first half has arrived.
        Picks ID 4 to leave the existing IDs alone.
     */
    const ST_GOT_CLIENT_HELLO = 4;
    const ST_FAILED = 99;
    /**
     * @var int current state machine position
     */
    protected $state = self::ST_AWAIT_CLIENT_HELLO;
    /**
     * @var string PEM-encoded server certificate chain, as
     *      loaded from the path the user passed in
     *      $context['ssl']['local_cert']. Multiple PEM blocks
     *      are kept concatenated; the encoder splits them.
     */
    protected $cert_pem = "";
    /**
     * @var resource|object the OpenSSL private-key handle
     *      from openssl_pkey_get_private(). Used for signing
     *      the CertificateVerify message. ECDSA keys go
     *      through openssl_sign directly; RSA keys go through
     *      our gmp-backed PSS path.
     */
    protected $pkey = null;
    /**
     * @var string 'ecdsa' or 'rsa' -- which signature path
     *      we will take. Determined at construction time
     *      from openssl_pkey_get_details.
     */
    protected $sig_path = "";
    /**
     * @var int signature scheme code we will advertise and
     *      use; SIG_ECDSA_SECP256R1_SHA256 or
     *      SIG_RSA_PSS_RSAE_SHA256.
     */
    protected $sig_scheme = 0;
    /**
     * @var array list of ALPN protocol byte-strings the server
     *      offers, e.g. ['h3'] for HTTP/3-only or ['h3', 'h2',
     *      'http/1.1']. The first one in the list that also
     *      appears in the client's offer is selected.
     */
    protected $alpn_offer = [];
    /**
     * @var string the ALPN we picked, or "" if no overlap.
     */
    protected $alpn_selected = "";
    /**
     * @var string opaque byte-string the QUIC layer passes in;
     *      we stuff it into the EncryptedExtensions message
     *      under the quic_transport_parameters extension ID.
     *      The peer's matching extension from ClientHello is
     *      saved in $client_quic_tp.
     */
    protected $server_quic_tp = "";
    /**
     * @var string client's quic_transport_parameters extension
     *      payload from ClientHello, captured for the QUIC
     *      layer to parse later.
     */
    protected $client_quic_tp = "";
    /**
     * @var int negotiated cipher suite code
     */
    protected $cipher = 0;
    /**
     * @var int hash output length in bytes for the negotiated
     *      cipher suite (32 for SHA-256, all current suites).
     */
    protected $hash_len = 32;
    /**
     * @var string our 32-byte X25519 ephemeral secret (kept
     *      only until shared-secret derivation completes;
     *      cleared afterwards for forward secrecy).
     */
    protected $x25519_secret = "";
    /**
     * @var string our 32-byte X25519 ephemeral public
     */
    protected $x25519_public = "";
    /**
     * @var string client's 32-byte X25519 public from the
     *      key_share extension. Empty if client did not
     *      offer X25519.
     */
    protected $client_x25519_public = "";
    /**
     * @var \OpenSSLAsymmetricKey|resource|null our P-256
     *      ephemeral keypair (when negotiated). Cleared
     *      after shared-secret derivation.
     */
    protected $p256_keypair = null;
    /**
     * @var string our P-256 public point on the wire, 65
     *      bytes (uncompressed: 0x04 || X || Y).
     */
    protected $p256_public_wire = "";
    /**
     * @var string client's 65-byte P-256 public from the
     *      key_share extension. Empty if client did not
     *      offer P-256.
     */
    protected $client_p256_public = "";
    /**
     * @var int the named group we picked for ECDHE. Either
     *      GROUP_X25519 or GROUP_SECP256R1; 0 until a
     *      ClientHello with a usable share has been
     *      parsed.
     */
    protected $selected_group = 0;
    /**
     * @var string ClientHello.random (32 bytes), captured.
     */
    protected $client_random = "";
    /**
     * @var string our ServerHello.random (32 bytes).
     */
    protected $server_random = "";
    /**
     * @var string client's legacy_session_id from ClientHello;
     *      we echo it back in ServerHello.legacy_session_id_echo
     *      per RFC 8446 sec 4.1.3.
     */
    protected $client_session_id = "";
    /**
     * @var string the running transcript hash. We keep the raw
     *      concatenation of every handshake message in
     *      $transcript_buf and rehash on demand; a streaming
     *      hash_init/hash_update/hash_final pipeline would also
     *      work but the buffer is at most a few KB and the
     *      simpler approach reads more clearly.
     */
    protected $transcript_buf = "";
    /**
     * @var string handshake_secret (32 bytes) from RFC 8446
     *      sec 7.1; intermediate, derived after both sides'
     *      key shares are known.
     */
    protected $handshake_secret = "";
    /**
     * @var string master_secret (32 bytes); derived after
     *      handshake_secret.
     */
    protected $master_secret = "";
    /**
     * @var array traffic secrets exposed to the QUIC layer
     *      after the handshake completes. Keys: 'c_hs',
     *      's_hs', 'c_ap', 's_ap'. Each value is a 32-byte
     *      string (SHA-256 output).
     */
    protected $secrets = [];
    /**
     * @var string the bytes the caller sends to the peer after
     *      feedClientHello succeeds. Populated by
     *      buildServerFlight().
     */
    protected $server_flight = "";
    /**
     * @var string the most recent error message; getError()
     *      returns this when state has reached ST_FAILED.
     */
    protected $error = "";
    /**
     * @param string $cert_pem PEM cert chain; first block is
     *      the leaf, remainder are intermediates.
     * @param string $key_pem PEM private key, ECDSA P-256 or
     *      RSA, PKCS#8 or traditional PEM.
     * @param array $alpn byte-strings offered for ALPN in
     *      priority order. Pass ['h3'] for HTTP/3-only; QUIC
     *      RFC 9001 sec 8.1 requires ALPN at the QUIC layer.
     * @param string $quic_tp opaque bytes from the QUIC
     *      layer; goes verbatim into EncryptedExtensions
     *      under the quic_transport_parameters extension ID.
     */
    public function __construct($cert_pem, $key_pem, $alpn,
        $quic_tp)
    {
        $this->cert_pem = (string) $cert_pem;
        $this->alpn_offer = (array) $alpn;
        $this->server_quic_tp = (string) $quic_tp;
        $this->pkey = @openssl_pkey_get_private($key_pem);
        if ($this->pkey === false) {
            $this->fail("private key did not parse");
            return;
        }
        $details = @openssl_pkey_get_details($this->pkey);
        if (!is_array($details)) {
            $this->fail("private key has no details");
            return;
        }
        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            /*
                Verify it is P-256 specifically. The TLS 1.3
                signature scheme we advertise commits us to
                that curve.
             */
            $curve = $details['ec']['curve_name'] ?? '';
            if ($curve !== 'prime256v1' &&
                $curve !== 'secp256r1') {
                $this->fail("ECDSA key is not P-256 (curve "
                    . "$curve); only secp256r1 supported");
                return;
            }
            $this->sig_path = 'ecdsa';
            $this->sig_scheme = self::SIG_ECDSA_SECP256R1_SHA256;
        } else if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            if (!extension_loaded('gmp')) {
                $this->fail("RSA key supplied but ext-gmp is "
                    . "not loaded; PHP's openssl_sign cannot "
                    . "produce TLS 1.3 RSA-PSS signatures, so "
                    . "the engine needs gmp for a hand-rolled "
                    . "modexp. Install ext-gmp or supply an "
                    . "ECDSA P-256 cert.");
                return;
            }
            $this->sig_path = 'rsa';
            $this->sig_scheme = self::SIG_RSA_PSS_RSAE_SHA256;
        } else {
            $this->fail("unsupported key type "
                . $details['type']);
            return;
        }
    }
    /**
     * Returns the most recent error message, or "" when no
     * error has been recorded.
     * @return string|false most recent error message, or false if no error has been recorded
     */
    public function getError()
    {
        return $this->error;
    }
    /**
     * Returns the negotiated cipher suite code, or 0 if no
     * cipher has been picked yet. Used by trace and key-
     * derivation paths that need to know whether to use
     * AES-128-GCM or ChaCha20-Poly1305.
     * @return int TLS cipher suite identifier negotiated during the handshake
     */
    public function negotiatedCipher()
    {
        return $this->cipher;
    }
    /**
     * Returns the selected named group code (X25519 or
     * SECP256R1), or 0 if no ClientHello has been
     * processed. Diagnostic only; the TLS engine drives
     * its own ECDHE internally.
     * @return int TLS named group identifier selected for the key share
     */
    public function selectedGroup()
    {
        return $this->selected_group;
    }
    /**
     * Returns true once the handshake has completed.
     * @return bool true if the operation has completed
     */
    public function isComplete()
    {
        return $this->state === self::ST_HANDSHAKE_COMPLETE;
    }
    /**
     * Returns true once a complete ClientHello has been
     * delivered via feedClientHello(). The QuicConnection
     * driver checks this before attempting buildServerFlight
     * -- when a client whose ClientHello straddles two QUIC
     * Initial packets connects (curl-with-quictls is one
     * example), the first Initial only carries a partial
     * CH and we should wait for the second before building
     * our reply.
     * @return bool true if a ClientHello has been processed
     */
    public function hasClientHello()
    {
        return $this->state === self::ST_GOT_CLIENT_HELLO
            || $this->state ===
                self::ST_AWAIT_CLIENT_FINISHED
            || $this->state === self::ST_HANDSHAKE_COMPLETE;
    }
    /**
     * Returns the four 1-RTT traffic secrets after handshake
     * completion. Empty array beforehand.
     * @return array currently active traffic secrets (initial/handshake/application)
     */
    public function trafficSecrets()
    {
        return $this->secrets;
    }
    /**
     * Returns the 32-byte client_random from the
     * ClientHello, or "" if not yet seen. Useful for
     * SSLKEYLOGFILE-style key logging during debugging.
     * @return string|false the client_random captured from the most recent ClientHello, or false if no ClientHello has been processed
     */
    public function clientRandom()
    {
        return $this->client_random;
    }
    /**
     * Returns the negotiated ALPN, or "" if none.
     * @return string ALPN protocol identifier negotiated for this connection
     */
    public function alpn()
    {
        return $this->alpn_selected;
    }
    /**
     * Sets the QUIC transport parameters bytes the engine
     * will emit in EncryptedExtensions. Called by
     * QuicConnection right before buildServerFlight, once
     * the original DCID is known so the
     * original_destination_connection_id parameter can
     * be included.
     * @param mixed $tp tp parameter
     */
    public function setServerQuicTransportParameters($tp)
    {
        $this->server_quic_tp = (string) $tp;
    }
    /**
     * Returns the peer's quic_transport_parameters bytes
     * captured from ClientHello.
     * @return string|false raw bytes of the client transport parameters extension, or false if not present
     */
    public function clientQuicTransportParameters()
    {
        return $this->client_quic_tp;
    }
    /**
     * Records a fatal error and moves the engine into
     * ST_FAILED. After this, all feed* methods are no-ops.
     * @param mixed $msg msg parameter
     */
    protected function fail($msg)
    {
        $this->error = $msg;
        $this->state = self::ST_FAILED;
    }
    /*
        Wire-format helpers.

        TLS uses big-endian length-prefixed structures throughout.
        The pack/unpack routines below mirror the way the spec
        writes them: a uint8 / uint16 / uint24 prefix giving the
        byte count, followed by that many bytes of payload.
     */
    /**
     * Reads a uint8 from $buf at offset $off, returns
     * [value, new_off]. Returns [false, $off] on
     * underflow.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [int $byte, int $new_off]
     */
    protected function readU8($buf, $off)
    {
        if (strlen($buf) < $off + 1) {
            return [false, $off];
        }
        return [ord($buf[$off]), $off + 1];
    }
    /**
     * Reads a uint16. Returns [value, new_off] or
     * [false, $off] on underflow.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [int $value, int $new_off]
     */
    protected function readU16($buf, $off)
    {
        if (strlen($buf) < $off + 2) {
            return [false, $off];
        }
        $v = (ord($buf[$off]) << 8) | ord($buf[$off + 1]);
        return [$v, $off + 2];
    }
    /**
     * Reads a uint24 (TLS-style 3-byte length).
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [int $value, int $new_off]
     */
    protected function readU24($buf, $off)
    {
        if (strlen($buf) < $off + 3) {
            return [false, $off];
        }
        $v = (ord($buf[$off]) << 16) |
            (ord($buf[$off + 1]) << 8) |
            ord($buf[$off + 2]);
        return [$v, $off + 3];
    }
    /**
     * Reads a vector with a uint8 length prefix; returns
     * [bytes, new_off] or [false, $off] on underflow.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [string $bytes, int $new_off]
     */
    protected function readVec8($buf, $off)
    {
        list($len, $off) = $this->readU8($buf, $off);
        if ($len === false) {
            return [false, $off];
        }
        if (strlen($buf) < $off + $len) {
            return [false, $off];
        }
        return [substr($buf, $off, $len), $off + $len];
    }
    /**
     * Reads a vector with a uint16 length prefix.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [string $bytes, int $new_off]
     */
    protected function readVec16($buf, $off)
    {
        list($len, $off) = $this->readU16($buf, $off);
        if ($len === false) {
            return [false, $off];
        }
        if (strlen($buf) < $off + $len) {
            return [false, $off];
        }
        return [substr($buf, $off, $len), $off + $len];
    }
    /**
     * Reads a vector with a uint24 length prefix.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [string $bytes, int $new_off]
     */
    protected function readVec24($buf, $off)
    {
        list($len, $off) = $this->readU24($buf, $off);
        if ($len === false) {
            return [false, $off];
        }
        if (strlen($buf) < $off + $len) {
            return [false, $off];
        }
        return [substr($buf, $off, $len), $off + $len];
    }
    /**
     * Encodes a uint16 in big-endian.
     * @param mixed $v value
     * @return string 2-byte big-endian encoding of the value
     */
    protected function packU16($v)
    {
        return chr(($v >> 8) & 0xFF) . chr($v & 0xFF);
    }
    /**
     * Encodes a uint24 in big-endian.
     * @param mixed $v value
     * @return string 3-byte big-endian encoding of the value
     */
    protected function packU24($v)
    {
        return chr(($v >> 16) & 0xFF) .
            chr(($v >> 8) & 0xFF) .
            chr($v & 0xFF);
    }
    /**
     * Wraps payload in a uint8-length-prefixed envelope.
     * @param string $payload payload bytes
     * @return string 1-byte length prefix followed by the vector bytes
     */
    protected function packVec8($payload)
    {
        return chr(strlen($payload)) . $payload;
    }
    /**
     * Wraps payload in a uint16-length-prefixed envelope.
     * @param string $payload payload bytes
     * @return string 2-byte length prefix followed by the vector bytes
     */
    protected function packVec16($payload)
    {
        return $this->packU16(strlen($payload)) . $payload;
    }
    /**
     * Wraps payload in a uint24-length-prefixed envelope.
     * @param string $payload payload bytes
     * @return string 3-byte length prefix followed by the vector bytes
     */
    protected function packVec24($payload)
    {
        return $this->packU24(strlen($payload)) . $payload;
    }
    /**
     * Wraps a TLS handshake message: prepends the 1-byte
     * type code and a uint24 length of the payload, and
     * also feeds the resulting bytes into the running
     * transcript.
     * @param int $type type code
     * @param string $body message body bytes
     * @return string serialized handshake message: 1-byte type, 3-byte length, body bytes
     */
    protected function packHandshake($type, $body)
    {
        $msg = chr($type) . $this->packU24(strlen($body)) .
            $body;
        $this->transcript_buf .= $msg;
        return $msg;
    }
    /*
        ClientHello parser.

        The bytes the caller hands feedClientHello() are the raw
        ClientHello message body (without TLS record framing) --
        type byte (1 = client_hello) and 24-bit length, then the
        body. Some callers will hand us the inside of a TLS record;
        QUIC will hand us the inside of a CRYPTO frame. Either
        way the message body is the same.
     */
    /**
     * Feeds the server a ClientHello message (handshake-message
     * bytes; type byte then uint24 length then body). Parses
     * extensions, picks cipher suite + key share + ALPN +
     * signature scheme, captures everything needed to build
     * the server flight. Returns true on success; false moves
     * the engine to ST_FAILED with getError() populated.
     * @param string $bytes bytes to operate on
     * @return bool true if the ClientHello was accepted
     */
    public function feedClientHello($bytes)
    {
        if ($this->state === self::ST_FAILED) {
            return false;
        }
        if ($this->state !== self::ST_AWAIT_CLIENT_HELLO) {
            $this->fail("unexpected ClientHello in state "
                . $this->state);
            return false;
        }
        if (strlen($bytes) < 4) {
            $this->fail("ClientHello shorter than 4 bytes");
            return false;
        }
        $type = ord($bytes[0]);
        if ($type !== self::HS_CLIENT_HELLO) {
            $this->fail("expected ClientHello, got type $type");
            return false;
        }
        list($body_len, ) = $this->readU24($bytes, 1);
        if ($body_len === false ||
            strlen($bytes) < 4 + $body_len) {
            $this->fail("ClientHello length mismatch");
            return false;
        }
        $this->transcript_buf .= substr($bytes, 0,
            4 + $body_len);
        $body = substr($bytes, 4, $body_len);
        if (!$this->parseClientHelloBody($body)) {
            if (getenv('ATTO_TLS_DEBUG_CH')) {
                $path = '/tmp/atto_clienthello.bin';
                file_put_contents($path, $bytes);
                error_log("Tls13Engine: ClientHello parse "
                    . "failed (" . $this->error . "); "
                    . "wrote " . strlen($bytes)
                    . " bytes of CH to " . $path);
            }
            return false;
        }
        $this->state = self::ST_GOT_CLIENT_HELLO;
        return true;
    }
    /**
     * Parses the body (everything after the type+length
     * header) of a ClientHello.
     * @param string $body message body bytes
     * @return array parsed ClientHello fields
     */
    protected function parseClientHelloBody($body)
    {
        $off = 0;
        list($legacy_version, $off) = $this->readU16($body,
            $off);
        if ($legacy_version === false) {
            $this->fail("ClientHello truncated at version");
            return false;
        }
        /*
            legacy_version SHOULD be 0x0303 (TLS 1.2). The real
            version negotiation happens via the
            supported_versions extension.
         */
        if (strlen($body) < $off + 32) {
            $this->fail("ClientHello truncated at random");
            return false;
        }
        $this->client_random = substr($body, $off, 32);
        $off += 32;
        list($session_id, $off) = $this->readVec8($body, $off);
        if ($session_id === false) {
            $this->fail("bad legacy_session_id");
            return false;
        }
        $this->client_session_id = $session_id;
        list($cipher_bytes, $off) = $this->readVec16($body,
            $off);
        if ($cipher_bytes === false) {
            $this->fail("bad cipher_suites vector");
            return false;
        }
        if (strlen($cipher_bytes) % 2 !== 0) {
            $this->fail("cipher_suites length not even");
            return false;
        }
        list($comp, $off) = $this->readVec8($body, $off);
        if ($comp === false) {
            $this->fail("bad compression_methods vector");
            return false;
        }
        list($ext_blob, $off) = $this->readVec16($body, $off);
        if ($ext_blob === false) {
            $this->fail("bad extensions vector");
            return false;
        }
        /*
            Pick our cipher: scan the client's offered list
            in their priority order and take the first one
            we support. Both supported suites use SHA-256, so
            $this->hash_len stays at 32.
         */
        $this->cipher = 0;
        for ($i = 0; $i < strlen($cipher_bytes); $i += 2) {
            $code = (ord($cipher_bytes[$i]) << 8) |
                ord($cipher_bytes[$i + 1]);
            if ($code === self::CIPHER_AES_128_GCM_SHA256 ||
                $code ===
                self::CIPHER_CHACHA20_POLY1305_SHA256) {
                $this->cipher = $code;
                break;
            }
        }
        if ($this->cipher === 0) {
            $this->fail("no shared cipher suite");
            return false;
        }
        if (!$this->parseClientHelloExtensions($ext_blob)) {
            return false;
        }
        /*
            Pick the named group for ECDHE. We prefer X25519
            when both shares are offered (smaller wire bytes
            and faster), but accept P-256 when X25519 isn't
            on the table -- BoringSSL/quictls clients sometimes
            offer only secp256r1 by default.
         */
        if ($this->client_x25519_public !== '') {
            $this->selected_group = self::GROUP_X25519;
        } else if ($this->client_p256_public !== '') {
            $this->selected_group = self::GROUP_SECP256R1;
        } else {
            $this->fail("client did not offer X25519 or "
                . "P-256 key share");
            return false;
        }
        return true;
    }
    /**
     * Walks the extension list. Each extension is a uint16
     * type, uint16-prefixed payload. Captures the ones we
     * care about; ignores the rest.
     * @param mixed $blob blob parameter
     * @return array parsed extensions map (extension type => extension data)
     */
    protected function parseClientHelloExtensions($blob)
    {
        $off = 0;
        $saw_supported_versions = false;
        $sig_algs = [];
        while ($off < strlen($blob)) {
            list($etype, $off) = $this->readU16($blob, $off);
            if ($etype === false) {
                $this->fail("extension type truncated");
                return false;
            }
            list($payload, $off) = $this->readVec16($blob,
                $off);
            if ($payload === false) {
                $this->fail("extension payload truncated");
                return false;
            }
            switch ($etype) {
                case self::EXT_SUPPORTED_VERSIONS:
                    $saw_supported_versions = true;
                    if (!$this->checkClientSupportsTls13(
                        $payload)) {
                        $this->fail(
                            "client did not offer TLS 1.3");
                        return false;
                    }
                    break;
                case self::EXT_KEY_SHARE:
                    if (!$this->parseClientKeyShare(
                        $payload)) {
                        return false;
                    }
                    break;
                case self::EXT_SIGNATURE_ALGORITHMS:
                    $sig_algs = $this->parseSigAlgs(
                        $payload);
                    break;
                case self::EXT_ALPN:
                    $this->parseClientAlpn($payload);
                    break;
                case self::EXT_QUIC_TRANSPORT_PARAMETERS:
                    $this->client_quic_tp = $payload;
                    break;
                default:
                    /* ignore unknown / uninteresting */
                    break;
            }
        }
        if (!$saw_supported_versions) {
            $this->fail(
                "client did not send supported_versions");
            return false;
        }
        /*
            Verify our sig scheme is in the client's offer.
            If we are an ECDSA server, we need
            ecdsa_secp256r1_sha256; if RSA, we need
            rsa_pss_rsae_sha256.
         */
        if (!in_array($this->sig_scheme, $sig_algs, true)) {
            $this->fail("client does not offer our signature "
                . "scheme " . sprintf("0x%04x",
                $this->sig_scheme));
            return false;
        }
        return true;
    }
    /**
     * Checks whether the client's supported_versions list
     * includes TLS 1.3 (0x0304).
     * @param string $payload payload bytes
     * @return bool true if the ClientHello indicates TLS 1.3 support
     */
    protected function checkClientSupportsTls13($payload)
    {
        list($vec, $off) = $this->readVec8($payload, 0);
        if ($vec === false) {
            return false;
        }
        for ($i = 0; $i < strlen($vec); $i += 2) {
            $v = (ord($vec[$i]) << 8) | ord($vec[$i + 1]);
            if ($v === self::TLS_VERSION_1_3) {
                return true;
            }
        }
        return false;
    }
    /**
     * Parses signature_algorithms extension into a flat
     * list of uint16 scheme codes.
     * @param string $payload payload bytes
     * @return array list of TLS signature scheme identifiers offered by the peer
     */
    protected function parseSigAlgs($payload)
    {
        list($vec, ) = $this->readVec16($payload, 0);
        if ($vec === false) {
            return [];
        }
        $out = [];
        for ($i = 0; $i + 1 < strlen($vec); $i += 2) {
            $out[] = (ord($vec[$i]) << 8) |
                ord($vec[$i + 1]);
        }
        return $out;
    }
    /**
     * Parses the client's key_share extension. Walks the
     * list of (group, key_exchange) pairs and captures the
     * X25519 public if present, P-256 public if present.
     * Other groups are ignored. The selection between the
     * two happens later (we prefer X25519 when both are
     * offered).
     * @param string $payload payload bytes
     * @return array parsed key-share record (group => raw public key)
     */
    protected function parseClientKeyShare($payload)
    {
        list($vec, ) = $this->readVec16($payload, 0);
        if ($vec === false) {
            $this->fail("bad key_share vector");
            return false;
        }
        $off = 0;
        while ($off < strlen($vec)) {
            list($group, $off) = $this->readU16($vec, $off);
            if ($group === false) {
                $this->fail("key_share group truncated");
                return false;
            }
            list($pub, $off) = $this->readVec16($vec, $off);
            if ($pub === false) {
                $this->fail("key_share key truncated");
                return false;
            }
            if ($group === self::GROUP_X25519 &&
                strlen($pub) === 32) {
                $this->client_x25519_public = $pub;
            } else if ($group === self::GROUP_SECP256R1 &&
                strlen($pub) === 65 &&
                $pub[0] === "\x04") {
                /*
                    P-256 wire form: 0x04 || X(32) || Y(32),
                    65 bytes total. Compressed forms are
                    legal (RFC 8446 sec 4.2.8.2) but every
                    common TLS stack sends uncompressed; we
                    don't bother handling 0x02/0x03 here.
                 */
                $this->client_p256_public = $pub;
            }
        }
        return true;
    }
    /**
     * Walks the ALPN list, picks the first protocol the
     * client offers that also appears in our offer.
     * @param string $payload payload bytes
     */
    protected function parseClientAlpn($payload)
    {
        list($vec, ) = $this->readVec16($payload, 0);
        if ($vec === false) {
            return;
        }
        $off = 0;
        while ($off < strlen($vec)) {
            list($name, $off) = $this->readVec8($vec, $off);
            if ($name === false) {
                return;
            }
            if (in_array($name, $this->alpn_offer, true)) {
                $this->alpn_selected = $name;
                return;
            }
        }
    }
    /*
        HKDF and the TLS 1.3 key schedule.

        TLS 1.3 derives every secret it needs from a chain of
        HKDF-Extract and HKDF-Expand-Label operations, all of
        which use the negotiated hash (SHA-256 for both cipher
        suites we support). The chain is:

            early_secret = HKDF-Extract(0, PSK || zeros)
            ...derived_secret_1 = HKDF-Expand-Label(early_secret,
                "derived", "")
            handshake_secret = HKDF-Extract(derived_secret_1,
                ECDHE_shared)
            c_hs = HKDF-Expand-Label(handshake_secret,
                "c hs traffic", transcript_hash)
            s_hs = HKDF-Expand-Label(handshake_secret,
                "s hs traffic", transcript_hash)
            ...derived_secret_2 = HKDF-Expand-Label(
                handshake_secret, "derived", "")
            master_secret = HKDF-Extract(derived_secret_2,
                zeros)
            c_ap = HKDF-Expand-Label(master_secret,
                "c ap traffic", transcript_hash_at_finished)
            s_ap = HKDF-Expand-Label(master_secret,
                "s ap traffic", transcript_hash_at_finished)

        The "transcript_hash" inputs are taken at specific
        moments: c_hs/s_hs after ServerHello, c_ap/s_ap after
        the server's Finished. We compute these on demand from
        $transcript_buf rather than keeping a streaming hash.
        That's a minor perf hit but the code stays much easier
        to follow.
     */
    /**
     * RFC 5869 HKDF-Extract. Returns 32 bytes (SHA-256
     * output length) regardless of input length.
     * @param string $salt HKDF salt
     * @param string $ikm HKDF input keying material
     * @return string HKDF-Extract output (PRK)
     */
    protected function hkdfExtract($salt, $ikm)
    {
        if ($salt === '') {
            $salt = str_repeat("\x00", $this->hash_len);
        }
        return hash_hmac('sha256', $ikm, $salt, true);
    }
    /**
     * HKDF-Expand-Label per RFC 8446 sec 7.1. The "TLS 1.3"
     * label prefix and length encoding are fixed.
     * @param string $secret TLS 1.3 traffic secret
     * @param string $label HKDF-Expand-Label label
     * @param array $context per-listener stream context overrides
     * @param int $length byte length
     * @return string HKDF-Expand-Label output of the requested length
     */
    protected function hkdfExpandLabel($secret, $label,
        $context, $length)
    {
        $full_label = "tls13 " . $label;
        $info = $this->packU16($length) .
            $this->packVec8($full_label) .
            $this->packVec8($context);
        return $this->hkdfExpand($secret, $info, $length);
    }
    /**
     * RFC 5869 HKDF-Expand. We never need more than 32 bytes
     * of output here (one hash block) so the loop is trivial.
     * @param mixed $prk prk parameter
     * @param string $info HKDF Info parameter (label + context)
     * @param int $length byte length
     * @return string HKDF-Expand output of the requested length
     */
    protected function hkdfExpand($prk, $info, $length)
    {
        $out = '';
        $t = '';
        $ctr = 1;
        while (strlen($out) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($ctr),
                $prk, true);
            $out .= $t;
            $ctr++;
        }
        return substr($out, 0, $length);
    }
    /**
     * Convenience wrapper used by the HKDF chain when the
     * "Derive-Secret" step calls for an empty messages
     * field (the hash of an empty input).
     * @param string $secret TLS 1.3 traffic secret
     * @param string $label HKDF-Expand-Label label
     * @param mixed $messages messages parameter
     * @return string derived TLS 1.3 secret for the given label and transcript
     */
    protected function deriveSecret($secret, $label,
        $messages)
    {
        return $this->hkdfExpandLabel($secret, $label,
            hash('sha256', $messages, true),
            $this->hash_len);
    }
    /**
     * Returns the SHA-256 of the running transcript buffer,
     * which by spec is the concatenation of all handshake
     * messages exchanged so far (each as
     * type || uint24-length || body).
     * @return string current handshake transcript hash digest
     */
    protected function transcriptHash()
    {
        return hash('sha256', $this->transcript_buf, true);
    }
    /**
     * Runs the TLS 1.3 key schedule up through the handshake
     * traffic secrets and stashes the four final outputs into
     * $this->secrets after master_secret derivation. Called
     * from buildServerFlight() once the client's key share
     * is known.
     * @return string derived secret bytes
     */
    protected function deriveHandshakeSecrets()
    {
        $shared = $this->computeEcdheShared();
        if ($shared === false) {
            return;
        }
        $zeros = str_repeat("\x00", $this->hash_len);
        $early_secret = $this->hkdfExtract('', $zeros);
        $derived_1 = $this->deriveSecret($early_secret,
            'derived', '');
        $this->handshake_secret = $this->hkdfExtract(
            $derived_1, $shared);
        /*
            Wipe the ephemeral private material as soon as we
            have the shared secret. RFC 8446 sec 4.2.8.1
            doesn't mandate this but it bounds the window for
            forward-secrecy compromise if the process is
            dumped.
         */
        if ($this->x25519_secret !== '') {
            $this->x25519_secret = str_repeat("\x00", 32);
        }
        $this->p256_keypair = null;
        $th = $this->transcriptHash();
        $this->secrets['c_hs'] = $this->hkdfExpandLabel(
            $this->handshake_secret, 'c hs traffic', $th,
            $this->hash_len);
        $this->secrets['s_hs'] = $this->hkdfExpandLabel(
            $this->handshake_secret, 's hs traffic', $th,
            $this->hash_len);
    }
    /**
     * Computes the ECDHE shared secret for the negotiated
     * named group. Returns the 32-byte secret on success
     * or false (with $this->fail invoked) on error.
     * @return string shared ECDHE secret with $peer_pub
     */
    protected function computeEcdheShared()
    {
        if ($this->selected_group === self::GROUP_X25519) {
            if (strlen($this->client_x25519_public) !== 32
                || strlen($this->x25519_secret) !== 32) {
                $this->fail("X25519 key share missing or "
                    . "wrong length (peer public="
                    . strlen($this->client_x25519_public)
                    . "B, local secret="
                    . strlen($this->x25519_secret) . "B)");
                return false;
            }
            return sodium_crypto_scalarmult(
                $this->x25519_secret,
                $this->client_x25519_public);
        }
        if ($this->selected_group ===
                self::GROUP_SECP256R1) {
            if (strlen($this->client_p256_public) !== 65
                || $this->p256_keypair === null) {
                $this->fail("P-256 key share missing or "
                    . "wrong length (peer public="
                    . strlen($this->client_p256_public)
                    . "B, local kp="
                    . ($this->p256_keypair === null
                        ? 'null' : 'set') . ")");
                return false;
            }
            $peer_pem = self::p256RawPointToPubPem(
                $this->client_p256_public);
            $peer_key = openssl_pkey_get_public($peer_pem);
            if ($peer_key === false) {
                $this->fail("openssl rejected peer P-256 "
                    . "public");
                return false;
            }
            $shared = openssl_pkey_derive($peer_key,
                $this->p256_keypair, 32);
            if ($shared === false || strlen($shared) !== 32) {
                $this->fail("P-256 ECDH derive failed");
                return false;
            }
            return $shared;
        }
        $this->fail("no ECDHE group selected");
        return false;
    }
    /**
     * Wraps a raw uncompressed P-256 point (65 bytes:
     * 0x04 || X || Y) in a SubjectPublicKeyInfo PEM so
     * openssl_pkey_get_public can parse it. The DER
     * structure is fixed: the inner AlgorithmIdentifier
     * for P-256 is the same constant 21-byte sequence
     * for any P-256 key (id-ecPublicKey + prime256v1
     * named curve), so we can prepend it verbatim.
     * @param mixed $point65 point65 parameter
     * @return string PEM-encoded public key for the raw P-256 point
     */
    protected static function p256RawPointToPubPem($point65)
    {
        /*
            ASN.1 SubjectPublicKeyInfo:
              SEQUENCE {
                SEQUENCE {
                  OID id-ecPublicKey 1.2.840.10045.2.1,
                  OID prime256v1     1.2.840.10045.3.1.7
                }
                BIT STRING (point bytes, prepended 0x00
                            for "no unused bits")
              }
            Total: 0x30 LEN 0x30 0x13 ... 0x03 0x42 0x00 ||
            point.
         */
        $algo_seq = hex2bin("301306072a8648ce3d020106082a"
            . "8648ce3d030107");
        $bit_string = "\x00" . $point65;
        $bit_string_wrapped = "\x03"
            . chr(strlen($bit_string)) . $bit_string;
        $inner = $algo_seq . $bit_string_wrapped;
        $der = "\x30" . chr(strlen($inner)) . $inner;
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }
    /**
     * Derives master_secret and the application traffic
     * secrets c_ap / s_ap. Called after the server's
     * Finished message has been added to the transcript.
     * @return string derived secret bytes
     */
    protected function deriveApplicationSecrets()
    {
        $zeros = str_repeat("\x00", $this->hash_len);
        $derived_2 = $this->deriveSecret(
            $this->handshake_secret, 'derived', '');
        $this->master_secret = $this->hkdfExtract(
            $derived_2, $zeros);
        $th = $this->transcriptHash();
        $this->secrets['c_ap'] = $this->hkdfExpandLabel(
            $this->master_secret, 'c ap traffic', $th,
            $this->hash_len);
        $this->secrets['s_ap'] = $this->hkdfExpandLabel(
            $this->master_secret, 's ap traffic', $th,
            $this->hash_len);
    }
    /**
     * Derives the AEAD record-protection key + IV from a
     * traffic secret. RFC 8446 sec 7.3 specifies the
     * "key" and "iv" labels and the lengths (16 + 12 for
     * AES-128-GCM, 32 + 12 for ChaCha20-Poly1305).
     *
     * Returns ['key' => string, 'iv' => string].
     * @param string $secret TLS 1.3 traffic secret
     * @return array derived [aead_key, iv, hp_key] for the traffic secret
     */
    protected function deriveRecordKeys($secret)
    {
        $key_len = ($this->cipher ===
            self::CIPHER_AES_128_GCM_SHA256) ? 16 : 32;
        return [
            'key' => $this->hkdfExpandLabel($secret, 'key',
                '', $key_len),
            'iv' => $this->hkdfExpandLabel($secret, 'iv',
                '', 12),
        ];
    }
    /*
        AEAD helpers.

        The TLS 1.3 record layer protects each handshake message
        sent after ServerHello with the appropriate handshake
        traffic secret's AEAD. For testing in isolation against
        openssl s_client we need both the encrypt and decrypt
        sides; for QUIC we only need the AEAD primitive itself
        (QUIC has its own packet protection layer that wraps
        these same keys differently). Keeping both keeps the
        engine usable for both purposes.

        Nonce construction per RFC 8446 sec 5.3: pad the
        record sequence number to the IV length, then XOR.
     */
    /**
     * AEAD encrypt. Cipher dispatch on $this->cipher.
     * @param string $key key
     * @param string $iv initialization vector
     * @param mixed $seq seq parameter
     * @param string $aad additional authenticated data (AAD) for AEAD
     * @param string $plaintext plaintext bytes
     * @return string ciphertext including the AEAD authentication tag
     */
    protected function aeadSeal($key, $iv, $seq, $aad,
        $plaintext)
    {
        $nonce = $this->aeadNonce($iv, $seq);
        if ($this->cipher === self::CIPHER_AES_128_GCM_SHA256) {
            $tag = '';
            $ct = openssl_encrypt($plaintext, 'aes-128-gcm',
                $key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce, $tag, $aad);
            return $ct . $tag;
        }
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext, $aad, $nonce, $key);
    }
    /**
     * AEAD decrypt. Returns plaintext on success, false on
     * authentication failure.
     * @param string $key key
     * @param string $iv initialization vector
     * @param mixed $seq seq parameter
     * @param string $aad additional authenticated data (AAD) for AEAD
     * @param string $ciphertext ciphertext bytes including AEAD tag
     * @return string|false plaintext on successful decryption, false if the AEAD tag does not verify
     */
    protected function aeadOpen($key, $iv, $seq, $aad,
        $ciphertext)
    {
        $nonce = $this->aeadNonce($iv, $seq);
        if ($this->cipher === self::CIPHER_AES_128_GCM_SHA256) {
            if (strlen($ciphertext) < 16) {
                return false;
            }
            $ct = substr($ciphertext, 0, -16);
            $tag = substr($ciphertext, -16);
            return openssl_decrypt($ct, 'aes-128-gcm', $key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce, $tag, $aad);
        }
        return @sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext, $aad, $nonce, $key);
    }
    /**
     * Builds the AEAD nonce by left-padding the 64-bit
     * record-sequence-number to 12 bytes and XORing with
     * the IV.
     * @param string $iv initialization vector
     * @param mixed $seq seq parameter
     * @return string AEAD nonce for the given packet number (IV XOR packet-number padded)
     */
    protected function aeadNonce($iv, $seq)
    {
        $padded = str_repeat("\x00", 4) .
            pack('J', (int) $seq);
        $out = '';
        for ($i = 0; $i < 12; $i++) {
            $out .= chr(ord($iv[$i]) ^ ord($padded[$i]));
        }
        return $out;
    }
    /*
        Server flight builder.

        After feedClientHello succeeds, the caller invokes
        buildServerFlight() to get the bytes to transmit. The
        flight consists of:

            ServerHello                           (cleartext)
            ChangeCipherSpec                      (cleartext, dummy)
            EncryptedExtensions                   (encrypted)
            Certificate                           (encrypted)
            CertificateVerify                     (encrypted)
            Finished                              (encrypted)

        The handshake messages after ServerHello are protected
        with the s_hs traffic key. We assemble them into one
        TLS application_data record (as is standard for the
        server's second flight) for ease of testing against
        openssl s_client; the QUIC layer in Phase 4 will not
        use this record framing -- it'll grab the inner
        handshake messages directly and stuff them into CRYPTO
        frames.

        The flight returned therefore has two flavors depending
        on the caller's needs. mode='tls' wraps everything in
        TLS records (used by the standalone test rig); mode
        ='quic' returns just the four handshake messages
        concatenated, with the AEAD applied at the TLS 1.3 level
        skipped (QUIC re-encrypts at its own layer).
     */
    /**
     * Builds and returns the bytes the server transmits.
     * $mode is either 'tls' (record-framed; includes the
     * legacy ChangeCipherSpec for middlebox compat) or
     * 'quic' (raw handshake messages, no record framing,
     * no encryption -- the QUIC packet protection
     * replaces it).
     * @param mixed $mode mode parameter
     * @return array list of handshake messages composing the server first flight
     */
    public function buildServerFlight($mode = 'tls')
    {
        if ($this->state === self::ST_FAILED) {
            return false;
        }
        if ($this->state !== self::ST_GOT_CLIENT_HELLO) {
            /*
                Legal entry state was originally ST_AWAIT_-
                CLIENT_HELLO, but that was wrong: it allowed
                buildServerFlight to fire before any CH had
                actually been parsed (which is what curl-with-
                quictls hits, since its ClientHello straddles
                two QUIC Initial packets). Now we require
                feedClientHello to have completed first.
             */
            $this->fail("buildServerFlight in state "
                . $this->state);
            return false;
        }
        /*
            Generate our ECDHE keypair for whichever group we
            picked during ClientHello validation. X25519 uses
            sodium_crypto_kx (libsodium-backed Curve25519);
            P-256 uses openssl_pkey_new with prime256v1. Both
            yield a 32-byte shared secret on the other side.
         */
        if ($this->selected_group === self::GROUP_X25519) {
            if ($this->x25519_secret === '') {
                $kp = sodium_crypto_kx_keypair();
                $this->x25519_secret =
                    sodium_crypto_kx_secretkey($kp);
                $this->x25519_public =
                    sodium_crypto_kx_publickey($kp);
            }
        } else if ($this->selected_group ===
                self::GROUP_SECP256R1) {
            if ($this->p256_keypair === null) {
                $this->p256_keypair = openssl_pkey_new([
                    'curve_name' => 'prime256v1',
                    'private_key_type' => OPENSSL_KEYTYPE_EC,
                ]);
                if ($this->p256_keypair === false) {
                    $this->p256_keypair = null;
                    $this->fail("openssl P-256 keypair "
                        . "generation failed");
                    return false;
                }
                $details = openssl_pkey_get_details(
                    $this->p256_keypair);
                /*
                    TLS 1.3 wire form for P-256: 0x04 (uncomp)
                    || X (32) || Y (32). RFC 8446 sec 4.2.8.2
                    citing SEC 1.
                 */
                $this->p256_public_wire = "\x04"
                    . $details['ec']['x']
                    . $details['ec']['y'];
            }
        } else {
            $this->fail("no usable named group selected");
            return false;
        }
        $this->server_random = random_bytes(32);
        /*
            Step 1: ServerHello. Builds the message and adds
            it to the transcript. We hand-roll it via
            packHandshake which appends to $transcript_buf.
         */
        $sh_body = $this->buildServerHelloBody();
        $sh = $this->packHandshake(self::HS_SERVER_HELLO,
            $sh_body);
        /*
            Step 2: derive handshake secrets now that the
            transcript through ServerHello is fixed.
         */
        $this->deriveHandshakeSecrets();
        if ($this->state === self::ST_FAILED) {
            return false;
        }
        /*
            Step 3: build the inner messages -- everything
            after ServerHello goes into the encrypted
            half.
         */
        $ee = $this->packHandshake(
            self::HS_ENCRYPTED_EXTENSIONS,
            $this->buildEncryptedExtensionsBody());
        $cert = $this->packHandshake(self::HS_CERTIFICATE,
            $this->buildCertificateBody());
        $cv = $this->packHandshake(self::HS_CERTIFICATE_VERIFY,
            $this->buildCertificateVerifyBody());
        if ($cv === false) {
            return false;
        }
        $fin = $this->packHandshake(self::HS_FINISHED,
            $this->buildFinishedBody($this->secrets['s_hs']));
        $this->deriveApplicationSecrets();
        $inner = $ee . $cert . $cv . $fin;
        $this->state = self::ST_AWAIT_CLIENT_FINISHED;
        if ($mode === 'quic') {
            $this->server_flight = $sh . $inner;
            return $this->server_flight;
        }
        /*
            TLS record framing. Three records:
              1. ServerHello in a handshake (22) cleartext
                 record.
              2. ChangeCipherSpec (20) cleartext record;
                 single 0x01 byte. Optional per RFC 8446
                 but openssl s_client and most middleboxes
                 still expect one for compat.
              3. application_data (23) record carrying the
                 AEAD-encrypted inner messages, with the
                 final inner-content-type byte = 22
                 (handshake) per TLS 1.3 sec 5.2.
         */
        $rec1 = chr(self::TLS_RECORD_HANDSHAKE) .
            $this->packU16(self::TLS_VERSION_LEGACY) .
            $this->packU16(strlen($sh)) . $sh;
        $rec2 = chr(self::TLS_RECORD_CCS) .
            $this->packU16(self::TLS_VERSION_LEGACY) .
            $this->packU16(1) . "\x01";
        $rec3 = $this->wrapRecord($inner . chr(
            self::TLS_RECORD_HANDSHAKE), $this->secrets['s_hs'],
            0);
        $this->server_flight = $rec1 . $rec2 . $rec3;
        return $this->server_flight;
    }
    /**
     * Encodes the ServerHello message body. ServerHello
     * encodes the chosen cipher suite, the chosen key
     * share (our X25519 public), and a supported_versions
     * extension committing us to TLS 1.3.
     * @return string serialized ServerHello handshake message body
     */
    protected function buildServerHelloBody()
    {
        /*
            Extensions: supported_versions (says 0x0304) and
            key_share (our X25519 public). No others -- TLS 1.3
            puts everything else in EncryptedExtensions.
         */
        $sv = $this->packU16(
            self::EXT_SUPPORTED_VERSIONS) .
            $this->packVec16(
            $this->packU16(self::TLS_VERSION_1_3));
        if ($this->selected_group === self::GROUP_X25519) {
            $ks_pub = $this->x25519_public;
        } else {
            $ks_pub = $this->p256_public_wire;
        }
        $ks_payload = $this->packU16($this->selected_group)
            . $this->packVec16($ks_pub);
        $ks = $this->packU16(self::EXT_KEY_SHARE) .
            $this->packVec16($ks_payload);
        $extensions = $this->packVec16($sv . $ks);
        return $this->packU16(self::TLS_VERSION_LEGACY) .
            $this->server_random .
            $this->packVec8($this->client_session_id) .
            $this->packU16($this->cipher) .
            chr(0) /* legacy_compression_method = null */
            . $extensions;
    }
    /**
     * EncryptedExtensions body: ALPN (if selected),
     * quic_transport_parameters (echo our QUIC layer's
     * blob if the caller passed one in, regardless of
     * whether the client sent one).
     * @return string serialized EncryptedExtensions handshake message body
     */
    protected function buildEncryptedExtensionsBody()
    {
        $exts = '';
        if ($this->alpn_selected !== '') {
            $alpn_payload = $this->packVec16(
                $this->packVec8($this->alpn_selected));
            $exts .= $this->packU16(self::EXT_ALPN) .
                $this->packVec16($alpn_payload);
        }
        if ($this->server_quic_tp !== '') {
            $exts .= $this->packU16(
                self::EXT_QUIC_TRANSPORT_PARAMETERS) .
                $this->packVec16($this->server_quic_tp);
        }
        return $this->packVec16($exts);
    }
    /**
     * Certificate message body. RFC 8446 sec 4.4.2:
     *
     *   certificate_request_context (vec8) -- empty for
     *       server cert
     *   certificate_list (vec24) of CertificateEntry:
     *       cert_data (vec24) -- DER bytes of one cert
     *       extensions (vec16) -- empty for us
     *
     * We split $this->cert_pem on the BEGIN/END markers and
     * decode each block to DER; the leaf is first, any
     * intermediates follow.
     * @return string serialized Certificate handshake message body
     */
    protected function buildCertificateBody()
    {
        $entries = '';
        $blocks = $this->splitPemCerts($this->cert_pem);
        foreach ($blocks as $der) {
            $entries .= $this->packVec24($der) .
                $this->packU16(0); /* no extensions */
        }
        return $this->packVec8('') .
            $this->packVec24($entries);
    }
    /**
     * Walks the certificate PEM blob and returns a list of
     * DER byte-strings, one per certificate. Tolerates
     * leading whitespace, comments, and CRLF line endings.
     * @param mixed $pem pem parameter
     * @return array list of PEM-formatted certificate strings split from a chain
     */
    protected function splitPemCerts($pem)
    {
        $out = [];
        $re = '/-----BEGIN CERTIFICATE-----' .
            '(.+?)-----END CERTIFICATE-----/s';
        if (preg_match_all($re, $pem, $m)) {
            foreach ($m[1] as $b64) {
                $der = base64_decode(preg_replace('/\s+/',
                    '', $b64));
                if ($der !== false && $der !== '') {
                    $out[] = $der;
                }
            }
        }
        return $out;
    }
    /**
     * CertificateVerify body. Per RFC 8446 sec 4.4.3 the
     * signature input is:
     *
     *   64 bytes of 0x20 || "TLS 1.3, server CertificateVerify"
     *     || 0x00 || transcript_hash_through_certificate
     *
     * The signature scheme code precedes the (vec16) sig
     * bytes in the message.
     *
     * Returns false (and calls fail) on signing error.
     * @return string serialized CertificateVerify handshake message body
     */
    protected function buildCertificateVerifyBody()
    {
        $signed_input = str_repeat("\x20", 64) .
            "TLS 1.3, server CertificateVerify" .
            "\x00" . $this->transcriptHash();
        if ($this->sig_path === 'ecdsa') {
            $sig = '';
            $ok = @openssl_sign($signed_input, $sig,
                $this->pkey, OPENSSL_ALGO_SHA256);
            if (!$ok) {
                $this->fail("ECDSA sign failed: " .
                    openssl_error_string());
                return false;
            }
            /* openssl_sign already returns DER (r,s) for ECDSA */
        } else {
            $sig = $this->rsaPssSign($signed_input);
            if ($sig === false) {
                return false;
            }
        }
        return $this->packU16($this->sig_scheme) .
            $this->packVec16($sig);
    }
    /**
     * RSA-PSS-RSAE-SHA256 signing using gmp for the modular
     * exponentiation. EMSA-PSS encoding per RFC 8017 sec
     * 9.1.1, with hash = mgf-hash = SHA-256 and salt length =
     * hash length (32). The mask-generation function is
     * MGF1-SHA-256.
     * @param string $message message bytes
     * @return string RSA-PSS signature bytes over $message using the supplied private key
     */
    protected function rsaPssSign($message)
    {
        $details = openssl_pkey_get_details($this->pkey);
        if (!isset($details['rsa']['n']) ||
            !isset($details['rsa']['d'])) {
            $this->fail("RSA key details missing n / d");
            return false;
        }
        $n = gmp_import($details['rsa']['n']);
        $d = gmp_import($details['rsa']['d']);
        $k = strlen(gmp_export($n));
        /*
            Compute mod_bits exactly: number of bits in n.
            For a 2048-bit key, mod_bits = 2048 and em_bits =
            2047, em_len = ceil(2047/8) = 256. The k = 256
            byte signature is then EM left-padded with zeros
            if necessary; here em_len = k since the modulus
            uses all 8 bits of its top byte.
         */
        $top_byte = ord(substr(gmp_export($n), 0, 1));
        $top_bits = 0;
        for ($b = 7; $b >= 0; $b--) {
            if ($top_byte & (1 << $b)) {
                $top_bits = $b + 1;
                break;
            }
        }
        $mod_bits = ($k - 1) * 8 + $top_bits;
        $em_bits = $mod_bits - 1;
        $em_len = (int) (($em_bits + 7) >> 3);
        $h_len = 32;
        $s_len = 32;
        if ($em_len < $h_len + $s_len + 2) {
            $this->fail("RSA modulus too small for PSS");
            return false;
        }
        $m_hash = hash('sha256', $message, true);
        $salt = random_bytes($s_len);
        $m_prime = str_repeat("\x00", 8) . $m_hash . $salt;
        $h = hash('sha256', $m_prime, true);
        $ps_len = $em_len - $s_len - $h_len - 2;
        $db = str_repeat("\x00", $ps_len) . "\x01" . $salt;
        $db_mask = $this->mgf1($h, $em_len - $h_len - 1);
        $masked_db = '';
        for ($i = 0; $i < strlen($db); $i++) {
            $masked_db .= chr(ord($db[$i]) ^
                ord($db_mask[$i]));
        }
        /*
            Clear the leftmost (8*em_len - em_bits) bits of
            maskedDB. Required by EMSA-PSS to ensure the
            integer representation of EM is < n.
         */
        $clear_bits = 8 * $em_len - $em_bits;
        if ($clear_bits > 0) {
            $mask = 0xFF >> $clear_bits;
            $first = ord($masked_db[0]) & $mask;
            $masked_db = chr($first) . substr($masked_db, 1);
        }
        $em = $masked_db . $h . "\xBC";
        /*
            RSA primitive: signature = m^d mod n.
         */
        $m_int = gmp_import($em);
        $sig_int = gmp_powm($m_int, $d, $n);
        $sig = gmp_export($sig_int);
        /* Pad to k bytes if leading zeros got stripped. */
        if (strlen($sig) < $k) {
            $sig = str_repeat("\x00", $k - strlen($sig)) .
                $sig;
        }
        return $sig;
    }
    /**
     * MGF1 mask generation function with SHA-256.
     * @param mixed $seed seed parameter
     * @param int $length byte length
     * @return string MGF1-SHA256 expansion of $seed to the requested length
     */
    protected function mgf1($seed, $length)
    {
        $out = '';
        $ctr = 0;
        while (strlen($out) < $length) {
            $out .= hash('sha256',
                $seed . pack('N', $ctr), true);
            $ctr++;
        }
        return substr($out, 0, $length);
    }
    /**
     * Finished message body: HMAC-SHA-256(finished_key,
     * transcript_hash) where finished_key =
     * HKDF-Expand-Label(traffic_secret, "finished", "", 32).
     * @param mixed $traffic_secret traffic_secret parameter
     * @return string serialized Finished handshake message body
     */
    protected function buildFinishedBody($traffic_secret)
    {
        $finished_key = $this->hkdfExpandLabel(
            $traffic_secret, 'finished', '',
            $this->hash_len);
        return hash_hmac('sha256', $this->transcriptHash(),
            $finished_key, true);
    }
    /*
        Record layer (TLS-mode only).

        wrapRecord builds one application_data TLS 1.3 record
        protected with the given traffic secret. The TLS-mode
        path only needs encrypt; QUIC mode bypasses this layer
        entirely. unwrapRecord is the inverse, used by
        feedClientFinished's TLS-mode path to decrypt the
        client's encrypted handshake records.
     */
    /**
     * Wraps $inner_plaintext (which must already include the
     * inner-content-type byte at the end -- see RFC 8446 sec
     * 5.2) in an application_data record protected by the
     * AEAD derived from $secret with sequence number $seq.
     * @param mixed $inner_plaintext inner_plaintext parameter
     * @param string $secret TLS 1.3 traffic secret
     * @param mixed $seq seq parameter
     * @return string TLS record framing applied around $plaintext
     */
    protected function wrapRecord($inner_plaintext, $secret,
        $seq)
    {
        $keys = $this->deriveRecordKeys($secret);
        $rec_len = strlen($inner_plaintext) + 16; /* + tag */
        $aad = chr(self::TLS_RECORD_APPLICATION_DATA) .
            $this->packU16(self::TLS_VERSION_LEGACY) .
            $this->packU16($rec_len);
        $sealed = $this->aeadSeal($keys['key'], $keys['iv'],
            $seq, $aad, $inner_plaintext);
        return $aad . $sealed;
    }
    /**
     * Inverse of wrapRecord. Returns the inner plaintext
     * (with trailing content-type byte) on success, false
     * on AEAD failure.
     * @param mixed $record_bytes record_bytes parameter
     * @param string $secret TLS 1.3 traffic secret
     * @param mixed $seq seq parameter
     * @return string plaintext after the TLS record layer has been stripped
     */
    protected function unwrapRecord($record_bytes, $secret,
        $seq)
    {
        if (strlen($record_bytes) < 5) {
            return false;
        }
        $type = ord($record_bytes[0]);
        if ($type !== self::TLS_RECORD_APPLICATION_DATA) {
            return false;
        }
        $aad = substr($record_bytes, 0, 5);
        $ct = substr($record_bytes, 5);
        $keys = $this->deriveRecordKeys($secret);
        return $this->aeadOpen($keys['key'], $keys['iv'],
            $seq, $aad, $ct);
    }
    /*
        Client Finished verification.
     */
    /**
     * Feeds the client's Finished message bytes (the
     * decrypted handshake message: type byte + uint24 length
     * + body). Verifies the HMAC against c_hs_traffic_secret
     * and, on success, transitions to ST_HANDSHAKE_COMPLETE.
     * @param string $bytes bytes to operate on
     * @return bool true if the Finished MAC verifies
     */
    public function feedClientFinished($bytes)
    {
        if ($this->state === self::ST_FAILED) {
            return false;
        }
        if ($this->state !== self::ST_AWAIT_CLIENT_FINISHED) {
            $this->fail("Finished in state " . $this->state);
            return false;
        }
        if (strlen($bytes) < 4) {
            $this->fail("Finished too short");
            return false;
        }
        $type = ord($bytes[0]);
        if ($type !== self::HS_FINISHED) {
            $this->fail("expected Finished, got type $type");
            return false;
        }
        list($body_len, ) = $this->readU24($bytes, 1);
        if ($body_len === false ||
            strlen($bytes) < 4 + $body_len) {
            $this->fail("Finished length mismatch");
            return false;
        }
        $body = substr($bytes, 4, $body_len);
        /*
            Compute the expected HMAC against the transcript
            BEFORE adding this Finished message to it.
         */
        $finished_key = $this->hkdfExpandLabel(
            $this->secrets['c_hs'], 'finished', '',
            $this->hash_len);
        $expected = hash_hmac('sha256', $this->transcriptHash(),
            $finished_key, true);
        if (!hash_equals($expected, $body)) {
            $this->fail("Finished HMAC did not verify");
            return false;
        }
        $this->transcript_buf .= substr($bytes, 0,
            4 + $body_len);
        $this->state = self::ST_HANDSHAKE_COMPLETE;
        return true;
    }
    /*
        TLS-mode conductor (testing only).

        These two methods let the engine drive a raw TCP socket
        directly so we can validate against openssl s_client. The
        QUIC layer (Phase 4) will not go through these helpers --
        it pulls handshake messages off CRYPTO frames and feeds
        them in piecewise. Kept here so the engine remains usable
        as a stand-alone TLS 1.3 server, which is genuinely useful
        for testing and for HTTPS deployments that don't go
        through stream_socket_enable_crypto.
     */
    /**
     * Reads bytes from $sock until a complete TLS record is
     * available, parses it, and returns
     * ['type' => int, 'body' => string]. Returns null on EOF.
     * @param resource $sock open UDP socket resource
     * @return array two-element list [string $record_bytes, int $new_off]
     */
    public function readRecord($sock)
    {
        $hdr = $this->fillExact($sock, 5);
        if ($hdr === null) {
            return null;
        }
        $type = ord($hdr[0]);
        $len = (ord($hdr[3]) << 8) | ord($hdr[4]);
        $body = $this->fillExact($sock, $len);
        if ($body === null) {
            return null;
        }
        return ['type' => $type, 'body' => $body];
    }
    /**
     * Reads exactly $n bytes from $sock, blocking up to
     * 5s. Returns the bytes or null on timeout / EOF.
     * @param resource $sock open UDP socket resource
     * @param int $n count
     * @return string exactly $length bytes read from the buffer; throws if not enough are available
     */
    protected function fillExact($sock, $n)
    {
        $buf = '';
        $deadline = microtime(true) + 5;
        while (strlen($buf) < $n) {
            if (microtime(true) > $deadline) {
                return null;
            }
            $chunk = @fread($sock, $n - strlen($buf));
            if ($chunk === false || $chunk === '') {
                $info = stream_get_meta_data($sock);
                if (!empty($info['eof'])) {
                    return null;
                }
                usleep(10000);
                continue;
            }
            $buf .= $chunk;
        }
        return $buf;
    }
    /**
     * Drives a TLS handshake to completion against the given
     * TCP socket. Reads ClientHello (record type 22), runs
     * feedClientHello + buildServerFlight, writes the flight,
     * then reads the client's first encrypted record (which
     * carries Finished), decrypts it under c_hs, verifies, and
     * returns true on success.
     *
     * This is the standalone-test path. QUIC will not call it.
     * @param resource $sock open UDP socket resource
     * @return bool true on successful handshake; provided for
     *      tests that proxy QUIC over TCP
     */
    public function runHandshakeOverTcp($sock)
    {
        /* Step 1: read ClientHello record */
        $rec = $this->readRecord($sock);
        if ($rec === null) {
            $this->fail("EOF before ClientHello");
            return false;
        }
        if ($rec['type'] !== self::TLS_RECORD_HANDSHAKE) {
            $this->fail("expected handshake record, got type "
                . $rec['type']);
            return false;
        }
        if (!$this->feedClientHello($rec['body'])) {
            return false;
        }
        $flight = $this->buildServerFlight('tls');
        if ($flight === false) {
            return false;
        }
        $flight_len = strlen($flight);
        $written = 0;
        while ($written < $flight_len) {
            set_error_handler(null);
            $num_written = fwrite($sock, ($written == 0) ?
                $flight : substr($flight, $written));
            restore_error_handler();
            if ($num_written === false || $num_written === 0) {
                $this->fail(
                    "short write sending server flight");
                return false;
            }
            $written += $num_written;
        }
        /*
            Step 2: read the client's response. Modern
            clients send a (now-ignored) ChangeCipherSpec
            (record type 20), then an application_data record
            carrying the encrypted Finished. Keep reading
            records until we see application_data.
         */
        $client_seq = 0;
        for ($i = 0; $i < 5; $i++) {
            $rec = $this->readRecord($sock);
            if ($rec === null) {
                $this->fail("EOF before client Finished");
                return false;
            }
            if ($rec['type'] === self::TLS_RECORD_CCS) {
                continue;
            }
            if ($rec['type'] !==
                self::TLS_RECORD_APPLICATION_DATA) {
                $this->fail("unexpected record type " .
                    $rec['type']);
                return false;
            }
            /*
                Decrypt with c_hs traffic key. The 5-byte
                AAD is the cleartext record header we
                already consumed; reconstruct it.
             */
            $aad = chr(self::TLS_RECORD_APPLICATION_DATA) .
                $this->packU16(self::TLS_VERSION_LEGACY) .
                $this->packU16(strlen($rec['body']));
            $keys = $this->deriveRecordKeys(
                $this->secrets['c_hs']);
            $pt = $this->aeadOpen($keys['key'], $keys['iv'],
                $client_seq, $aad, $rec['body']);
            $client_seq++;
            if ($pt === false) {
                $this->fail("client record AEAD failed");
                return false;
            }
            /*
                Strip the trailing inner-content-type byte
                (and any zero padding before it). RFC 8446
                sec 5.2: the TLSInnerPlaintext.type sits
                after any zero-padding bytes.
             */
            $pt = rtrim($pt, "\x00");
            if (strlen($pt) < 1) {
                continue;
            }
            $inner_type = ord($pt[strlen($pt) - 1]);
            $pt = substr($pt, 0, -1);
            if ($inner_type !== self::TLS_RECORD_HANDSHAKE) {
                continue; /* skip non-handshake */
            }
            return $this->feedClientFinished($pt);
        }
        $this->fail("never saw client Finished record");
        return false;
    }
}
/**
 * QUIC packet keys for one encryption level (Initial,
 * Handshake, or 1-RTT). Bundles the AEAD key, AEAD IV,
 * header-protection key, and cipher suite code so callers
 * can sealPacket / openPacket without re-deriving keys per
 * packet. Two construction paths: fromInitialDcid (RFC 9001
 * sec 5.2 deterministic Initial keys from the client's DCID
 * + Initial salt) and fromTrafficSecret (RFC 9001 sec 5.1
 * Handshake / 1-RTT keys from a TLS 1.3 traffic secret plus
 * the negotiated cipher suite).
 */
class QuicPacketKeys
{
    /*
        Initial salt, RFC 9001 sec 5.2 (constant for QUIC v1).
     */
    const INITIAL_SALT_HEX =
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    /*
        RFC 8439 sec 2.3.2 self-test vector. Used by
        chachaUseOpenssl() to detect whether this PHP build's
        openssl_encrypt('chacha20', ...) handles the IV layout
        the same way RFC 8439 specifies. Some LibreSSL builds
        ship a chacha20 cipher that interprets the IV as
        nonce-only (no 4-byte counter prefix), which would
        produce wrong header-protection masks; the self-test
        catches that and forces the pure-PHP fallback. The
        plaintext is 16 NUL bytes; the key is the integers
        0..31 as a 32-byte string.
     */
    const CHACHA_TEST_IV =
        "\x01\x00\x00\x00\x00\x00\x00\x09"
        . "\x00\x00\x00\x4a\x00\x00\x00\x00";
    const CHACHA_TEST_EXPECTED =
        "\x10\xf1\xe7\xe4\xd1\x3b\x59\x15"
        . "\x50\x0f\xdd\x1f\xa3\x20\x71\xc4";
    /**
     * @var int cipher suite code, mirroring
     *      Tls13Engine::CIPHER_*. Determines AEAD/HP
     *      primitive, key/IV lengths.
     */
    public $cipher = 0;
    /**
     * @var string AEAD key. 16 bytes for AES-128-GCM
     *      (Initial always uses this), 32 bytes for
     *      ChaCha20-Poly1305.
     */
    public $key = "";
    /**
     * @var string AEAD IV. Always 12 bytes.
     */
    public $iv = "";
    /**
     * @var string Header-protection key, same length as
     *      the AEAD key.
     */
    public $hp_key = "";
    /**
     * Builds Initial keys for both client-to-server and
     * server-to-client directions from the client's
     * Destination Connection ID. Returns
     * ['client' => QuicPacketKeys, 'server' => QuicPacketKeys].
     * @param string $dcid destination Connection ID
     * @return QuicPacketKeys initial packet protection keys derived from the destination Connection ID
     */
    public static function fromInitialDcid($dcid)
    {
        $salt = hex2bin(self::INITIAL_SALT_HEX);
        $initial_secret = self::hkdfExtract($salt, $dcid);
        $client_secret = self::hkdfExpandLabel(
            $initial_secret, 'client in', '', 32);
        $server_secret = self::hkdfExpandLabel(
            $initial_secret, 'server in', '', 32);
        return [
            'client' => self::fromTrafficSecret(
                $client_secret,
                Tls13Engine::CIPHER_AES_128_GCM_SHA256),
            'server' => self::fromTrafficSecret(
                $server_secret,
                Tls13Engine::CIPHER_AES_128_GCM_SHA256),
        ];
    }
    /**
     * Builds keys for one direction from a traffic secret
     * (TLS handshake_traffic_secret_c/_s for Handshake-
     * level keys, or application_traffic_secret_c/_s for
     * 1-RTT keys). $cipher selects the primitive.
     * @param string $secret TLS 1.3 traffic secret
     * @param int $cipher TLS cipher suite identifier
     * @return QuicPacketKeys packet protection keys derived from the given traffic secret
     */
    public static function fromTrafficSecret($secret,
        $cipher)
    {
        $key_len = ($cipher ===
            Tls13Engine::CIPHER_AES_128_GCM_SHA256) ? 16 : 32;
        $self = new self();
        $self->cipher = $cipher;
        $self->key = self::hkdfExpandLabel($secret,
            'quic key', '', $key_len);
        $self->iv = self::hkdfExpandLabel($secret,
            'quic iv', '', 12);
        $self->hp_key = self::hkdfExpandLabel($secret,
            'quic hp', '', $key_len);
        return $self;
    }
    /**
     * RFC 5869 HKDF-Extract; small reimpl of the same
     * helper Tls13Engine has, made static so this class
     * doesn't have to construct an engine just to derive
     * Initial keys.
     * @param string $salt HKDF salt
     * @param string $ikm HKDF input keying material
     * @return string HKDF-Extract output (PRK)
     */
    protected static function hkdfExtract($salt, $ikm)
    {
        if ($salt === '') {
            $salt = str_repeat("\x00", 32);
        }
        return hash_hmac('sha256', $ikm, $salt, true);
    }
    /**
     * HKDF-Expand-Label per RFC 8446 sec 7.1, with the
     * "tls13 " label prefix. QUIC labels are "client in",
     * "server in", "quic key", "quic iv", "quic hp",
     * "quic ku" (key update; unused here).
     * @param string $secret TLS 1.3 traffic secret
     * @param string $label HKDF-Expand-Label label
     * @param array $context per-listener stream context overrides
     * @param int $length byte length
     * @return string HKDF-Expand-Label output of the requested length
     */
    protected static function hkdfExpandLabel($secret,
        $label, $context, $length)
    {
        $full = "tls13 " . $label;
        $info = chr(($length >> 8) & 0xFF) .
            chr($length & 0xFF) .
            chr(strlen($full)) . $full .
            chr(strlen($context)) . $context;
        $out = '';
        $t = '';
        $ctr = 1;
        while (strlen($out) < $length) {
            $t = hash_hmac('sha256',
                $t . $info . chr($ctr), $secret, true);
            $out .= $t;
            $ctr++;
        }
        return substr($out, 0, $length);
    }
    /**
     * Computes the 16-byte sample-derived header-protection
     * mask, per RFC 9001 sec 5.4.3. Sample length is
     * always 16 bytes regardless of cipher.
     *
     * For AES-128-ECB: mask = AES-ECB(hp_key, sample),
     *     keep low 5 bytes for header use.
     * For ChaCha20: mask = ChaCha20(hp_key, counter, nonce,
     *     5 zero bytes), where counter is the first 4
     *     bytes of the sample (LE) and nonce is the next
     *     12 bytes.
     *
     * Returns the 5-byte mask (1 byte for first-byte XOR,
     * 4 bytes for packet-number XOR -- only as many as the
     * actual packet-number length will be used).
     * @param string $sample header protection sample bytes (16 bytes typically)
     * @return string 5-byte header-protection mask derived from the sample
     */
    public function headerProtectionMask($sample)
    {
        if (strlen($sample) < 16) {
            return false;
        }
        if ($this->cipher ===
            Tls13Engine::CIPHER_AES_128_GCM_SHA256) {
            /*
                AES-128-ECB on a single 16-byte block.
                openssl_encrypt with no padding gives us
                the raw block.
             */
            $block = openssl_encrypt(substr($sample, 0, 16),
                'aes-128-ecb', $this->hp_key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
            return substr($block, 0, 5);
        }
        /*
            ChaCha20 keystream block. RFC 9001 sec 5.4.4
            uses sample[0..3] as a 32-bit LE counter and
            sample[4..15] as the 12-byte nonce, then takes
            the first 5 bytes of the keystream as the mask.

            We try OpenSSL's 'chacha20' EVP cipher first
            because it's an order of magnitude faster than
            pure PHP, but fall back to pure PHP if the
            cipher is unavailable (LibreSSL on stock macOS
            does not expose raw chacha20 -- only the AEAD
            ChaCha20-Poly1305) or if its IV layout differs
            from RFC 8439's. self::chachaUseOpenssl() runs
            a one-shot RFC 8439 self-test the first time
            it's called and caches the result.
         */
        $counter = ord($sample[0])
            | (ord($sample[1]) << 8)
            | (ord($sample[2]) << 16)
            | (ord($sample[3]) << 24);
        $nonce = substr($sample, 4, 12);
        if (self::chachaUseOpenssl()) {
            $iv = substr($sample, 0, 16);
            $ks = openssl_encrypt(
                "\x00\x00\x00\x00\x00", 'chacha20',
                $this->hp_key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);
            if ($ks === false) {
                return false;
            }
            return substr($ks, 0, 5);
        }
        $block = self::chacha20Block($this->hp_key, $counter,
            $nonce);
        if ($block === false) {
            return false;
        }
        return substr($block, 0, 5);
    }
    /**
     * True iff this PHP build's openssl_encrypt supports the
     * 'chacha20' raw-stream cipher with the RFC 8439 IV
     * layout (counter[4 LE] || nonce[12]). Cached. LibreSSL
     * builds on macOS may ship a chacha20 cipher with a
     * different layout, in which case headerProtectionMask
     * falls back to pure PHP. Self-tests against the RFC
     * 8439 sec 2.3.2 vector; a mismatch is treated as the
     * cipher being absent.
     * @return bool true if the OpenSSL ChaCha20 path should be used; false to fall back to the pure-PHP implementation
     */
    public static function chachaUseOpenssl()
    {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        /*
            32-byte key = bytes 0..31. range() + array_map +
            implode is one builtin call each instead of a 32-
            iteration PHP loop; the explicit chr-loop was the
            old shape but pack('C*', ...) is both clearer and
            slightly faster.
         */
        $key = pack('C*', ...range(0, 31));
        $got = @openssl_encrypt(
            str_repeat("\x00", 16), 'chacha20', $key,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            self::CHACHA_TEST_IV);
        $cached = ($got !== false
            && $got === self::CHACHA_TEST_EXPECTED);
        return $cached;
    }
    /**
     * Pure-PHP ChaCha20 block function per RFC 8439 sec
     * 2.3. Produces 64 bytes of keystream from $key (32
     * bytes), $counter (32-bit unsigned int), and $nonce
     * (12 bytes). Used as a fallback for the HP mask when
     * OpenSSL's 'chacha20' cipher isn't available; only the
     * first 5 bytes of output are needed there. Slower than
     * OpenSSL by ~10x but inconsequential for QUIC HP at
     * realistic packet rates (5 bytes per packet).
     * @param string $key key
     * @param mixed $counter counter parameter
     * @param string $nonce AEAD nonce
     * @return string 64-byte ChaCha20 keystream block for the given counter
     */
    public static function chacha20Block($key, $counter,
        $nonce)
    {
        if (strlen($key) !== 32 || strlen($nonce) !== 12) {
            return false;
        }
        /*
            Initialize 16-word state per RFC 8439 sec 2.3:
                row 0: four "expand 32-byte k" constants
                row 1: words 4..7 = key[0..15]
                row 2: words 8..11 = key[16..31]
                row 3: word 12 = counter, 13..15 = nonce
            All as 32-bit little-endian words.
         */
        $s = [];
        $s[0] = 0x61707865;
        $s[1] = 0x3320646e;
        $s[2] = 0x79622d32;
        $s[3] = 0x6b206574;
        for ($i = 0; $i < 8; $i++) {
            $b = $i * 4;
            $s[4 + $i] = ord($key[$b])
                | (ord($key[$b + 1]) << 8)
                | (ord($key[$b + 2]) << 16)
                | (ord($key[$b + 3]) << 24);
        }
        $s[12] = $counter & 0xffffffff;
        for ($i = 0; $i < 3; $i++) {
            $b = $i * 4;
            $s[13 + $i] = ord($nonce[$b])
                | (ord($nonce[$b + 1]) << 8)
                | (ord($nonce[$b + 2]) << 16)
                | (ord($nonce[$b + 3]) << 24);
        }
        $w = $s;
        /* 20 rounds = 10 double rounds. */
        for ($r = 0; $r < 10; $r++) {
            self::chacha20Qr($w, 0, 4, 8, 12);
            self::chacha20Qr($w, 1, 5, 9, 13);
            self::chacha20Qr($w, 2, 6, 10, 14);
            self::chacha20Qr($w, 3, 7, 11, 15);
            self::chacha20Qr($w, 0, 5, 10, 15);
            self::chacha20Qr($w, 1, 6, 11, 12);
            self::chacha20Qr($w, 2, 7, 8, 13);
            self::chacha20Qr($w, 3, 4, 9, 14);
        }
        /* Add original state, then serialize little-
           endian. */
        $out = '';
        for ($i = 0; $i < 16; $i++) {
            $v = ($w[$i] + $s[$i]) & 0xffffffff;
            $out .= chr($v & 0xff)
                . chr(($v >> 8) & 0xff)
                . chr(($v >> 16) & 0xff)
                . chr(($v >> 24) & 0xff);
        }
        return $out;
    }
    /**
     * One ChaCha20 quarter-round on words a, b, c, d of
     * the working state. RFC 8439 sec 2.1. PHP integers
     * are 64-bit on every platform we run on, so we mask
     * with 0xffffffff to keep additions in 32-bit space.
     * @param mixed $w w parameter
     * @param mixed $a first operand
     * @param mixed $b second operand
     * @param mixed $c c parameter
     * @param mixed $d d parameter
     */
    protected static function chacha20Qr(&$w, $a, $b, $c, $d)
    {
        $w[$a] = ($w[$a] + $w[$b]) & 0xffffffff;
        $w[$d] = $w[$d] ^ $w[$a];
        $w[$d] = ((($w[$d] << 16) & 0xffffffff)
            | (($w[$d] >> 16) & 0xffff))
            & 0xffffffff;
        $w[$c] = ($w[$c] + $w[$d]) & 0xffffffff;
        $w[$b] = $w[$b] ^ $w[$c];
        $w[$b] = ((($w[$b] << 12) & 0xffffffff)
            | (($w[$b] >> 20) & 0xfff))
            & 0xffffffff;
        $w[$a] = ($w[$a] + $w[$b]) & 0xffffffff;
        $w[$d] = $w[$d] ^ $w[$a];
        $w[$d] = ((($w[$d] << 8) & 0xffffffff)
            | (($w[$d] >> 24) & 0xff))
            & 0xffffffff;
        $w[$c] = ($w[$c] + $w[$d]) & 0xffffffff;
        $w[$b] = $w[$b] ^ $w[$c];
        $w[$b] = ((($w[$b] << 7) & 0xffffffff)
            | (($w[$b] >> 25) & 0x7f))
            & 0xffffffff;
    }
    /**
     * Constructs the AEAD nonce by left-padding the 64-bit
     * packet number to 12 bytes and XORing with the IV.
     * @param int $packet_number packet number for the packet number space
     * @return string AEAD nonce for the given packet number
     */
    public function packetNonce($packet_number)
    {
        $padded = str_repeat("\x00", 4) .
            pack('J', (int) $packet_number);
        $out = '';
        for ($i = 0; $i < 12; $i++) {
            $out .= chr(ord($this->iv[$i]) ^
                ord($padded[$i]));
        }
        return $out;
    }
    /**
     * AEAD-seals $plaintext with the per-packet nonce
     * derived from $packet_number, using $aad as the
     * authenticated header. Returns ciphertext || tag.
     * @param int $packet_number packet number for the packet number space
     * @param string $aad additional authenticated data (AAD) for AEAD
     * @param string $plaintext plaintext bytes
     * @return string AEAD-sealed bytes (ciphertext including authentication tag)
     */
    public function seal($packet_number, $aad, $plaintext)
    {
        $nonce = $this->packetNonce($packet_number);
        if ($this->cipher ===
            Tls13Engine::CIPHER_AES_128_GCM_SHA256) {
            $tag = '';
            $ct = openssl_encrypt($plaintext, 'aes-128-gcm',
                $this->key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce, $tag, $aad);
            return $ct . $tag;
        }
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext, $aad, $nonce, $this->key);
    }
    /**
     * Inverse of seal. Returns plaintext on success, false
     * on auth failure.
     * @param int $packet_number packet number for the packet number space
     * @param string $aad additional authenticated data (AAD) for AEAD
     * @param string $ciphertext ciphertext bytes including AEAD tag
     * @return bool true on successful open
     */
    public function open($packet_number, $aad, $ciphertext)
    {
        $nonce = $this->packetNonce($packet_number);
        if ($this->cipher ===
            Tls13Engine::CIPHER_AES_128_GCM_SHA256) {
            if (strlen($ciphertext) < 16) {
                return false;
            }
            $ct = substr($ciphertext, 0, -16);
            $tag = substr($ciphertext, -16);
            return openssl_decrypt($ct, 'aes-128-gcm',
                $this->key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce, $tag, $aad);
        }
        return @sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext, $aad, $nonce, $this->key);
    }
}
/**
 * QUIC variable-length integer codec, RFC 9000 sec 16.
 * The top two bits of the first byte encode the length:
 *   00xxxxxx -- 1 byte,  values 0..63
 *   01xxxxxx -- 2 bytes, values 0..16383
 *   10xxxxxx -- 4 bytes, values 0..1073741823
 *   11xxxxxx -- 8 bytes, values 0..(2^62 - 1)
 *
 * The remaining 6 bits of the first byte are the high
 * 6 bits of the integer.
 */
class QuicVarint
{
    /**
     * Decodes a varint at offset $off in $buf. Returns
     * [value, new_off] or [false, $off] on underflow.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return string|false bytes read, or false on error
     */
    public static function read($buf, $off)
    {
        $buf_len = strlen($buf);
        if ($buf_len < $off + 1) {
            return [false, $off];
        }
        $first = ord($buf[$off]);
        $size_class = $first >> 6;
        $byte_count = 1 << $size_class; /* 1, 2, 4, or 8 */
        if ($buf_len < $off + $byte_count) {
            return [false, $off];
        }
        $value = $first & 0x3F;
        for ($i = 1; $i < $byte_count; $i++) {
            $value = ($value << 8) | ord($buf[$off + $i]);
        }
        return [$value, $off + $byte_count];
    }
    /**
     * Encodes a value as a QUIC varint with minimal
     * length. Returns the bytes.
     * @param mixed $value value
     * @return int|false number of bytes written, or false on error
     */
    public static function write($value)
    {
        if ($value < 0) {
            return false;
        }
        if ($value < 64) {
            return chr($value);
        }
        if ($value < 16384) {
            /*
                2-byte form: top two bits are 01, rest is
                the 14-bit integer in big-endian. The chr-
                concat is microbench-faster than pack('n')
                for this two-byte case (~10% in PHP 8.x).
             */
            return chr(0x40 | ($value >> 8))
                . chr($value & 0xFF);
        }
        if ($value < 1073741824) {
            /*
                4-byte form: top two bits are 10, rest is
                the 30-bit integer big-endian. pack('N')
                handles this in one libc call which beats
                the 4-iteration chr/concat loop.
             */
            return pack('N', 0x80000000 | $value);
        }
        /*
            8-byte form: top two bits are 11, rest is the
            62-bit integer in big-endian. PHP int is signed
            64-bit but QUIC caps at 2^62 - 1, so packing
            via 'J' (big-endian uint64) is safe.
         */
        $packed = pack('J', $value);
        $first = ord($packed[0]) | 0xC0;
        return chr($first) . substr($packed, 1);
    }
    /**
     * Returns how many bytes a value will occupy when
     * encoded -- useful for sizing payloads ahead of
     * actual encoding.
     * @param mixed $value value
     * @return int byte length
     */
    public static function size($value)
    {
        if ($value < 64) {
            return 1;
        }
        if ($value < 16384) {
            return 2;
        }
        if ($value < 1073741824) {
            return 4;
        }
        return 8;
    }
}
/**
 * Decoded QUIC packet structure. Long-header packets
 * (Initial, 0-RTT, Handshake, Retry) have all the type-
 * specific fields populated; short-header (1-RTT) packets
 * fill only the destination_cid, packet_number, and payload
 * fields. The fully-decoded payload (post-AEAD) is in
 * $payload; the bytes that comprised the unprotected
 * packet header are in $header_bytes (used as AEAD AAD on
 * the receive side, and to check we encoded the header
 * matching the sender's expectations).
 */
class QuicPacket
{
    /*
        Header forms.
     */
    const FORM_LONG = 1;
    const FORM_SHORT = 0;
    /*
        Long-header packet types (RFC 9000 sec 17.2).
        These are the values of bits 4-5 of the first byte
        when form=long (bit 7), fixed=1 (bit 6).
     */
    const LONG_INITIAL = 0;
    const LONG_ZERO_RTT = 1;
    const LONG_HANDSHAKE = 2;
    const LONG_RETRY = 3;
    /*
        QUIC v1 version number (RFC 9000 sec 15).
     */
    const VERSION_QUIC_V1 = 0x00000001;
    /**
     * Header form: FORM_LONG (long-header packets carry version
     * and CIDs explicitly; used for Initial, Handshake, 0-RTT,
     * Retry) or FORM_SHORT (1-RTT data packets where the
     * connection has been established). RFC 9000 sec 17.
     * @var int
     */
    public $form = self::FORM_LONG;
    /**
     * Long-header packet sub-type when $form is FORM_LONG; one
     * of LONG_INITIAL / LONG_ZERO_RTT / LONG_HANDSHAKE /
     * LONG_RETRY.
     * @var int
     */
    public $long_type = self::LONG_INITIAL;
    /**
     * QUIC version number from the wire; VERSION_QUIC_V1 for
     * RFC 9000 traffic.
     * @var int
     */
    public $version = self::VERSION_QUIC_V1;
    /**
     * Destination Connection ID as it appears on the wire; the
     * peer's chosen CID that addresses this connection at the
     * receiver.
     * @var string
     */
    public $destination_cid = "";
    /**
     * Source Connection ID as it appears on the wire; the
     * sender's chosen CID that the receiver will use when
     * sending packets back.
     * @var string
     */
    public $source_cid = "";
    /**
     * Token payload carried by Initial packets (server-issued
     * retry token, RFC 9000 sec 8) or Retry packets. Empty
     * string when no token is present.
     * @var string
     */
    public $token = "";
    /**
     * Decoded packet number after the truncated wire value is
     * reconstructed against the largest acknowledged number
     * for the corresponding packet number space.
     * @var int
     */
    public $packet_number = 0;
    /**
     * Length in bytes (1-4) of the on-wire packet-number field.
     * @var int
     */
    public $packet_number_length = 0; /* 1..4 bytes on wire */
    /**
     * Decrypted packet payload after header protection has been
     * removed and AEAD decryption has succeeded; raw frames are
     * still concatenated and must be parsed by QuicFrame.
     * @var string
     */
    public $payload = "";
    /**
     * Bytes of the packet header (form byte plus version, CIDs,
     * token, packet-number depending on form). Stashed during
     * parsing so the AEAD AAD can be reconstructed at decrypt
     * time.
     * @var string
     */
    public $header_bytes = "";
    /**
     * Decodes one QUIC packet from $buf starting at $off.
     * Returns [QuicPacket, new_off] on success or
     * [false, $off, $reason_string] on failure. For Initial
     * / Handshake packets, $keys is the QuicPacketKeys for
     * the receive direction at that encryption level; we use
     * it to remove header protection (giving us the PN
     * length and payload position) and to decrypt the
     * payload. Retry packets are not decrypted; their
     * integrity tag is verified against a fixed key. One UDP
     * datagram may coalesce multiple QUIC packets, so the
     * caller loops with the advanced offset until $off
     * equals strlen($buf).
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @param QuicPacketKeys $keys packet protection keys for this encryption level
     * @param mixed $is_server_recv is_server_recv parameter
     * @param mixed $largest_pn_seen largest_pn_seen parameter
     * @return array two-element list [QuicPacket|false, int $new_off]; false on parse failure
     */
    public static function decode($buf, $off, $keys,
        $is_server_recv, $largest_pn_seen)
    {
        if (strlen($buf) < $off + 1) {
            return [false, $off, "datagram too short"];
        }
        $first = ord($buf[$off]);
        if (($first & 0x80) === 0) {
            return self::decodeShort($buf, $off, $keys,
                $largest_pn_seen);
        }
        return self::decodeLong($buf, $off, $keys,
            $is_server_recv, $largest_pn_seen);
    }
    /**
     * Decodes a long-header packet. Implements the bits-4-5
     * type dispatch and runs the version, DCID, SCID, type-
     * specific extras (token for Initial, integrity tag for
     * Retry), then the protected payload.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @param QuicPacketKeys $keys packet protection keys for this encryption level
     * @param mixed $is_server_recv is_server_recv parameter
     * @param mixed $largest_pn_seen largest_pn_seen parameter
     * @return array two-element list [QuicPacket|false, int $new_off]; false on parse failure
     */
    protected static function decodeLong($buf, $off, $keys,
        $is_server_recv, $largest_pn_seen)
    {
        $packet_off = $off;
        $first = ord($buf[$off]);
        if (($first & 0x40) === 0) {
            /*
                The "fixed bit" (bit 6) must be 1 in QUIC v1.
                A zero indicates either a malformed packet or
                a different protocol; reject.
             */
            return [false, $off, "fixed bit not set"];
        }
        $long_type = ($first >> 4) & 0x03;
        $buf_len = strlen($buf);
        if ($buf_len < $off + 7) {
            return [false, $off, "long header truncated"];
        }
        $off++;
        $version = unpack('N', substr($buf, $off, 4))[1];
        $off += 4;
        $dcid_len = ord($buf[$off]);
        $off++;
        if ($buf_len < $off + $dcid_len + 1) {
            return [false, $off, "DCID truncated"];
        }
        $dcid = substr($buf, $off, $dcid_len);
        $off += $dcid_len;
        $scid_len = ord($buf[$off]);
        $off++;
        if ($buf_len < $off + $scid_len) {
            return [false, $off, "SCID truncated"];
        }
        $scid = substr($buf, $off, $scid_len);
        $off += $scid_len;
        $token = "";
        if ($long_type === self::LONG_INITIAL) {
            list($token_len, $off) = QuicVarint::read($buf,
                $off);
            if ($token_len === false ||
                $buf_len < $off + $token_len) {
                return [false, $off, "token truncated"];
            }
            $token = substr($buf, $off, $token_len);
            $off += $token_len;
        }
        if ($long_type === self::LONG_RETRY) {
            /*
                Retry packets are not encrypted; everything
                after the SCID is the retry token followed
                by a 16-byte integrity tag. We surface the
                raw contents and let the caller verify the
                tag via the QUIC v1 retry integrity key.
             */
            $rest = substr($buf, $off);
            $packet = new self();
            $packet->form = self::FORM_LONG;
            $packet->long_type = self::LONG_RETRY;
            $packet->version = $version;
            $packet->destination_cid = $dcid;
            $packet->source_cid = $scid;
            $packet->payload = $rest;
            $packet->header_bytes = substr($buf,
                $packet_off, $off - $packet_off);
            return [$packet, $buf_len];
        }
        /*
            Initial / Handshake / 0-RTT all carry a varint
            "Length" field followed by Length bytes of
            (packet number || protected payload).
         */
        list($length, $off) = QuicVarint::read($buf, $off);
        if ($length === false ||
            $buf_len < $off + $length) {
            return [false, $off, "length field bad"];
        }
        $pn_offset = $off;
        $sample_offset = $pn_offset + 4;
        if ($buf_len < $sample_offset + 16) {
            return [false, $off, "no room for HP sample"];
        }
        $sample = substr($buf, $sample_offset, 16);
        $mask = $keys->headerProtectionMask($sample);
        if ($mask === false) {
            return [false, $off, "HP mask failed"];
        }
        /*
            Long-header HP unmask: low 4 bits of byte 0
            (packet number length lives in low 2 bits).
         */
        $unprotected_first = $first ^ (ord($mask[0]) & 0x0F);
        $pn_length = ($unprotected_first & 0x03) + 1;
        $pn_truncated = 0;
        for ($i = 0; $i < $pn_length; $i++) {
            $b = ord($buf[$pn_offset + $i]) ^
                ord($mask[$i + 1]);
            $pn_truncated = ($pn_truncated << 8) | $b;
        }
        $packet_number = self::decodePacketNumber(
            $pn_truncated, $pn_length, $largest_pn_seen);
        $body_start = $pn_offset + $pn_length;
        $body_len = $length - $pn_length;
        if ($buf_len < $body_start + $body_len) {
            return [false, $off, "body truncated"];
        }
        /*
            Reassemble the AAD. AAD is the unprotected
            packet header: bytes from $packet_off through
            (but not including) $body_start, with byte 0
            replaced by $unprotected_first and the
            packet-number bytes replaced by their
            unprotected values. substr(pack('N', ...), ...)
            grabs the low $pn_length bytes from a 4-byte
            big-endian render -- one libc dispatch instead
            of an N-iteration chr loop.
         */
        $hdr = chr($unprotected_first) .
            substr($buf, $packet_off + 1,
                $pn_offset - $packet_off - 1);
        $pn_bytes = substr(pack('N', $packet_number),
            4 - $pn_length);
        $aad = $hdr . $pn_bytes;
        $protected = substr($buf, $body_start, $body_len);
        $plaintext = $keys->open($packet_number, $aad,
            $protected);
        if ($plaintext === false) {
            return [false, $body_start,
                "AEAD authentication failed"];
        }
        $packet = new self();
        $packet->form = self::FORM_LONG;
        $packet->long_type = $long_type;
        $packet->version = $version;
        $packet->destination_cid = $dcid;
        $packet->source_cid = $scid;
        $packet->token = $token;
        $packet->packet_number = $packet_number;
        $packet->packet_number_length = $pn_length;
        $packet->payload = $plaintext;
        $packet->header_bytes = $aad;
        return [$packet, $body_start + $body_len];
    }
    /**
     * Decodes a short-header (1-RTT) packet. Unlike long-
     * headers, the DCID length isn't on the wire; the
     * receiver knows it from the connection ID it
     * allocated. Caller passes $dcid_len so we know where
     * the packet number bytes start.
     *
     * Top 3 bits of byte 0 stay protected (form, fixed,
     * key-phase) -- we only XOR the low 5 bits with the
     * mask. This differs from long-header HP which only
     * touches the low 4 bits.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @param QuicPacketKeys $keys packet protection keys for this encryption level
     * @param mixed $dcid_len dcid_len parameter
     * @param mixed $largest_pn_seen largest_pn_seen parameter
     * @return array two-element list [QuicPacket|false, int $new_off]; false on parse failure
     */
    public static function decodeShort($buf, $off, $keys,
        $dcid_len, $largest_pn_seen)
    {
        $packet_off = $off;
        $buf_len = strlen($buf);
        if ($buf_len < $off + 1 + $dcid_len + 4 + 16) {
            return [false, $off, "short header truncated"];
        }
        $first = ord($buf[$off]);
        $off++;
        $dcid = substr($buf, $off, $dcid_len);
        $off += $dcid_len;
        $pn_offset = $off;
        $sample_offset = $pn_offset + 4;
        $sample = substr($buf, $sample_offset, 16);
        $mask = $keys->headerProtectionMask($sample);
        if ($mask === false) {
            return [false, $off, "HP mask failed"];
        }
        $unprotected_first = $first ^ (ord($mask[0]) & 0x1F);
        $pn_length = ($unprotected_first & 0x03) + 1;
        $pn_truncated = 0;
        for ($i = 0; $i < $pn_length; $i++) {
            $b = ord($buf[$pn_offset + $i]) ^
                ord($mask[$i + 1]);
            $pn_truncated = ($pn_truncated << 8) | $b;
        }
        $packet_number = self::decodePacketNumber(
            $pn_truncated, $pn_length, $largest_pn_seen);
        $body_start = $pn_offset + $pn_length;
        /*
            For short-header packets there is no Length
            field; the entire remainder of the datagram is
            the protected payload + 16-byte AEAD tag.
         */
        $body_len = $buf_len - $body_start;
        if ($body_len < 16) {
            return [false, $off, "no room for AEAD tag"];
        }
        $hdr = chr($unprotected_first)
            . substr($buf, $packet_off + 1,
                $pn_offset - $packet_off - 1);
        /* See decodeLong for the substr(pack,...) idiom. */
        $pn_bytes = substr(pack('N', $packet_number),
            4 - $pn_length);
        $aad = $hdr . $pn_bytes;
        $protected_body = substr($buf, $body_start,
            $body_len);
        $plaintext = $keys->open($packet_number, $aad,
            $protected_body);
        if ($plaintext === false) {
            return [false, $body_start,
                "AEAD authentication failed"];
        }
        $packet = new self();
        $packet->form = self::FORM_SHORT;
        $packet->destination_cid = $dcid;
        $packet->packet_number = $packet_number;
        $packet->packet_number_length = $pn_length;
        $packet->payload = $plaintext;
        $packet->header_bytes = $aad;
        return [$packet, $buf_len];
    }
    /**
     * Encodes a short-header (1-RTT) packet. Always uses
     * 4-byte PN encoding for simplicity. First byte
     * structure (RFC 9000 sec 17.3): bit 7 = 0 (form),
     * bit 6 = 1 (fixed), bit 5 = 0 (spin), bits 4-3 = 0
     * (reserved), bit 2 = 0 (key phase), bits 1-0 = pn
     * length - 1.
     * @param QuicPacketKeys $keys packet protection keys for this encryption level
     * @param int $packet_number packet number for the packet number space
     * @param mixed $payload_unprotected payload_unprotected parameter
     * @return string encoded short-header packet bytes
     */
    public function encodeShort($keys, $packet_number,
        $payload_unprotected)
    {
        $pn_length = 4;
        $first = 0x40 | ($pn_length - 1);
        $hdr = chr($first) . $this->destination_cid;
        /*
            4-byte big-endian packet number. pack('N', ...)
            is one libc dispatch instead of a 4-iteration
            chr/concat loop.
         */
        $pn_bytes = pack('N', $packet_number);
        $aad = $hdr . $pn_bytes;
        $sealed = $keys->seal($packet_number, $aad,
            $payload_unprotected);
        $unprotected = $aad . $sealed;
        $hdr_len = strlen($hdr);
        $sample = substr($unprotected, $hdr_len + 4, 16);
        $mask = $keys->headerProtectionMask($sample);
        if ($mask === false) {
            return false;
        }
        /*
            Header protection: XOR the first byte's low bits
            against the mask, and the 4 PN bytes against
            mask[1..4]. PHP's binary-string ^ operates on
            equal-length operands so we slice both sides to
            $pn_length first.
         */
        $protected_first = ord($unprotected[0]) ^
            (ord($mask[0]) & 0x1F);
        $protected_pn =
            substr($unprotected, $hdr_len, $pn_length)
            ^ substr($mask, 1, $pn_length);
        return chr($protected_first)
            . substr($unprotected, 1, $hdr_len - 1)
            . $protected_pn
            . substr($unprotected, $hdr_len + $pn_length);
    }
    /**
     * Decodes a truncated packet number into the full
     * 62-bit packet number. RFC 9000 sec A.3.
     * @param mixed $truncated truncated parameter
     * @param mixed $pn_length pn_length parameter
     * @param mixed $largest_pn_seen largest_pn_seen parameter
     * @return int reconstructed full packet number
     */
    public static function decodePacketNumber($truncated,
        $pn_length, $largest_pn_seen)
    {
        $pn_nbits = $pn_length * 8;
        $expected = $largest_pn_seen + 1;
        $pn_win = 1 << $pn_nbits;
        $pn_hwin = $pn_win >> 1;
        $pn_mask = $pn_win - 1;
        $candidate = ($expected & ~$pn_mask) | $truncated;
        if ($candidate <= $expected - $pn_hwin &&
            $candidate < (1 << 62) - $pn_win) {
            $candidate += $pn_win;
        } else if ($candidate > $expected + $pn_hwin &&
            $candidate >= $pn_win) {
            $candidate -= $pn_win;
        }
        return $candidate;
    }
    /**
     * Encodes a long-header packet. The caller supplies
     * the unprotected payload (frames concatenated; will
     * be padded out by the caller for Initial packets per
     * RFC 9000 sec 14.1) and the packet-keys for sealing
     * + HP. Returns the on-wire bytes. $packet_number
     * here is the *full* PN (the function chooses an
     * encoding length and truncates).
     *
     * Always uses 4-byte PN encoding for simplicity.
     * Works as long as the connection sends fewer than
     * 2^31 packets per PN space, always true in practice.
     * @param QuicPacketKeys $keys packet protection keys for this encryption level
     * @param int $packet_number packet number for the packet number space
     * @param mixed $payload_unprotected payload_unprotected parameter
     * @return string encoded long-header packet bytes
     */
    public function encodeLong($keys, $packet_number,
        $payload_unprotected)
    {
        $pn_length = 4;
        $first = 0xC0 | ($this->long_type << 4)
            | ($pn_length - 1);
        $hdr = chr($first)
            . pack('N', $this->version)
            . chr(strlen($this->destination_cid))
            . $this->destination_cid
            . chr(strlen($this->source_cid))
            . $this->source_cid;
        if ($this->long_type === self::LONG_INITIAL) {
            $hdr .= QuicVarint::write(strlen($this->token))
                . $this->token;
        }
        $body_len = $pn_length + strlen($payload_unprotected)
            + 16; /* +tag */
        $hdr .= QuicVarint::write($body_len);
        $pn_bytes = pack('N', $packet_number);
        $aad = $hdr . $pn_bytes;
        $sealed = $keys->seal($packet_number, $aad,
            $payload_unprotected);
        $unprotected_packet = $aad . $sealed;
        /*
            Apply header protection. Sample is 16 bytes
            starting 4 bytes into the protected payload
            (always at the same offset regardless of
            actual PN length, per RFC 9001 sec 5.4.2).
         */
        $hdr_len = strlen($hdr);
        $sample = substr($unprotected_packet,
            $hdr_len + 4, 16);
        $mask = $keys->headerProtectionMask($sample);
        if ($mask === false) {
            return false;
        }
        $protected_first = ord($unprotected_packet[0]) ^
            (ord($mask[0]) & 0x0F);
        $protected_pn =
            substr($unprotected_packet, $hdr_len, $pn_length)
            ^ substr($mask, 1, $pn_length);
        return chr($protected_first)
            . substr($unprotected_packet, 1, $hdr_len - 1)
            . $protected_pn
            . substr($unprotected_packet,
                $hdr_len + $pn_length);
    }
}
/**
 * QUIC frame codec, RFC 9000 sec 19. A frame is the payload
 * unit of a QUIC packet; one packet's payload is a sequence
 * of contiguous frames (no length prefixes between them --
 * each frame's own type byte determines how many bytes it
 * consumes).
 *
 * Atto handles all 28 type codes defined in QUIC v1, though
 * many are simple stubs:
 *
 *   0x00          PADDING
 *   0x01          PING
 *   0x02-0x03     ACK (with / without ECN counts)
 *   0x04          RESET_STREAM
 *   0x05          STOP_SENDING
 *   0x06          CRYPTO
 *   0x07          NEW_TOKEN
 *   0x08-0x0F     STREAM (8 variants by FIN/LEN/OFF bits)
 *   0x10          MAX_DATA
 *   0x11          MAX_STREAM_DATA
 *   0x12-0x13     MAX_STREAMS (bidi / uni)
 *   0x14          DATA_BLOCKED
 *   0x15          STREAM_DATA_BLOCKED
 *   0x16-0x17     STREAMS_BLOCKED (bidi / uni)
 *   0x18          NEW_CONNECTION_ID
 *   0x19          RETIRE_CONNECTION_ID
 *   0x1A          PATH_CHALLENGE
 *   0x1B          PATH_RESPONSE
 *   0x1C-0x1D     CONNECTION_CLOSE (transport / app)
 *   0x1E          HANDSHAKE_DONE
 *
 * Decoded frames are returned as associative arrays with a
 * 'type' key plus per-type payload fields, kept loose to
 * avoid the ceremony of one PHP class per type. The encoder
 * functions take the same array shape.
 */
class QuicFrame
{
    /*
        Frame type codes, RFC 9000 sec 19.
     */
    const F_PADDING = 0x00;
    const F_PING = 0x01;
    const F_ACK = 0x02;
    const F_ACK_ECN = 0x03;
    const F_RESET_STREAM = 0x04;
    const F_STOP_SENDING = 0x05;
    const F_CRYPTO = 0x06;
    const F_NEW_TOKEN = 0x07;
    const F_STREAM_BASE = 0x08;
    /* bits: 0x01 = FIN, 0x02 = LEN, 0x04 = OFF */
    const F_STREAM_FIN = 0x01;
    const F_STREAM_LEN = 0x02;
    const F_STREAM_OFF = 0x04;
    const F_MAX_DATA = 0x10;
    const F_MAX_STREAM_DATA = 0x11;
    const F_MAX_STREAMS_BIDI = 0x12;
    const F_MAX_STREAMS_UNI = 0x13;
    const F_DATA_BLOCKED = 0x14;
    const F_STREAM_DATA_BLOCKED = 0x15;
    const F_STREAMS_BLOCKED_BIDI = 0x16;
    const F_STREAMS_BLOCKED_UNI = 0x17;
    const F_NEW_CONNECTION_ID = 0x18;
    const F_RETIRE_CONNECTION_ID = 0x19;
    const F_PATH_CHALLENGE = 0x1A;
    const F_PATH_RESPONSE = 0x1B;
    const F_CONNECTION_CLOSE = 0x1C;
    const F_CONNECTION_CLOSE_APP = 0x1D;
    const F_HANDSHAKE_DONE = 0x1E;
    /**
     * Decodes a sequence of frames from $buf starting at
     * $off through end of buffer. Returns
     * [array_of_frames, error] where error is "" on
     * success or a description on failure (in which case
     * the partial frame list is still returned so the
     * caller can ACK what was successfully parsed).
     *
     * Each returned frame is an array; the 'type' key is
     * always present, plus type-specific fields:
     *   PADDING/PING/HANDSHAKE_DONE: just type.
     *   ACK: type, largest, delay, ranges (array of pairs
     *        [gap, ack_range_length]), first_range,
     *        ecn (optional).
     *   CRYPTO: type, offset, data.
     *   STREAM: type, stream_id, offset, data, fin (bool).
     *   RESET_STREAM: type, stream_id, error_code,
     *                 final_size.
     *   STOP_SENDING: type, stream_id, error_code.
     *   MAX_DATA / MAX_STREAMS_*: type, value.
     *   MAX_STREAM_DATA: type, stream_id, value.
     *   DATA_BLOCKED / STREAMS_BLOCKED_*: type, value.
     *   STREAM_DATA_BLOCKED: type, stream_id, value.
     *   NEW_CONNECTION_ID: type, sequence, retire_prior_to,
     *                      cid, stateless_reset_token.
     *   RETIRE_CONNECTION_ID: type, sequence.
     *   PATH_CHALLENGE / PATH_RESPONSE: type, data (8 B).
     *   NEW_TOKEN: type, token.
     *   CONNECTION_CLOSE / _APP: type, error_code,
     *                             frame_type (0x1C only),
     *                             reason.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array list of parsed QuicPacket records
     */
    public static function decodeAll($buf, $off = 0)
    {
        $frames = [];
        while ($off < strlen($buf)) {
            list($type, $off2) = QuicVarint::read($buf, $off);
            if ($type === false) {
                return [$frames, "frame type truncated"];
            }
            $off = $off2;
            /* PADDING is type 0x00 with no body; collapse
               consecutive padding bytes into one frame for
               cleanliness. */
            if ($type === self::F_PADDING) {
                $start = $off - 1;
                while ($off < strlen($buf) &&
                    ord($buf[$off]) === self::F_PADDING) {
                    $off++;
                }
                $frames[] = ['type' => self::F_PADDING,
                    'count' => $off - $start];
                continue;
            }
            list($frame, $off, $err) = self::decodeOne($type,
                $buf, $off);
            if ($err !== '') {
                return [$frames, $err];
            }
            $frames[] = $frame;
        }
        return [$frames, ''];
    }
    /**
     * Decodes a single frame whose type byte has already
     * been consumed. Returns [frame, new_off, err].
     * @param int $type type code
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return array two-element list [QuicPacket|false, int $new_off]
     */
    protected static function decodeOne($type, $buf, $off)
    {
        switch ($type) {
            case self::F_PING:
                return [['type' => $type], $off, ''];
            case self::F_HANDSHAKE_DONE:
                return [['type' => $type], $off, ''];
            case self::F_ACK:
            case self::F_ACK_ECN:
                return self::decodeAck($type, $buf, $off);
            case self::F_CRYPTO:
                return self::decodeCrypto($buf, $off);
            case self::F_NEW_TOKEN:
                list($len, $off) = QuicVarint::read($buf,
                    $off);
                if ($len === false ||
                    strlen($buf) < $off + $len) {
                    return [null, $off,
                        "NEW_TOKEN truncated"];
                }
                return [['type' => $type,
                    'token' => substr($buf, $off, $len)],
                    $off + $len, ''];
            case self::F_RESET_STREAM:
                list($sid, $off) = QuicVarint::read($buf,
                    $off);
                list($ec, $off) = QuicVarint::read($buf,
                    $off);
                list($fs, $off) = QuicVarint::read($buf,
                    $off);
                if ($fs === false) {
                    return [null, $off,
                        "RESET_STREAM truncated"];
                }
                return [['type' => $type,
                    'stream_id' => $sid,
                    'error_code' => $ec,
                    'final_size' => $fs], $off, ''];
            case self::F_STOP_SENDING:
                list($sid, $off) = QuicVarint::read($buf,
                    $off);
                list($ec, $off) = QuicVarint::read($buf,
                    $off);
                if ($ec === false) {
                    return [null, $off,
                        "STOP_SENDING truncated"];
                }
                return [['type' => $type,
                    'stream_id' => $sid,
                    'error_code' => $ec], $off, ''];
            case self::F_MAX_DATA:
            case self::F_MAX_STREAMS_BIDI:
            case self::F_MAX_STREAMS_UNI:
            case self::F_DATA_BLOCKED:
            case self::F_STREAMS_BLOCKED_BIDI:
            case self::F_STREAMS_BLOCKED_UNI:
                list($v, $off) = QuicVarint::read($buf, $off);
                if ($v === false) {
                    return [null, $off, "varint frame trunc"];
                }
                return [['type' => $type, 'value' => $v],
                    $off, ''];
            case self::F_MAX_STREAM_DATA:
            case self::F_STREAM_DATA_BLOCKED:
                list($sid, $off) = QuicVarint::read($buf,
                    $off);
                list($v, $off) = QuicVarint::read($buf, $off);
                if ($v === false) {
                    return [null, $off,
                        "stream-id frame trunc"];
                }
                return [['type' => $type,
                    'stream_id' => $sid,
                    'value' => $v], $off, ''];
            case self::F_NEW_CONNECTION_ID:
                return self::decodeNewConnectionId($buf, $off);
            case self::F_RETIRE_CONNECTION_ID:
                list($seq, $off) = QuicVarint::read($buf,
                    $off);
                if ($seq === false) {
                    return [null, $off,
                        "RETIRE_CONNECTION_ID truncated"];
                }
                return [['type' => $type, 'sequence' => $seq],
                    $off, ''];
            case self::F_PATH_CHALLENGE:
            case self::F_PATH_RESPONSE:
                if (strlen($buf) < $off + 8) {
                    return [null, $off, "PATH_* trunc"];
                }
                return [['type' => $type,
                    'data' => substr($buf, $off, 8)],
                    $off + 8, ''];
            case self::F_CONNECTION_CLOSE:
            case self::F_CONNECTION_CLOSE_APP:
                return self::decodeConnectionClose($type,
                    $buf, $off);
        }
        if ($type >= self::F_STREAM_BASE && $type <= 0x0F) {
            return self::decodeStream($type, $buf, $off);
        }
        return [null, $off, sprintf(
            "unknown frame type 0x%02x", $type)];
    }
    /**
     * ACK frame body. Fields per RFC 9000 sec 19.3:
     *   Largest Acknowledged (varint)
     *   ACK Delay (varint, in microseconds * 2^ack_delay_exp)
     *   ACK Range Count (varint)
     *   First ACK Range (varint)
     *   ACK Range[] each: Gap (varint), ACK Range Length
     *     (varint)
     *   ECN counts (3 varints, only if type == F_ACK_ECN)
     * @param int $type type code
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return QuicFrame parsed ACK frame
     */
    protected static function decodeAck($type, $buf, $off)
    {
        list($largest, $off) = QuicVarint::read($buf, $off);
        list($delay, $off) = QuicVarint::read($buf, $off);
        list($range_count, $off) = QuicVarint::read($buf,
            $off);
        list($first_range, $off) = QuicVarint::read($buf,
            $off);
        if ($first_range === false) {
            return [null, $off, "ACK head truncated"];
        }
        $ranges = [];
        for ($i = 0; $i < $range_count; $i++) {
            list($gap, $off) = QuicVarint::read($buf, $off);
            list($ack_len, $off) = QuicVarint::read($buf,
                $off);
            if ($ack_len === false) {
                return [null, $off, "ACK range truncated"];
            }
            $ranges[] = [$gap, $ack_len];
        }
        $frame = ['type' => $type, 'largest' => $largest,
            'delay' => $delay, 'first_range' => $first_range,
            'ranges' => $ranges];
        if ($type === self::F_ACK_ECN) {
            list($e0, $off) = QuicVarint::read($buf, $off);
            list($e1, $off) = QuicVarint::read($buf, $off);
            list($ce, $off) = QuicVarint::read($buf, $off);
            if ($ce === false) {
                return [null, $off, "ACK ECN truncated"];
            }
            $frame['ecn'] = ['ect0' => $e0, 'ect1' => $e1,
                'ce' => $ce];
        }
        return [$frame, $off, ''];
    }
    /**
     * CRYPTO frame body, RFC 9000 sec 19.6:
     *   Offset (varint), Length (varint), Crypto Data.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return QuicFrame parsed CRYPTO frame
     */
    protected static function decodeCrypto($buf, $off)
    {
        list($offset, $off) = QuicVarint::read($buf, $off);
        list($len, $off) = QuicVarint::read($buf, $off);
        if ($len === false ||
            strlen($buf) < $off + $len) {
            return [null, $off, "CRYPTO truncated"];
        }
        return [['type' => self::F_CRYPTO,
            'offset' => $offset,
            'data' => substr($buf, $off, $len)],
            $off + $len, ''];
    }
    /**
     * STREAM frame body, RFC 9000 sec 19.8. The type-byte
     * low 3 bits (FIN, LEN, OFF) toggle the optional
     * Offset / Length fields and the FIN flag.
     *
     * If LEN is unset, the frame extends to the end of the
     * containing packet's payload, so we consume all
     * remaining bytes.
     * @param int $type type code
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return QuicFrame parsed STREAM frame
     */
    protected static function decodeStream($type, $buf, $off)
    {
        $fin = (bool)($type & self::F_STREAM_FIN);
        $has_len = (bool)($type & self::F_STREAM_LEN);
        $has_off = (bool)($type & self::F_STREAM_OFF);
        list($sid, $off) = QuicVarint::read($buf, $off);
        if ($sid === false) {
            return [null, $off, "STREAM sid trunc"];
        }
        $offset = 0;
        if ($has_off) {
            list($offset, $off) = QuicVarint::read($buf,
                $off);
            if ($offset === false) {
                return [null, $off, "STREAM offset trunc"];
            }
        }
        if ($has_len) {
            list($len, $off) = QuicVarint::read($buf, $off);
            if ($len === false ||
                strlen($buf) < $off + $len) {
                return [null, $off, "STREAM data trunc"];
            }
            $data = substr($buf, $off, $len);
            $off += $len;
        } else {
            $data = substr($buf, $off);
            $off = strlen($buf);
        }
        return [['type' => self::F_STREAM_BASE,
            'stream_id' => $sid, 'offset' => $offset,
            'data' => $data, 'fin' => $fin,
            'wire_type' => $type], $off, ''];
    }
    /**
     * NEW_CONNECTION_ID frame body, RFC 9000 sec 19.15:
     *   Sequence Number (varint), Retire Prior To (varint),
     *   Length (1 byte), Connection ID, Stateless Reset
     *   Token (16 bytes).
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return QuicFrame parsed NEW_CONNECTION_ID frame
     */
    protected static function decodeNewConnectionId($buf, $off)
    {
        list($seq, $off) = QuicVarint::read($buf, $off);
        list($retire, $off) = QuicVarint::read($buf, $off);
        if ($retire === false || strlen($buf) < $off + 1) {
            return [null, $off,
                "NEW_CONNECTION_ID head trunc"];
        }
        $cid_len = ord($buf[$off]);
        $off++;
        if (strlen($buf) < $off + $cid_len + 16) {
            return [null, $off,
                "NEW_CONNECTION_ID body trunc"];
        }
        $cid = substr($buf, $off, $cid_len);
        $off += $cid_len;
        $token = substr($buf, $off, 16);
        $off += 16;
        return [['type' => self::F_NEW_CONNECTION_ID,
            'sequence' => $seq,
            'retire_prior_to' => $retire,
            'cid' => $cid,
            'stateless_reset_token' => $token],
            $off, ''];
    }
    /**
     * CONNECTION_CLOSE frame body, RFC 9000 sec 19.19.
     * Transport variant (0x1C) carries a Frame Type field
     * indicating which frame triggered the close; the
     * application variant (0x1D) does not.
     * @param int $type type code
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return QuicFrame parsed CONNECTION_CLOSE frame
     */
    protected static function decodeConnectionClose($type,
        $buf, $off)
    {
        list($ec, $off) = QuicVarint::read($buf, $off);
        $frame_type = 0;
        if ($type === self::F_CONNECTION_CLOSE) {
            list($frame_type, $off) = QuicVarint::read($buf,
                $off);
        }
        list($reason_len, $off) = QuicVarint::read($buf, $off);
        if ($reason_len === false ||
            strlen($buf) < $off + $reason_len) {
            return [null, $off, "CONNECTION_CLOSE trunc"];
        }
        return [['type' => $type, 'error_code' => $ec,
            'frame_type' => $frame_type,
            'reason' => substr($buf, $off, $reason_len)],
            $off + $reason_len, ''];
    }
    /*
        Encoders.
     */
    /**
     * Encodes a frame array. Reverse of decodeOne().
     * @param QuicFrame $frame parsed QUIC frame
     * @return string encoded packet bytes ready to send
     */
    public static function encode($frame)
    {
        $type = $frame['type'];
        switch ($type) {
            case self::F_PADDING:
                $count = $frame['count'] ?? 1;
                return str_repeat("\x00", $count);
            case self::F_PING:
            case self::F_HANDSHAKE_DONE:
                return chr($type);
            case self::F_ACK:
            case self::F_ACK_ECN:
                return self::encodeAck($frame);
            case self::F_CRYPTO:
                return chr($type) .
                    QuicVarint::write($frame['offset']) .
                    QuicVarint::write(strlen($frame['data']))
                    . $frame['data'];
            case self::F_NEW_TOKEN:
                return chr($type) .
                    QuicVarint::write(strlen($frame['token']))
                    . $frame['token'];
            case self::F_RESET_STREAM:
                return chr($type) .
                    QuicVarint::write($frame['stream_id']) .
                    QuicVarint::write($frame['error_code']) .
                    QuicVarint::write($frame['final_size']);
            case self::F_STOP_SENDING:
                return chr($type) .
                    QuicVarint::write($frame['stream_id']) .
                    QuicVarint::write($frame['error_code']);
            case self::F_MAX_DATA:
            case self::F_MAX_STREAMS_BIDI:
            case self::F_MAX_STREAMS_UNI:
            case self::F_DATA_BLOCKED:
            case self::F_STREAMS_BLOCKED_BIDI:
            case self::F_STREAMS_BLOCKED_UNI:
                return chr($type) .
                    QuicVarint::write($frame['value']);
            case self::F_MAX_STREAM_DATA:
            case self::F_STREAM_DATA_BLOCKED:
                return chr($type) .
                    QuicVarint::write($frame['stream_id']) .
                    QuicVarint::write($frame['value']);
            case self::F_NEW_CONNECTION_ID:
                return chr($type) .
                    QuicVarint::write($frame['sequence']) .
                    QuicVarint::write(
                        $frame['retire_prior_to']) .
                    chr(strlen($frame['cid'])) .
                    $frame['cid'] .
                    $frame['stateless_reset_token'];
            case self::F_RETIRE_CONNECTION_ID:
                return chr($type) .
                    QuicVarint::write($frame['sequence']);
            case self::F_PATH_CHALLENGE:
            case self::F_PATH_RESPONSE:
                return chr($type) . $frame['data'];
            case self::F_CONNECTION_CLOSE:
                return chr($type) .
                    QuicVarint::write($frame['error_code']) .
                    QuicVarint::write(
                        $frame['frame_type'] ?? 0) .
                    QuicVarint::write(
                        strlen($frame['reason'])) .
                    $frame['reason'];
            case self::F_CONNECTION_CLOSE_APP:
                return chr($type) .
                    QuicVarint::write($frame['error_code']) .
                    QuicVarint::write(
                        strlen($frame['reason'])) .
                    $frame['reason'];
            case self::F_STREAM_BASE:
                return self::encodeStream($frame);
        }
        return false;
    }
    /**
     * Encodes an ACK frame from a frame array of the same
     * shape decodeAck produces.
     * @param QuicFrame $frame parsed QUIC frame
     * @return string encoded ACK frame bytes
     */
    protected static function encodeAck($frame)
    {
        $type = $frame['type'];
        $body = QuicVarint::write($frame['largest']) .
            QuicVarint::write($frame['delay']) .
            QuicVarint::write(count($frame['ranges'])) .
            QuicVarint::write($frame['first_range']);
        foreach ($frame['ranges'] as $r) {
            $body .= QuicVarint::write($r[0]) .
                QuicVarint::write($r[1]);
        }
        if ($type === self::F_ACK_ECN &&
            isset($frame['ecn'])) {
            $body .= QuicVarint::write(
                $frame['ecn']['ect0']) .
                QuicVarint::write($frame['ecn']['ect1']) .
                QuicVarint::write($frame['ecn']['ce']);
        }
        return chr($type) . $body;
    }
    /**
     * Encodes a STREAM frame. Always sets LEN=1 and OFF=1
     * for clarity; the FIN flag is taken from the frame
     * array.
     * @param QuicFrame $frame parsed QUIC frame
     * @return string encoded STREAM frame bytes
     */
    protected static function encodeStream($frame)
    {
        $type = self::F_STREAM_BASE | self::F_STREAM_LEN |
            self::F_STREAM_OFF;
        if (!empty($frame['fin'])) {
            $type |= self::F_STREAM_FIN;
        }
        return chr($type) .
            QuicVarint::write($frame['stream_id']) .
            QuicVarint::write($frame['offset']) .
            QuicVarint::write(strlen($frame['data'])) .
            $frame['data'];
    }
    /**
     * Builds an ACK frame from a sorted list of received
     * packet numbers in one PN space. RFC 9000 sec 13.2.4.
     * @param mixed $received_pns received_pns parameter
     * @param mixed $delay delay parameter
     * @return string encoded ACK frame bytes ready to include in an outgoing packet
     */
    public static function buildAck($received_pns,
        $delay = 0)
    {
        if (empty($received_pns)) {
            return false;
        }
        rsort($received_pns);
        $largest = $received_pns[0];
        /* Walk through gaps, building (gap, ack-range-len)
           pairs. A run is a maximal contiguous descending
           subsequence; gaps are between runs. */
        $first_range = 0;
        $ranges = [];
        $i = 0;
        $n = count($received_pns);
        $cur = $largest;
        while ($i + 1 < $n &&
            $received_pns[$i + 1] === $cur - 1) {
            $first_range++;
            $cur--;
            $i++;
        }
        $i++;
        $prev_run_smallest = $cur;
        while ($i < $n) {
            $gap_top = $received_pns[$i];
            $gap = $prev_run_smallest - $gap_top - 2;
            $run_len = 0;
            $cur = $gap_top;
            while ($i + 1 < $n &&
                $received_pns[$i + 1] === $cur - 1) {
                $run_len++;
                $cur--;
                $i++;
            }
            $i++;
            $ranges[] = [$gap, $run_len];
            $prev_run_smallest = $cur;
        }
        return ['type' => self::F_ACK,
            'largest' => $largest, 'delay' => $delay,
            'first_range' => $first_range,
            'ranges' => $ranges];
    }
    /**
     * Inverse of buildAck: walks an ACK frame's ranges and
     * returns the explicit list of packet numbers covered.
     * Used by the loss-detection layer.
     * @param QuicFrame $frame parsed QUIC frame
     * @return array list of packet-number ranges encoded in the ACK frame
     */
    public static function expandAckRanges($frame)
    {
        $largest = $frame['largest'];
        $first = $frame['first_range'];
        $out = [];
        $cur = $largest;
        for ($k = 0; $k <= $first; $k++) {
            $out[] = $cur - $k;
        }
        $smallest = $largest - $first;
        foreach ($frame['ranges'] as $r) {
            list($gap, $ack_len) = $r;
            $top = $smallest - $gap - 2;
            for ($k = 0; $k <= $ack_len; $k++) {
                $out[] = $top - $k;
            }
            $smallest = $top - $ack_len;
        }
        return $out;
    }
}
/**
 * Receive-side stream state per RFC 9000 sec 3.2.
 * Substates that differ only in whether a STREAM frame with FIN has
 * been buffered vs. delivered are collapsed.
 */
enum RecvState: int
{
    case Open = 0;
    case SizeKnown = 1; // FIN seen, more bytes may still arrive
    case Done = 2;      // FIN seen and all bytes delivered to app
    case Reset = 3;     // peer sent RESET_STREAM; no more bytes expected
}
/**
 * Send-side stream state per RFC 9000 sec 3.1.
 * Substates that differ only in whether a STREAM frame with FIN has
 * been buffered vs. transmitted are collapsed.
 */
enum SendState: int
{
    case Ready = 0;
    case Data = 1;
    case DataSent = 2;
    case Done = 3;
    case Reset = 4;     // peer sent STOP_SENDING; we stop transmitting
}
/**
 * Per-stream state for one QUIC stream. Streams are
 * identified by a 62-bit stream ID; bits 0-1 of the ID
 * encode the stream's initiator (client / server) and
 * type (bidi / uni) per RFC 9000 sec 2.1.
 *
 * This class keeps it minimal: a receive-side reassembly
 * map (offset -> bytes) so out-of-order STREAM frames can
 * be coalesced into in-order delivery, plus a send-side
 * buffer that the QuicConnection's emit loop chunks into
 * STREAM frames as packets are built.
 *
 * Flow control windows are per-stream (MAX_STREAM_DATA)
 * and connection-wide (MAX_DATA, owned by QuicConnection,
 * not here). We track the per-stream values; the
 * connection updates them on receipt of frames.
 */
class QuicStream
{
    /**
     * @var RecvState the receive-side state flag
     */
    public RecvState $recv_state = RecvState::Open;
    /**
     * @var SendState the send-side state flag
     */
    public SendState $send_state = SendState::Ready;
    /**
     * @var array offset => bytes, for out-of-order
     *      reassembly. Cleared as in-order data is
     *      delivered to the app via consume().
     */
    public $recv_chunks = [];
    /**
     * @var int next offset the app expects to receive on
     *      this stream. consume() returns bytes starting
     *      at this offset.
     */
    public $recv_next_offset = 0;
    /**
     * @var int largest offset+length received on this
     *      stream. When recv_state is SIZE_KNOWN, this
     *      equals the final size.
     */
    public $recv_seen_max = 0;
    /**
     * @var string send-side outgoing buffer. Append-only
     *      from the application side; the takeForFrame
     *      reader advances $send_buf_off rather than
     *      mutating the buffer. Without that the buffer
     *      shift was O(n) per drained frame and the
     *      cumulative cost of draining a single 1 MiB
     *      response in MAX_STREAM_FRAME_BYTES STREAM frames was
     *      O(n^2) -- about 47 ms of pure substr-shift
     *      cost per request observed in profiling. The
     *      buffer is compacted in place when send_buf_off
     *      crosses SEND_BUF_COMPACT_THRESHOLD so memory
     *      does not grow unboundedly across long-lived
     *      streams.
     */
    public $send_buf = "";
    /**
     * @var int byte offset into $send_buf marking the next
     *      byte not yet handed to a STREAM frame. Always
     *      <= strlen(send_buf). The exposed
     *      bufferedLength() returns
     *      strlen(send_buf) - send_buf_off.
     */
    public $send_buf_off = 0;
    /**
     * @var int compaction threshold. When $send_buf_off
     *      grows past this many bytes we substr the
     *      consumed prefix away in one shot. 64 KiB is
     *      large enough that compactions are rare on
     *      bursty traffic but small enough that idle
     *      memory does not bloat per stream.
     */
    const SEND_BUF_COMPACT_THRESHOLD = 65536;
    /**
     * @var int next offset to use for an outgoing STREAM
     *      frame.
     */
    public $send_next_offset = 0;
    /**
     * @var bool true when the app has signaled FIN on the
     *      send side (no more data will be appended).
     */
    public $send_fin = false;
    /**
     * @var bool true once a STREAM frame with FIN has been
     *      transmitted by us. Used to skip retransmission
     *      of the FIN.
     */
    public $send_fin_sent = false;
    /**
     * Constructor: assigns the stream ID and bootstraps
     * receive flow-control window from the
     * initial_max_stream_data_* transport parameter the
     * QuicConnection passes through.
     *
     * @param int $id 62-bit stream ID
     * @param int $recv_window receive-side flow-control window
     *      (MAX_STREAM_DATA we've granted the peer)
     * @param int $send_window send-side flow-control window the peer
     *      has granted us via MAX_STREAM_DATA
     */
    public function __construct(public $id = 0,
        public $recv_window = 1048576, public $send_window = 1048576)
    {
    }
    /**
     * Buffers incoming STREAM-frame bytes. RFC 9000
     * sec 19.8: bytes at an offset already received are
     * silently discarded; new bytes are merged into the
     * reassembly map. Returns true on success, false if
     * the bytes would exceed our advertised
     * flow-control window.
     * @param int $offset byte offset into the buffer
     * @param string $data data bytes
     * @param bool $fin whether the FIN flag is set
     * @return void no return; the received datagram is processed in place
     */
    public function deliverIncoming($offset, $data, $fin)
    {
        if ($offset + strlen($data) > $this->recv_window) {
            return false; /* FLOW_CONTROL_ERROR */
        }
        $end = $offset + strlen($data);
        if ($end > $this->recv_seen_max) {
            $this->recv_seen_max = $end;
        }
        if (strlen($data) > 0) {
            $this->recv_chunks[$offset] = $data;
        }
        if ($fin) {
            $this->recv_state = RecvState::SizeKnown;
        }
        return true;
    }
    /**
     * Returns whatever in-order bytes are immediately
     * available, advancing recv_next_offset past them.
     * Empty string when nothing new (e.g. waiting on a
     * gap).
     * @return int number of bytes consumed from the buffer
     */
    public function consume()
    {
        $out = "";
        $next = $this->recv_next_offset;
        while (isset($this->recv_chunks[$next])) {
            $chunk = $this->recv_chunks[$next];
            unset($this->recv_chunks[$next]);
            $out .= $chunk;
            $next += strlen($chunk);
        }
        $this->recv_next_offset = $next;
        /* Coalesce overlapping / adjacent entries. The
           map keys are offsets; if the next offset to
           deliver matches some earlier-buffered chunk
           starting before recv_next_offset, slice and
           include the suffix. */
        foreach ($this->recv_chunks as $off => $chunk) {
            $end = $off + strlen($chunk);
            if ($end <= $next) {
                unset($this->recv_chunks[$off]);
            } else if ($off < $next) {
                $skip = $next - $off;
                $tail = substr($chunk, $skip);
                unset($this->recv_chunks[$off]);
                $this->recv_chunks[$next] = $tail;
            }
        }
        if ($this->recv_state === RecvState::SizeKnown &&
            $next >= $this->recv_seen_max) {
            $this->recv_state = RecvState::Done;
        }
        return $out;
    }
    /**
     * Returns true once no more data will arrive on the
     * receive side and everything queued has been
     * consumed.
     * @return bool true if no more data is expected on the receive side
     */
    public function isReceiveDone()
    {
        return $this->recv_state === RecvState::Done ||
            $this->recv_state === RecvState::Reset;
    }
    /**
     * Appends bytes to the send buffer. The
     * QuicConnection's emit loop chunks them into STREAM
     * frames in flight, taking flow-control limits into
     * account.
     * @param string $bytes bytes to operate on
     * @return int|false number of bytes written, or false on error
     */
    public function write($bytes)
    {
        $this->send_buf .= (string) $bytes;
        if ($this->send_state === SendState::Ready) {
            $this->send_state = SendState::Data;
        }
    }
    /**
     * Marks the send-side as finished. Once the buffer
     * drains, the next STREAM frame carries FIN.
     */
    public function finish()
    {
        $this->send_fin = true;
        if ($this->bufferedLength() === 0 &&
            $this->send_state === SendState::Ready) {
            $this->send_state = SendState::DataSent;
        }
    }
    /**
     * Number of bytes still queued in $send_buf and not
     * yet handed to a STREAM frame. Cheap (two strlen +
     * one subtract) and the canonical replacement for
     * send_buf === '' / strlen(send_buf) tests so the
     * head-pointer optimisation stays opaque to callers.
     * @return int number of bytes currently buffered awaiting send
     */
    public function bufferedLength()
    {
        return strlen($this->send_buf) - $this->send_buf_off;
    }
    /**
     * Consumes up to $max_bytes for the next outgoing
     * STREAM frame, returning [offset, data, fin] or
     * null if nothing to send. Updates send_next_offset
     * and advances the send_buf head pointer so the
     * underlying string is not rewritten on every call --
     * see the $send_buf docblock for why that matters.
     * @param mixed $max_bytes max_bytes parameter
     * @return string next chunk of bytes to send in a single STREAM frame
     */
    public function takeForFrame($max_bytes)
    {
        if ($this->send_state === SendState::Reset) {
            return null;
        }
        $buffered = $this->bufferedLength();
        if ($buffered === 0 && !$this->send_fin) {
            return null;
        }
        if ($buffered === 0 && $this->send_fin
            && $this->send_fin_sent) {
            return null;
        }
        $allowed = min($buffered, $max_bytes,
            max(0, $this->send_window
                - $this->send_next_offset));
        $data = substr($this->send_buf,
            $this->send_buf_off, $allowed);
        $this->send_buf_off += $allowed;
        /*
            Periodic compaction: when the head pointer has
            crossed SEND_BUF_COMPACT_THRESHOLD (and at
            least half the buffer is consumed prefix), drop
            the consumed prefix in one shot. This bounds
            steady-state memory regardless of how long the
            stream stays open. The compaction itself is
            O(unconsumed-tail), so amortised it is O(1)
            per byte across the lifetime of the stream.
         */
        if ($this->send_buf_off >=
                self::SEND_BUF_COMPACT_THRESHOLD
            && $this->send_buf_off * 2 >=
                strlen($this->send_buf)) {
            $this->send_buf = substr($this->send_buf,
                $this->send_buf_off);
            $this->send_buf_off = 0;
        }
        $offset = $this->send_next_offset;
        $this->send_next_offset += $allowed;
        $fin = ($this->send_fin &&
            $this->bufferedLength() === 0);
        if ($fin) {
            $this->send_fin_sent = true;
            $this->send_state = SendState::DataSent;
        }
        return [$offset, $data, $fin];
    }
    /**
     * True when there are more bytes queued in send_buf
     * that haven't been packetized into STREAM frames yet,
     * or when send_fin is set but the FIN-bearing frame
     * hasn't been emitted yet. flushStreams uses this to
     * tell its caller whether the next event-loop tick
     * needs to come back for more.
     * @return bool true if there are pending bytes or control frames to send
     */
    public function hasPendingSend()
    {
        if ($this->send_state === SendState::Reset) {
            return false;
        }
        if ($this->bufferedLength() > 0) {
            return true;
        }
        if ($this->send_fin && !$this->send_fin_sent) {
            return true;
        }
        return false;
    }
}
/**
 * One QUIC connection's state. Owns the TLS 1.3 engine, per-
 * encryption-level packet keys (rx and tx for Initial,
 * Handshake, 1-RTT), per-PN-space received and next-to-send
 * packet numbers, the crypto receive buffer for reassembling
 * CRYPTO frames, the local and peer connection IDs, the stream
 * table, and the local + peer QUIC transport parameters.
 *
 * Server-side handshake: receive an Initial, decrypt, parse
 * CRYPTO frames, feed Tls13Engine, build server flight, split
 * across CRYPTO frames in Initial+Handshake packets, queue for
 * transmit. ACK per PN space. Mark handshake done on the
 * client's Handshake-level Finished.
 */
class QuicConnection
{
    /*
        Encryption levels. Mirror the QUIC v1 packet types
        with an extra slot for 1-RTT (which uses short-
        header packets, not long ones).
     */
    const LEVEL_INITIAL = 0;
    const LEVEL_HANDSHAKE = 1;
    const LEVEL_APPLICATION = 2;
    /*
        Connection states.
     */
    const ST_NEW = 0;
    const ST_HANDSHAKING = 1;
    const ST_ESTABLISHED = 2;
    const ST_CLOSED = 3;
    /**
     * @var int current connection state
     */
    public $state = self::ST_NEW;
    /**
     * @var Tls13Engine the TLS handshake engine
     */
    public $tls = null;
    /**
     * @var array level => ['rx' => QuicPacketKeys, 'tx' =>
     *      QuicPacketKeys]. Initial keys populated on first
     *      packet receipt; Handshake keys populated when
     *      Tls13Engine surfaces handshake-traffic secrets
     *      after ClientHello has been processed; 1-RTT
     *      keys populated when the TLS handshake completes
     *      (after client Finished).
     */
    public $keys = [];
    /**
     * @var array level => list of received packet numbers
     *      (for building outgoing ACK frames).
     */
    public $received_pns = [];
    /**
     * @var array level => next packet number to use for
     *      outgoing packets.
     */
    public $next_pn = [];
    /**
     * @var array level => largest received packet number
     *      so far (for packet-number recovery on the next
     *      receive).
     */
    public $largest_pn = [];
    /**
     * @var array level => bool. Set true when
     *      processPacketFrames sees an ACK-eliciting frame at
     *      that level; emit() clears it after sending the
     *      corresponding ACK. RFC 9000 sec 13.2.1: receiver
     *      MUST ack every ACK-eliciting packet within
     *      max_ack_delay. We do not delay; emit() drains the
     *      flag on the next call. Without this tracking, a
     *      1-RTT STREAM whose carrying packet arrives after
     *      ESTABLISHED is never acked and ngtcp2 clients
     *      retransmit indefinitely.
     */
    public $ack_pending = [
        self::LEVEL_INITIAL => false,
        self::LEVEL_HANDSHAKE => false,
        self::LEVEL_APPLICATION => false,
    ];
    /**
     * @var array level => packet_number => entry. Every packet
     *      emit() has encrypted and queued for sendto, until
     *      the peer ACKs it or we declare it lost. Entry shape:
     *          'pn' => int packet number
     *          'time_sent' => float microtime(true)
     *          'ack_eliciting' => bool, whether the packet
     *                             carries any ack-eliciting
     *                             frames; non-eliciting packets
     *                             are tracked for congestion
     *                             accounting but do not advance
     *                             loss detection
     *          'in_flight' => bool, anything except pure
     *                             ACK frames (RFC 9002 A.1)
     *          'sent_bytes' => int wire length, summed into
     *                             bytes_in_flight
     *          'frames' => array of decoded frame dicts;
     *                             walked when declaring a packet
     *                             lost to requeue underlying
     *                             CRYPTO / STREAM bytes
     *      Consumed by processAck (ACK-covered entries removed)
     *      and the PTO timer (oldest unACKed ack-eliciting
     *      entry sets the loss-detection deadline).
     */
    public $sent_packets = [
        self::LEVEL_INITIAL => [],
        self::LEVEL_HANDSHAKE => [],
        self::LEVEL_APPLICATION => [],
    ];
    /**
     * @var float|null microtime(true) at which the most
     *      recently observed largest-acked packet was
     *      originally sent. Phase 11b folds this into
     *      smoothed_rtt and rttvar; Phase 11a only
     *      records it.
     */
    public $latest_rtt = null;
    /**
     * @var float|null exponentially-smoothed RTT estimate
     *      per RFC 9002 sec 5.3. First sample seeds the
     *      EWMA (smoothed_rtt = latest_rtt, rttvar =
     *      latest_rtt / 2); subsequent samples blend
     *      latest_rtt at weight 1/8 against the prior
     *      smoothed_rtt at weight 7/8. Null until the
     *      first ack-eliciting packet is acknowledged.
     */
    public $smoothed_rtt = null;
    /**
     * @var float|null RTT variance estimator per RFC 9002
     *      sec 5.3. Half of latest_rtt on first sample,
     *      then EWMA at weight 1/4 against |smoothed_rtt -
     *      latest_rtt|.
     */
    public $rttvar = null;
    /**
     * @var float|null minimum observed RTT sample. RFC
     *      9002 sec 5.2: used to clamp ack_delay so a
     *      misbehaving (or simply long-paused) peer's
     *      reported ack_delay can't push smoothed_rtt
     *      below the observed floor.
     */
    public $min_rtt = null;
    /**
     * @var int RFC 9002 sec 6.2 PTO backoff exponent.
     *      Reset to 0 on every ACK that acknowledges new
     *      ack-eliciting packets; doubles each time the
     *      timer fires without progress. Effective PTO is
     *      base_pto << pto_count.
     */
    public $pto_count = 0;
    /**
     * @var float|null microtime(true) at which the
     *      probe-timeout timer fires. Set whenever there
     *      is at least one ack-eliciting packet in flight
     *      and cleared once sent_packets is empty (or all
     *      remaining entries are non-eliciting). The
     *      listener's tick loop dispatches
     *      onLossDetectionTimeout() when now >= this
     *      value.
     */
    public $loss_detection_timer = null;
    /**
     * @var array level => float|null. Earliest microtime
     *      at which a still-in-flight packet at this level
     *      will cross the RFC 9002 sec 6.1.2 time-
     *      threshold and be declared lost. Maintained by
     *      detectAndRemoveLostPackets(); consumed by
     *      setLossDetectionTimer() so the timer fires for
     *      a time-loss event rather than a PTO event when
     *      the former comes first.
     */
    public $loss_time = [
        self::LEVEL_INITIAL => null,
        self::LEVEL_HANDSHAKE => null,
        self::LEVEL_APPLICATION => null,
    ];
    /**
     * @var array level => int largest acknowledged packet
     *      number we have ever observed at this level.
     *      Loss detection (RFC 9002 sec 6.1.1) needs this
     *      to apply the packet-number reordering threshold
     *      against the most recent ACK rather than the one
     *      currently being processed.
     */
    public $largest_acked_pn = [
        self::LEVEL_INITIAL => -1,
        self::LEVEL_HANDSHAKE => -1,
        self::LEVEL_APPLICATION => -1,
    ];
    /**
     * @var float minimum loss-detection granularity per
     *      RFC 9002 sec A.2 (kGranularity). Clamps the
     *      4*rttvar term in the PTO formula so very
     *      small variance estimates don't shrink the PTO
     *      below useful resolution. Seconds.
     */
    const PTO_GRANULARITY_SEC = 0.001;
    /**
     * @var float fallback peer max_ack_delay in seconds.
     *      RFC 9000 sec 18.2: default value when the peer
     *      does not advertise transport parameter 0x0b.
     *      We currently use this constant for every peer
     *      because the H3Listener doesn't yet parse
     *      TP 0x0b out of EncryptedExtensions.
     */
    const PEER_MAX_ACK_DELAY_SEC = 0.025;
    /**
     * @var int RFC 9002 sec 6.1.1 kPacketThreshold. A
     *      packet is declared lost via the reordering
     *      threshold when its packet number is at least
     *      this many below the largest acknowledged packet
     *      in the same number space. The value of 3 is
     *      the RFC's recommended default; smaller values
     *      cause spurious retransmissions on out-of-order
     *      delivery, larger values delay loss recovery.
     */
    const LOSS_PKT_THRESHOLD = 3;
    /**
     * @var float RFC 9002 sec 6.1.2 kTimeThreshold,
     *      expressed as a multiplier on max(latest_rtt,
     *      smoothed_rtt). A packet is declared lost via
     *      the time threshold when it was sent more than
     *      kTimeThreshold * max(latest_rtt, smoothed_rtt)
     *      ago. The 9/8 default tolerates one round of
     *      delayed-ACK without false-positive loss
     *      declarations.
     */
    const LOSS_TIME_THRESHOLD = 1.125;
    /**
     * @var int RFC 9002 sec B.2 kInitialWindow. The
     *      initial congestion window in bytes; here
     *      14 * MAX_DATAGRAM_SIZE = 14 * 1200, matching
     *      the RFC's recommended starting point. Smaller
     *      values delay cwnd's exit from slow-start;
     *      larger values invite congestion on bandwidth-
     *      constrained paths.
     */
    const CC_INITIAL_WINDOW_BYTES = 16800;
    /**
     * @var int RFC 9002 sec B.2 kMinimumWindow. cwnd
     *      never falls below this even after loss. Two
     *      max-datagrams' worth ensures we can always
     *      send at least one ack-eliciting probe.
     */
    const CC_MINIMUM_WINDOW_BYTES = 2400;
    /**
     * @var int the maximum-size datagram we transmit, in
     *      bytes. Used as the MSS in cwnd arithmetic.
     *      Conservative 1200 since we don't yet probe
     *      Path MTU and 1200 is the RFC 9000 sec 14.1
     *      minimum every QUIC implementation must accept.
     */
    const CC_MAX_DATAGRAM_BYTES = 1200;
    /**
     * @var int RFC 9002 sec B.2 kLossReductionFactor as a
     *      pair of integers (numerator / denominator) so
     *      we can multiply cwnd in integer arithmetic.
     *      0.5 is NewReno's recommended halving.
     */
    const CC_LOSS_REDUCTION_NUMERATOR = 1;
    const CC_LOSS_REDUCTION_DENOMINATOR = 2;
    /**
     * @var int RFC 9000 sec 8.1 anti-amplification factor.
     *      Before path validation, the server MUST NOT send
     *      more than this many times the bytes received from
     *      the client. The path is validated implicitly when
     *      the server receives a Handshake-level packet whose
     *      AEAD authenticates (only the legitimate client can
     *      produce one), at which point the cap lifts.
     */
    const ANTI_AMP_FACTOR = 3;
    /**
     * @var int per-packet overhead headroom for the
     *      anti-amplification gate. Bounds the difference
     *      between the unencrypted payload length we have at
     *      gate time and the encoded wire-packet length
     *      (header + variable PN + 16-byte AEAD tag). Long-
     *      header packets carry the largest header so 80 is
     *      a safe upper bound for any real QUIC v1 packet
     *      atto produces.
     */
    const ANTI_AMP_PACKET_OVERHEAD = 80;
    /**
     * @var int total bytes of packets that have been
     *      handed to the network and are not yet
     *      acknowledged or declared lost. Bookkeeping
     *      lives in addToBytesInFlight() /
     *      removeFromBytesInFlight() which are called from
     *      every site that adds to or removes from
     *      sent_packets. emit() consults this against
     *      congestion_window before encrypting a queued
     *      payload.
     */
    public $bytes_in_flight = 0;
    /**
     * @var int RFC 9002 sec 7 congestion window in bytes.
     *      Starts at CC_INITIAL_WINDOW_BYTES, grows on
     *      ACK (slow-start while < ssthresh, then linear
     *      congestion-avoidance), drops to ssthresh on
     *      declared-lost. Floor at CC_MINIMUM_WINDOW_BYTES.
     */
    public $congestion_window = self::CC_INITIAL_WINDOW_BYTES;
    /**
     * @var int slow-start threshold. Stays at PHP_INT_MAX
     *      until first loss event; dropping below pushes
     *      cwnd updates from exponential to linear. Per
     *      RFC 9002 sec 7.3 the threshold is set to half
     *      the in-flight cwnd at the moment of loss.
     */
    public $ssthresh = PHP_INT_MAX;
    /**
     * @var float|null microtime(true) at which the most
     *      recent loss event was observed. ACKs that
     *      acknowledge packets sent before this timestamp
     *      do NOT grow cwnd (RFC 9002 sec 7.3.2 fast-
     *      recovery: the connection stays in recovery
     *      until the largest pre-loss packet is acked).
     *      Null when not in a recovery period.
     */
    public $congestion_recovery_start = null;
    /**
     * @var array level => crypto data byte buffer
     *      (offset => bytes) and next-expected-offset for
     *      in-order delivery to Tls13Engine.
     */
    public $crypto_buf = [
        self::LEVEL_INITIAL => ['chunks' => [],
            'next_offset' => 0],
        self::LEVEL_HANDSHAKE => ['chunks' => [],
            'next_offset' => 0],
        self::LEVEL_APPLICATION => ['chunks' => [],
            'next_offset' => 0],
    ];
    /**
     * @var int outgoing CRYPTO frame offset per level
     *      (we never split or reorder our own crypto
     *      stream, but the offset must still be tracked).
     */
    public $crypto_send_offset = [
        self::LEVEL_INITIAL => 0,
        self::LEVEL_HANDSHAKE => 0,
        self::LEVEL_APPLICATION => 0,
    ];
    /**
     * @var string the destination connection ID the peer
     *      uses when sending packets to us. Initially
     *      taken from the client's first Initial.
     */
    public $local_cid = "";
    /**
     * @var string the destination connection ID we use
     *      when sending packets to the peer. Initially
     *      taken from the client's source CID.
     */
    public $peer_cid = "";
    /**
     * @var array path-validation state for client-initiated
     *      migration per RFC 9000 sec 8.2 + sec 9. Empty when
     *      no migration is in progress. Populated when an
     *      inbound datagram arrives from a source address
     *      different from the one the H3Listener has recorded
     *      for this connection. Shape:
     *        'address' => string "ip:port" of the
     *                          alternative path
     *        'challenge' => string 8 random bytes that the
     *                          peer must echo via PATH_-
     *                          RESPONSE on the alternative
     *                          path
     *        'first_seen' => float microtime when validation
     *                          began (used for timeout)
     *        'response_received' => bool flipped true when
     *                          the matching PATH_RESPONSE
     *                          arrives; the H3Listener
     *                          consults this to perform the
     *                          peer_address swap and CC reset
     *      The H3Listener owns peer_address and the address-
     *      change detection; QuicConnection owns the wire-
     *      level challenge/response correlation. Splitting
     *      it this way keeps the per-path bookkeeping where
     *      it can see all addresses (the listener) while the
     *      protocol logic stays with the QUIC stack.
     */
    public $pending_path = [];
    /**
     * @var array list of 8-byte data values pending an
     *      outbound PATH_RESPONSE frame. Filled when an
     *      inbound PATH_CHALLENGE is parsed; drained by
     *      emit() onto the same path the challenge arrived
     *      on (so the peer can validate its own path).
     */
    public $path_responses_pending = [];
    /**
     * @var array sequence => cid_bytes for every local CID
     *      we've issued to the peer. Sequence 0 is the
     *      initial $local_cid (set in the constructor);
     *      additional entries are added as we emit
     *      NEW_CONNECTION_ID frames after the handshake to
     *      fill the peer's active_connection_id_limit.
     *      Entries are removed when the peer sends
     *      RETIRE_CONNECTION_ID with the matching sequence,
     *      at which point we top the pool back up.
     */
    public $issued_cids = [];
    /**
     * @var int sequence number to assign to the next CID we
     *      issue. Starts at 1 because seq 0 is reserved for
     *      $local_cid (issued during the handshake via the
     *      long-header SCID).
     */
    public $cid_seq_next = 1;
    /**
     * @var int how many CIDs we make active for the peer at
     *      a time. RFC 9000 sec 18.2 caps the count at the
     *      peer's active_connection_id_limit transport
     *      parameter; we top the pool up to that minus 1
     *      (since seq 0 is the original $local_cid).
     */
    public $active_cid_limit_peer = 2;
    /**
     * @var array list of [sequence, cid_bytes,
     *      stateless_reset_token] pending emit() of a
     *      NEW_CONNECTION_ID frame. fillCidPool() pushes
     *      onto this; the emit loop drains it into 1-RTT
     *      packets after ST_ESTABLISHED.
     */
    public $new_cids_pending = [];
    /**
     * @var string 32-byte secret keying material for
     *      deriving stateless-reset tokens (RFC 9000 sec
     *      10.3). Stamped onto the connection by the
     *      listener at construction time so all connections
     *      under one listener use the same token derivation
     *      key. Empty in unit-test contexts; fallback there
     *      is a random per-call token.
     */
    public $stateless_reset_secret = "";
    /**
     * @var callable|null callback invoked whenever the peer
     *      retires one of our local CIDs. Receives the
     *      retired CID bytes; the listener uses it to drop
     *      the corresponding routing-table entry. Set by
     *      the listener at construction time. Stays null
     *      in unit-test contexts; the protocol logic still
     *      runs and retireLocalCid() still issues a
     *      replacement, the listener just doesn't get
     *      notified.
     */
    public $on_cid_retired = null;
    /**
     * @var string the original DCID the client used on
     *      its first Initial -- this is what derives
     *      Initial keys, and we must echo it as our
     *      original_destination_connection_id transport
     *      parameter.
     */
    public $original_dcid = "";
    /**
     * @var array stream_id => QuicStream
     */
    public $streams = [];
    /**
     * @var array of [level, packet_bytes] -- packets queued
     *      to send on the next emit() call.
     */
    public $send_queue = [];
    /**
     * @var string verbatim QUIC transport parameters from
     *      the peer's TLS handshake (parsed by the QUIC
     *      layer in Phase 4 when HTTP/3 cares about them).
     */
    public $peer_transport_params = "";
    /**
     * @var string our QUIC transport parameters, encoded
     *      ready to drop into the TLS quic_transport_-
     *      parameters extension.
     */
    public $local_transport_params = "";
    /**
     * @var string most recent error (empty on success).
     */
    public $error = "";
    /**
     * @var bool whether we have already queued the
     *      HANDSHAKE_DONE frame on the 1-RTT level.
     *      Server sends this exactly once, immediately
     *      after handshake completion (RFC 9001 sec 4.1.2).
     */
    public $handshake_done_sent = false;
    /**
     * @var float Unix time the connection was created.
     *      Used by the listener to expire stuck handshakes.
     */
    public $created_at = 0.0;
    /**
     * @var float Unix time of the most recent inbound or
     *      outbound packet. Drives the idle-timeout
     *      check.
     */
    public $last_packet_at = 0.0;
    /**
     * @var int total UDP bytes received on this
     *      connection (raw datagram bytes, including
     *      packets we couldn't decrypt).
     */
    public $stats_bytes_received = 0;
    /**
     * @var int total UDP bytes sent on this connection.
     */
    public $stats_bytes_sent = 0;
    /**
     * @var int total packets received successfully (at
     *      any encryption level).
     */
    public $stats_packets_received = 0;
    /**
     * @var int total packets sent.
     */
    public $stats_packets_sent = 0;
    /**
     * @var int peer's max_idle_timeout transport
     *      parameter, in milliseconds. Defaults to 30s
     *      until parsed from peer's TPs in Phase 5+;
     *      Phase 4 didn't surface this from
     *      Tls13Engine::clientQuicTransportParameters.
     */
    public $peer_max_idle_ms = 30000;
    /**
     * @var int peer's initial_max_data transport parameter
     *      (TP id 0x04, RFC 9000 sec 18.2). The maximum
     *      number of bytes we may send across all streams
     *      until the peer grants more via MAX_DATA. Default
     *      until the peer's TPs are parsed is large enough
     *      to handle a 1 MiB response without immediate
     *      stall. Raised when the peer sends MAX_DATA
     *      frames; flushStreams enforces it against
     *      $conn_data_sent so the connection never sends
     *      stream bytes past the granted credit.
     */
    public $peer_initial_max_data = 16777216;
    /**
     * @var int total new stream-payload bytes sent on this
     *      connection across all streams, the quantity RFC
     *      9000 sec 4.1 counts against the peer's MAX_DATA
     *      credit. Retransmissions re-send recorded frames
     *      and do not count again.
     */
    public $conn_data_sent = 0;
    /**
     * @var int peer's initial_max_stream_data_bidi_local
     *      (TP id 0x05, RFC 9000 sec 18.2): the receive cap
     *      the peer applies to streams the peer itself
     *      initiated. Server-initiated responses to a
     *      client-opened bidi request stream are bound by
     *      this value. Default 16 MiB until parsed.
     */
    public $peer_initial_max_stream_data_bidi_local = 16777216;
    /**
     * @var int peer's initial_max_stream_data_bidi_remote
     *      (TP id 0x06): cap the peer applies to streams
     *      the local endpoint initiates. Used when the
     *      server opens a bidi stream toward the client
     *      (rare in HTTP/3; mostly for symmetry).
     */
    public $peer_initial_max_stream_data_bidi_remote = 16777216;
    /**
     * @var int peer's initial_max_stream_data_uni (TP id
     *      0x07): cap on uni streams the local endpoint
     *      opens (for example, the HTTP/3 server control
     *      stream). Default 16 MiB.
     */
    public $peer_initial_max_stream_data_uni = 16777216;
    /**
     * Constructs a server-side connection. $cert_pem and
     * $key_pem are the server's certificate and key for
     * the TLS 1.3 handshake; $alpn is the list of ALPN
     * byte-strings the server offers.
     * @param string $cert_pem certificate in PEM format
     * @param string $key_pem private key in PEM format
     * @param mixed $alpn alpn parameter
     */
    public function __construct($cert_pem, $key_pem, $alpn)
    {
        $this->created_at = microtime(true);
        $this->last_packet_at = $this->created_at;
        /*
            Generate our own connection ID. This is what the
            peer will use as DCID on packets after the first
            Initial; we look up the connection by this value.
            8 bytes is the conventional length.
         */
        $this->local_cid = random_bytes(8);
        /*
            Sequence 0 in the CID pool is the original CID we
            generated above; record it now so RETIRE_-
            CONNECTION_ID(seq=0) can find it later if the
            peer migrates off this CID first.
         */
        $this->issued_cids[0] = $this->local_cid;
        $this->local_transport_params =
            self::buildLocalTransportParams();
        $this->tls = new Tls13Engine($cert_pem, $key_pem,
            $alpn, $this->local_transport_params);
        if ($this->tls->getError()) {
            $this->error = $this->tls->getError();
            $this->state = self::ST_CLOSED;
            return;
        }
        $this->next_pn = [self::LEVEL_INITIAL => 0,
            self::LEVEL_HANDSHAKE => 0,
            self::LEVEL_APPLICATION => 0];
        $this->largest_pn = [self::LEVEL_INITIAL => -1,
            self::LEVEL_HANDSHAKE => -1,
            self::LEVEL_APPLICATION => -1];
        $this->received_pns = [self::LEVEL_INITIAL => [],
            self::LEVEL_HANDSHAKE => [],
            self::LEVEL_APPLICATION => []];
    }
    /**
     * Builds the transport parameters block per RFC 9000
     * sec 18. Each parameter is (varint id, varint length,
     * value). Phase 3 emits a small fixed set: enough for
     * a real client to accept the handshake. Phase 4 will
     * extend this.
     * @return string serialized local QUIC transport parameters extension
     */
    protected static function buildLocalTransportParams()
    {
        $tp = "";
        $tp .= self::tpVarint(0x04, 1048576);
        /* initial_max_data = 1 MiB */
        $tp .= self::tpVarint(0x05, 1048576);
        /* initial_max_stream_data_bidi_local */
        $tp .= self::tpVarint(0x06, 1048576);
        /* initial_max_stream_data_bidi_remote */
        $tp .= self::tpVarint(0x07, 1048576);
        /* initial_max_stream_data_uni */
        $tp .= self::tpVarint(0x08, 100);
        /* initial_max_streams_bidi */
        $tp .= self::tpVarint(0x09, 100);
        /* initial_max_streams_uni */
        $tp .= self::tpVarint(0x01, 30000);
        /* max_idle_timeout in milliseconds */
        $tp .= self::tpVarint(0x03, 1452);
        /* max_udp_payload_size */
        $tp .= self::tpVarint(0x0e, 4);
        /*
            active_connection_id_limit (RFC 9000 sec 18.2).
            The peer may keep up to this many CIDs active
            for us at once; we offer 4 so the client has
            headroom for a couple of NAT rebindings without
            re-handshaking.
         */
        return $tp;
    }
    /**
     * Helper: encodes one transport parameter whose value
     * is a single varint.
     * @param mixed $id id parameter
     * @param mixed $value value
     * @return string varint-encoded transport-parameter value
     */
    protected static function tpVarint($id, $value)
    {
        $val = QuicVarint::write($value);
        return QuicVarint::write($id) .
            QuicVarint::write(strlen($val)) . $val;
    }
    /**
     * Helper: encodes one transport parameter whose value
     * is opaque bytes (used for the connection-ID-binding
     * parameters: original_destination_connection_id,
     * initial_source_connection_id, retry_source_-
     * connection_id).
     * @param mixed $id id parameter
     * @param string $bytes bytes to operate on
     * @return string serialized transport-parameter id+value pair
     */
    protected static function tpBytes($id, $bytes)
    {
        return QuicVarint::write($id) .
            QuicVarint::write(strlen($bytes)) . $bytes;
    }
    /**
     * Main entry: feeds a UDP datagram from $peer into the
     * connection. Decodes any contained QUIC packets,
     * processes their frames, advances the handshake,
     * queues outgoing packets onto $this->send_queue.
     *
     * Returns true on success, false on fatal error
     * (caller should close the connection).
     * @param string $buf raw byte buffer
     * @param string $peer peer address as returned by stream_socket_recvfrom
     * @return void no return; the datagram is processed in place
     */
    public function processDatagram($buf, $peer)
    {
        $this->last_packet_at = microtime(true);
        $buf_len = strlen($buf);
        $this->stats_bytes_received += $buf_len;
        $local_cid_len = strlen($this->local_cid);
        $off = 0;
        while ($off < $buf_len) {
            $start = $off;
            $first = ord($buf[$off]);
            if (($first & 0x80) === 0) {
                /*
                    Short-header (1-RTT) packet, OR trailing
                    UDP-level padding bytes after a long-
                    header packet. If we have 1-RTT keys
                    (handshake complete), try to decode;
                    otherwise treat as padding and break.
                 */
                if (!isset(
                    $this->keys[self::LEVEL_APPLICATION])) {
                    break;
                }
                $level = self::LEVEL_APPLICATION;
                $level_keys = $this->keys[$level];
                $largest_pn = $this->largest_pn[$level];
                $result = QuicPacket::decodeShort($buf,
                    $start,
                    $level_keys['rx'],
                    $local_cid_len,
                    $largest_pn);
                $pkt = $result[0];
                $end = $result[1];
                if (getenv('ATTO_H3_TRACE')) {
                    $err = $result[2] ?? '';
                    error_log(sprintf(
                        "[H3TRACE]   decode level=2 "
                        . "result=%s err=%s end=%d "
                        . "pn=%s",
                        $pkt === false ? 'fail' : 'ok',
                        $err, $end,
                        $pkt === false ? '?'
                            : (string) $pkt->packet_number));
                }
                if ($pkt === false) {
                    break;
                }
                $off = $end;
                $this->stats_packets_received++;
                $pn = $pkt->packet_number;
                $this->received_pns[$level][] = $pn;
                if ($pn > $largest_pn) {
                    $this->largest_pn[$level] = $pn;
                }
                $this->processPacketFrames($level, $pkt);
                continue;
            }
            /* Long-header packet. Determine the level
               from bits 4-5, then derive / look up the
               keys for that level. */
            $long_type = ($first >> 4) & 0x03;
            if ($long_type === QuicPacket::LONG_INITIAL) {
                $level = self::LEVEL_INITIAL;
                /* Bootstrap Initial keys from the DCID on
                   the first Initial. We need the DCID to
                   derive keys before we can decrypt. */
                if (!isset($this->keys[$level])) {
                    $dcid = self::peekInitialDcid($buf,
                        $start);
                    if ($dcid === false) {
                        return true;
                    }
                    /*
                        Save the client's original DCID
                        (used to derive Initial keys and
                        echoed in the
                        original_destination_connection_id
                        transport parameter). Do NOT
                        overwrite our own local_cid -- the
                        server uses its own freshly-
                        generated CID for everything it
                        sends.
                     */
                    $this->original_dcid = $dcid;
                    $pair = QuicPacketKeys::fromInitialDcid(
                        $dcid);
                    /* Server perspective: client encrypts
                       with client keys, server decrypts
                       with client keys. Server encrypts
                       with server keys for replies. */
                    $this->keys[$level] = [
                        'rx' => $pair['client'],
                        'tx' => $pair['server']];
                }
            } else if ($long_type ===
                QuicPacket::LONG_HANDSHAKE) {
                $level = self::LEVEL_HANDSHAKE;
                if (!isset($this->keys[$level])) {
                    /* We can't decrypt Handshake-level
                       packets until our Tls13Engine has
                       surfaced handshake-traffic secrets
                       (which happens during
                       buildServerFlight()). If we get a
                       Handshake packet before then,
                       discard it. */
                    return true;
                }
            } else {
                /* 0-RTT and Retry: not implemented in
                   Phase 3. */
                return true;
            }
            $result = QuicPacket::decode($buf, $start,
                $this->keys[$level]['rx'], true,
                $this->largest_pn[$level]);
            $pkt = $result[0];
            $end = $result[1];
            $err = $result[2] ?? '';
            if (getenv('ATTO_H3_TRACE')) {
                error_log(sprintf(
                    "[H3TRACE]   decode level=%d "
                    . "result=%s err=%s end=%d",
                    $level,
                    $pkt === false ? 'fail' : 'ok',
                    $err, $end));
            }
            if ($pkt === false) {
                /* Could not decode this packet (HP/AEAD
                   failure or truncation). Per RFC 9000
                   sec 5.2.2, drop and continue scanning
                   the datagram for more packets. */
                if ($end <= $start) {
                    /* No progress; bail to avoid loop. */
                    return true;
                }
                $off = $end;
                continue;
            }
            $off = $end;
            $this->stats_packets_received++;
            $pn = $pkt->packet_number;
            $this->received_pns[$level][] = $pn;
            if ($pn > $this->largest_pn[$level]) {
                $this->largest_pn[$level] = $pn;
            }
            $this->processPacketFrames($level, $pkt);
        }
        $this->driveHandshake();
        return true;
    }
    /**
     * Reads the destination connection ID out of a
     * long-header Initial packet without parsing the
     * whole packet -- needed before keys are available.
     * @param string $buf raw byte buffer
     * @param int $off byte offset into the buffer
     * @return string|false destination Connection ID from an Initial packet, or false if not an Initial
     */
    protected static function peekInitialDcid($buf, $off)
    {
        $buf_len = strlen($buf);
        if ($buf_len < $off + 7) {
            return false;
        }
        $dcid_len = ord($buf[$off + 5]);
        if ($buf_len < $off + 6 + $dcid_len) {
            return false;
        }
        return substr($buf, $off + 6, $dcid_len);
    }
    /**
     * Walks the frames in a decoded packet and dispatches
     * each to its handler. Phase 3 routes CRYPTO,
     * STREAM, ACK, PADDING, PING, CONNECTION_CLOSE; the
     * rest are accepted but ignored.
     * @param int $level encryption level
     * @param mixed $pkt pkt parameter
     */
    protected function processPacketFrames($level, $pkt)
    {
        list($frames, $err) = QuicFrame::decodeAll(
            $pkt->payload);
        if ($err !== '' && $err !== 'unknown frame type') {
            /* Partial decode -- still process what we got. */
        }
        foreach ($frames as $f) {
            if (self::isAckEliciting($f['type'])) {
                $this->ack_pending[$level] = true;
            }
            switch ($f['type']) {
                case QuicFrame::F_CRYPTO:
                    $this->onCrypto($level, $f);
                    break;
                case QuicFrame::F_STREAM_BASE:
                    $this->onStream($f);
                    break;
                case QuicFrame::F_ACK:
                case QuicFrame::F_ACK_ECN:
                    $this->processAck($level, $f);
                    break;
                case QuicFrame::F_PING:
                case QuicFrame::F_PADDING:
                case QuicFrame::F_HANDSHAKE_DONE:
                case QuicFrame::F_NEW_CONNECTION_ID:
                case QuicFrame::F_NEW_TOKEN:
                    /*
                        NEW_CONNECTION_ID from the peer adds
                        to the pool of DCIDs we may use on
                        outbound packets. atto does not yet
                        actively migrate (we always reply to
                        the original $peer_cid), so we
                        accept the frame -- the peer needs
                        us to ack it so it can rotate its
                        own pool -- but discard the values.
                        Activating peer-side migration is a
                        follow-up phase.
                     */
                    break;
                case QuicFrame::F_RETIRE_CONNECTION_ID:
                    /*
                        Peer is dropping one of the local
                        CIDs we issued. Remove it from
                        $issued_cids, tell the listener to
                        drop its routing entry, and queue
                        a fresh NEW_CONNECTION_ID to top
                        the pool back up. RFC 9000 sec
                        19.16: it's a protocol violation
                        for the peer to RETIRE a sequence
                        we never issued, but we tolerate
                        it (idempotently no-op).
                     */
                    $retired_cid = $this->retireLocalCid(
                        $f['sequence']);
                    if ($retired_cid !== ''
                        && $this->on_cid_retired !== null) {
                        call_user_func(
                            $this->on_cid_retired,
                            $retired_cid);
                    }
                    break;
                case QuicFrame::F_MAX_DATA:
                    if ($f['value'] >
                            $this->peer_initial_max_data) {
                        $this->peer_initial_max_data =
                            (int) $f['value'];
                    }
                    if (getenv('ATTO_H3_TRACE')) {
                        error_log(sprintf(
                            "[H3TRACE]   F_MAX_DATA "
                            . "value=%d", (int) $f['value']));
                    }
                    break;
                case QuicFrame::F_MAX_STREAM_DATA:
                    if (isset(
                        $this->streams[$f['stream_id']])) {
                        $stream = $this->streams[
                            $f['stream_id']];
                        if ($f['value'] >
                                $stream->send_window) {
                            $stream->send_window =
                                (int) $f['value'];
                        }
                    }
                    if (getenv('ATTO_H3_TRACE')) {
                        error_log(sprintf(
                            "[H3TRACE]   F_MAX_STREAM_DATA "
                            . "sid=%d value=%d",
                            (int) $f['stream_id'],
                            (int) $f['value']));
                    }
                    break;
                case QuicFrame::F_RESET_STREAM:
                    /*
                        Peer abandoned the send side of a
                        stream. Mark the receive half done
                        and surface anything we have. RFC
                        9000 sec 3.5: receiver may discard
                        any buffered data; we keep what we
                        have so the app can read partial
                        results, but no more bytes will
                        arrive.
                     */
                    if (isset(
                        $this->streams[$f['stream_id']])) {
                        $stream = $this->streams[
                            $f['stream_id']];
                        $stream->recv_state =
                            QuicStream::RECV_RESET;
                    }
                    break;
                case QuicFrame::F_STOP_SENDING:
                    /*
                        Peer asked us to stop sending on a
                        stream. Mark the send half reset so
                        flushStreams skips it. RFC 9000 sec
                        3.5 also requires us to send
                        RESET_STREAM in response, but for
                        now we just stop pushing data; the
                        peer will see no more frames and
                        the connection's idle timer will
                        eventually clean up.
                     */
                    if (isset(
                        $this->streams[$f['stream_id']])) {
                        $stream = $this->streams[
                            $f['stream_id']];
                        $stream->send_state =
                            QuicStream::SEND_RESET;
                    }
                    break;
                case QuicFrame::F_CONNECTION_CLOSE:
                case QuicFrame::F_CONNECTION_CLOSE_APP:
                    $this->state = self::ST_CLOSED;
                    return;
                case QuicFrame::F_PATH_CHALLENGE:
                    /*
                        RFC 9000 sec 8.2.2: server MUST echo
                        the 8-byte data verbatim in a PATH_-
                        RESPONSE on the same path the
                        challenge arrived on. Queue here;
                        emit() encodes the frame.
                     */
                    $this->path_responses_pending[] =
                        $f['data'];
                    break;
                case QuicFrame::F_PATH_RESPONSE:
                    /*
                        RFC 9000 sec 8.2.2: a PATH_RESPONSE
                        whose 8-byte data matches a challenge
                        we sent confirms the alternative path.
                        Mark the pending entry; the listener
                        will see this on its next inspection
                        and perform the peer_address swap +
                        CC reset.
                     */
                    if (!empty($this->pending_path)
                        && $this->pending_path['challenge']
                        === $f['data']) {
                        $this->pending_path[
                            'response_received'] = true;
                    }
                    break;
                /* All other frame types: silently ignore.
                   They aren't needed to complete a basic
                   handshake. */
            }
            /* On the first Initial packet, capture the
               peer's source connection ID so we know
               where to send our reply. */
            if ($this->peer_cid === '' &&
                $pkt->source_cid !== '') {
                $this->peer_cid = $pkt->source_cid;
            }
        }
    }
    /**
     * CRYPTO frame handler: append the bytes to the
     * level's crypto receive buffer (offset-keyed for
     * reassembly), then deliver any complete TLS
     * handshake messages to the engine.
     *
     * A complete TLS handshake message is type byte +
     * uint24 length + body, so 4+length bytes total. We
     * may receive partial messages across multiple CRYPTO
     * frames; the buffer accumulates until enough bytes
     * are present.
     * @param int $level encryption level
     * @param mixed $f f parameter
     */
    protected function onCrypto($level, $f)
    {
        $buf = &$this->crypto_buf[$level];
        $buf['chunks'][$f['offset']] = $f['data'];
        /* Coalesce contiguous chunks starting at next_off
           into a single accumulator string. */
        if (!isset($buf['accum'])) {
            $buf['accum'] = '';
        }
        while (isset($buf['chunks'][$buf['next_offset']])) {
            $chunk = $buf['chunks'][$buf['next_offset']];
            unset($buf['chunks'][$buf['next_offset']]);
            $buf['next_offset'] += strlen($chunk);
            $buf['accum'] .= $chunk;
        }
        /* Drain complete TLS messages from accum. */
        while (strlen($buf['accum']) >= 4) {
            $msg_len = (ord($buf['accum'][1]) << 16) |
                (ord($buf['accum'][2]) << 8) |
                ord($buf['accum'][3]);
            $total = 4 + $msg_len;
            if (strlen($buf['accum']) < $total) {
                break;
            }
            $msg = substr($buf['accum'], 0, $total);
            $buf['accum'] = substr($buf['accum'], $total);
            $this->feedTlsCrypto($level, $msg);
        }
    }
    /**
     * Routes crypto bytes from one encryption level to the
     * appropriate Tls13Engine method. Initial-level CRYPTO
     * carries ClientHello; Handshake-level CRYPTO carries
     * the client's Finished after the server flight has
     * been sent.
     * @param int $level encryption level
     * @param string $bytes bytes to operate on
     */
    protected function feedTlsCrypto($level, $bytes)
    {
        if (getenv('ATTO_H3_TRACE')) {
            error_log(sprintf(
                "[H3TRACE]   feedTlsCrypto level=%d "
                . "bytes=%dB tls_err=%s",
                $level, strlen($bytes),
                $this->tls->getError() === ''
                    ? '(none)' : $this->tls->getError()));
        }
        if ($level === self::LEVEL_INITIAL) {
            $ok = $this->tls->feedClientHello($bytes);
            if (getenv('ATTO_H3_TRACE')) {
                error_log(sprintf(
                    "[H3TRACE]   feedClientHello "
                    . "returned=%s err=%s",
                    $ok ? 'true' : 'false',
                    $this->tls->getError() === ''
                        ? '(none)' : $this->tls->getError()
                ));
            }
            return;
        }
        if ($level === self::LEVEL_HANDSHAKE) {
            $this->tls->feedClientFinished($bytes);
            if ($this->tls->isComplete()) {
                $this->state = self::ST_ESTABLISHED;
            }
            return;
        }
    }
    /**
     * Picks the per-stream send-window cap for a stream of
     * the given ID, based on the peer's transport parameters
     * and the stream's "kind" (low 2 bits per RFC 9000 sec
     * 2.1). For HTTP/3:
     *   0b00 client-initiated bidi: server replies bound by
     *        peer's initial_max_stream_data_bidi_local
     *   0b01 server-initiated bidi: bound by bidi_remote
     *   0b03 server-initiated uni  (control stream): bound
     *        by initial_max_stream_data_uni
     *   0b02 client-initiated uni  (encoder/decoder/QPACK):
     *        receive-side from server's perspective; we
     *        return a sane fallback for symmetry.
     * @param mixed $sid sid parameter
     * @return int number of bytes that may be sent on the stream right now
     */
    protected function pickStreamSendWindow($sid)
    {
        $kind = $sid & 0x03;
        if ($kind === 0x00) {
            return
                $this->peer_initial_max_stream_data_bidi_local;
        }
        if ($kind === 0x01) {
            return
                $this->peer_initial_max_stream_data_bidi_remote;
        }
        if ($kind === 0x03) {
            return $this->peer_initial_max_stream_data_uni;
        }
        return 1048576;
    }
    /**
     * STREAM frame handler: route to the per-stream
     * QuicStream, allocating one if this is the first
     * frame on that stream ID.
     * @param mixed $f f parameter
     */
    protected function onStream($f)
    {
        $sid = $f['stream_id'];
        if (!isset($this->streams[$sid])) {
            $this->streams[$sid] = new QuicStream($sid,
                1048576, $this->pickStreamSendWindow($sid));
        }
        $this->streams[$sid]->deliverIncoming(
            $f['offset'], $f['data'], $f['fin']);
    }
    /**
     * Advances the handshake whenever something has just
     * changed (typically: just received a CRYPTO frame).
     * Walks the TLS engine's state and queues the
     * appropriate outgoing packets.
     */
    protected function driveHandshake()
    {
        if (getenv('ATTO_H3_TRACE')) {
            error_log(sprintf(
                "[H3TRACE]   driveHandshake state=%d "
                . "tls_complete=%s tls_err=%s",
                $this->state,
                $this->tls->isComplete() ? 'yes' : 'no',
                $this->tls->getError() === ''
                    ? '(none)' : $this->tls->getError()));
        }
        if ($this->tls->getError() !== '') {
            $this->error = $this->tls->getError();
            $this->state = self::ST_CLOSED;
            return;
        }
        /* If we just received the ClientHello and haven't
           sent our flight yet, build it now. The
           hasClientHello() gate prevents us from trying to
           build a flight before any CH bytes have been
           parsed -- the case curl-with-quictls hits, since
           its CH straddles two QUIC Initials. */
        if ($this->state === self::ST_NEW &&
            $this->tls->hasClientHello() &&
            $this->tls->isComplete() === false) {
            $secrets = $this->tls->trafficSecrets();
            if (empty($secrets)) {
                /*
                    Extend our local transport parameters
                    with the two CID-binding fields that
                    require knowledge of the peer's first
                    Initial. The client validates these
                    against the actual on-wire CIDs and
                    drops the connection on mismatch.
                 */
                $tp = $this->local_transport_params .
                    self::tpBytes(0x00,
                        $this->original_dcid) .
                    self::tpBytes(0x0F,
                        $this->local_cid);
                $this->tls->setServerQuicTransportParameters(
                    $tp);
                $flight = $this->tls->buildServerFlight(
                    'quic');
                if (getenv('ATTO_H3_TRACE')) {
                    error_log(sprintf(
                        "[H3TRACE]   buildServerFlight "
                        . "result=%s flight_len=%d "
                        . "cipher=0x%04x group=0x%04x "
                        . "tls_err=%s",
                        $flight === false ? 'fail' : 'ok',
                        $flight === false ? 0
                            : strlen($flight),
                        $this->tls->negotiatedCipher(),
                        $this->tls->selectedGroup(),
                        $this->tls->getError() === ''
                            ? '(none)'
                            : $this->tls->getError()));
                }
                if ($flight === false) {
                    $this->error = $this->tls->getError();
                    $this->state = self::ST_CLOSED;
                    return;
                }
                $this->splitServerFlight($flight);
                /* After buildServerFlight, the TLS engine
                   has 'c_hs' and 's_hs' secrets ready --
                   Handshake-level keys can be derived. */
                $secrets = $this->tls->trafficSecrets();
                /*
                    Use whatever cipher TLS actually
                    negotiated, not a hard-coded
                    AES-128-GCM. RFC 9001 sec 5.1: QUIC
                    Handshake and 1-RTT keys derive from
                    the same AEAD as TLS picked for the
                    handshake. (Initial keys are always
                    AES-128-GCM-SHA256 per sec 5.2; that
                    derivation is in the Initial-key path
                    and unchanged.)
                 */
                $hs_cipher = $this->tls->negotiatedCipher();
                $this->keys[self::LEVEL_HANDSHAKE] = [
                    'rx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['c_hs'], $hs_cipher),
                    'tx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['s_hs'], $hs_cipher),
                ];
                $this->keys[self::LEVEL_APPLICATION] = [
                    'rx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['c_ap'], $hs_cipher),
                    'tx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['s_ap'], $hs_cipher),
                ];
                $this->state = self::ST_HANDSHAKING;
            }
        }
        $this->peer_transport_params =
            $this->tls->clientQuicTransportParameters();
        if ($this->peer_transport_params !== '') {
            $this->parsePeerTransportParams();
        }
    }
    /**
     * Walks the peer's QUIC transport parameters block
     * (RFC 9000 sec 18) and surfaces the values atto
     * tracks. Each parameter is encoded as
     *   (varint id, varint length, value bytes).
     * Currently extracts:
     *   0x01 max_idle_timeout (ms)
     *   0x04 initial_max_data
     *   0x05 initial_max_stream_data_bidi_local
     *   0x06 initial_max_stream_data_bidi_remote
     *   0x07 initial_max_stream_data_uni
     * Other parameters (max_udp_payload_size,
     * initial_max_streams_*, etc.) are accepted by the wire
     * but used only at their defaults.
     */
    protected function parsePeerTransportParams()
    {
        $tp = $this->peer_transport_params;
        $off = 0;
        while ($off < strlen($tp)) {
            list($id, $off) = QuicVarint::read($tp, $off);
            list($len, $off) = QuicVarint::read($tp, $off);
            if ($len === false ||
                strlen($tp) < $off + $len) {
                break;
            }
            $value = substr($tp, $off, $len);
            $off += $len;
            list($v, ) = QuicVarint::read($value, 0);
            if ($v === false) {
                continue;
            }
            switch ($id) {
                case 0x01:
                    /* max_idle_timeout in ms. 0 = no timeout;
                       we keep our 30s default so a stuck peer
                       still gets reaped. */
                    if ($v > 0) {
                        $this->peer_max_idle_ms = (int) $v;
                    }
                    break;
                case 0x04:
                    $this->peer_initial_max_data = (int) $v;
                    break;
                case 0x05:
                    $this->peer_initial_max_stream_data_bidi_local
                        = (int) $v;
                    break;
                case 0x06:
                    $this->peer_initial_max_stream_data_bidi_remote
                        = (int) $v;
                    break;
                case 0x07:
                    $this->peer_initial_max_stream_data_uni
                        = (int) $v;
                    break;
                case 0x0e:
                    /*
                        active_connection_id_limit (RFC 9000
                        sec 18.2). Minimum legal value is 2.
                        Caps how many additional CIDs we may
                        issue to the peer; emit() tops up
                        the pool to (limit - 1) NEW_CONNEC-
                        TION_ID frames once ST_ESTABLISHED.
                     */
                    if ($v >= 2) {
                        $this->active_cid_limit_peer =
                            (int) $v;
                    }
                    break;
            }
        }
    }
    /**
     * Splits the bytes returned by Tls13Engine::build-
     * ServerFlight('quic') into Initial-level and
     * Handshake-level CRYPTO frames, then packetizes them.
     *
     * The first message in the flight (ServerHello) goes
     * in an Initial packet; everything after (Encrypted-
     * Extensions, Certificate, CertificateVerify,
     * Finished) goes in Handshake packets.
     * @param mixed $flight flight parameter
     */
    protected function splitServerFlight($flight)
    {
        if (strlen($flight) < 4) {
            return;
        }
        /* The flight is a concatenation of complete TLS
           handshake messages; each message is type byte +
           uint24 length + body. ServerHello is first. */
        $sh_len = (ord($flight[1]) << 16) |
            (ord($flight[2]) << 8) | ord($flight[3]);
        $sh = substr($flight, 0, 4 + $sh_len);
        $rest = substr($flight, 4 + $sh_len);
        /* Build Initial packet carrying the ServerHello
           in a CRYPTO frame, plus an ACK frame for the
           client's Initial. */
        $initial_payload = $this->ackFrameBytes(
            self::LEVEL_INITIAL);
        $crypto = QuicFrame::encode([
            'type' => QuicFrame::F_CRYPTO,
            'offset' => $this->crypto_send_offset[
                self::LEVEL_INITIAL],
            'data' => $sh,
        ]);
        $this->crypto_send_offset[self::LEVEL_INITIAL] +=
            strlen($sh);
        $initial_payload .= $crypto;
        $this->queuePacket(self::LEVEL_INITIAL,
            $initial_payload);
        /* Build Handshake packet carrying the rest of the
           flight. The Handshake-level keys aren't yet in
           $this->keys, but driveHandshake will populate
           them right after this method returns; we emit
           the packet at that point via emit(). For now
           save the payload bytes. */
        if ($rest !== '') {
            $crypto2 = QuicFrame::encode([
                'type' => QuicFrame::F_CRYPTO,
                'offset' => $this->crypto_send_offset[
                    self::LEVEL_HANDSHAKE],
                'data' => $rest,
            ]);
            $this->crypto_send_offset[
                self::LEVEL_HANDSHAKE] += strlen($rest);
            /* Defer the Handshake packet until keys
               exist. We just queue the level + payload
               and let emit() encrypt at flush time. */
            $this->send_queue[] = [self::LEVEL_HANDSHAKE,
                $crypto2, 'pending'];
        }
    }
    /**
     * Returns true if a frame of the given type obligates
     * the receiver to send an ACK. Per RFC 9000 sec 1.2
     * the ack-eliciting set is every frame type EXCEPT
     * ACK, ACK_ECN, PADDING, and the two CONNECTION_CLOSE
     * variants. Ack obligation is tracked per packet-number
     * space in $ack_pending and drained from emit().
     * @param int $type type code
     * @return bool true if the frame is ack-eliciting per RFC 9002
     */
    protected static function isAckEliciting($type)
    {
        if ($type === QuicFrame::F_ACK ||
            $type === QuicFrame::F_ACK_ECN ||
            $type === QuicFrame::F_PADDING ||
            $type === QuicFrame::F_CONNECTION_CLOSE ||
            $type === QuicFrame::F_CONNECTION_CLOSE_APP) {
            return false;
        }
        return true;
    }
    /**
     * Builds an ACK frame's wire bytes covering all
     * received packet numbers in the given PN space.
     * Returns "" if nothing to ACK.
     * @param int $level encryption level
     * @return string encoded ACK frame bytes for the given packet number space
     */
    protected function ackFrameBytes($level)
    {
        if (empty($this->received_pns[$level])) {
            return "";
        }
        $ack = QuicFrame::buildAck(
            $this->received_pns[$level]);
        if ($ack === false) {
            return "";
        }
        return QuicFrame::encode($ack);
    }
    /**
     * Derives a 16-byte stateless-reset token for a CID per
     * RFC 9000 sec 10.3. The token is HMAC-SHA256 of the CID
     * bytes truncated to 16 bytes, keyed by the listener's
     * stateless-reset secret. The listener stamps the
     * secret onto the connection at construction; if it's
     * absent (e.g. a unit test) we fall back to a random
     * 16-byte token, which is correct as long as the peer
     * never tries to validate it (atto doesn't currently
     * generate stateless resets, only emit tokens for the
     * peer's records).
     * @param string $cid QUIC Connection ID bytes
     * @return string stateless-reset token for the given Connection ID
     */
    public function statelessResetToken($cid)
    {
        if ($this->stateless_reset_secret !== "") {
            return substr(hash_hmac('sha256',
                $cid, $this->stateless_reset_secret, true),
                0, 16);
        }
        return random_bytes(16);
    }
    /**
     * Tops the local CID pool up to the peer's
     * active_connection_id_limit by minting fresh CIDs and
     * pushing them onto $new_cids_pending for emit() to
     * encode as NEW_CONNECTION_ID frames. Called once after
     * ST_ESTABLISHED and again after each RETIRE_CONNECTION
     * _ID, so the peer always has spare CIDs available for
     * migration. Returns the count of CIDs queued by this
     * call.
     * @return void no return; the connection-id pool is refilled in place
     */
    public function fillCidPool()
    {
        $queued = 0;
        $target = $this->active_cid_limit_peer;
        while (count($this->issued_cids) < $target) {
            $cid = random_bytes(8);
            $seq = $this->cid_seq_next++;
            $this->issued_cids[$seq] = $cid;
            $this->new_cids_pending[] = [
                'sequence' => $seq,
                'cid' => $cid,
                'token' => $this->statelessResetToken($cid),
            ];
            $queued++;
        }
        return $queued;
    }
    /**
     * Honors a RETIRE_CONNECTION_ID frame from the peer.
     * Removes the matching sequence from $issued_cids and
     * tops the pool back up. Returns the retired CID bytes
     * so the listener can drop its routing-table entry, or
     * '' if the sequence wasn't issued (which is a protocol
     * violation but we tolerate it -- the peer may be
     * retiring a CID we already retired ourselves).
     * @param mixed $sequence sequence parameter
     * @return void no return; the named local CID is retired and removed from the pool
     */
    public function retireLocalCid($sequence)
    {
        if (!isset($this->issued_cids[$sequence])) {
            return "";
        }
        $cid = $this->issued_cids[$sequence];
        unset($this->issued_cids[$sequence]);
        $this->fillCidPool();
        return $cid;
    }
    /**
     * Phase 11a: handles an inbound ACK frame at $level.
     * Removes every ACKed packet number from
     * $sent_packets[$level] and records latest_rtt as
     * (now - time_sent of the largest ACKed packet) when
     * that largest packet was ack-eliciting (RFC 9002 sec
     * 5.1: only ack-eliciting packets contribute valid
     * RTT samples). Phase 11b consumes latest_rtt to
     * smooth RTT and arm the PTO timer; phase 11c will
     * also use the removal to drive loss detection.
     * @param int $level encryption level
     * @param QuicFrame $frame parsed QUIC frame
     */
    protected function processAck($level, $frame)
    {
        $largest = (int) $frame['largest'];
        $first_range = (int) $frame['first_range'];
        /*
            Walk the ACK ranges from highest to lowest
            packet number per RFC 9000 sec 19.3. The first
            range covers [largest - first_range, largest];
            each subsequent (gap, length) entry skips
            (gap + 1) packet numbers and then acks the next
            (length + 1) of them.
         */
        $cursor = $largest;
        $ranges = [[$cursor - $first_range, $cursor]];
        if (!empty($frame['ranges'])) {
            $cursor = $cursor - $first_range;
            foreach ($frame['ranges'] as $r) {
                list($gap, $ack_len) = $r;
                /* RFC 9000 sec 19.3.1: Smallest = Largest -
                   ACK Range Length. The next range's
                   "Largest Acknowledged" is computed as
                   previous-smallest - gap - 2 because the
                   gap field is 1 less than the actual gap
                   size and ranges don't overlap. */
                $next_largest = $cursor - (int) $gap - 2;
                $next_smallest = $next_largest -
                    (int) $ack_len;
                if ($next_largest < 0 ||
                    $next_smallest < 0) {
                    /* Malformed range; stop processing. */
                    break;
                }
                $ranges[] = [$next_smallest, $next_largest];
                $cursor = $next_smallest;
            }
        }
        $largest_acked_time = null;
        $largest_was_ack_eliciting = false;
        $newly_acked_count = 0;
        foreach ($ranges as $r) {
            list($lo, $hi) = $r;
            for ($pn = $hi; $pn >= $lo; $pn--) {
                if (isset(
                    $this->sent_packets[$level][$pn])) {
                    $entry =
                        $this->sent_packets[$level][$pn];
                    if ($pn === $largest &&
                        $entry['ack_eliciting']) {
                        $largest_acked_time =
                            $entry['time_sent'];
                        $largest_was_ack_eliciting = true;
                    }
                    if (!empty($entry['in_flight'])) {
                        $this->removeFromBytesInFlight(
                            $entry['sent_bytes']);
                        $this->onPacketAckedForCwnd(
                            $entry);
                    }
                    unset(
                        $this->sent_packets[$level][$pn]);
                    $newly_acked_count++;
                }
            }
        }
        if ($largest_was_ack_eliciting &&
            $largest_acked_time !== null) {
            $this->latest_rtt = microtime(true) -
                $largest_acked_time;
            $this->updateRtt((float) $frame['delay']);
        }
        if ($newly_acked_count > 0) {
            /*
                RFC 9002 sec 6.2.1: progress was made.
                Track largest_acked_pn for the reordering
                threshold, declare any older still-in-
                flight packets lost (sec 6.1), reset PTO
                backoff, and rearm the timer.
             */
            if ($largest > $this->largest_acked_pn[$level]) {
                $this->largest_acked_pn[$level] = $largest;
            }
            $this->detectAndRemoveLostPackets($level);
            $this->pto_count = 0;
            $this->setLossDetectionTimer();
        }
    }
    /**
     * Walks $sent_packets[$level] applying the RFC 9002
     * sec 6.1 loss-detection thresholds and removes any
     * packet that meets either: (a) the packet-number
     * reordering threshold (largest_acked_pn - pn >=
     * LOSS_PKT_THRESHOLD), or (b) the time threshold
     * (time_sent + loss_delay <= now). Re-queues the
     * frames carried by those packets via onPacketsLost,
     * and updates loss_time[level] to point at the next
     * packet that is going to cross the time threshold.
     * Returns the count of packets declared lost.
     * @param int $level encryption level
     * @return array list of lost packet records that have been removed from the in-flight set
     */
    protected function detectAndRemoveLostPackets($level)
    {
        $this->loss_time[$level] = null;
        if (empty($this->sent_packets[$level])) {
            return 0;
        }
        $largest_acked = $this->largest_acked_pn[$level];
        /*
            loss_delay = kTimeThreshold *
                max(latest_rtt, smoothed_rtt), floored at
            kGranularity to keep the threshold meaningful
            on extremely-low-RTT paths (loopback can show
            sub-millisecond latest_rtt). Before the first
            RTT sample we use kInitialRtt (333 ms) so the
            packet-number threshold dominates.
         */
        $rtt = $this->smoothed_rtt;
        if ($this->latest_rtt !== null
            && $this->latest_rtt > $rtt) {
            $rtt = $this->latest_rtt;
        }
        if ($rtt === null) {
            $rtt = 0.333;
        }
        $loss_delay = self::LOSS_TIME_THRESHOLD * $rtt;
        if ($loss_delay < self::PTO_GRANULARITY_SEC) {
            $loss_delay = self::PTO_GRANULARITY_SEC;
        }
        $now = microtime(true);
        $lost_send_time_threshold = $now - $loss_delay;
        $lost_packets = [];
        foreach ($this->sent_packets[$level] as $pn => $entry) {
            if ($pn > $largest_acked) {
                /* This packet is newer than anything the
                   peer has acknowledged; cannot yet be
                   declared lost. */
                continue;
            }
            $time_threshold_lost =
                $entry['time_sent'] <=
                $lost_send_time_threshold;
            $pn_threshold_lost =
                ($largest_acked - $pn) >=
                self::LOSS_PKT_THRESHOLD;
            if ($time_threshold_lost ||
                $pn_threshold_lost) {
                $lost_packets[] = $entry;
                if (!empty($entry['in_flight'])) {
                    $this->removeFromBytesInFlight(
                        $entry['sent_bytes']);
                }
                unset($this->sent_packets[$level][$pn]);
                continue;
            }
            /*
                Not yet lost, but track the earliest moment
                a still-in-flight packet at or below
                largest_acked will cross the time threshold
                so the loss-detection timer can fire then.
             */
            $deadline = $entry['time_sent'] + $loss_delay;
            if ($this->loss_time[$level] === null ||
                $deadline < $this->loss_time[$level]) {
                $this->loss_time[$level] = $deadline;
            }
        }
        if (!empty($lost_packets)) {
            $this->onPacketsLost($level, $lost_packets);
        }
        return count($lost_packets);
    }
    /**
     * Re-queues frames from packets just declared lost.
     * RFC 9002 sec 6.1: data-carrying lost frames MUST be
     * retransmitted; PADDING and ACK are regenerated rather
     * than copied. We handle CRYPTO (re-emit at original
     * offset), STREAM (same; the peer dedups by stream
     * offset, so a small amount of duplicate transmission is
     * tolerated rather than per-byte ACK tracking),
     * HANDSHAKE_DONE (re-arm the one-shot flag), and
     * NEW_CONNECTION_ID (re-emit the same frame verbatim per
     * RFC 9000 sec 13.3). MAX_DATA / MAX_STREAM_DATA /
     * MAX_STREAMS_* / RETIRE_CONNECTION_ID are skipped: rare
     * server-initiated frames whose retransmission a follow-
     * up phase will either add or document.
     * @param int $level encryption level
     * @param mixed $lost_packets lost_packets parameter
     */
    protected function onPacketsLost($level, $lost_packets)
    {
        /*
            RFC 9002 sec 7.6: the congestion event uses the
            largest time_sent across the lost batch so an
            ACK that simultaneously declares many packets
            lost only triggers ONE cwnd halving. Already-
            in-recovery duplicates are filtered out by
            inCongestionRecovery() inside onCongestionEvent.
         */
        $latest_lost_time = null;
        foreach ($lost_packets as $entry) {
            if ($latest_lost_time === null
                || $entry['time_sent'] > $latest_lost_time) {
                $latest_lost_time = $entry['time_sent'];
            }
        }
        if ($latest_lost_time !== null) {
            $this->onCongestionEvent($latest_lost_time);
        }
        foreach ($lost_packets as $entry) {
            foreach ($entry['frames'] as $f) {
                $type = $f['type'];
                if ($type === QuicFrame::F_CRYPTO) {
                    /* Re-encode at the original offset. */
                    $bytes = QuicFrame::encode([
                        'type' => QuicFrame::F_CRYPTO,
                        'offset' => $f['offset'],
                        'data' => $f['data'],
                    ]);
                    if ($level ===
                        self::LEVEL_APPLICATION) {
                        $this->queue1Rtt($bytes);
                    } else {
                        $this->send_queue[] = [$level,
                            $bytes, 'pending'];
                    }
                    continue;
                }
                if ($type === QuicFrame::F_STREAM_BASE) {
                    $bytes = QuicFrame::encode([
                        'type' => QuicFrame::F_STREAM_BASE,
                        'stream_id' => $f['stream_id'],
                        'offset' => $f['offset'],
                        'data' => $f['data'],
                        'fin' => !empty($f['fin']),
                    ]);
                    /* STREAM frames only ever ride 1-RTT
                       packets, so this path is always
                       LEVEL_APPLICATION. Use queue1Rtt for
                       symmetry with normal stream sends. */
                    $this->queue1Rtt($bytes);
                    continue;
                }
                if ($type === QuicFrame::F_HANDSHAKE_DONE) {
                    /* Re-arm the one-shot flag so emit()
                       ships HANDSHAKE_DONE again. */
                    $this->handshake_done_sent = false;
                    continue;
                }
                if ($type === QuicFrame::F_NEW_CONNECTION_ID) {
                    /*
                        RFC 9000 sec 13.3: NEW_CONNECTION_ID
                        frames MUST be retransmitted if lost.
                        The CID and stateless-reset token in
                        the original frame are still the ones
                        we want the peer to know -- our
                        $issued_cids entry hasn't gone
                        anywhere -- so re-emit the same frame
                        verbatim. retire_prior_to is preserved
                        from the original (always 0 in atto's
                        current emit path).
                     */
                    $bytes = QuicFrame::encode([
                        'type' => QuicFrame::F_NEW_CONNECTION_ID,
                        'sequence' => $f['sequence'],
                        'retire_prior_to' =>
                            $f['retire_prior_to'] ?? 0,
                        'cid' => $f['cid'],
                        'stateless_reset_token' =>
                            $f['stateless_reset_token'],
                    ]);
                    $hint = ['ack_eliciting' => true,
                        'in_flight' => true,
                        'frames' => [$f]];
                    $this->queue1Rtt($bytes, $hint);
                    continue;
                }
                /* Other frame types fall through silently
                   for now -- see method docblock. */
            }
        }
    }
    /**
     * Folds latest_rtt into smoothed_rtt and rttvar per
     * RFC 9002 sec 5.3. $ack_delay is the peer-reported
     * delay (in microseconds, scaled by ack_delay_exponent
     * which defaults to 3 -- so the wire value times 8 is
     * microseconds; QuicFrame::decodeAck already returns
     * the raw varint, so we treat it as the encoded form
     * and multiply by 8 to get microseconds, then convert
     * to seconds for arithmetic against smoothed_rtt).
     * @param mixed $ack_delay_raw ack_delay_raw parameter
     */
    protected function updateRtt($ack_delay_raw)
    {
        if ($this->latest_rtt === null) {
            return;
        }
        /*
            ack_delay_exponent default is 3; we don't yet
            parse a peer override, so ack_delay seconds =
            ack_delay_raw * 2^3 / 1e6.
         */
        $ack_delay_sec = ((float) $ack_delay_raw * 8.0)
            / 1000000.0;
        if ($this->min_rtt === null ||
            $this->latest_rtt < $this->min_rtt) {
            $this->min_rtt = $this->latest_rtt;
        }
        /*
            RFC 9002 sec 5.3: subtract ack_delay from
            latest_rtt before folding it in, but only if
            doing so keeps the result >= min_rtt. This
            guards against a peer that misreports its delay
            and would otherwise drag smoothed_rtt below the
            real floor.
         */
        $adjusted = $this->latest_rtt;
        if ($adjusted >= $this->min_rtt + $ack_delay_sec) {
            $adjusted -= $ack_delay_sec;
        }
        if ($this->smoothed_rtt === null) {
            /* RFC 9002 sec 5.3: first sample. */
            $this->smoothed_rtt = $adjusted;
            $this->rttvar = $adjusted / 2.0;
            return;
        }
        $diff = abs($this->smoothed_rtt - $adjusted);
        $this->rttvar = 0.75 * $this->rttvar + 0.25 * $diff;
        $this->smoothed_rtt =
            0.875 * $this->smoothed_rtt + 0.125 * $adjusted;
    }
    /**
     * Adds an in-flight packet's wire size to bytes_in_-
     * flight. Called from queuePacket() and emit() each
     * time a packet is encrypted into a sent_packets entry
     * that has in_flight = true. Pure-ACK packets are not
     * tracked because they do not consume cwnd per RFC
     * 9002 sec A.1.
     * @param string $bytes bytes to operate on
     */
    protected function addToBytesInFlight($bytes)
    {
        $this->bytes_in_flight += $bytes;
    }
    /**
     * Subtracts a packet's wire size from bytes_in_flight.
     * Called when a packet is removed from sent_packets,
     * either because an ACK covered it (processAck) or
     * because it was declared lost (detectAndRemoveLost-
     * Packets). Floor at zero in case bookkeeping
     * disagrees -- safer than letting bytes_in_flight go
     * negative and gating emit() forever.
     * @param string $bytes bytes to operate on
     */
    protected function removeFromBytesInFlight($bytes)
    {
        $this->bytes_in_flight = max(0,
            $this->bytes_in_flight - $bytes);
    }
    /**
     * Returns true if the packet at $entry was sent during
     * the current congestion-recovery period and so should
     * not contribute to cwnd growth on ACK. RFC 9002 sec
     * 7.3.2: while in recovery, ACKs only exit recovery
     * once the largest packet sent before recovery is
     * acked.
     * @param mixed $time_sent time_sent parameter
     * @return bool true if the sender is currently in the congestion-recovery state
     */
    protected function inCongestionRecovery($time_sent)
    {
        return $this->congestion_recovery_start !== null
            && $time_sent <= $this->congestion_recovery_start;
    }
    /**
     * Grows cwnd in response to an ACK that newly
     * acknowledged $newly_acked_bytes worth of in-flight
     * data. Slow-start while cwnd < ssthresh: cwnd grows
     * by exactly the bytes acked (exponential per RTT).
     * Otherwise congestion-avoidance: cwnd grows by
     * approximately one MSS per RTT, computed as
     * MSS * acked_bytes / cwnd. Both modes skip packets
     * sent during the current recovery period.
     * @param mixed $entry entry parameter
     */
    protected function onPacketAckedForCwnd($entry)
    {
        if ($this->inCongestionRecovery($entry['time_sent'])) {
            return;
        }
        if ($this->congestion_window < $this->ssthresh) {
            /* Slow start. */
            $this->congestion_window +=
                $entry['sent_bytes'];
            return;
        }
        /*
            Congestion avoidance: integer-arithmetic
            equivalent of cwnd += MSS * acked / cwnd. The
            CC_MAX_DATAGRAM_BYTES factor and integer
            division mean very small ACKs may not bump
            cwnd at all on a given iteration, which is the
            correct quantization behaviour.
         */
        $delta = intdiv(self::CC_MAX_DATAGRAM_BYTES
            * $entry['sent_bytes'],
            max(1, $this->congestion_window));
        $this->congestion_window += $delta;
    }
    /**
     * Halves cwnd in response to a declared-lost packet
     * and enters a recovery period. Subsequent acks for
     * packets sent before $time_sent_lost will not grow
     * cwnd; acks for packets sent after will. Per RFC
     * 9002 sec 7.6.2 we use the NewReno reduction (cwnd
     * halved, ssthresh = new cwnd) rather than the
     * deprecated rate-halving variant.
     * @param mixed $time_sent_lost time_sent_lost parameter
     */
    protected function onCongestionEvent($time_sent_lost)
    {
        /*
            Don't double-react if we're already in recovery
            from an earlier loss in the same RTT (RFC 9002
            sec 7.3.2).
         */
        if ($this->inCongestionRecovery($time_sent_lost)) {
            return;
        }
        $this->congestion_recovery_start = microtime(true);
        $halved = intdiv(
            $this->congestion_window
            * self::CC_LOSS_REDUCTION_NUMERATOR,
            self::CC_LOSS_REDUCTION_DENOMINATOR);
        $this->ssthresh = max($halved,
            self::CC_MINIMUM_WINDOW_BYTES);
        $this->congestion_window = $this->ssthresh;
    }
    /**
     * Returns the RFC 9002 sec 6.2.1 base PTO duration in
     * seconds. Uses kInitialRtt (333 ms) before any RTT
     * sample has been collected. Caller multiplies by
     * 2^pto_count for backoff.
     * @return int baseline Probe Timeout in milliseconds per RFC 9002 sec 6.2.1
     */
    protected function basePto()
    {
        if ($this->smoothed_rtt === null) {
            /* RFC 9002 sec A.2 kInitialRtt = 333 ms */
            return 0.333 + self::PEER_MAX_ACK_DELAY_SEC;
        }
        $rttvar4 = 4.0 * $this->rttvar;
        if ($rttvar4 < self::PTO_GRANULARITY_SEC) {
            $rttvar4 = self::PTO_GRANULARITY_SEC;
        }
        return $this->smoothed_rtt + $rttvar4
            + self::PEER_MAX_ACK_DELAY_SEC;
    }
    /**
     * (Re-)arms the loss-detection timer per RFC 9002 sec
     * 6.2.2. The timer fires at the earliest of:
     *   - the next loss_time across all packet-number
     *     spaces (a packet about to cross the time-
     *     threshold for being declared lost), or
     *   - basePto * 2^pto_count seconds after the oldest
     *     in-flight ack-eliciting send (RFC 9002 sec
     *     6.2.1, the probe-timeout deadline).
     * Disarms when there is no ack-eliciting packet in
     * flight at all. The dispatcher in
     * onLossDetectionTimeout decides which case fired
     * by re-running detectAndRemoveLostPackets first --
     * if it removes anything the firing was a loss
     * event, otherwise it was a PTO event and we send a
     * PING.
     */
    public function setLossDetectionTimer()
    {
        $earliest_loss_time = null;
        foreach ($this->loss_time as $lt) {
            if ($lt === null) {
                continue;
            }
            if ($earliest_loss_time === null
                || $lt < $earliest_loss_time) {
                $earliest_loss_time = $lt;
            }
        }
        if ($earliest_loss_time !== null) {
            $this->loss_detection_timer =
                $earliest_loss_time;
            return;
        }
        $oldest_eliciting_send = null;
        foreach ($this->sent_packets as $level => $pkts) {
            foreach ($pkts as $entry) {
                if (!$entry['ack_eliciting']) {
                    continue;
                }
                if ($oldest_eliciting_send === null ||
                    $entry['time_sent'] <
                        $oldest_eliciting_send) {
                    $oldest_eliciting_send =
                        $entry['time_sent'];
                }
            }
        }
        if ($oldest_eliciting_send === null) {
            $this->loss_detection_timer = null;
            return;
        }
        $pto = $this->basePto() *
            (1 << $this->pto_count);
        $this->loss_detection_timer =
            $oldest_eliciting_send + $pto;
    }
    /**
     * Called by the listener tick loop when the loss-
     * detection timer expires. RFC 9002 sec 6.2.2 / 6.2.4:
     * if any packet-number space has a non-null loss_time
     * the firing was a time-threshold loss event -- run
     * loss detection there, retransmit the lost frames,
     * and rearm the timer. Otherwise the firing was a PTO
     * event -- send a PING in 1-RTT to elicit fresh ACK
     * coverage, double the backoff exponent, and rearm.
     */
    public function onLossDetectionTimeout()
    {
        if ($this->loss_detection_timer === null) {
            return;
        }
        $loss_event_level = null;
        $earliest_loss_time = null;
        foreach ($this->loss_time as $level => $lt) {
            if ($lt === null) {
                continue;
            }
            if ($earliest_loss_time === null
                || $lt < $earliest_loss_time) {
                $earliest_loss_time = $lt;
                $loss_event_level = $level;
            }
        }
        if ($loss_event_level !== null) {
            $this->detectAndRemoveLostPackets(
                $loss_event_level);
            $this->setLossDetectionTimer();
            return;
        }
        if (!isset($this->keys[self::LEVEL_APPLICATION])) {
            /* Should not happen -- timer is only armed
               once we have ack-eliciting packets in
               flight, which implies keys exist -- but
               guard defensively. */
            return;
        }
        $ping = chr(QuicFrame::F_PING);
        $this->queue1Rtt($ping);
        $this->pto_count++;
        $this->setLossDetectionTimer();
    }
    /**
     * Encrypts and queues a packet for sending. $payload
     * is the unprotected frame sequence; we wrap it in a
     * QuicPacket with the right keys and queue the wire
     * bytes onto $send_queue.
     * @param int $level encryption level
     * @param string $payload payload bytes
     */
    protected function queuePacket($level, $payload)
    {
        $pn = $this->next_pn[$level]++;
        $packet = new QuicPacket();
        $packet->long_type = ($level ===
            self::LEVEL_INITIAL) ? QuicPacket::LONG_INITIAL
            : QuicPacket::LONG_HANDSHAKE;
        $packet->version = QuicPacket::VERSION_QUIC_V1;
        $packet->destination_cid = $this->peer_cid;
        $packet->source_cid = $this->local_cid;
        if ($level === self::LEVEL_INITIAL) {
            /* RFC 9000 sec 14.1: client Initial packets
               must be padded to >= 1200 bytes. The
               server's Initial ACK packets don't have to
               be (the inflation rule is one-way), so we
               leave ours at natural size. */
        }
        /*
            Phase 11a: classify the unencrypted payload
            for sent_packets bookkeeping before we encrypt.
            See the matching block in emit() for the
            rationale -- congestion control / loss
            detection in 11b-d need a packet's frame list
            and in_flight bytes regardless of whether the
            packet was encoded here or in emit().
         */
        list($pkt_frames, $_dec_err) =
            QuicFrame::decodeAll($payload);
        $pkt_ack_eliciting = false;
        $pkt_in_flight = false;
        foreach ($pkt_frames as $pf) {
            if (self::isAckEliciting($pf['type'])) {
                $pkt_ack_eliciting = true;
            }
            if ($pf['type'] !== QuicFrame::F_ACK
                && $pf['type'] !== QuicFrame::F_ACK_ECN) {
                $pkt_in_flight = true;
            }
        }
        $wire = $packet->encodeLong(
            $this->keys[$level]['tx'], $pn, $payload);
        if ($pkt_in_flight) {
            $this->sent_packets[$level][$pn] = [
                'pn' => $pn,
                'time_sent' => microtime(true),
                'ack_eliciting' => $pkt_ack_eliciting,
                'in_flight' => true,
                'sent_bytes' => strlen($wire),
                'frames' => $pkt_frames,
            ];
            $this->addToBytesInFlight(strlen($wire));
            if ($pkt_ack_eliciting) {
                $this->setLossDetectionTimer();
            }
        }
        $this->send_queue[] = [$level, $wire, 'ready'];
    }
    /**
     * Returns datagrams (concatenations of one or more
     * encoded packets) ready to send to the peer, then
     * clears the queue. Pending Handshake-level entries
     * waiting for keys are encrypted now if the keys are
     * available.
     * @return string serialized bytes ready to send
     */
    public function emit()
    {
        $out = [];
        $current = "";
        $pending_remaining = [];
        /*
            Anti-amplification budget per RFC 9000 sec 8.1.
            Before the path is validated (handshake-level
            packet authenticates -> ST_ESTABLISHED), the
            server may send at most ANTI_AMP_FACTOR times
            the bytes received from this peer, total. We
            capture the budget once at the start of emit()
            and decrement it as packets are added to $out
            or $current; once exhausted, remaining queued
            payloads are pushed to $pending_remaining and
            re-attempted on the next emit() call (which
            fires after the next inbound datagram grows the
            budget). After ST_ESTABLISHED the cap no longer
            applies; we use PHP_INT_MAX as a sentinel so
            the per-packet gate cheaply short-circuits.
         */
        if ($this->state === self::ST_ESTABLISHED) {
            $amp_budget = PHP_INT_MAX;
        } else {
            $amp_budget = self::ANTI_AMP_FACTOR
                * $this->stats_bytes_received
                - $this->stats_bytes_sent;
        }
        /*
            Queue HANDSHAKE_DONE the first time we hit
            ESTABLISHED. RFC 9001 sec 4.1.2: server must
            send HANDSHAKE_DONE to inform the client that
            the handshake is fully complete. We also queue
            an ACK at LEVEL_APPLICATION since by the time
            we hit ESTABLISHED we will have received the
            client's first 1-RTT packet (the one carrying
            the Handshake-level Finished came in a long-
            header Handshake packet, but a 1-RTT
            HANDSHAKE_DONE makes sure we have *something*
            on the application PN space to ACK against).
         */
        if ($this->state === self::ST_ESTABLISHED &&
            !$this->handshake_done_sent &&
            isset($this->keys[self::LEVEL_APPLICATION])) {
            $payload = chr(QuicFrame::F_HANDSHAKE_DONE);
            $ack_payload = $this->ackFrameBytes(
                self::LEVEL_APPLICATION);
            $this->queue1Rtt($ack_payload . $payload);
            $this->handshake_done_sent = true;
            $this->ack_pending[self::LEVEL_APPLICATION] =
                false;
            /*
                Now that we're established and the peer has
                advertised its active_connection_id_limit,
                top the local CID pool up to that limit.
                Each fresh CID emits as a NEW_CONNECTION_ID
                frame in 1-RTT data so the peer can rotate
                or migrate without re-handshaking.
             */
            $this->fillCidPool();
        }
        /*
            Drain queued NEW_CONNECTION_ID frames into 1-RTT
            payloads. Each frame goes in its own packet so
            the peer's ACK granularity is per CID; a packet
            carrying just one frame stays well under the
            anti-amp gate's per-packet bound. Frames are
            ack-eliciting and in_flight per RFC 9002 A.1.
         */
        if (!empty($this->new_cids_pending) &&
            isset($this->keys[self::LEVEL_APPLICATION])) {
            foreach ($this->new_cids_pending as $entry) {
                $frame = ['type'
                    => QuicFrame::F_NEW_CONNECTION_ID,
                    'sequence' => $entry['sequence'],
                    'retire_prior_to' => 0,
                    'cid' => $entry['cid'],
                    'stateless_reset_token' =>
                        $entry['token']];
                $payload = QuicFrame::encode($frame);
                $hint = ['ack_eliciting' => true,
                    'in_flight' => true,
                    'frames' => [$frame]];
                $this->queue1Rtt($payload, $hint);
            }
            $this->new_cids_pending = [];
        }
        /*
            Drain any pending PATH_RESPONSE frames -- one per
            PATH_CHALLENGE the peer sent us. RFC 9000 sec 8.2:
            response goes on the same path the challenge
            arrived on, so we ride the standard 1-RTT queue
            (the listener uses peer_address for sendto, which
            is the path the inbound packet came from). Each
            response is its own packet so the encoded frame
            type 0x1B carries 8 bytes; trivially fits.
         */
        if (!empty($this->path_responses_pending) &&
            isset($this->keys[self::LEVEL_APPLICATION])) {
            foreach ($this->path_responses_pending
                as $data) {
                $frame = ['type' => QuicFrame::F_PATH_RESPONSE,
                    'data' => $data];
                $payload = QuicFrame::encode($frame);
                $hint = ['ack_eliciting' => true,
                    'in_flight' => true,
                    'frames' => [$frame]];
                $this->queue1Rtt($payload, $hint);
            }
            $this->path_responses_pending = [];
        }
        /*
            Discharge any pending ACK obligation in the
            application packet-number space (RFC 9000 sec
            13.2.1). Piggyback the ACK onto the first
            already-queued 1-RTT payload if there is one,
            otherwise queue an ACK-only payload. Either way
            the ACK leaves on this emit() call. See the
            $ack_pending property docblock for context on
            why this is required.
         */
        if ($this->ack_pending[self::LEVEL_APPLICATION] &&
            isset($this->keys[self::LEVEL_APPLICATION])) {
            $ack_payload = $this->ackFrameBytes(
                self::LEVEL_APPLICATION);
            if ($ack_payload !== '') {
                $piggybacked = false;
                foreach ($this->send_queue as $idx => $sq) {
                    list($lv, $b, $st) = $sq;
                    if ($lv === self::LEVEL_APPLICATION
                        && $st === 'pending') {
                        $this->send_queue[$idx][1] =
                            $ack_payload . $b;
                        $piggybacked = true;
                        break;
                    }
                }
                if (!$piggybacked) {
                    $this->send_queue[] = [
                        self::LEVEL_APPLICATION,
                        $ack_payload, 'pending'];
                }
            }
            $this->ack_pending[self::LEVEL_APPLICATION] =
                false;
        }
        foreach ($this->send_queue as $entry) {
            $level = $entry[0];
            $bytes = $entry[1];
            $status = $entry[2];
            $hint = $entry[3] ?? null;
            if ($status === 'pending') {
                if (!isset($this->keys[$level])) {
                    $pending_remaining[] = $entry;
                    continue;
                }
                /*
                    Classify the payload. Callers who built
                    the payload from a single known frame
                    (the dominant case: flushStreams
                    queueing one STREAM frame per packet)
                    pass a $hint that gives us the answer
                    in O(1). Otherwise we decodeAll the
                    payload back -- a hot-path fallback
                    that costs ~1.8 µs per packet and adds
                    up over a 1 MiB response shipped in
                    ~950 packets.
                 */
                if ($hint !== null) {
                    $pkt_frames = $hint['frames'];
                    $pkt_ack_eliciting =
                        $hint['ack_eliciting'];
                    $pkt_in_flight = $hint['in_flight'];
                } else {
                    list($pkt_frames, $_dec_err) =
                        QuicFrame::decodeAll($bytes);
                    $pkt_ack_eliciting = false;
                    $pkt_in_flight = false;
                    foreach ($pkt_frames as $pf) {
                        if (self::isAckEliciting(
                            $pf['type'])) {
                            $pkt_ack_eliciting = true;
                        }
                        if ($pf['type']
                                !== QuicFrame::F_ACK
                            && $pf['type']
                                !== QuicFrame::F_ACK_ECN) {
                            $pkt_in_flight = true;
                        }
                    }
                }
                if ($pkt_in_flight
                    && $this->bytes_in_flight
                        + self::CC_MAX_DATAGRAM_BYTES
                    > $this->congestion_window) {
                    $pending_remaining[] = $entry;
                    continue;
                }
                /*
                    Anti-amplification gate (RFC 9000 sec
                    8.1). $bytes here is the unencrypted
                    payload; the encoded wire packet adds a
                    header plus a 16-byte AEAD tag.
                    ANTI_AMP_PACKET_OVERHEAD bounds that
                    difference. Defer the entry when the
                    estimate exceeds the remaining budget;
                    the budget grows on the next inbound
                    datagram and the entry retries.
                 */
                if (strlen($bytes)
                        + self::ANTI_AMP_PACKET_OVERHEAD
                    > $amp_budget) {
                    $pending_remaining[] = $entry;
                    continue;
                }
                $pn = $this->next_pn[$level]++;
                if ($level === self::LEVEL_APPLICATION) {
                    /* Short-header packet. */
                    $packet = new QuicPacket();
                    $packet->destination_cid =
                        $this->peer_cid;
                    $bytes = $packet->encodeShort(
                        $this->keys[$level]['tx'],
                        $pn, $bytes);
                    if ($pkt_in_flight) {
                        $this->sent_packets[$level][$pn] = [
                            'pn' => $pn,
                            'time_sent' => microtime(true),
                            'ack_eliciting' =>
                                $pkt_ack_eliciting,
                            'in_flight' => true,
                            'sent_bytes' => strlen($bytes),
                            'frames' => $pkt_frames,
                        ];
                        $this->addToBytesInFlight(
                            strlen($bytes));
                        if ($pkt_ack_eliciting) {
                            $this->setLossDetectionTimer();
                        }
                    }
                    /*
                        RFC 9000 sec 12.2: short-header
                        packets MUST be the last packet in a
                        UDP datagram. Flush whatever long-
                        header packets are accumulated, then
                        emit this 1-RTT packet on its own
                        and reset.
                     */
                    if ($current !== '') {
                        $out[] = $current;
                        $current = "";
                    }
                    $out[] = $bytes;
                    $amp_budget -= strlen($bytes);
                    continue;
                }
                $packet = new QuicPacket();
                $packet->long_type = ($level ===
                    self::LEVEL_HANDSHAKE) ?
                    QuicPacket::LONG_HANDSHAKE :
                    QuicPacket::LONG_INITIAL;
                $packet->version =
                    QuicPacket::VERSION_QUIC_V1;
                $packet->destination_cid =
                    $this->peer_cid;
                $packet->source_cid = $this->local_cid;
                $bytes = $packet->encodeLong(
                    $this->keys[$level]['tx'], $pn, $bytes);
                if ($pkt_in_flight) {
                    $this->sent_packets[$level][$pn] = [
                        'pn' => $pn,
                        'time_sent' => microtime(true),
                        'ack_eliciting' =>
                            $pkt_ack_eliciting,
                        'in_flight' => true,
                        'sent_bytes' => strlen($bytes),
                        'frames' => $pkt_frames,
                    ];
                    $this->addToBytesInFlight(
                        strlen($bytes));
                    if ($pkt_ack_eliciting) {
                        $this->setLossDetectionTimer();
                    }
                }
            }
            $current .= $bytes;
            $amp_budget -= strlen($bytes);
        }
        if ($current !== '') {
            $out[] = $current;
        }
        $this->send_queue = $pending_remaining;
        if (!empty($out)) {
            $this->last_packet_at = microtime(true);
            foreach ($out as $datagram) {
                $this->stats_bytes_sent += strlen($datagram);
                /*
                    Counting datagrams here. A datagram may
                    contain multiple coalesced QUIC packets
                    (Initial+Handshake during the handshake)
                    but tracking per-packet count would
                    require splitting bookkeeping below in
                    encodeLong/encodeShort. Datagram count
                    is the more useful number for ops
                    debugging anyway.
                 */
                $this->stats_packets_sent++;
            }
        }
        return $out;
    }
    /**
     * Queues a 1-RTT payload (one or more frames already
     * encoded into wire bytes) for the next emit() call.
     * AEAD + header-protection happens lazily inside emit().
     * Optional $hint lets callers skip emit()'s decode-
     * classify pass with shape ['ack_eliciting' => bool,
     * 'in_flight' => bool, 'frames' => array]; frames matches
     * QuicFrame::decodeAll output for retransmission.
     * singleFrameHint() builds it cheaply for the common
     * single-frame case.
     * @param string $payload payload bytes
     * @param mixed $hint hint parameter
     */
    public function queue1Rtt($payload, $hint = null)
    {
        if ($payload === '') {
            return;
        }
        if ($hint === null) {
            $this->send_queue[] = [self::LEVEL_APPLICATION,
                $payload, 'pending'];
            return;
        }
        $this->send_queue[] = [self::LEVEL_APPLICATION,
            $payload, 'pending', $hint];
    }
    /**
     * Builds a queue1Rtt hint for a payload that contains
     * exactly one frame whose decoded form is already in
     * hand. Cheap (no decode) and lets callers like
     * flushStreams skip emit()'s decodeAll pass entirely
     * for the dominant STREAM-frame-per-packet case.
     *
     * @param array $frame already-decoded frame dict
     * @return string|null a single-frame encoding when one fits, or null to fall back to general encoding
     */
    public static function singleFrameHint($frame)
    {
        $type = $frame['type'];
        $ack_eliciting = self::isAckEliciting($type);
        $in_flight = ($type !== QuicFrame::F_ACK
            && $type !== QuicFrame::F_ACK_ECN);
        return [
            'ack_eliciting' => $ack_eliciting,
            'in_flight' => $in_flight,
            'frames' => [$frame],
        ];
    }
    /**
     * Convenience: write data to a QUIC stream and
     * optionally close the send side. Used by the H3
     * layer for response bodies.
     * @param mixed $sid sid parameter
     * @param string $data data bytes
     * @param bool $fin whether the FIN flag is set
     */
    public function sendStreamData($sid, $data, $fin = false)
    {
        if (!isset($this->streams[$sid])) {
            $this->streams[$sid] = new QuicStream($sid,
                1048576, $this->pickStreamSendWindow($sid));
        }
        $this->streams[$sid]->write($data);
        if ($fin) {
            $this->streams[$sid]->finish();
        }
    }
    /**
     * Number of bytes queued but not yet framed on stream $sid's
     * send side, or 0 if the stream does not exist yet. Lets a
     * caller pacing its own producer (the H3 streaming path) see
     * how much is still waiting to go out before queuing more.
     *
     * @param int $sid stream id to inspect
     * @return int bytes still buffered awaiting send on that stream
     */
    public function bufferedLength($sid)
    {
        if (!isset($this->streams[$sid])) {
            return 0;
        }
        return $this->streams[$sid]->bufferedLength();
    }
    /**
     * Drains every writable stream into 1-RTT STREAM
     * frames. One STREAM frame body is bounded at
     * MAX_STREAM_FRAME_BYTES so multiple frames fit
     * comfortably in a single max-size UDP datagram.
     */
    /**
     * Default per-tick byte budget for flushStreams. Caps how
     * many bytes of stream data the connection emits in a
     * single event-loop iteration so we don't burst more
     * than the peer's UDP receive buffer can hold (default
     * 212 KiB on Linux loopback). At ~320 KB/sec this lets
     * the typical 1 MiB response complete in 3-4 seconds
     * without packet loss, while still keeping latency low
     * for normal-sized responses (which fit in one tick).
     * Phase 10 will replace this with real congestion-
     * controlled pacing per RFC 9002.
     */
    const DEFAULT_FLUSH_BUDGET = 32768;
    /**
     * Largest STREAM-frame payload, in bytes, flushStreams emits
     * per frame. Held below CC_MAX_DATAGRAM_BYTES (1200) so the
     * frame plus its QUIC/UDP framing overhead still fits in one
     * datagram without fragmentation; the 100-byte margin covers
     * the short and long header, packet number, frame type,
     * stream id, offset, and length fields.
     */
    const MAX_STREAM_FRAME_BYTES =
        self::CC_MAX_DATAGRAM_BYTES - 100;
    /**
     * Drains pending stream-send buffers into 1-RTT STREAM
     * frames, queued for emit(). Caps total bytes pushed per
     * call to $budget; returns true if more data remains in
     * any stream's send_buf so the caller can run again next
     * tick. The cap protects against bursting more than the
     * peer's UDP recv buffer can hold between reads.
     * @param mixed $budget budget parameter
     * @return void no return; pending stream bytes are queued for the next outgoing packet
     */
    public function flushStreams($budget = self::DEFAULT_FLUSH_BUDGET)
    {
        if (!isset($this->keys[self::LEVEL_APPLICATION])) {
            return false;
        }
        $sent = 0;
        $more = false;
        /*
            Order streams so the smallest pending buffer
            drains first. The HTTP/3 server control stream
            (~12 bytes of stream-type + SETTINGS) MUST reach
            the client before any HEADERS/DATA on a request
            stream, per RFC 9114 sec 6.2.1. Without this
            ordering a long response on a request stream
            would consume the whole tick budget and starve
            the control stream, leaving the client unable to
            advance its H3 state machine -- aioquic in
            particular silently stops surfacing DataReceived
            events under that condition. Sorting by buffer
            size ascending also lets short responses overlap
            cheaply alongside long ones.
         */
        $sids = array_keys($this->streams);
        usort($sids, function ($a, $b) {
            $la = $this->streams[$a]->bufferedLength();
            $lb = $this->streams[$b]->bufferedLength();
            return $la - $lb;
        });
        foreach ($sids as $sid) {
            $stream = $this->streams[$sid];
            while ($sent < $budget) {
                $remaining = $budget - $sent;
                /* Cap each STREAM frame at the smallest of
                   MAX_STREAM_FRAME_BYTES (leaves UDP/QUIC
                   headroom under the max datagram), what's left
                   of this tick's budget, and the peer's
                   remaining connection-level MAX_DATA credit
                   (RFC 9000 sec 4.1; a zero cap still lets an
                   empty FIN-only frame through, which costs no
                   credit). */
                $chunk = min(self::MAX_STREAM_FRAME_BYTES,
                    $remaining, max(0, $this->peer_initial_max_data
                    - $this->conn_data_sent));
                $tup = $stream->takeForFrame($chunk);
                if ($tup === null) {
                    break;
                }
                list($offset, $data, $fin) = $tup;
                if ($data === '' && !$fin) {
                    break;
                }
                $this->conn_data_sent += strlen($data);
                $stream_frame = [
                    'type' => QuicFrame::F_STREAM_BASE,
                    'stream_id' => $sid,
                    'offset' => $offset,
                    'data' => $data,
                    'fin' => $fin,
                ];
                $frame = QuicFrame::encode($stream_frame);
                $this->queue1Rtt($frame,
                    self::singleFrameHint($stream_frame));
                $sent += strlen($data);
            }
            if ($stream->hasPendingSend()) {
                $more = true;
            }
        }
        return $more;
    }
    /**
     * Returns true once the QUIC + TLS handshake has
     * completed end-to-end (server has received and
     * verified the client's Finished).
     * @return bool true if the QUIC handshake has completed
     */
    public function isEstablished()
    {
        return $this->state === self::ST_ESTABLISHED;
    }
    /**
     * Returns true if the connection is in the closed
     * state (CONNECTION_CLOSE seen, idle timeout, or
     * local error).
     * @return bool true if the connection has been closed
     */
    public function isClosed()
    {
        return $this->state === self::ST_CLOSED;
    }
    /**
     * Returns true if no inbound or outbound packet has
     * crossed this connection in $timeout_seconds. The
     * caller (typically H3Listener::reapStale-
     * Connections) closes the connection silently when
     * this is true. Idle timeout is symmetrical: either
     * peer can declare the connection dead per RFC 9000
     * sec 10.1 once min(local_max_idle_timeout,
     * peer_max_idle_timeout) elapses.
     * @param int $now current Unix timestamp
     * @return bool true if the idle timeout has elapsed since last activity
     */
    public function isIdleExpired($now)
    {
        if ($this->state === self::ST_CLOSED) {
            return false;
        }
        if ($this->last_packet_at <= 0.0) {
            return false;
        }
        $idle_ms = min(30000, $this->peer_max_idle_ms);
        $threshold = $idle_ms / 1000.0;
        return ($now - $this->last_packet_at) > $threshold;
    }
    /**
     * Sends a CONNECTION_CLOSE frame and marks the
     * connection closed. Best-effort; the frame goes out
     * on the next emit() call (assuming we have keys at
     * the appropriate level).
     * @param int $error_code error code
     * @param string $reason reason phrase
     */
    public function close($error_code = 0, $reason = '')
    {
        if ($this->state === self::ST_CLOSED) {
            return;
        }
        $frame = QuicFrame::encode([
            'type' => QuicFrame::F_CONNECTION_CLOSE,
            'error_code' => $error_code,
            'frame_type' => 0,
            'reason' => $reason,
        ]);
        if (isset($this->keys[self::LEVEL_APPLICATION])) {
            $this->queue1Rtt($frame);
        }
        $this->state = self::ST_CLOSED;
    }
    /**
     * Marks the connection closed without queuing a
     * CONNECTION_CLOSE frame. Used by the listener on idle-
     * timeout reaps, which RFC 9000 sec 10.1 requires to be
     * silent: both peers run their own idle timers and tear
     * down independently when the timeout elapses, so any
     * frame on the wire would just confuse the peer.
     */
    public function markClosedSilently()
    {
        $this->state = self::ST_CLOSED;
    }
    /**
     * Returns a flat associative array of stats for this
     * connection, suitable for JSON encoding. Read-only;
     * does not mutate state.
     * @return array live statistics for this connection
     */
    public function stats()
    {
        return [
            'state' => $this->state,
            'established' => $this->isEstablished(),
            'closed' => $this->isClosed(),
            'cid' => bin2hex($this->local_cid),
            'peer_cid' => bin2hex($this->peer_cid),
            'created_at' => $this->created_at,
            'last_packet_at' => $this->last_packet_at,
            'bytes_received' => $this->stats_bytes_received,
            'bytes_sent' => $this->stats_bytes_sent,
            'packets_received' =>
                $this->stats_packets_received,
            'packets_sent' => $this->stats_packets_sent,
            'streams_open' => count($this->streams),
        ];
    }
}
/**
 * HTTP/3 frame codec, RFC 9114 sec 7.2. HTTP/3 frames are
 * deliberately simpler than HTTP/2 frames: a frame is a
 * varint type, a varint length, and length bytes of body.
 * No flags, no stream ID inside the frame (the stream is
 * identified by the QUIC stream the frame travels on).
 *
 * Type codes (RFC 9114 sec 7.2):
 *   0x0  DATA
 *   0x1  HEADERS
 *   0x3  CANCEL_PUSH
 *   0x4  SETTINGS
 *   0x5  PUSH_PROMISE
 *   0x7  GOAWAY
 *   0xd  MAX_PUSH_ID
 *
 * Type codes 0x2, 0x6, 0x8, 0x9 are reserved and indicate
 * a connection error if seen. Greased frame types
 * (0x1f * N + 0x21) MUST be ignored.
 */
class H3FrameCodec
{
    /** HTTP/3 DATA frame type (RFC 9114 §7.2.1). */
    const H3_DATA = 0x00;
    /** HTTP/3 HEADERS frame type (RFC 9114 §7.2.2). */
    const H3_HEADERS = 0x01;
    /** HTTP/3 CANCEL_PUSH frame type (RFC 9114 §7.2.3). */
    const H3_CANCEL_PUSH = 0x03;
    /** HTTP/3 SETTINGS frame type (RFC 9114 §7.2.4). */
    const H3_SETTINGS = 0x04;
    /** HTTP/3 PUSH_PROMISE frame type (RFC 9114 §7.2.5). */
    const H3_PUSH_PROMISE = 0x05;
    /** HTTP/3 GOAWAY frame type (RFC 9114 §7.2.6). */
    const H3_GOAWAY = 0x07;
    /** HTTP/3 MAX_PUSH_ID frame type (RFC 9114 §7.2.7). */
    const H3_MAX_PUSH_ID = 0x0D;
    /**
     * Decodes as many complete HTTP/3 frames as possible
     * from $buf. Returns
     *   [array_of_frames, leftover_bytes, err]
     * leftover_bytes is the trailing portion not consumed
     * because a frame was cut short; the caller should
     * accumulate it and re-feed once more bytes arrive.
     * err is "" on success.
     * @param string $buf raw byte buffer
     * @return array list of parsed QuicPacket records
     */
    public static function decodeAll($buf)
    {
        $frames = [];
        $off = 0;
        $end = strlen($buf);
        while ($off < $end) {
            $save = $off;
            list($type, $off2) = QuicVarint::read($buf, $off);
            if ($type === false) {
                return [$frames, substr($buf, $save), ''];
            }
            list($len, $off3) = QuicVarint::read($buf, $off2);
            if ($len === false ||
                $end < $off3 + $len) {
                return [$frames, substr($buf, $save), ''];
            }
            $body = substr($buf, $off3, $len);
            $off = $off3 + $len;
            $frames[] = ['type' => $type, 'body' => $body];
        }
        return [$frames, '', ''];
    }
    /**
     * Encodes a single frame (type + length-prefixed
     * body).
     * @param int $type type code
     * @param string $body message body bytes
     * @return string encoded packet bytes ready to send
     */
    public static function encode($type, $body)
    {
        return QuicVarint::write($type) .
            QuicVarint::write(strlen($body)) . $body;
    }
    /**
     * Encodes a SETTINGS frame body. $settings is a flat
     * associative array of setting_id => value, both
     * varints. RFC 9114 sec 7.2.4 plus RFC 9204 sec 5
     * for QPACK-related settings.
     * @param mixed $settings settings parameter
     * @return string serialized HTTP/3 SETTINGS frame body
     */
    public static function encodeSettingsBody($settings)
    {
        $out = '';
        foreach ($settings as $id => $value) {
            $out .= QuicVarint::write($id) .
                QuicVarint::write($value);
        }
        return $out;
    }
    /**
     * Decodes a SETTINGS frame body into associative
     * array.
     * @param string $body message body bytes
     * @return array parsed HTTP/3 SETTINGS map
     */
    public static function decodeSettingsBody($body)
    {
        $settings = [];
        $off = 0;
        while ($off < strlen($body)) {
            list($id, $off) = QuicVarint::read($body, $off);
            list($v, $off) = QuicVarint::read($body, $off);
            if ($v === false) {
                break;
            }
            $settings[$id] = $v;
        }
        return $settings;
    }
}
/**
 * QPACK header compression, RFC 9204. HTTP/3's HPACK
 * counterpart. Intentionally minimal: encoder never uses the
 * dynamic table, emitting "indexed field line" (4.5.2) for
 * static-table hits, "literal with name reference" (4.5.4)
 * when only the name matches, "literal with literal name"
 * (4.5.6) otherwise; no encoder-side Huffman (allowed). The
 * decoder accepts all four representations and Huffman input
 * (decoding via QpackHuffman) but throws on dynamic-table
 * refs and treats Required Insert Count > 0 as an error,
 * matching what's required when SETTINGS_QPACK_MAX_TABLE_-
 * CAPACITY is zero.
 */
class Qpack
{
    /**
     * @var array static table, index => [name, value].
     *      99 entries from RFC 9204 Appendix A.
     */
    protected static $static = null;
    /**
     * @var array name => first index in static table.
     */
    protected static $static_by_name = null;
    /**
     * @var array (name . "\0" . value) => index.
     */
    protected static $static_by_pair = null;
    /**
     * Returns the static table; built lazily.
     * @return array reference to the QPACK static table from RFC 9204 Appendix A
     */
    public static function staticTable()
    {
        if (self::$static !== null) {
            return self::$static;
        }
        self::$static = [
            [':authority', ''],
            [':path', '/'],
            ['age', '0'],
            ['content-disposition', ''],
            ['content-length', '0'],
            ['cookie', ''],
            ['date', ''],
            ['etag', ''],
            ['if-modified-since', ''],
            ['if-none-match', ''],
            ['last-modified', ''],
            ['link', ''],
            ['location', ''],
            ['referer', ''],
            ['set-cookie', ''],
            [':method', 'CONNECT'],
            [':method', 'DELETE'],
            [':method', 'GET'],
            [':method', 'HEAD'],
            [':method', 'OPTIONS'],
            [':method', 'POST'],
            [':method', 'PUT'],
            [':scheme', 'http'],
            [':scheme', 'https'],
            [':status', '103'],
            [':status', '200'],
            [':status', '304'],
            [':status', '404'],
            [':status', '503'],
            ['accept', '*/*'],
            ['accept', 'application/dns-message'],
            ['accept-encoding', 'gzip, deflate, br'],
            ['accept-ranges', 'bytes'],
            ['access-control-allow-headers', 'cache-control'],
            ['access-control-allow-headers', 'content-type'],
            ['access-control-allow-origin', '*'],
            ['cache-control', 'max-age=0'],
            ['cache-control', 'max-age=2592000'],
            ['cache-control', 'max-age=604800'],
            ['cache-control', 'no-cache'],
            ['cache-control', 'no-store'],
            ['cache-control', 'public, max-age=31536000'],
            ['content-encoding', 'br'],
            ['content-encoding', 'gzip'],
            ['content-type', 'application/dns-message'],
            ['content-type', 'application/javascript'],
            ['content-type', 'application/json'],
            ['content-type',
                'application/x-www-form-urlencoded'],
            ['content-type', 'image/gif'],
            ['content-type', 'image/jpeg'],
            ['content-type', 'image/png'],
            ['content-type', 'text/css'],
            ['content-type', 'text/html; charset=utf-8'],
            ['content-type', 'text/plain'],
            ['content-type', 'text/plain;charset=utf-8'],
            ['range', 'bytes=0-'],
            ['strict-transport-security',
                'max-age=31536000'],
            ['strict-transport-security',
                'max-age=31536000; includesubdomains'],
            ['strict-transport-security',
                'max-age=31536000; includesubdomains; '
                . 'preload'],
            ['vary', 'accept-encoding'],
            ['vary', 'origin'],
            ['x-content-type-options', 'nosniff'],
            ['x-xss-protection', '1; mode=block'],
            [':status', '100'],
            [':status', '204'],
            [':status', '206'],
            [':status', '302'],
            [':status', '400'],
            [':status', '403'],
            [':status', '421'],
            [':status', '425'],
            [':status', '500'],
            ['accept-language', ''],
            ['access-control-allow-credentials', 'FALSE'],
            ['access-control-allow-credentials', 'TRUE'],
            ['access-control-allow-headers', '*'],
            ['access-control-allow-methods', 'get'],
            ['access-control-allow-methods',
                'get, post, options'],
            ['access-control-allow-methods', 'options'],
            ['access-control-expose-headers',
                'content-length'],
            ['access-control-request-headers',
                'content-type'],
            ['access-control-request-method', 'get'],
            ['access-control-request-method', 'post'],
            ['alt-svc', 'clear'],
            ['authorization', ''],
            ['content-security-policy',
                "script-src 'none'; object-src 'none'; "
                . "base-uri 'none'"],
            ['early-data', '1'],
            ['expect-ct', ''],
            ['forwarded', ''],
            ['if-range', ''],
            ['origin', ''],
            ['purpose', 'prefetch'],
            ['server', ''],
            ['timing-allow-origin', '*'],
            ['upgrade-insecure-requests', '1'],
            ['user-agent', ''],
            ['x-forwarded-for', ''],
            ['x-frame-options', 'deny'],
            ['x-frame-options', 'sameorigin'],
        ];
        self::$static_by_name = [];
        self::$static_by_pair = [];
        foreach (self::$static as $i => $entry) {
            list($name, $value) = $entry;
            if (!isset(self::$static_by_name[$name])) {
                self::$static_by_name[$name] = $i;
            }
            self::$static_by_pair[$name . "\0" . $value] = $i;
        }
        return self::$static;
    }
    /**
     * Encodes a list of [name, value] pairs as a QPACK
     * encoded field section. The first two bytes are the
     * Required Insert Count and Base; we always emit
     * (0, 0) since we don't use the dynamic table.
     * @param array $headers list of [name, value] header pairs
     * @return string encoded packet bytes ready to send
     */
    public static function encode($headers)
    {
        self::staticTable();
        /*
            Required Insert Count = 0 (8-bit prefix)
            Delta Base sign = 0, value = 0 (7-bit prefix)
         */
        $out = "\x00\x00";
        foreach ($headers as $h) {
            list($name, $value) = $h;
            $name = strtolower($name);
            $pair_key = $name . "\0" . $value;
            if (isset(self::$static_by_pair[$pair_key])) {
                $out .= self::encodeIndexedFieldLine(
                    self::$static_by_pair[$pair_key],
                    true);
                continue;
            }
            if (isset(self::$static_by_name[$name])) {
                $out .= self::encodeLiteralWithNameRef(
                    self::$static_by_name[$name], true,
                    $value);
                continue;
            }
            $out .= self::encodeLiteralWithLiteralName(
                $name, $value);
        }
        return $out;
    }
    /**
     * Indexed Field Line, sec 4.5.2.
     *   1 T x x x x x x  index (6-bit prefix integer)
     * T = 1 means static table.
     * @param int $index index
     * @param bool $is_static true to look up the static table; dynamic table is not implemented
     * @return string QPACK indexed-field-line encoding bytes
     */
    protected static function encodeIndexedFieldLine($index,
        $is_static)
    {
        $first = 0x80 | ($is_static ? 0x40 : 0x00);
        return self::encodePrefixedInt($index, 6, $first);
    }
    /**
     * Literal Field Line With Name Reference, sec 4.5.4.
     *   0 1 N T x x x x  index (4-bit prefix)
     *   value as string-with-huffman (we omit huffman).
     * N = Never-Indexed flag (0 here), T = static.
     * @param int $index index
     * @param bool $is_static true to look up the static table; dynamic table is not implemented
     * @param mixed $value value
     * @return string QPACK literal-with-name-reference encoding bytes
     */
    protected static function encodeLiteralWithNameRef(
        $index, $is_static, $value)
    {
        $first = 0x40 | ($is_static ? 0x10 : 0x00);
        return self::encodePrefixedInt($index, 4, $first) .
            self::encodeString($value, 7);
    }
    /**
     * Literal Field Line With Literal Name, sec 4.5.6.
     *   0 0 1 N H x x x  name-length (3-bit prefix)
     *   name bytes
     *   value (string-with-huffman)
     * H = use Huffman (we set 0).
     * @param string $name name
     * @param mixed $value value
     * @return string QPACK literal-with-literal-name encoding bytes
     */
    protected static function encodeLiteralWithLiteralName(
        $name, $value)
    {
        $first = 0x20;
        return self::encodePrefixedInt(strlen($name), 3,
            $first) . $name .
            self::encodeString($value, 7);
    }
    /**
     * Encodes a value preceded by a length, with a
     * variable-bit prefix. The Huffman bit is bit
     * (prefix_bits) of the first byte; we always set 0
     * (no Huffman on encode).
     * @param mixed $s s parameter
     * @param int $prefix_bits prefix width in bits for the QPACK length integer
     * @return string QPACK string-literal encoding bytes
     */
    protected static function encodeString($s, $prefix_bits)
    {
        return self::encodePrefixedInt(strlen($s),
            $prefix_bits, 0) . $s;
    }
    /**
     * QPACK prefixed-integer encoding, RFC 7541 sec 5.1
     * (HPACK; QPACK reuses the same primitive). N is the
     * number of bits in the first byte allocated to the
     * integer; the remaining (8-N) bits are flag bits the
     * caller pre-OR-ed into $high_bits.
     * @param mixed $value value
     * @param int $n_bits prefix width in bits (1..8) for the prefixed-integer encoding
     * @param mixed $high_bits high_bits parameter
     * @return string QPACK prefixed-integer encoding bytes
     */
    protected static function encodePrefixedInt($value,
        $n_bits, $high_bits)
    {
        $cap = (1 << $n_bits) - 1;
        if ($value < $cap) {
            return chr($high_bits | $value);
        }
        $out = chr($high_bits | $cap);
        $value -= $cap;
        while ($value >= 128) {
            $out .= chr(($value & 0x7F) | 0x80);
            $value >>= 7;
        }
        $out .= chr($value);
        return $out;
    }
    /**
     * Decoder: reads $bytes (a complete QPACK-encoded
     * field section) and returns a list of [name, value]
     * pairs. Throws on malformed input or dynamic-table
     * references.
     * @param string $bytes bytes to operate on
     * @return array two-element list [QuicPacket|false, int $new_off]; false on parse failure
     */
    public static function decode($bytes)
    {
        self::staticTable();
        $off = 0;
        list($insert_count, $off) =
            self::readPrefixedInt($bytes, $off, 8);
        if ($insert_count !== 0) {
            throw new \RuntimeException(
                "Required Insert Count nonzero; dynamic " .
                "table not supported");
        }
        list($base_first, $off) = self::readU8($bytes, $off);
        list($delta_base, $off) =
            self::readPrefixedIntFrom($bytes, $off, 7,
                $base_first & 0x7F);
        $headers = [];
        while ($off < strlen($bytes)) {
            list($byte, ) = self::readU8($bytes, $off);
            if (($byte & 0x80) !== 0) {
                /* Indexed Field Line, 4.5.2 */
                $is_static = (bool)($byte & 0x40);
                list($index, $off) =
                    self::readPrefixedInt($bytes, $off, 6);
                $headers[] = self::lookupStatic($index,
                    $is_static, true);
            } else if (($byte & 0x40) !== 0) {
                /* Literal Field Line With Name Reference,
                   4.5.4 */
                $is_static = (bool)($byte & 0x10);
                list($index, $off) =
                    self::readPrefixedInt($bytes, $off, 4);
                $entry = self::lookupStatic($index,
                    $is_static, false);
                list($value, $off) =
                    self::readStringWithHuffman($bytes,
                        $off, 7);
                $headers[] = [$entry[0], $value];
            } else if (($byte & 0x20) !== 0) {
                /* Literal Field Line With Literal Name,
                   4.5.6 */
                list($name, $off) =
                    self::readStringWithHuffman($bytes,
                        $off, 3);
                list($value, $off) =
                    self::readStringWithHuffman($bytes,
                        $off, 7);
                $headers[] = [strtolower($name), $value];
            } else if (($byte & 0x10) !== 0) {
                throw new \RuntimeException(
                    "post-base index not supported");
            } else {
                throw new \RuntimeException(
                    "post-base name ref not supported");
            }
        }
        return $headers;
    }
    /**
     * Reads a single byte from $buf at $off.
     *
     * @param string $buf raw buffer being decoded
     * @param int $off current byte offset
     * @return array two-element list [int $byte, int $new_off]
     */
    protected static function readU8($buf, $off)
    {
        if (strlen($buf) <= $off) {
            throw new \RuntimeException("QPACK truncated");
        }
        return [ord($buf[$off]), $off + 1];
    }
    /**
     * Reads a QPACK/HPACK-style prefixed integer (RFC 7541 sec
     * 5.1) starting at $off. The first byte's low $n_bits hold
     * the value (or signal continuation when all set).
     *
     * @param string $buf raw buffer being decoded
     * @param int $off byte offset of the integer
     * @param int $n_bits prefix width in bits (1..8)
     * @return array two-element list [int $value, int $new_off]
     */
    protected static function readPrefixedInt($buf, $off,
        $n_bits)
    {
        list($byte, $off) = self::readU8($buf, $off);
        $cap = (1 << $n_bits) - 1;
        $value = $byte & $cap;
        return self::readPrefixedIntFrom($buf, $off,
            $n_bits, $value);
    }
    /**
     * Continuation of readPrefixedInt: caller has already
     * extracted the prefix-bits and passes the partial value
     * in. Walks continuation bytes until the high bit clears.
     *
     * @param string $buf raw buffer being decoded
     * @param int $off byte offset of the next continuation byte
     * @param int $n_bits original prefix width
     * @param int $value partial value extracted from the first
     *      byte's prefix bits
     * @return array two-element list [int $value, int $new_off]
     */
    protected static function readPrefixedIntFrom($buf, $off,
        $n_bits, $value)
    {
        $cap = (1 << $n_bits) - 1;
        if ($value < $cap) {
            return [$value, $off];
        }
        $shift = 0;
        while (true) {
            list($b, $off) = self::readU8($buf, $off);
            $value += ($b & 0x7F) << $shift;
            if (($b & 0x80) === 0) {
                break;
            }
            $shift += 7;
            if ($shift > 56) {
                throw new \RuntimeException(
                    "prefixed int overflow");
            }
        }
        return [$value, $off];
    }
    /**
     * Reads a QPACK string literal (RFC 9204 sec 4.1.1): a
     * length-prefixed byte sequence with an optional Huffman
     * flag bit one position above the length prefix.
     *
     * @param string $buf raw buffer being decoded
     * @param int $off byte offset of the string's first byte
     * @param int $prefix_bits prefix width for the length
     *      integer (1..7); the Huffman flag occupies
     *      $prefix_bits position above
     * @return array two-element list [string $bytes,
     *      int $new_off]
     */
    protected static function readStringWithHuffman($buf,
        $off, $prefix_bits)
    {
        list($byte, ) = self::readU8($buf, $off);
        $huffman_bit = 1 << $prefix_bits;
        $is_huffman = (bool)($byte & $huffman_bit);
        list($len, $off) =
            self::readPrefixedInt($buf, $off, $prefix_bits);
        if (strlen($buf) < $off + $len) {
            throw new \RuntimeException(
                "QPACK string truncated");
        }
        $bytes = substr($buf, $off, $len);
        $off += $len;
        if ($is_huffman) {
            $bytes = QpackHuffman::decode($bytes);
        }
        return [$bytes, $off];
    }
    /**
     * Looks up an entry in the QPACK static table (RFC 9204
     * Appendix A).
     *
     * @param int $index static-table index
     * @param bool $is_static must be true; dynamic-table
     *      indexing is not implemented (throws otherwise)
     * @param bool $want_value if true return the value side of
     *      the pair, otherwise the name side
     * @return string name or value bytes from the static table
     */
    protected static function lookupStatic($index,
        $is_static, $want_value)
    {
        if (!$is_static) {
            throw new \RuntimeException(
                "dynamic table not supported");
        }
        if (!isset(self::$static[$index])) {
            throw new \RuntimeException(
                "static table index out of range: $index");
        }
        list($name, $value) = self::$static[$index];
        if ($want_value) {
            return [$name, $value];
        }
        return [$name, ''];
    }
}
/**
 * QPACK Huffman codec, using the table from RFC 7541
 * Appendix B (which QPACK adopts unchanged). Phase 4 only
 * implements decode -- our encoder doesn't Huffman-encode
 * strings (the spec allows this).
 *
 * The table maps each of 257 symbols (0-255 plus EOS=256)
 * to a code of 5-30 bits. We build a binary lookup tree
 * lazily on first decode.
 */
class QpackHuffman
{
    /**
     * @var array binary tree: each node is a 2-element
     *      array [left, right] where each branch is
     *      either an int (leaf, the symbol) or a 2-element
     *      array (internal node).
     */
    protected static $tree = null;
    /**
     * @var array list of [code, bit_length] from
     *      RFC 7541 Appendix B.
     */
    protected static $codes = null;
    /**
     * Builds the codes table on first use. Embedded as a
     * compact comma-separated string ("hex:bits" pairs) so
     * the file stays under 80 columns and the data bulk is
     * small.
     */
    protected static function loadCodes()
    {
        if (self::$codes !== null) {
            return;
        }
        $raw = "1ff8:13,7fffd8:23,fffffe2:28,fffffe3:28,"
            . "fffffe4:28,fffffe5:28,fffffe6:28,fffffe7:28,"
            . "fffffe8:28,ffffea:24,3ffffffc:30,fffffe9:28,"
            . "fffffea:28,3ffffffd:30,fffffeb:28,fffffec:28,"
            . "fffffed:28,fffffee:28,fffffef:28,ffffff0:28,"
            . "ffffff1:28,ffffff2:28,3ffffffe:30,ffffff3:28,"
            . "ffffff4:28,ffffff5:28,ffffff6:28,ffffff7:28,"
            . "ffffff8:28,ffffff9:28,ffffffa:28,ffffffb:28,"
            . "14:6,3f8:10,3f9:10,ffa:12,1ff9:13,15:6,"
            . "f8:8,7fa:11,3fa:10,3fb:10,f9:8,7fb:11,"
            . "fa:8,16:6,17:6,18:6,0:5,1:5,2:5,19:6,"
            . "1a:6,1b:6,1c:6,1d:6,1e:6,1f:6,5c:7,fb:8,"
            . "7ffc:15,20:6,ffb:12,3fc:10,1ffa:13,21:6,"
            . "5d:7,5e:7,5f:7,60:7,61:7,62:7,63:7,64:7,"
            . "65:7,66:7,67:7,68:7,69:7,6a:7,6b:7,6c:7,"
            . "6d:7,6e:7,6f:7,70:7,71:7,72:7,fc:8,73:7,"
            . "fd:8,1ffb:13,7fff0:19,1ffc:13,3ffc:14,"
            . "22:6,7ffd:15,3:5,23:6,4:5,24:6,5:5,25:6,"
            . "26:6,27:6,6:5,74:7,75:7,28:6,29:6,2a:6,"
            . "7:5,2b:6,76:7,2c:6,8:5,9:5,2d:6,77:7,"
            . "78:7,79:7,7a:7,7b:7,7ffe:15,7fc:11,3ffd:14,"
            . "1ffd:13,ffffffc:28,fffe6:20,3fffd2:22,"
            . "fffe7:20,fffe8:20,3fffd3:22,3fffd4:22,"
            . "3fffd5:22,7fffd9:23,3fffd6:22,7fffda:23,"
            . "7fffdb:23,7fffdc:23,7fffdd:23,7fffde:23,"
            . "ffffeb:24,7fffdf:23,ffffec:24,ffffed:24,"
            . "3fffd7:22,7fffe0:23,ffffee:24,7fffe1:23,"
            . "7fffe2:23,7fffe3:23,7fffe4:23,1fffdc:21,"
            . "3fffd8:22,7fffe5:23,3fffd9:22,7fffe6:23,"
            . "7fffe7:23,ffffef:24,3fffda:22,1fffdd:21,"
            . "fffe9:20,3fffdb:22,3fffdc:22,7fffe8:23,"
            . "7fffe9:23,1fffde:21,7fffea:23,3fffdd:22,"
            . "3fffde:22,fffff0:24,1fffdf:21,3fffdf:22,"
            . "7fffeb:23,7fffec:23,1fffe0:21,1fffe1:21,"
            . "3fffe0:22,1fffe2:21,7fffed:23,3fffe1:22,"
            . "7fffee:23,7fffef:23,fffea:20,3fffe2:22,"
            . "3fffe3:22,3fffe4:22,7ffff0:23,3fffe5:22,"
            . "3fffe6:22,7ffff1:23,3ffffe0:26,3ffffe1:26,"
            . "fffeb:20,7fff1:19,3fffe7:22,7ffff2:23,"
            . "3fffe8:22,1ffffec:25,3ffffe2:26,3ffffe3:26,"
            . "3ffffe4:26,7ffffde:27,7ffffdf:27,3ffffe5:26,"
            . "fffff1:24,1ffffed:25,7fff2:19,1fffe3:21,"
            . "3ffffe6:26,7ffffe0:27,7ffffe1:27,3ffffe7:26,"
            . "7ffffe2:27,fffff2:24,1fffe4:21,1fffe5:21,"
            . "3ffffe8:26,3ffffe9:26,ffffffd:28,7ffffe3:27,"
            . "7ffffe4:27,7ffffe5:27,fffec:20,fffff3:24,"
            . "fffed:20,1fffe6:21,3fffe9:22,1fffe7:21,"
            . "1fffe8:21,7ffff3:23,3fffea:22,3fffeb:22,"
            . "1ffffee:25,1ffffef:25,fffff4:24,fffff5:24,"
            . "3ffffea:26,7ffff4:23,3ffffeb:26,7ffffe6:27,"
            . "3ffffec:26,3ffffed:26,7ffffe7:27,7ffffe8:27,"
            . "7ffffe9:27,7ffffea:27,7ffffeb:27,ffffffe:28,"
            . "7ffffec:27,7ffffed:27,7ffffee:27,7ffffef:27,"
            . "7fffff0:27,3ffffee:26,3fffffff:30";
        self::$codes = [];
        foreach (explode(',', $raw) as $tok) {
            list($hex, $bits) = explode(':', $tok);
            self::$codes[] = [hexdec($hex), (int) $bits];
        }
        /*
            Either 256 (no EOS) or 257 (with EOS) is fine;
            257 is the canonical RFC 7541 form. If the
            count is anything else the table is corrupted
            and decode would silently produce wrong output;
            bail loudly instead.
         */
        $n = count(self::$codes);
        if ($n !== 256 && $n !== 257) {
            throw new \RuntimeException(
                "QpackHuffman table wrong size: $n");
        }
    }
    /**
     * Builds the binary lookup tree from the codes table.
     * @return string serialized bytes
     */
    protected static function buildTree()
    {
        if (self::$tree !== null) {
            return;
        }
        self::loadCodes();
        $root = [null, null];
        foreach (self::$codes as $sym => $entry) {
            list($code, $bits) = $entry;
            $node = &$root;
            for ($i = $bits - 1; $i >= 0; $i--) {
                $bit = ($code >> $i) & 1;
                if ($i === 0) {
                    $node[$bit] = $sym;
                } else {
                    if (!is_array($node[$bit])) {
                        $node[$bit] = [null, null];
                    }
                    $node = &$node[$bit];
                }
            }
            unset($node);
        }
        self::$tree = $root;
    }
    /**
     * Decodes a Huffman-encoded byte string. The encoded
     * stream is padded with the most significant bits of
     * the EOS symbol (all 1s); we ignore trailing bits
     * once we have walked through every full byte.
     * @param string $bytes bytes to operate on
     * @return array two-element list [QuicPacket|false, int $new_off]; false on parse failure
     */
    public static function decode($bytes)
    {
        self::buildTree();
        $out = '';
        $node = self::$tree;
        $bitlen = strlen($bytes) * 8;
        for ($i = 0; $i < $bitlen; $i++) {
            $byte_idx = $i >> 3;
            $bit = (ord($bytes[$byte_idx])
                >> (7 - ($i & 7))) & 1;
            $next = $node[$bit];
            if (is_int($next)) {
                $out .= chr($next);
                $node = self::$tree;
            } else if (is_array($next)) {
                $node = $next;
            } else {
                /*
                    Hit a missing branch -- this is the
                    EOS-style padding; we should have
                    consumed all real symbols by now. Just
                    stop.
                 */
                break;
            }
        }
        return $out;
    }
}
/**
 * Public H3 Connection. Extends atto's Connection so it
 * fits seamlessly into the existing $_SERVER routing.
 * Wraps a QuicConnection plus the H3-layer state for one
 * peer.
 */
class H3Connection extends Connection
{
    /**
     * @var int|null QUIC stream ID of the server's
     *      uni control stream (allocated lazily on first
     *      flush).
     */
    public $control_stream_id = null;
    /**
     * @var bool whether we have written the SETTINGS
     *      frame on the control stream.
     */
    public $settings_sent = false;
    /**
     * @var array per-bidi-stream H3 state. Key is the QUIC
     *      stream id; value is an associative array
     *      ['headers' => [...], ':method' => 'GET', etc.,
     *       'body_chunks' => [...], 'fin_seen' => bool,
     *       'dispatched' => bool, 'h3_buf' => '' (partial
     *       frames waiting for more data)].
     */
    public $h3_streams = [];
    /**
     * @var array per-uni-stream state. Key is QUIC stream
     *      id; value is ['type' => varint or null,
     *       'header_buf' => '' (waiting for the type byte
     *       prefix)].
     */
    public $uni_streams = [];
    /**
     * @var int next bidi stream id to use for server-
     *      initiated streams. Server-initiated bidi
     *      streams in QUIC are 0b01 (id mod 4 == 1); we
     *      currently don't open any (servers respond on
     *      client-initiated streams), so this is unused
     *      but reserved.
     */
    public $next_server_bidi = 1;
    /**
     * @var int next uni stream id for our control stream
     *      and any server-initiated uni streams. Server-
     *      initiated uni streams in QUIC have id mod 4
     *      == 3 (binary 0b11). The lowest valid value is
     *      3.
     */
    public $next_server_uni = 3;
    /**
     * Constructor: wraps a QuicConnection.
     *
     * @param QuicConnection $quic underlying QUIC connection
     * @param string $scid_hex hex-string view of the local CID, for
     *      logging
     * @param string $peer_address peer address in "ip:port" form, for
     *      REMOTE_ADDR / REMOTE_PORT building
     */
    public function __construct(public $quic, public $scid_hex = '',
        public $peer_address = '')
    {
        /*
            'h3' is a separate protocol code from 'h3'
            (which is reserved for H3Connection from the FFI
            backend). The two share the same wire protocol
            but route through different per-protocol Transport
            instances inside WebSite.
         */
        $this->protocol = 'h3';
        $this->client_http = 'HTTP/3';
        $this->is_secure = true;
        $this->https = 'on';
    }
    /**
     * True once the QUIC handshake has finished and the
     * connection can carry application data.
     * @return bool true if the QUIC handshake has completed
     */
    public function isEstablished()
    {
        return $this->quic->isEstablished();
    }
    /**
     * True if the connection has gone into closed state
     * (CONNECTION_CLOSE seen, idle timeout, fatal error).
     * @return bool true if the connection has been closed
     */
    public function isClosed()
    {
        return $this->quic->isClosed();
    }
    /**
     * Tears down the connection, sending CONNECTION_CLOSE
     * if possible.
     * @param int $error_code error code
     * @param string $reason reason phrase
     */
    public function close($error_code = 0, $reason = '')
    {
        $this->quic->close($error_code, $reason);
    }
}
/**
 * H3Listener: the public listener class. Owns the UDP
 * socket, the connection table, and the lazy-init of
 * H3Transport. Mirrors the FFI-version's surface so
 * WebSite::listen() routes the same way regardless of
 * which backend is active.
 */
class H3Listener extends Listener
{
    /**
     * @var int the byte length we use for connection IDs
     *      we mint locally. The wire format places no
     *      length restriction (RFC 9000 sec 5.1.1: 0..20
     *      bytes); 8 is enough entropy to collision-avoid
     *      an in-process map and small enough to keep the
     *      short-header overhead modest. If we ever
     *      rotate CIDs (Phase 5) this becomes per-
     *      connection state instead of a class constant.
     */
    const COMMON_CID_LENGTH = 8;
    /**
     * @var string PEM bytes of the server certificate,
     *      cached so each new H3Connection's underlying
     *      Tls13Engine can be constructed without re-
     *      reading the file.
     */
    public $cert_pem = '';
    /**
     * @var string PEM bytes of the server private key.
     */
    public $key_pem = '';
    /**
     * @var array list of ALPN byte-strings the listener
     *      offers, in preference order.
     */
    public $alpn_offered = ['h3'];
    /**
     * @var array dcid-hex => H3Connection. Active
     *      connections.
     */
    public $connections = [];
    /**
     * @var array dcid-hex => float (Unix time of last
     *      activity). Used to reap idle connections.
     */
    public $last_activity = [];
    /**
     * @var array cid-hex => primary key in $connections.
     *      Every active local CID for every connection has
     *      an entry here. The first CID a connection mints
     *      (sequence 0) keeps its hex as the primary key,
     *      so $connections[$primary] === the H3Connection
     *      and $cid_index[$primary] === $primary; later
     *      CIDs (issued via NEW_CONNECTION_ID) point at the
     *      same primary, letting the peer use any active
     *      CID as the DCID on outbound packets without us
     *      having to scan.
     */
    public $cid_index = [];
    /**
     * @var string 32-byte secret used to derive stateless
     *      reset tokens (RFC 9000 sec 10.3) for every CID
     *      this listener issues. Generated once at tryOpen
     *      time so all connections under one listener share
     *      a derivation key.
     */
    protected $stateless_reset_secret = "";
    /**
     * @var int total stateless-reset packets emitted in
     *      response to inbound 1-RTT packets bearing a
     *      DCID we no longer recognize (RFC 9000 sec 10.3).
     *      Surfaced for ops debugging via /h3stats; expected
     *      to stay at zero in healthy steady state.
     */
    public $stats_resets_sent = 0;
    /**
     * @var int total successful client-initiated migrations:
     *      a connection's peer_address was switched after
     *      PATH_RESPONSE confirmed the new path. Surfaced
     *      via /h3stats for ops debugging.
     */
    public $stats_path_migrations = 0;
    /**
     * @var WebSite|null back-reference to the WebSite that
     *      opened this listener. Set by WebSite::listen()
     *      right after tryOpen() returns. Used by
     *      processDatagram to reach
     *      $site->transports['h3'] for application-
     *      level dispatch.
     */
    public $site = null;
    /**
     * Standard listener constructor; cert/key/alpn are
     * filled in by tryOpen.
     * @param mixed $server server parameter
     * @param string $address peer or local address
     * @param array $globals per-listener server globals overrides
     * @param string $cert_pem certificate in PEM format
     * @param string $key_pem private key in PEM format
     * @param mixed $alpn alpn parameter
     */
    public function __construct($server, $address, $globals,
        $cert_pem, $key_pem, $alpn = ['h3'])
    {
        parent::__construct($server, $address, true,
            $globals);
        $this->cert_pem = $cert_pem;
        $this->key_pem = $key_pem;
        $this->alpn_offered = $alpn;
    }
    /**
     * Opens an H3Listener on $bind_address. $context is the
     * PHP stream context array typically built from the
     * 'ssl' settings in the listen() spec; we pull
     * 'local_cert' and 'local_pk' out of it. Returns null
     * if the listener cannot be opened (missing cert/key,
     * UDP bind failure).
     * @param string $bind_address udp:// bind address for stream_socket_server
     * @param array $context per-listener stream context overrides
     * @param array $globals per-listener server globals overrides
     * @return H3Listener|null newly opened listener, or null if the required extensions or key material are not available
     */
    public static function tryOpen($bind_address, $context,
        $globals)
    {
        $ssl = $context['ssl'] ?? [];
        $cert_path = $ssl['local_cert'] ?? '';
        $key_path = $ssl['local_pk'] ?? '';
        if (empty($cert_path) || empty($key_path)) {
            echo "H3Listener for $bind_address: missing "
                . "ssl.local_cert / ssl.local_pk\n";
            return null;
        }
        if (!is_file($cert_path) || !is_file($key_path)) {
            echo "H3Listener for $bind_address: cert or "
                . "key file does not exist\n";
            return null;
        }
        $cert_pem = file_get_contents($cert_path);
        $key_pem = file_get_contents($key_path);
        if (!$cert_pem || !$key_pem) {
            echo "H3Listener for $bind_address: cert or "
                . "key file unreadable\n";
            return null;
        }
        $udp_address = preg_replace('/^tcp:\/\//', 'udp://',
            $bind_address);
        if ($udp_address === $bind_address &&
            !str_contains($bind_address, '://')) {
            $udp_address = 'udp://' . $bind_address;
        }
        $server = stream_socket_server($udp_address, $errno,
            $errstr, STREAM_SERVER_BIND);
        if (!$server) {
            echo "H3Listener bind $udp_address: $errstr\n";
            return null;
        }
        stream_set_blocking($server, false);
        /*
            Bump the kernel UDP send buffer if we can.
            Default Linux net.core.wmem_default is ~208 KiB
            which is smaller than a typical RFC 9002 cwnd
            after a few RTTs of slow-start. emit() can hand
            sendto more bytes than that fit in one go --
            the kernel silently drops the overflow, which
            our peer treats as packet loss, which trips
            NewReno halving and stalls /big throughput. A
            larger buffer absorbs the bursts. We ask for
            2 MiB; Linux doubles that internally (man
            socket(7) SO_SNDBUF) so the effective ceiling
            is ~4 MiB. socket_import_stream + socket_set_-
            option is the only way to tune this on a
            stream_socket_server resource. Best-effort: if
            the ext/sockets functions aren't compiled in,
            we proceed with the default buffer.
         */
        if (function_exists('socket_import_stream')) {
            $sock = @socket_import_stream($server);
            if ($sock !== false && $sock !== null) {
                @socket_set_option($sock, SOL_SOCKET,
                    SO_SNDBUF, 2 * 1024 * 1024);
            }
        }
        /*
            Pass the udp:// form to the parent so dashboard
            output ("SERVER listening at ...") shows the real
            transport instead of the tcp:// alias the user
            wrote in their listen spec.
         */
        $listener = new self($server, $udp_address, $globals,
            $cert_pem, $key_pem, ['h3']);
        /*
            Generate the per-listener stateless-reset secret
            once at open time. Every connection under this
            listener uses it (via $stateless_reset_secret on
            each QuicConnection) to derive consistent reset
            tokens for the CIDs it issues.
         */
        $listener->stateless_reset_secret = random_bytes(32);
        return $listener;
    }
    /**
     * Closes the UDP socket and tears down all tracked
     * connections. For each live connection, queues a
     * CONNECTION_CLOSE (RFC 9000 sec 10.2) and flushes once
     * so the peer sees a deliberate close rather than
     * waiting on its idle timer. Best-effort: no
     * retransmission of CONNECTION_CLOSE itself; a peer that
     * loses it falls back to idle timeout. Full RFC 9000 sec
     * 10.2.2 closing-state behaviour (CONNECTION_CLOSE
     * retransmitted for at least 3 PTO) is deferred.
     */
    public function close()
    {
        foreach ($this->connections as $h3) {
            if ($h3->isClosed()) {
                continue;
            }
            $h3->close();
            $this->flushConnectionOnce($h3);
        }
        $this->connections = [];
        parent::close();
    }
    /**
     * Drains pending datagrams from one H3Connection's QUIC
     * emit() queue and writes them to the wire. Used by
     * close() so a queued CONNECTION_CLOSE frame actually
     * reaches the peer before the connection is dropped
     * from the listener's map. Safe to call on a closed or
     * partially-closed connection; emit() returns an empty
     * list when there's nothing to send.
     * @param mixed $h3 h3 parameter
     */
    protected function flushConnectionOnce($h3)
    {
        if (!is_resource($this->server)) {
            return;
        }
        foreach ($h3->quic->emit() as $datagram) {
            @stream_socket_sendto($this->server,
                $datagram, 0, $h3->peer_address);
        }
    }
    /**
     * Drains pending UDP datagrams, demuxes them to the
     * right H3Connection, and returns the first newly-
     * established connection (matching the H1/H2 pattern
     * where accept returns at most one new Connection per
     * call). Stale handshakes are reaped here on every
     * UDP wake-up.
     *
     * @param ConnectionAcceptor $acceptor unused for H3
     *     (kept for parent-class compat)
     * @param float $timeout unused
     * @return array [Connection|null, array|null]
     */
    public function accept($acceptor, $timeout)
    {
        $this->reapStaleConnections();
        $first_new = null;
        $first_context = null;
        $max = 4096;
        while ($max-- > 0) {
            $peer = '';
            $buf = @stream_socket_recvfrom($this->server,
                65535, 0, $peer);
            if ($buf === false || $buf === '') {
                break;
            }
            list($conn, $is_new) = $this->processDatagram(
                $buf, $peer);
            if ($conn === null) {
                continue;
            }
            $this->last_activity[$conn->scid_hex] =
                microtime(true);
            if ($is_new && $first_new === null) {
                $first_new = $conn;
                $first_context = [
                    'protocol' => 'h3',
                    'is_secure' => true,
                ];
            }
        }
        /*
            Even if no inbound packets arrived this turn,
            something may have queued up output (typically
            the response from a prior dispatchRequest). Flush
            every connection unconditionally.
         */
        foreach ($this->connections as $h3) {
            foreach ($h3->quic->emit() as $datagram) {
                if (getenv('ATTO_H3_TRACE')) {
                    error_log(sprintf(
                        "[H3TRACE] SEND %dB to %s",
                        strlen($datagram), $h3->peer_address));
                }
                @stream_socket_sendto($this->server,
                    $datagram, 0, $h3->peer_address);
            }
        }
        if ($first_new !== null) {
            return [$first_new, $first_context];
        }
        return [null, null];
    }
    /**
     * Demuxes one inbound datagram. Returns
     *   [H3Connection|null, $is_new]
     * where $is_new is true if this datagram opened a new
     * connection.
     * @param string $buf raw byte buffer
     * @param string $peer peer address as returned by stream_socket_recvfrom
     * @return void no return; the datagram is processed in place
     */
    public function processDatagram($buf, $peer)
    {
        if (getenv('ATTO_H3_TRACE')) {
            $first = strlen($buf) > 0 ? ord($buf[0]) : 0;
            $is_long = ($first & 0x80) ? 'long' : 'short';
            $type = ($first & 0x80) ? (($first >> 4) & 3)
                : -1;
            error_log(sprintf(
                "[H3TRACE] RECV %dB from %s first=0x%02x "
                . "form=%s long_type=%d",
                strlen($buf), $peer, $first, $is_long,
                $type));
        }
        $dcid = self::peekDcid($buf,
            self::COMMON_CID_LENGTH);
        if ($dcid === '' || $dcid === false) {
            if (getenv('ATTO_H3_TRACE')) {
                error_log(
                    "[H3TRACE]   peekDcid failed; dropping");
            }
            return [null, false];
        }
        $key_h_dcid = bin2hex($dcid);
        $is_new = false;
        if (isset($this->cid_index[$key_h_dcid])) {
            $key_h = $this->cid_index[$key_h_dcid];
        } else {
            /*
                The DCID isn't one we recognize. For a
                brand-new client Initial this is expected
                (the DCID is whatever value the client
                picked before learning ours), so accept it
                if the packet looks like an Initial; for a
                short-header (1-RTT) packet on an unknown
                DCID, attempt a stateless reset per RFC
                9000 sec 10.3 to nudge the peer to give up
                on a connection we no longer know about.
             */
            if (strlen($buf) < 1 ||
                (ord($buf[0]) & 0x80) === 0) {
                $reset = self::buildStatelessReset(
                    $dcid, $this->stateless_reset_secret,
                    strlen($buf));
                if ($reset !== '') {
                    @stream_socket_sendto($this->server,
                        $reset, 0, $peer);
                    $this->stats_resets_sent++;
                    if (getenv('ATTO_H3_TRACE')) {
                        error_log(sprintf(
                            "[H3TRACE]   stateless reset "
                            . "%dB to %s for DCID %s",
                            strlen($reset), $peer,
                            $key_h_dcid));
                    }
                }
                return [null, false];
            }
            $quic = new QuicConnection(
                $this->cert_pem, $this->key_pem,
                $this->alpn_offered);
            /*
                Stamp the per-listener stateless-reset
                secret onto the connection so its
                statelessResetToken() emits stable,
                listener-wide consistent tokens; and
                install the retired-CID callback so the
                listener's $cid_index drops the entry when
                the peer retires a CID.
             */
            $quic->stateless_reset_secret =
                $this->stateless_reset_secret;
            $primary_h = bin2hex($quic->local_cid);
            $cid_index_ref =& $this->cid_index;
            $quic->on_cid_retired =
                function ($retired_cid)
                    use (&$cid_index_ref, $primary_h) {
                    $hex = bin2hex($retired_cid);
                    if ($hex !== $primary_h) {
                        unset($cid_index_ref[$hex]);
                    }
                };
            $h3 = new H3Connection($quic,
                $primary_h, $peer);
            $h3->listener_name =
                $this->globals['SERVER_NAME'] ?? '';
            $h3->listener_port =
                $this->globals['SERVER_PORT'] ?? '';
            $this->connections[$primary_h] = $h3;
            /*
                Register both routing keys in the index:
                (a) the DCID the client picked for its very
                first packet, valid until it switches to
                ours; (b) our generated local_cid which the
                peer adopts after seeing our reply.
                Additional CIDs minted later by fillCidPool
                land in the index via syncCidIndex below.
             */
            $this->cid_index[$key_h_dcid] = $primary_h;
            $this->cid_index[$primary_h] = $primary_h;
            $key_h = $primary_h;
            $is_new = true;
        }
        $h3 = $this->connections[$key_h];
        /*
            Detect a peer-address change on an established
            connection: client migration per RFC 9000 sec 9.
            If the inbound datagram's source address differs
            from the one we've recorded and this isn't a
            brand-new connection, queue a PATH_CHALLENGE on
            the new path. We continue replying to the old
            address until the matching PATH_RESPONSE confirms
            the new path is reachable and not spoofed.
            Pre-handshake migration isn't supported: only
            mark a pending path once ST_ESTABLISHED so the
            challenge has 1-RTT keys to ride. If validation
            is already in progress for a different alternative,
            cancel and start fresh against the new address;
            queueing two challenges simultaneously would
            cross-validate paths the peer didn't ask about.
         */
        if (!$is_new
            && $h3->isEstablished()
            && $h3->peer_address !== $peer) {
            $alt = $h3->quic->pending_path['address'] ?? null;
            if ($alt !== $peer) {
                $challenge = random_bytes(8);
                $h3->quic->pending_path = [
                    'address' => $peer,
                    'challenge' => $challenge,
                    'first_seen' => microtime(true),
                    'response_received' => false,
                ];
                /*
                    Build a single 1-RTT packet carrying just
                    the PATH_CHALLENGE frame and send it
                    directly to the new path. We bypass the
                    normal emit() queue here because that
                    queue's sendto target is bound to one
                    address per call -- the peer_address
                    we're still validating. A direct send
                    keeps the contract simple: validated
                    traffic on the old path, the lone
                    challenge on the new path.
                 */
                $packet =
                    self::buildPathChallengePacket($h3->quic,
                        $challenge);
                if ($packet !== '') {
                    @stream_socket_sendto($this->server,
                        $packet, 0, $peer);
                }
                if (getenv('ATTO_H3_TRACE')) {
                    error_log(sprintf(
                        "[H3TRACE]   path validation start: "
                        . "old=%s new=%s challenge=%s",
                        $h3->peer_address, $peer,
                        bin2hex($challenge)));
                }
            }
        }
        $ok = $h3->quic->processDatagram($buf, $peer);
        /*
            If the inbound datagram carried a PATH_RESPONSE
            that confirmed our pending path, swap the
            connection's peer_address to the new one and
            reset RFC 9000 sec 9.4 congestion-control state.
            cwnd resets to its initial value, bytes_in_flight
            zeros (the prior counts were against the old path
            and don't apply to the new one).
         */
        if (!empty($h3->quic->pending_path)
            && !empty(
                $h3->quic->pending_path['response_received'])) {
            $new_address = $h3->quic->pending_path['address'];
            if (getenv('ATTO_H3_TRACE')) {
                error_log(sprintf(
                    "[H3TRACE]   path validation done: "
                    . "swapping peer_address %s -> %s",
                    $h3->peer_address, $new_address));
            }
            $h3->peer_address = $new_address;
            $h3->quic->congestion_window =
                QuicConnection::CC_INITIAL_WINDOW_BYTES;
            $h3->quic->bytes_in_flight = 0;
            $h3->quic->pending_path = [];
            $this->stats_path_migrations++;
        }
        if (!$ok || $h3->isClosed()) {
            unset($this->connections[$key_h]);
            unset($this->last_activity[$key_h]);
            /*
                Drop every $cid_index entry pointing at
                this connection so a stray late datagram on
                a CID we used to recognize doesn't try to
                route into a dropped connection.
             */
            foreach ($this->cid_index as $hex => $primary) {
                if ($primary === $key_h) {
                    unset($this->cid_index[$hex]);
                }
            }
            return [$h3, false];
        }
        /*
            Drive the H3 layer for this connection so any
            request frames just received get parsed,
            dispatched through the WebSite app handler, and
            their responses queued into the QUIC send queue.
            The transport reference is reached via the
            WebSite back-pointer that listen() sets after
            tryOpen returns. Without this call the request
            never reaches the app and the client sits at
            "GET sent" forever (this is the integration
            point that the Phase 4 standalone test rig
            exercised manually after each accept).

            Skip if no site is wired (e.g. unit tests that
            instantiate the listener directly). Also skip
            until the connection is ESTABLISHED so we don't
            poke the H3 layer mid-handshake.
         */
        if ($this->site !== null &&
            isset($this->site->transports['h3']) &&
            $h3->isEstablished()) {
            $this->site->transports['h3']
                ->driveConnection($this, $h3);
        }
        /* Send any datagrams the QUIC layer has produced.
           Per RFC 9000 sec 9, replies go to the *validated*
           peer_address, never to a freshly-observed source
           that hasn't yet completed PATH_CHALLENGE/PATH_-
           RESPONSE; sending to an unvalidated address would
           let an attacker amplify reflected traffic to a
           victim by spoofing the source. The above
           address-change branch handles the validation
           dance separately. */
        foreach ($h3->quic->emit() as $datagram) {
            if (getenv('ATTO_H3_TRACE')) {
                error_log(sprintf(
                    "[H3TRACE] SEND %dB to %s",
                    strlen($datagram), $h3->peer_address));
            }
            @stream_socket_sendto($this->server, $datagram,
                0, $h3->peer_address);
        }
        /*
            Sync the routing index with the connection's
            current set of issued CIDs. fillCidPool()
            populates new entries in $issued_cids; emit()
            ships them as NEW_CONNECTION_ID frames; we
            register them here so a future inbound packet
            using one of them as DCID routes back to this
            connection. Idempotent across repeated entries
            and cheap (the set is bounded by
            active_connection_id_limit, default 4).
         */
        foreach ($h3->quic->issued_cids as $cid) {
            $this->cid_index[bin2hex($cid)] = $key_h;
        }
        return [$h3, $is_new];
    }
    /**
     * Builds a single 1-RTT QUIC packet carrying just one
     * PATH_CHALLENGE frame for the supplied $challenge
     * (8 random bytes). Used by the address-change branch
     * to send the challenge directly to a not-yet-validated
     * peer source address, bypassing the QuicConnection's
     * normal emit() queue (whose sendto target is one
     * address per call). Returns the encoded wire bytes,
     * or '' if 1-RTT keys are not yet available or the
     * encoding fails.
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $challenge challenge parameter
     * @return string encoded PATH_CHALLENGE packet bytes
     */
    public static function buildPathChallengePacket($conn,
        $challenge)
    {
        if (!isset($conn->keys[
                QuicConnection::LEVEL_APPLICATION])) {
            return '';
        }
        $payload = QuicFrame::encode([
            'type' => QuicFrame::F_PATH_CHALLENGE,
            'data' => $challenge,
        ]);
        $packet = new QuicPacket();
        $packet->destination_cid = $conn->peer_cid;
        /*
            Use a fresh PN from the application space; the
            packet is real 1-RTT data and the peer will ACK
            it the same way as any other 1-RTT packet. We
            do not enter it into sent_packets here (no loss
            recovery for path probes -- if the peer never
            sees the challenge, the validation just times
            out and the migration is abandoned, which is
            the simplest sound behaviour).
         */
        $pn = $conn->next_pn[
            QuicConnection::LEVEL_APPLICATION]++;
        $tx = $conn->keys[
            QuicConnection::LEVEL_APPLICATION]['tx'];
        $bytes = $packet->encodeShort($tx, $pn, $payload);
        if ($bytes === false) {
            return '';
        }
        return $bytes;
    }
    /**
     * Peeks the DCID out of a datagram. For long-header
     * packets the DCID length is on the wire. For short-
     * header packets we have to assume the locally chosen
     * length, which we standardize at 8 bytes for all
     * connections opened by this listener.
     * @param string $buf raw byte buffer
     * @param mixed $short_dcid_len short_dcid_len parameter
     * @return string|false the destination Connection ID extracted without consuming the packet, or false if the buffer is not a parseable QUIC packet
     */
    protected static function peekDcid($buf, $short_dcid_len)
    {
        $buf_len = strlen($buf);
        if ($buf_len < 1) {
            return false;
        }
        if (ord($buf[0]) & 0x80) {
            if ($buf_len < 6) {
                return false;
            }
            $dcid_len = ord($buf[5]);
            if ($buf_len < 6 + $dcid_len) {
                return false;
            }
            return substr($buf, 6, $dcid_len);
        }
        if ($buf_len < 1 + $short_dcid_len) {
            return false;
        }
        return substr($buf, 1, $short_dcid_len);
    }
    /**
     * Builds a stateless reset packet per RFC 9000 sec 10.3
     * for $dcid: a short-header-shaped packet whose trailing
     * 16 bytes are the stateless-reset token derived from
     * $secret and $dcid (HMAC-SHA256 truncated to 16 bytes,
     * matching the token we previously gave the peer for any
     * CID we issued). The leading bytes are random padding
     * bounded so the reset is shorter than $triggering_len
     * (RFC 9000 sec 10.3.1: a reset MUST be smaller than the
     * packet that triggered it, which prevents reset loops).
     * Returns the wire bytes, or '' if no reset is possible
     * (no secret available, triggering packet too small to
     * fit even the minimum 21-byte reset, or HMAC failure).
     * @param string $dcid destination Connection ID
     * @param string $secret TLS 1.3 traffic secret
     * @param mixed $triggering_len triggering_len parameter
     * @return string stateless-reset packet bytes per RFC 9000 sec 10.3
     */
    public static function buildStatelessReset($dcid, $secret,
        $triggering_len)
    {
        if ($secret === '' || strlen($dcid) === 0) {
            return '';
        }
        /*
            Reset is at most $triggering_len - 1 bytes (so
            it's strictly smaller) and at most a normal QUIC
            datagram size. Floor at 21 bytes (1 first-byte +
            4 random + 16 token, the RFC 9000 fig 16
            minimum); if the triggering packet is too small,
            don't reset.
         */
        $max_len = min($triggering_len - 1, 1200);
        if ($max_len < 21) {
            return '';
        }
        $token = substr(hash_hmac('sha256', $dcid, $secret,
            true), 0, 16);
        if (strlen($token) !== 16) {
            return '';
        }
        $padding_len = $max_len - 16;
        /*
            RFC 9000 sec 10.3 figure 16: first byte must
            have header form (top bit) clear and fixed bit
            (second bit) set, so it looks like a 1-RTT
            packet. The remaining bits are random.
         */
        $first = chr((ord(random_bytes(1)) & 0x3f) | 0x40);
        $padding = $first . random_bytes($padding_len - 1);
        return $padding . $token;
    }
    /**
     * Tick all live connections: send any queued packets
     * (e.g. ACKs whose timer just expired), drop any whose
     * idle timer has elapsed.
     */
    public function tickAllConnections()
    {
        $now = microtime(true);
        foreach ($this->connections as $kh => $h3) {
            if ($h3->isClosed()) {
                unset($this->connections[$kh]);
                unset($this->last_activity[$kh]);
                continue;
            }
            /*
                Phase 11b: dispatch the loss-detection timer
                if it has expired. onLossDetectionTimeout()
                queues a PING and rearms with backoff. This
                runs before flushStreams so the PING gets
                included in any datagram emit() builds for
                this tick.
             */
            if ($h3->quic->loss_detection_timer !== null &&
                $now >= $h3->quic->loss_detection_timer) {
                $h3->quic->onLossDetectionTimeout();
            }
            /*
                Drain any STREAM data that didn't fit in the
                previous tick's flush budget. Without this,
                a 1 MiB response would emit ~32 KB on the
                tick that started it (during driveConnection)
                and then sit forever waiting for new inbound
                traffic to trigger another flushStreams.
                Calling it here lets pending bytes drain on
                every event-loop iteration even if no new
                packets arrive from the peer.
             */
            /*
                Top up any streamed responses on this
                connection before draining. For each stream
                with a parked generator, pull more chunks
                while its send buffer sits below the refill
                threshold, so flushStreams has data to emit
                this tick without the whole body being held
                in memory. Production is paced by how fast
                the QUIC layer drains earlier chunks, which
                in turn follows the peer's flow-control
                window. The transport owns the generator
                bookkeeping, so the advance runs there.
             */
            if ($this->site !== null &&
                isset($this->site->transports['h3']) &&
                !empty($h3->h3_streams)) {
                $transport = $this->site->transports['h3'];
                foreach ($h3->h3_streams as $sid => $st) {
                    if (!empty($st['streaming_gen'])) {
                        $transport->advanceH3StreamingGenerator(
                            $h3, $sid);
                    }
                }
            }
            $h3->quic->flushStreams();
            foreach ($h3->quic->emit() as $datagram) {
                @stream_socket_sendto($this->server,
                    $datagram, 0, $h3->peer_address);
            }
        }
    }
    /**
     * Expires connections whose QuicConnection has gone
     * idle past the negotiated max_idle_timeout. Keeps the
     * connection map small under load. RFC 9000 sec 10.1:
     * idle timeout is the minimum of the two peers' values
     * (which we don't currently parse from peer transport
     * params; in Phase 5 the QuicConnection defaults to
     * 30 seconds).
     */
    public function reapStaleConnections()
    {
        $now = microtime(true);
        foreach ($this->connections as $kh => $h3) {
            if ($h3->quic->isIdleExpired($now)) {
                /*
                    RFC 9000 sec 10.1: idle-timeout MUST be a
                    silent close. Mark the connection closed
                    locally and drop it without queuing a
                    CONNECTION_CLOSE frame. The peer is
                    expected to do the same on its own idle
                    timer.
                 */
                $h3->quic->markClosedSilently();
                unset($this->connections[$kh]);
                unset($this->last_activity[$kh]);
                continue;
            }
            if ($h3->isClosed()) {
                /*
                    Connection was closed earlier (peer sent
                    CONNECTION_CLOSE, or we did during a
                    handshake failure). Flush once so any
                    queued CONNECTION_CLOSE frame actually
                    reaches the peer before we drop the
                    connection from the table.
                 */
                $this->flushConnectionOnce($h3);
                unset($this->connections[$kh]);
                unset($this->last_activity[$kh]);
            }
        }
    }
    /**
     * Returns the number of milliseconds until the next
     * connection-level timer fires. Used by the event loop
     * to bound select() waits. Phase 4 uses a fixed 100 ms
     * poll, which is small enough that idle-timeout reaps
     * fire promptly without tying the event loop to a
     * full RTT-aware PTO calculation. A future phase can
     * compute the actual minimum across per-connection
     * PTO + idle timers if 100 ms wakeups become a CPU
     * concern.
     * @return int|null milliseconds until the next timer fires, or null if none scheduled
     */
    public function nextTimeoutMillis()
    {
        return 100;
    }
    /**
     * Returns a snapshot of every active connection's
     * stats. Useful for ops dashboards and the same
     * shape the FFI listener returns for sibling stats
     * tools. Each entry is the dict produced by
     * QuicConnection::stats().
     * @return array snapshot of all per-connection statistics
     */
    public function snapshotAllStats()
    {
        $out = [];
        foreach ($this->connections as $kh => $h3) {
            $out[$kh] = $h3->quic->stats();
        }
        return $out;
    }
    /**
     * No-op compatibility method for the FFI listener's
     * forceSnapshotAll(). The FFI version uses this to
     * flush a quiche-internal stats ring buffer that
     * batches updates; the pure-PHP listener computes
     * stats live from connection state inside
     * snapshotAllStats() so there is nothing to flush.
     * Defined here so callers (e.g. /h3stats endpoints)
     * can call it without an instanceof check.
     */
    public function forceSnapshotAll()
    {
        /* no-op; see method docblock */
    }
    /**
     * Returns stats for connections that have been reaped
     * since the last snapshot. The pure-PHP listener does
     * not currently retain a reaped-connection history
     * (it simply unsets entries on close); returns an
     * empty array for now. A future revision could keep
     * a small ring of recent closures.
     * @return array snapshot of statistics for connections reaped in the last interval
     */
    public function snapshotReapedStats()
    {
        return [];
    }
}
/**
 * H3Transport: the per-protocol parser. WebSite holds one
 * Transport instance per supported protocol and routes
 * each readable event to the Transport matching the
 * Connection's negotiated protocol. For H3 the readable
 * events are produced by H3Listener::accept rather than
 * by the dispatcher's per-connection select set, so
 * onReadable is a no-op. driveConnection is the real
 * entry point: it polls the QUIC layer for new STREAM
 * frame data, reassembles HTTP/3 frames, and dispatches
 * full requests through WebSite::setGlobals +
 * WebSite::getResponseData.
 */
class H3Transport extends Transport
{
    /**
     * Buffered-byte threshold below which advanceH3StreamingGenerator
     * pulls more from a parked generator. Keeping a little more than
     * one flush budget queued means flushStreams always has data to
     * send each tick without the whole body being buffered at once,
     * so a streamed response stays memory-bounded while still filling
     * the per-tick send budget. Producing past this only wastes
     * memory, since the QUIC layer drains no faster than the peer's
     * flow-control window allows.
     */
    const H3_STREAM_REFILL_BYTES = 65536;
    /**
     * No-op for H3: per-connection readable events are
     * driven by H3Listener::accept reading the shared UDP
     * socket and dispatching datagrams. WebSite never
     * adds an H3Connection to its select set.
     * @param string $key key
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $in_stream in_stream parameter
     * @param mixed $too_long too_long parameter
     */
    public function onReadable($key, $conn, $in_stream,
        $too_long)
    {
        /* nothing -- see class docblock */
    }
    /**
     * Drives the HTTP/3 protocol layer on a freshly fed
     * QUIC connection. Polls each QuicStream for
     * application data, parses HTTP/3 frames, captures
     * HEADERS via Qpack::decode, dispatches the request
     * once FIN is seen, and ships back a response.
     * @param mixed $listener listener parameter
     * @param QuicConnection $conn live QUIC connection
     */
    public function driveConnection($listener, $conn)
    {
        if (!$conn->isEstablished()) {
            return;
        }
        $this->ensureControlStream($listener, $conn);
        foreach ($conn->quic->streams as $sid => $stream) {
            $is_uni = self::isUni($sid);
            $is_client_init = self::isClientInitiated($sid);
            if (!$is_client_init) {
                /* Server-initiated stream (our control
                   stream, push streams, etc.) -- nothing
                   to consume here. flushStreams handles
                   their outbound side. */
                continue;
            }
            $bytes = $stream->consume();
            if ($is_uni) {
                $this->handleUniStream($conn, $sid, $stream,
                    $bytes);
                continue;
            }
            $this->handleBidiStream($listener, $conn, $sid,
                $stream, $bytes);
        }
        /* Top up any streamed responses before draining, so
           the buffer stays fed on this inbound-driven flush
           (an ACK opening flow-control credit) rather than
           waiting for the next timer tick. Without this a
           streamed body only refills on the periodic tick and
           its throughput collapses to one refill per tick. */
        if (!empty($conn->h3_streams)) {
            foreach ($conn->h3_streams as $sid => $st) {
                if (!empty($st['streaming_gen'])) {
                    $this->advanceH3StreamingGenerator($conn,
                        $sid);
                }
            }
        }
        /* Drain anything our handlers wrote into the
           stream-send buffers, then flush the resulting
           1-RTT packets to the wire. */
        $conn->quic->flushStreams();
        foreach ($conn->quic->emit() as $datagram) {
            @stream_socket_sendto($listener->server,
                $datagram, 0, $conn->peer_address);
        }
    }
    /**
     * If we have not yet opened our server-initiated uni
     * control stream, do so and write a SETTINGS frame
     * (RFC 9114 sec 6.2.1). Server-initiated uni streams
     * in QUIC have stream IDs of the form 4n + 3.
     * @param mixed $listener listener parameter
     * @param QuicConnection $conn live QUIC connection
     */
    protected function ensureControlStream($listener, $conn)
    {
        if ($conn->settings_sent) {
            return;
        }
        $sid = $conn->next_server_uni;
        $conn->next_server_uni += 4;
        $conn->control_stream_id = $sid;
        /*
            First byte on a uni stream is the unidirectional
            stream type (varint). 0x00 = control stream
            (RFC 9114 sec 6.2.1).
         */
        $type = QuicVarint::write(0x00);
        $settings_body =
            H3FrameCodec::encodeSettingsBody([
                /* QPACK_MAX_TABLE_CAPACITY = 0: we don't
                   maintain a dynamic table. */
                0x01 => 0,
                /* QPACK_BLOCKED_STREAMS = 0 */
                0x07 => 0,
                /* MAX_FIELD_SECTION_SIZE = 65536 */
                0x06 => 65536,
            ]);
        $settings_frame = H3FrameCodec::encode(
            H3FrameCodec::H3_SETTINGS, $settings_body);
        $conn->quic->sendStreamData($sid,
            $type . $settings_frame, false);
        $conn->settings_sent = true;
    }
    /**
     * RFC 9000 sec 2.1: stream IDs whose lowest bit is 1
     * are uni-directional.
     * @param mixed $sid sid parameter
     * @return bool true if the stream is unidirectional
     */
    protected static function isUni($sid)
    {
        return ($sid & 0x02) !== 0;
    }
    /**
     * Stream IDs whose second-lowest bit is 0 are client-
     * initiated.
     * @param mixed $sid sid parameter
     * @return bool true if the stream id is client-initiated (low bit clear)
     */
    protected static function isClientInitiated($sid)
    {
        return ($sid & 0x01) === 0;
    }
    /**
     * Handles bytes received on a peer-initiated
     * unidirectional stream. The first varint on every
     * uni stream is the type; the rest is type-specific.
     * We accept type 0x00 (control stream) so we can read
     * the client's SETTINGS frame, and silently discard
     * other types (push, encoder, decoder streams) since
     * we don't use them.
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $sid sid parameter
     * @param QuicStream $stream QUIC stream object
     * @param string $bytes bytes to operate on
     */
    protected function handleUniStream($conn, $sid, $stream,
        $bytes)
    {
        if (!isset($conn->uni_streams[$sid])) {
            $conn->uni_streams[$sid] = [
                'type' => null,
                'header_buf' => '',
            ];
        }
        $st = &$conn->uni_streams[$sid];
        $st['header_buf'] .= $bytes;
        if ($st['type'] === null) {
            list($t, $off) = QuicVarint::read(
                $st['header_buf'], 0);
            if ($t === false) {
                return;
            }
            $st['type'] = $t;
            $st['header_buf'] = substr($st['header_buf'],
                $off);
        }
        if ($st['type'] === 0x00) {
            /* Control stream: parse and discard SETTINGS,
               ignore the rest. */
            list($frames, $left, $err) =
                H3FrameCodec::decodeAll($st['header_buf']);
            $st['header_buf'] = $left;
            /* No action needed; settings come across but
               don't change our behavior in Phase 4. */
        } else {
            /* Push streams (0x01), QPACK encoder (0x02),
               decoder (0x03), and grease types -- discard
               buffered bytes since we don't act on them. */
            $st['header_buf'] = '';
        }
        unset($st);
    }
    /**
     * Handles bytes received on a client-initiated bidi
     * stream. These carry HTTP/3 request frames: HEADERS
     * always first, optional DATA frames, eventually a
     * stream FIN.
     * @param mixed $listener listener parameter
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $sid sid parameter
     * @param QuicStream $stream QUIC stream object
     * @param string $bytes bytes to operate on
     */
    protected function handleBidiStream($listener, $conn,
        $sid, $stream, $bytes)
    {
        if (!isset($conn->h3_streams[$sid])) {
            $conn->h3_streams[$sid] = [
                'h3_buf' => '',
                'headers' => [],
                'method' => '',
                'path' => '',
                'authority' => '',
                'scheme' => '',
                'body_chunks' => [],
                'fin_seen' => false,
                'dispatched' => false,
            ];
        }
        $st = &$conn->h3_streams[$sid];
        $st['h3_buf'] .= $bytes;
        list($frames, $left, $err) =
            H3FrameCodec::decodeAll($st['h3_buf']);
        $st['h3_buf'] = $left;
        foreach ($frames as $f) {
            if ($f['type'] === H3FrameCodec::H3_HEADERS) {
                try {
                    $headers = Qpack::decode($f['body']);
                } catch (\Throwable $e) {
                    $conn->close(0x010C,
                        "QPACK_DECOMPRESSION_FAILED");
                    return;
                }
                foreach ($headers as $h) {
                    list($n, $v) = $h;
                    if ($n === ':method') {
                        $st['method'] = $v;
                    } else if ($n === ':path') {
                        $st['path'] = $v;
                    } else if ($n === ':authority') {
                        $st['authority'] = $v;
                    } else if ($n === ':scheme') {
                        $st['scheme'] = $v;
                    } else if (!str_starts_with($n, ':')) {
                        $st['headers'][$n] = $v;
                    }
                }
            } else if ($f['type'] === H3FrameCodec::H3_DATA) {
                $st['body_chunks'][] = $f['body'];
            }
            /* Other frame types: silently ignore */
        }
        if ($stream->isReceiveDone() && !$st['fin_seen']) {
            $st['fin_seen'] = true;
        }
        unset($st);
        if ($conn->h3_streams[$sid]['fin_seen'] &&
            !$conn->h3_streams[$sid]['dispatched']) {
            $this->dispatchRequest($listener, $conn, $sid);
        }
    }
    /**
     * Dispatches one fully-received request through atto's
     * setGlobals + getResponseData pipeline, then writes
     * the response back as an HTTP/3 HEADERS + DATA frame
     * pair.
     * @param mixed $listener listener parameter
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $sid sid parameter
     */
    protected function dispatchRequest($listener, $conn, $sid)
    {
        $st = &$conn->h3_streams[$sid];
        $st['dispatched'] = true;
        $context = $this->buildContext($listener, $conn,
            $st);
        $this->site->setGlobals($context, $conn);
        /*
            Tell WebSite this request is served over H3 so a route
            that calls $site->stream($generator) parks the generator
            instead of draining it into a buffered body. After
            getResponseData the parked generator (if any) is taken
            and advanced from the QUIC event loop, so a large or
            lazily produced body is sent in bounded chunks rather
            than assembled in memory whole.
         */
        $this->site->setStreamingProtocol('h3');
        $this->site->beginDeferrableH3($this, $conn, $sid);
        try {
            $body = $this->site->getResponseData(false);
        } catch (\Throwable $e) {
            $this->site->endDeferrableH3();
            $this->site->setStreamingProtocol('');
            $this->sendErrorResponse($conn, $sid, 500);
            return;
        }
        $this->site->endDeferrableH3();
        if ($body === WebSite::RESPONSE_DEFERRED) {
            /*
                The route deferred itself; its response is framed and
                sent on this same QUIC stream by the cooperative task
                once its fiber finishes (see emitDeferredResponse).
                Send nothing here; other streams keep being served.
             */
            $this->site->setStreamingProtocol('');
            return;
        }
        $producer = $this->site->takeStreamingProducer();
        $this->site->setStreamingProtocol('');
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
        if ($producer !== null) {
            $this->sendResponseHeaders($conn, $sid, $status,
                $headers);
            $st['streaming_gen'] = $producer;
            $this->advanceH3StreamingGenerator($conn, $sid);
            return;
        }
        $this->sendResponse($conn, $sid, $status, $headers,
            $body);
        /*
            Keep the per-stream record around with
            dispatched=true so handleBidiStream's idempotence
            check stops re-dispatching. The H3 stream entry
            is small; reaping happens when the QUIC layer
            shuts the stream down or when the connection
            closes.
         */
    }
    /**
     * Builds an H1/H2-style $context array from captured
     * H3 request state. Mirrors what the FFI version
     * produces so apps don't see a difference.
     * @param mixed $listener listener parameter
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $st st parameter
     * @return array request context map suitable for setGlobals
     */
    protected function buildContext($listener, $conn, $st)
    {
        $path_only = $st['path'];
        $query = '';
        $qpos = strpos($st['path'], '?');
        if ($qpos !== false) {
            $path_only = substr($st['path'], 0, $qpos);
            $query = substr($st['path'], $qpos + 1);
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
        $authority = 'localhost';
        $candidate = trim($st['authority'] ?? '');
        if ($candidate === '' &&
            isset($st['headers']['host'])) {
            $candidate = trim($st['headers']['host']);
        }
        if ($candidate !== '' && filter_var(
                "http://$candidate", FILTER_VALIDATE_URL)) {
            $authority = $candidate;
        }
        $body = empty($st['body_chunks']) ? ''
            : implode('', $st['body_chunks']);
        $context = [
            'REQUEST_METHOD' => $st['method'],
            'REQUEST_URI' => $st['path'],
            'QUERY_STRING' => $query,
            'PATH_INFO' => $path_only,
            'SCRIPT_NAME' => '',
            'HTTP_HOST' => $authority,
            'SERVER_PROTOCOL' => 'HTTP/3',
            'SERVER_NAME' =>
                $listener->globals['SERVER_NAME'] ?? '',
            'SERVER_PORT' =>
                $listener->globals['SERVER_PORT'] ?? '',
            'REMOTE_ADDR' => $remote_addr,
            'REMOTE_PORT' => $remote_port,
            'HTTPS' => 'on',
            'CONTENT' => $body,
        ];
        foreach ($st['headers'] as $name => $value) {
            if ($name === 'host') {
                continue;
            }
            $h = 'HTTP_' . strtoupper(
                str_replace('-', '_', $name));
            $context[$h] = $value;
        }
        return $context;
    }
    /**
     * Builds and queues a complete H3 response on $sid:
     * one HEADERS frame followed by one DATA frame, then
     * FIN.
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $sid sid parameter
     * @param int $status HTTP response status code
     * @param mixed $header_lines header_lines parameter
     * @param string $body message body bytes
     */
    protected function sendResponse($conn, $sid, $status,
        $header_lines, $body)
    {
        $this->sendResponseHeaders($conn, $sid, $status,
            $header_lines);
        if ($body !== '') {
            $data_frame = H3FrameCodec::encode(
                H3FrameCodec::H3_DATA, $body);
            $conn->quic->sendStreamData($sid, $data_frame,
                true);
        } else {
            $conn->quic->sendStreamData($sid, '', true);
        }
    }
    /**
     * Sends a deferred request's finished response on its QUIC stream,
     * once its cooperative task has finished. Reads the status and header
     * lines the handler left in the site's header buffer the same way
     * dispatchRequest does for an ordinary request, then hands them and
     * the body to sendResponse. WebSite calls this from the task's
     * completion when the request was served over HTTP/3.
     *
     * @param object $conn the live QUIC connection the request arrived on
     * @param int $sid the request's QUIC stream id
     * @param string $body the finished response body
     * @return void
     */
    public function emitDeferredResponse($conn, $sid, $body)
    {
        $status = 200;
        if (preg_match('/HTTP\/[\d.]+ (\d+)/',
            $this->site->header_data, $matches)) {
            $status = (int) $matches[1];
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
        $this->sendResponse($conn, $sid, $status, $headers, $body);
    }
    /**
     * Emits the QPACK-encoded HEADERS frame for a response on
     * stream $sid without finishing the stream, so a body (one
     * or more DATA frames) can follow. Shared by sendResponse
     * and the generator-streaming path.
     *
     * @param QuicConnection $conn live QUIC connection
     * @param int $sid bidirectional request stream id
     * @param int $status HTTP response status code
     * @param array $header_lines response header lines, each a
     *      "Name: value" string from the app's header_data
     */
    protected function sendResponseHeaders($conn, $sid, $status,
        $header_lines)
    {
        $h3_headers = [
            [':status', (string) $status],
        ];
        foreach ($header_lines as $line) {
            $cpos = strpos($line, ':');
            if ($cpos === false) {
                continue;
            }
            $name = strtolower(trim(
                substr($line, 0, $cpos)));
            $value = trim(substr($line, $cpos + 1));
            /*
                HTTP/3 (RFC 9114 sec 4.2) forbids the
                connection-specific headers Connection,
                Keep-Alive, Proxy-Connection, Transfer-
                Encoding, Upgrade. Skip them silently.
             */
            if ($name === 'connection' ||
                $name === 'keep-alive' ||
                $name === 'proxy-connection' ||
                $name === 'transfer-encoding' ||
                $name === 'upgrade') {
                continue;
            }
            $h3_headers[] = [$name, $value];
        }
        $headers_body = Qpack::encode($h3_headers);
        $headers_frame = H3FrameCodec::encode(
            H3FrameCodec::H3_HEADERS, $headers_body);
        $conn->quic->sendStreamData($sid, $headers_frame,
            false);
    }
    /**
     * Advances a parked streaming generator for stream $sid,
     * keeping the QUIC send buffer topped up without assembling
     * the whole body in memory. While the stream's buffered
     * (not-yet-framed) bytes sit below H3_STREAM_REFILL_BYTES
     * and the generator has more to give, pulls the next chunk
     * and writes it as its own DATA frame. When the generator
     * is exhausted, finishes the stream with an empty FIN write
     * and unparks it. Called once when the response is first
     * dispatched and again from the connection tick as the
     * QUIC layer drains earlier chunks, so production is paced
     * by the peer's per-stream flow-control window rather than
     * running ahead of it.
     *
     * @param QuicConnection $conn live QUIC connection
     * @param int $sid bidirectional request stream id whose
     *      generator is being advanced
     */
    public function advanceH3StreamingGenerator($conn, $sid)
    {
        if (empty($conn->h3_streams[$sid]['streaming_gen'])) {
            return;
        }
        $generator = $conn->h3_streams[$sid]['streaming_gen'];
        $buffered = $conn->quic->bufferedLength($sid);
        while ($buffered < self::H3_STREAM_REFILL_BYTES) {
            if (!$generator->valid()) {
                $conn->quic->sendStreamData($sid, '', true);
                unset($conn->h3_streams[$sid]['streaming_gen']);
                return;
            }
            $chunk = $generator->current();
            $generator->next();
            if ($chunk === null || $chunk === '') {
                continue;
            }
            $data_frame = H3FrameCodec::encode(
                H3FrameCodec::H3_DATA, $chunk);
            $conn->quic->sendStreamData($sid, $data_frame,
                false);
            $buffered += strlen($data_frame);
        }
    }
    /**
     * Best-effort error response when the app handler
     * throws.
     * @param QuicConnection $conn live QUIC connection
     * @param mixed $sid sid parameter
     * @param int $status HTTP response status code
     */
    protected function sendErrorResponse($conn, $sid,
        $status)
    {
        $body = "HTTP $status\r\n";
        $this->sendResponse($conn, $sid, $status,
            ['content-type: text/plain'], $body);
    }
}
