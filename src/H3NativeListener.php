<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Pure-PHP HTTP/3 (QUIC) listener. Drop-in replacement for the
 * libquiche-FFI-backed H3Listener.php that shipped through atto
 * 2.0.x. The public API surface is unchanged: H3Listener,
 * H3Connection, H3Transport in this same namespace, with the same
 * tryOpen() / accept() / driveConnection() / dispatchRequest()
 * shape WebSite already calls. WebSite.php loads this file
 * lazily on first listen() spec that requests 'protocol' => 'h3',
 * exactly the same way the FFI version was loaded.
 *
 * --- WHAT'S IMPLEMENTED ---
 *
 * RFC 8446 (TLS 1.3) -- server-side handshake, no resumption,
 *     no 0-RTT, no PSK. Cipher suites:
 *       TLS_AES_128_GCM_SHA256
 *       TLS_CHACHA20_POLY1305_SHA256
 *     Signature schemes:
 *       ecdsa_secp256r1_sha256 (always)
 *       rsa_pss_rsae_sha256 (only when ext-gmp is loaded; PHP's
 *           openssl_sign cannot produce PSS signatures, so we
 *           hand-roll EMSA-PSS encoding and a raw RSA modexp via
 *           gmp when an RSA cert is supplied).
 *     Key share: x25519.
 *     Extensions handled: server_name, supported_versions, key_share,
 *         signature_algorithms, application_layer_protocol_negotiation,
 *         supported_groups, quic_transport_parameters.
 *
 * RFC 9000 (QUIC), RFC 9001 (QUIC + TLS), RFC 9002 (loss det),
 * RFC 9114 (HTTP/3), RFC 9204 (QPACK) -- pending phases 2-4.
 *
 * --- LIMITATIONS ---
 *
 * Performance: every byte goes through PHP-level packet decode,
 * AEAD, and frame parsing. Realistic throughput is a few MB/sec
 * per connection. This is a reference-quality implementation,
 * not a high-throughput one. Use the FFI version (the older
 * H3Listener.php that wraps libquiche) when ten-megabit-plus
 * sustained per-connection throughput matters.
 *
 * Cert types: ECDSA P-256 always works. RSA works only when the
 * optional gmp extension is loaded. Atto will log a friendly
 * notice and skip the H3 listener if neither path is viable.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * TLS 1.3 server-side handshake engine. Self-contained, no
 * external dependencies beyond ext-openssl, ext-sodium, and
 * ext-hash. Used by H3Listener; can also be exercised in
 * isolation against a TCP socket for testing (the QUIC stack
 * adds its own framing on top, so the engine itself does not
 * speak TCP or UDP -- it speaks bytes-in / bytes-out and lets
 * the caller decide how to deliver them).
 *
 * --- LIFECYCLE ---
 *
 *   1. $eng = new Tls13Engine($cert_pem, $key_pem, $alpn_list,
 *                             $quic_transport_params);
 *   2. $eng->feedClientHello($bytes); -- one-shot, returns true
 *      on success.
 *   3. $eng->buildServerFlight();    -- returns the bytes the
 *      caller transmits (in QUIC: as CRYPTO frames split across
 *      Initial and Handshake packets).
 *   4. $eng->feedClientFinished($bytes); -- one-shot, returns
 *      true on HMAC verification success.
 *   5. $eng->trafficSecrets() -- returns ['c_hs', 's_hs',
 *      'c_ap', 's_ap'] mapping each TLS 1.3 traffic secret to
 *      its 32-byte SHA-256 output. QUIC will derive its own
 *      packet-protection keys from these per RFC 9001 sec 5.
 *
 * The engine never reads or writes to a socket itself.
 */
class Tls13Engine
{
    /*
        --- TLS 1.3 record-layer constants (RFC 8446 sec 5) ---
     */
    const TLS_RECORD_HANDSHAKE = 22;
    const TLS_RECORD_APPLICATION_DATA = 23;
    const TLS_RECORD_ALERT = 21;
    const TLS_RECORD_CCS = 20;
    const TLS_VERSION_LEGACY = 0x0303;  /* TLS 1.2 (record-layer) */
    const TLS_VERSION_1_3 = 0x0304;     /* real version, in
                                           supported_versions */
    /*
        --- Handshake message types (RFC 8446 sec 4) ---
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
        --- Extension type codes (RFC 8446 sec 4.2) ---
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
        --- QUIC transport parameters (RFC 9001 sec 8.2) ---
        Encoded as a TLS extension in ClientHello and
        EncryptedExtensions; we just round-trip the peer's
        bytes here in Phase 1. The QUIC layer in later
        phases will parse them.
     */
    const EXT_QUIC_TRANSPORT_PARAMETERS = 0x39;
    /*
        --- Cipher suites we support (RFC 8446 sec B.4) ---
     */
    const CIPHER_AES_128_GCM_SHA256 = 0x1301;
    const CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303;
    /*
        --- Named groups for key share (RFC 8446 sec 4.2.7) ---
     */
    const GROUP_X25519 = 0x001D;
    /*
        --- Signature schemes (RFC 8446 sec 4.2.3) ---
        Atto offers two: ecdsa_secp256r1_sha256 always,
        rsa_pss_rsae_sha256 only when ext-gmp is loaded
        (because PHP's openssl_sign cannot produce PSS
        signatures and we hand-roll the primitive via gmp).
     */
    const SIG_RSA_PKCS1_SHA256 = 0x0401; /* parsed only, never sent */
    const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
    const SIG_RSA_PSS_RSAE_SHA256 = 0x0804;
    /*
        --- Alert codes (RFC 8446 sec 6) ---
     */
    const ALERT_LEVEL_FATAL = 2;
    const ALERT_HANDSHAKE_FAILURE = 40;
    const ALERT_BAD_CERTIFICATE = 42;
    const ALERT_DECODE_ERROR = 50;
    const ALERT_PROTOCOL_VERSION = 70;
    const ALERT_INTERNAL_ERROR = 80;
    /*
        --- Engine state machine ---
     */
    const ST_AWAIT_CLIENT_HELLO = 0;
    const ST_SENT_SERVER_FLIGHT = 1;
    const ST_AWAIT_CLIENT_FINISHED = 2;
    const ST_HANDSHAKE_COMPLETE = 3;
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
     *      key_share extension.
     */
    protected $client_x25519_public = "";
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
     * @param string $cert_pem PEM-encoded server certificate
     *      chain. Multiple "-----BEGIN CERTIFICATE-----" blocks
     *      may appear; the first is the leaf and the rest are
     *      sent as intermediate certs.
     * @param string $key_pem PEM-encoded server private key.
     *      Must be ECDSA P-256 or RSA. PKCS#8 and traditional
     *      PEM both work because openssl_pkey_get_private
     *      accepts either.
     * @param array $alpn list of byte-strings to offer for
     *      ALPN, in priority order. Pass ['h3'] for HTTP/3-
     *      only listeners; the engine itself does not require
     *      ALPN to be set, but QUIC RFC 9001 sec 8.1 makes it
     *      mandatory at the QUIC layer.
     * @param string $quic_tp opaque byte-string the QUIC layer
     *      hands us; goes verbatim into EncryptedExtensions
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
     */
    public function getError()
    {
        return $this->error;
    }
    /**
     * Returns true once the handshake has completed.
     */
    public function isComplete()
    {
        return $this->state === self::ST_HANDSHAKE_COMPLETE;
    }
    /**
     * Returns the four 1-RTT traffic secrets after handshake
     * completion. Empty array beforehand.
     */
    public function trafficSecrets()
    {
        return $this->secrets;
    }
    /**
     * Returns the negotiated ALPN, or "" if none.
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
     */
    public function setServerQuicTransportParameters($tp)
    {
        $this->server_quic_tp = (string) $tp;
    }
    /**
     * Returns the peer's quic_transport_parameters bytes
     * captured from ClientHello.
     */
    public function clientQuicTransportParameters()
    {
        return $this->client_quic_tp;
    }
    /**
     * Records a fatal error and moves the engine into
     * ST_FAILED. After this, all feed* methods are no-ops.
     */
    protected function fail($msg)
    {
        $this->error = $msg;
        $this->state = self::ST_FAILED;
    }
    /*
        ============================================================
        --- Wire-format helpers ---
        ============================================================

        TLS uses big-endian length-prefixed structures throughout.
        The pack/unpack routines below mirror the way the spec
        writes them: a uint8 / uint16 / uint24 prefix giving the
        byte count, followed by that many bytes of payload.
     */
    /**
     * Reads a uint8 from $buf at offset $off, returns
     * [value, new_off]. Returns [false, $off] on
     * underflow.
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
     */
    protected function packU16($v)
    {
        return chr(($v >> 8) & 0xFF) . chr($v & 0xFF);
    }
    /**
     * Encodes a uint24 in big-endian.
     */
    protected function packU24($v)
    {
        return chr(($v >> 16) & 0xFF) .
            chr(($v >> 8) & 0xFF) .
            chr($v & 0xFF);
    }
    /**
     * Wraps payload in a uint8-length-prefixed envelope.
     */
    protected function packVec8($payload)
    {
        return chr(strlen($payload)) . $payload;
    }
    /**
     * Wraps payload in a uint16-length-prefixed envelope.
     */
    protected function packVec16($payload)
    {
        return $this->packU16(strlen($payload)) . $payload;
    }
    /**
     * Wraps payload in a uint24-length-prefixed envelope.
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
     */
    protected function packHandshake($type, $body)
    {
        $msg = chr($type) . $this->packU24(strlen($body)) .
            $body;
        $this->transcript_buf .= $msg;
        return $msg;
    }
    /*
        ============================================================
        --- ClientHello parser ---
        ============================================================

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
            return false;
        }
        return true;
    }
    /**
     * Parses the body (everything after the type+length
     * header) of a ClientHello.
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
        if ($this->client_x25519_public === '') {
            $this->fail("client did not offer x25519 key share");
            return false;
        }
        return true;
    }
    /**
     * Walks the extension list. Each extension is a uint16
     * type, uint16-prefixed payload. Captures the ones we
     * care about; ignores the rest.
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
     * x25519 public if present. Other groups are ignored
     * since x25519 is the only one we offer.
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
            }
        }
        return true;
    }
    /**
     * Walks the ALPN list, picks the first protocol the
     * client offers that also appears in our offer.
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
        ============================================================
        --- HKDF and the TLS 1.3 key schedule ---
        ============================================================

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
     */
    protected function deriveHandshakeSecrets()
    {
        $zeros = str_repeat("\x00", $this->hash_len);
        $early_secret = $this->hkdfExtract('', $zeros);
        $derived_1 = $this->deriveSecret($early_secret,
            'derived', '');
        $shared = sodium_crypto_scalarmult($this->x25519_secret,
            $this->client_x25519_public);
        $this->handshake_secret = $this->hkdfExtract(
            $derived_1, $shared);
        /*
            Wipe the X25519 ephemeral key as soon as we have
            the shared secret. RFC 8446 sec 4.2.8.1 doesn't
            mandate this but it bounds the window for forward-
            secrecy compromise if the process is dumped.
         */
        $this->x25519_secret = str_repeat("\x00", 32);
        $th = $this->transcriptHash();
        $this->secrets['c_hs'] = $this->hkdfExpandLabel(
            $this->handshake_secret, 'c hs traffic', $th,
            $this->hash_len);
        $this->secrets['s_hs'] = $this->hkdfExpandLabel(
            $this->handshake_secret, 's hs traffic', $th,
            $this->hash_len);
    }
    /**
     * Derives master_secret and the application traffic
     * secrets c_ap / s_ap. Called after the server's
     * Finished message has been added to the transcript.
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
        ============================================================
        --- AEAD helpers ---
        ============================================================

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
        ============================================================
        --- Server flight builder ---
        ============================================================

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
     */
    public function buildServerFlight($mode = 'tls')
    {
        if ($this->state === self::ST_FAILED) {
            return false;
        }
        if ($this->state !== self::ST_AWAIT_CLIENT_HELLO) {
            $this->fail("buildServerFlight in state "
                . $this->state);
            return false;
        }
        /*
            Generate our X25519 keypair if we haven't already.
            sodium_crypto_kx_keypair returns 64 bytes:
            32 secret + 32 public, in that order.
         */
        if ($this->x25519_secret === '') {
            $kp = sodium_crypto_kx_keypair();
            $this->x25519_secret =
                sodium_crypto_kx_secretkey($kp);
            $this->x25519_public =
                sodium_crypto_kx_publickey($kp);
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
        $ks_payload = $this->packU16(self::GROUP_X25519) .
            $this->packVec16($this->x25519_public);
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
        ============================================================
        --- Record layer (TLS-mode only) ---
        ============================================================

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
        ============================================================
        --- Client Finished verification ---
        ============================================================
     */
    /**
     * Feeds the client's Finished message bytes (the
     * decrypted handshake message: type byte + uint24 length
     * + body). Verifies the HMAC against c_hs_traffic_secret
     * and, on success, transitions to ST_HANDSHAKE_COMPLETE.
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
        ============================================================
        --- TLS-mode conductor (testing only) ---
        ============================================================

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
        @fwrite($sock, $flight);
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
 * Handshake, 1-RTT, or 0-RTT-not-implemented). Bundles the
 * AEAD key, AEAD IV, header-protection key, and the cipher
 * suite code so the rest of the stack can call sealPacket()
 * / openPacket() without re-deriving keys per packet.
 *
 * Two construction paths:
 *   - fromInitialDcid($dcid, $is_server) -- the
 *     deterministic Initial keys, derived per RFC 9001
 *     sec 5.2 from the client's Destination Connection ID
 *     and the Initial salt.
 *   - fromTrafficSecret($secret, $cipher) -- Handshake or
 *     1-RTT keys, derived from a TLS 1.3 traffic secret
 *     plus the negotiated cipher suite, per RFC 9001
 *     sec 5.1.
 */
class QuicPacketKeys
{
    /*
        Initial salt, RFC 9001 sec 5.2 (constant for QUIC v1).
     */
    const INITIAL_SALT_HEX =
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
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
            ChaCha20 with counter from sample[0..3] (LE),
            nonce from sample[4..15]. The IETF variant
            treats the first 4 bytes of the 16-byte counter
            +nonce input as the counter.
         */
        $counter = unpack('V', substr($sample, 0, 4))[1];
        $nonce = substr($sample, 4, 12);
        return sodium_crypto_stream_chacha20_ietf_xor_ic(
            "\x00\x00\x00\x00\x00",
            $nonce, $counter, $this->hp_key);
    }
    /**
     * Constructs the AEAD nonce by left-padding the 64-bit
     * packet number to 12 bytes and XORing with the IV.
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
     */
    public static function read($buf, $off)
    {
        if (strlen($buf) < $off + 1) {
            return [false, $off];
        }
        $first = ord($buf[$off]);
        $size_class = $first >> 6;
        $byte_count = 1 << $size_class; /* 1, 2, 4, or 8 */
        if (strlen($buf) < $off + $byte_count) {
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
            return chr(0x40 | ($value >> 8)) .
                chr($value & 0xFF);
        }
        if ($value < 1073741824) {
            return chr(0x80 | (($value >> 24) & 0x3F)) .
                chr(($value >> 16) & 0xFF) .
                chr(($value >> 8) & 0xFF) .
                chr($value & 0xFF);
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
    public $form = self::FORM_LONG;
    public $long_type = self::LONG_INITIAL;
    public $version = self::VERSION_QUIC_V1;
    public $destination_cid = "";
    public $source_cid = "";
    public $token = "";
    public $packet_number = 0;
    public $packet_number_length = 0; /* 1..4 bytes on wire */
    public $payload = "";
    public $header_bytes = "";
    /**
     * Decodes one QUIC packet from $buf starting at $off.
     * Returns [QuicPacket, new_off] on success or
     * [false, $off, $reason_string] on failure.
     *
     * For Initial / Handshake packets, $keys is the
     * QuicPacketKeys for the receive direction at that
     * encryption level; we use it both to remove header
     * protection (which gives us the packet-number length
     * and therefore the position of the payload) and to
     * decrypt the payload.
     *
     * For Retry packets we don't decrypt -- the integrity
     * tag is verified against a fixed key rather than the
     * Initial keys.
     *
     * One UDP datagram may coalesce multiple QUIC packets
     * (e.g. an Initial followed by a Handshake). The
     * caller should loop, calling decode() with the
     * advanced offset until $off equals strlen($buf).
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
        if (strlen($buf) < $off + 7) {
            return [false, $off, "long header truncated"];
        }
        $off++;
        $version = unpack('N', substr($buf, $off, 4))[1];
        $off += 4;
        $dcid_len = ord($buf[$off]);
        $off++;
        if (strlen($buf) < $off + $dcid_len + 1) {
            return [false, $off, "DCID truncated"];
        }
        $dcid = substr($buf, $off, $dcid_len);
        $off += $dcid_len;
        $scid_len = ord($buf[$off]);
        $off++;
        if (strlen($buf) < $off + $scid_len) {
            return [false, $off, "SCID truncated"];
        }
        $scid = substr($buf, $off, $scid_len);
        $off += $scid_len;
        $token = "";
        if ($long_type === self::LONG_INITIAL) {
            list($token_len, $off) = QuicVarint::read($buf,
                $off);
            if ($token_len === false ||
                strlen($buf) < $off + $token_len) {
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
            return [$packet, strlen($buf)];
        }
        /*
            Initial / Handshake / 0-RTT all carry a varint
            "Length" field followed by Length bytes of
            (packet number || protected payload).
         */
        list($length, $off) = QuicVarint::read($buf, $off);
        if ($length === false ||
            strlen($buf) < $off + $length) {
            return [false, $off, "length field bad"];
        }
        $pn_offset = $off;
        $sample_offset = $pn_offset + 4;
        if (strlen($buf) < $sample_offset + 16) {
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
        if (strlen($buf) < $body_start + $body_len) {
            return [false, $off, "body truncated"];
        }
        /*
            Reassemble the AAD. AAD is the unprotected
            packet header: bytes from $packet_off through
            (but not including) $body_start, with byte 0
            replaced by $unprotected_first and the
            packet-number bytes replaced by their
            unprotected values.
         */
        $hdr = chr($unprotected_first) .
            substr($buf, $packet_off + 1,
                $pn_offset - $packet_off - 1);
        $pn_bytes = '';
        for ($i = $pn_length - 1; $i >= 0; $i--) {
            $pn_bytes .= chr(($packet_number >> ($i * 8))
                & 0xFF);
        }
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
     * Decodes a short-header (1-RTT) packet. Phase 2 stub:
     * 1-RTT requires keys derived from TLS application
     * traffic secrets, which we'll have in Phase 3 once
     * the QUIC handshake completes end-to-end.
     */
    protected static function decodeShort($buf, $off, $keys,
        $largest_pn_seen)
    {
        return [false, $off,
            "1-RTT decode not yet implemented"];
    }
    /**
     * Decodes a truncated packet number into the full
     * 62-bit packet number. RFC 9000 sec A.3.
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
     */
    public function encodeLong($keys, $packet_number,
        $payload_unprotected)
    {
        $pn_length = 4;
        $pn_low_bits = $pn_length - 1;
        $first = 0xC0 | ($this->long_type << 4) |
            $pn_low_bits;
        $hdr = chr($first) .
            pack('N', $this->version) .
            chr(strlen($this->destination_cid)) .
            $this->destination_cid .
            chr(strlen($this->source_cid)) .
            $this->source_cid;
        if ($this->long_type === self::LONG_INITIAL) {
            $hdr .= QuicVarint::write(strlen($this->token)) .
                $this->token;
        }
        $body_len = $pn_length + strlen($payload_unprotected)
            + 16; /* +tag */
        $hdr .= QuicVarint::write($body_len);
        $pn_bytes = '';
        for ($i = $pn_length - 1; $i >= 0; $i--) {
            $pn_bytes .= chr(($packet_number >> ($i * 8))
                & 0xFF);
        }
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
        $sample_offset = strlen($hdr) + 4;
        $sample = substr($unprotected_packet, $sample_offset,
            16);
        $mask = $keys->headerProtectionMask($sample);
        if ($mask === false) {
            return false;
        }
        $protected_first = ord($unprotected_packet[0]) ^
            (ord($mask[0]) & 0x0F);
        $packet = chr($protected_first) .
            substr($unprotected_packet, 1, strlen($hdr) - 1);
        for ($i = 0; $i < $pn_length; $i++) {
            $packet .= chr(
                ord($unprotected_packet[strlen($hdr) + $i])
                ^ ord($mask[$i + 1]));
        }
        $packet .= substr($unprotected_packet,
            strlen($hdr) + $pn_length);
        return $packet;
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
        ============================================================
        --- Encoders ---
        ============================================================
     */
    /**
     * Encodes a frame array. Reverse of decodeOne().
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
    /*
        Stream-side state flags. Names mirror RFC 9000
        sec 3.1 / 3.2 but we collapse the substates that
        differ only in whether a STREAM frame with FIN
        has been buffered vs. delivered.
     */
    const RECV_OPEN = 0;
    const RECV_SIZE_KNOWN = 1; /* FIN seen, more bytes
                                  may still arrive */
    const RECV_DONE = 2; /* FIN seen and all bytes
                            delivered to app */
    const SEND_READY = 0;
    const SEND_DATA = 1;
    const SEND_DATA_SENT = 2;
    const SEND_DONE = 3;
    /**
     * @var int 62-bit stream ID
     */
    public $id = 0;
    /**
     * @var int the receive-side state flag
     */
    public $recv_state = self::RECV_OPEN;
    /**
     * @var int the send-side state flag
     */
    public $send_state = self::SEND_READY;
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
     * @var int receive-side flow-control window
     *      (MAX_STREAM_DATA we've granted the peer).
     */
    public $recv_window = 1048576;
    /**
     * @var string send-side outgoing buffer (not yet
     *      packaged into STREAM frames).
     */
    public $send_buf = "";
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
     * @var int send-side flow-control window the peer
     *      has granted us via MAX_STREAM_DATA.
     */
    public $send_window = 1048576;
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
     */
    public function __construct($id, $recv_window = 1048576,
        $send_window = 1048576)
    {
        $this->id = $id;
        $this->recv_window = $recv_window;
        $this->send_window = $send_window;
    }
    /**
     * Buffers incoming STREAM-frame bytes. RFC 9000
     * sec 19.8: bytes at an offset already received are
     * silently discarded; new bytes are merged into the
     * reassembly map. Returns true on success, false if
     * the bytes would exceed our advertised
     * flow-control window.
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
            $this->recv_state = self::RECV_SIZE_KNOWN;
        }
        return true;
    }
    /**
     * Returns whatever in-order bytes are immediately
     * available, advancing recv_next_offset past them.
     * Empty string when nothing new (e.g. waiting on a
     * gap).
     */
    public function consume()
    {
        $out = "";
        while (isset($this->recv_chunks[
                $this->recv_next_offset])) {
            $chunk = $this->recv_chunks[
                $this->recv_next_offset];
            unset($this->recv_chunks[
                $this->recv_next_offset]);
            $out .= $chunk;
            $this->recv_next_offset += strlen($chunk);
        }
        /* Coalesce overlapping / adjacent entries. The
           map keys are offsets; if the next offset to
           deliver matches some earlier-buffered chunk
           starting before recv_next_offset, slice and
           include the suffix. */
        foreach ($this->recv_chunks as $off => $chunk) {
            $end = $off + strlen($chunk);
            if ($end <= $this->recv_next_offset) {
                unset($this->recv_chunks[$off]);
            } else if ($off < $this->recv_next_offset) {
                $skip = $this->recv_next_offset - $off;
                $tail = substr($chunk, $skip);
                unset($this->recv_chunks[$off]);
                $this->recv_chunks[
                    $this->recv_next_offset] = $tail;
            }
        }
        if ($this->recv_state === self::RECV_SIZE_KNOWN &&
            $this->recv_next_offset >=
            $this->recv_seen_max) {
            $this->recv_state = self::RECV_DONE;
        }
        return $out;
    }
    /**
     * Returns true once no more data will arrive on the
     * receive side and everything queued has been
     * consumed.
     */
    public function isReceiveDone()
    {
        return $this->recv_state === self::RECV_DONE;
    }
    /**
     * Appends bytes to the send buffer. The
     * QuicConnection's emit loop chunks them into STREAM
     * frames in flight, taking flow-control limits into
     * account.
     */
    public function write($bytes)
    {
        $this->send_buf .= (string) $bytes;
        if ($this->send_state === self::SEND_READY) {
            $this->send_state = self::SEND_DATA;
        }
    }
    /**
     * Marks the send-side as finished. Once the buffer
     * drains, the next STREAM frame carries FIN.
     */
    public function finish()
    {
        $this->send_fin = true;
        if ($this->send_buf === '' &&
            $this->send_state === self::SEND_READY) {
            $this->send_state = self::SEND_DATA_SENT;
        }
    }
    /**
     * Consumes up to $max_bytes for the next outgoing
     * STREAM frame, returning [offset, data, fin] or
     * null if nothing to send. Updates send_next_offset.
     * Caller writes the returned tuple into a STREAM
     * frame.
     */
    public function takeForFrame($max_bytes)
    {
        if ($this->send_buf === '' && !$this->send_fin) {
            return null;
        }
        if ($this->send_buf === '' && $this->send_fin
            && $this->send_fin_sent) {
            return null;
        }
        $allowed = min(strlen($this->send_buf), $max_bytes,
            max(0, $this->send_window
                - $this->send_next_offset));
        $data = substr($this->send_buf, 0, $allowed);
        $this->send_buf = substr($this->send_buf, $allowed);
        $offset = $this->send_next_offset;
        $this->send_next_offset += $allowed;
        $fin = ($this->send_fin &&
            $this->send_buf === '');
        if ($fin) {
            $this->send_fin_sent = true;
            $this->send_state = self::SEND_DATA_SENT;
        }
        return [$offset, $data, $fin];
    }
}
/**
 * One QUIC connection's state. Owns:
 *
 *   - the TLS 1.3 engine (Tls13Engine)
 *   - per-encryption-level packet keys (Initial, Handshake,
 *     1-RTT) for each direction (rx vs tx)
 *   - per-PN-space received packet numbers (so we can ACK)
 *   - per-PN-space next-PN-to-send (so we can number our
 *     own outgoing packets correctly)
 *   - the crypto receive buffer per encryption level (for
 *     reassembling handshake messages from CRYPTO frames
 *     that may arrive in pieces)
 *   - the local + peer connection IDs
 *   - the stream table
 *   - peer + local QUIC transport parameters
 *
 * Phase 3 implements the server side of the handshake
 * end-to-end: receive an Initial, decrypt, parse CRYPTO
 * frames, feed Tls13Engine, build server flight, split it
 * across CRYPTO frames in Initial+Handshake packets, queue
 * them for transmit. ACK incoming packets per PN space.
 * Mark handshake done once the client's Finished is
 * received (in Handshake-level CRYPTO).
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
     * Constructs a server-side connection. $cert_pem and
     * $key_pem are the server's certificate and key for
     * the TLS 1.3 handshake; $alpn is the list of ALPN
     * byte-strings the server offers.
     */
    public function __construct($cert_pem, $key_pem, $alpn)
    {
        /*
            Generate our own connection ID. This is what the
            peer will use as DCID on packets after the first
            Initial; we look up the connection by this value.
            8 bytes is the conventional length.
         */
        $this->local_cid = random_bytes(8);
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
        return $tp;
    }
    /**
     * Helper: encodes one transport parameter whose value
     * is a single varint.
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
     */
    public function processDatagram($buf, $peer)
    {
        $off = 0;
        while ($off < strlen($buf)) {
            $start = $off;
            $first = ord($buf[$off]);
            if (($first & 0x80) === 0) {
                /*
                    Short-header (1-RTT) packet, OR trailing
                    UDP-level padding bytes after a long-
                    header packet. Either way, we can't
                    process the rest of the datagram in
                    Phase 3. Break (don't return) so
                    driveHandshake still gets called below.
                 */
                break;
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
            $this->received_pns[$level][] =
                $pkt->packet_number;
            if ($pkt->packet_number >
                $this->largest_pn[$level]) {
                $this->largest_pn[$level] =
                    $pkt->packet_number;
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
     */
    protected static function peekInitialDcid($buf, $off)
    {
        if (strlen($buf) < $off + 7) {
            return false;
        }
        $dcid_len = ord($buf[$off + 5]);
        if (strlen($buf) < $off + 6 + $dcid_len) {
            return false;
        }
        return substr($buf, $off + 6, $dcid_len);
    }
    /**
     * Walks the frames in a decoded packet and dispatches
     * each to its handler. Phase 3 routes CRYPTO,
     * STREAM, ACK, PADDING, PING, CONNECTION_CLOSE; the
     * rest are accepted but ignored.
     */
    protected function processPacketFrames($level, $pkt)
    {
        list($frames, $err) = QuicFrame::decodeAll(
            $pkt->payload);
        if ($err !== '' && $err !== 'unknown frame type') {
            /* Partial decode -- still process what we got. */
        }
        foreach ($frames as $f) {
            switch ($f['type']) {
                case QuicFrame::F_CRYPTO:
                    $this->onCrypto($level, $f);
                    break;
                case QuicFrame::F_STREAM_BASE:
                    $this->onStream($f);
                    break;
                case QuicFrame::F_ACK:
                case QuicFrame::F_ACK_ECN:
                    /* Phase 3: just note them; no real
                       loss detection / RTT smoothing yet.
                       Phase 5 will. */
                    break;
                case QuicFrame::F_PING:
                case QuicFrame::F_PADDING:
                case QuicFrame::F_HANDSHAKE_DONE:
                case QuicFrame::F_NEW_CONNECTION_ID:
                case QuicFrame::F_NEW_TOKEN:
                    break;
                case QuicFrame::F_CONNECTION_CLOSE:
                case QuicFrame::F_CONNECTION_CLOSE_APP:
                    $this->state = self::ST_CLOSED;
                    return;
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
     */
    protected function feedTlsCrypto($level, $bytes)
    {
        if ($level === self::LEVEL_INITIAL) {
            $this->tls->feedClientHello($bytes);
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
     * STREAM frame handler: route to the per-stream
     * QuicStream, allocating one if this is the first
     * frame on that stream ID.
     */
    protected function onStream($f)
    {
        $sid = $f['stream_id'];
        if (!isset($this->streams[$sid])) {
            $this->streams[$sid] = new QuicStream($sid);
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
        if ($this->tls->getError() !== '') {
            $this->error = $this->tls->getError();
            $this->state = self::ST_CLOSED;
            return;
        }
        /* If we just received the ClientHello and haven't
           sent our flight yet, build it now. */
        if ($this->state === self::ST_NEW &&
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
                $this->keys[self::LEVEL_HANDSHAKE] = [
                    'rx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['c_hs'],
                        Tls13Engine::CIPHER_AES_128_GCM_SHA256
                    ),
                    'tx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['s_hs'],
                        Tls13Engine::CIPHER_AES_128_GCM_SHA256
                    ),
                ];
                $this->keys[self::LEVEL_APPLICATION] = [
                    'rx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['c_ap'],
                        Tls13Engine::CIPHER_AES_128_GCM_SHA256
                    ),
                    'tx' => QuicPacketKeys::fromTrafficSecret(
                        $secrets['s_ap'],
                        Tls13Engine::CIPHER_AES_128_GCM_SHA256
                    ),
                ];
                $this->state = self::ST_HANDSHAKING;
            }
        }
        $this->peer_transport_params =
            $this->tls->clientQuicTransportParameters();
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
     * Builds an ACK frame's wire bytes covering all
     * received packet numbers in the given PN space.
     * Returns "" if nothing to ACK.
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
     * Encrypts and queues a packet for sending. $payload
     * is the unprotected frame sequence; we wrap it in a
     * QuicPacket with the right keys and queue the wire
     * bytes onto $send_queue.
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
        $wire = $packet->encodeLong(
            $this->keys[$level]['tx'], $pn, $payload);
        $this->send_queue[] = [$level, $wire, 'ready'];
    }
    /**
     * Returns datagrams (concatenations of one or more
     * encoded packets) ready to send to the peer, then
     * clears the queue. Pending Handshake-level entries
     * waiting for keys are encrypted now if the keys are
     * available.
     */
    public function emit()
    {
        $out = [];
        $current = "";
        $pending_remaining = [];
        foreach ($this->send_queue as $entry) {
            list($level, $bytes, $status) = $entry;
            if ($status === 'pending') {
                if (!isset($this->keys[$level])) {
                    $pending_remaining[] = $entry;
                    continue;
                }
                /* $bytes is the unprotected payload; wrap
                   it now. */
                $pn = $this->next_pn[$level]++;
                $packet = new QuicPacket();
                $packet->long_type = ($level ===
                    self::LEVEL_HANDSHAKE) ?
                    QuicPacket::LONG_HANDSHAKE :
                    QuicPacket::LONG_INITIAL;
                $packet->version =
                    QuicPacket::VERSION_QUIC_V1;
                $packet->destination_cid = $this->peer_cid;
                $packet->source_cid = $this->local_cid;
                $bytes = $packet->encodeLong(
                    $this->keys[$level]['tx'], $pn, $bytes);
            }
            $current .= $bytes;
        }
        if ($current !== '') {
            $out[] = $current;
        }
        $this->send_queue = $pending_remaining;
        return $out;
    }
    /**
     * Returns true once the QUIC + TLS handshake has
     * completed end-to-end (server has received and
     * verified the client's Finished).
     */
    public function isEstablished()
    {
        return $this->state === self::ST_ESTABLISHED;
    }
}
