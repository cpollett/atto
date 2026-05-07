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
