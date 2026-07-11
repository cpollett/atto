<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Benchmarks for the AEAD hotpath methods on QuicPacketKeys, the
 * largest single cost the bottlenecks note attributes to a pure-PHP
 * HTTP/3 response (about a third of a /big transfer). Each method is
 * timed on its own over many calls with representative inputs, so
 * its per-call cost can be inspected and a later tweak measured
 * against it.
 *
 * seal encrypts a packet payload, open decrypts one, and
 * headerProtectionMask derives the five-byte mask that hides the
 * packet-number bits. The keys are real AES-128-GCM packet keys
 * built from a Connection ID through the same derivation the
 * listener uses, so the openssl round trip the note points at as the
 * real cost is exercised exactly as it is in the running server. No
 * connection or socket is stood up; this is one class's methods in
 * isolation.
 *
 * A second block repeats seal, open, and the mask on AES-256-GCM,
 * whose seal and open run through libsodium, where hardware
 * AES-256-GCM is available. That path measured close to twice as
 * quick as the AES-128-GCM one at packet sizes here, and it is the
 * only place the AES-256 cost appears: every other benchmark, and
 * the workload counts, use AES-128-GCM Initial keys.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_aead.php
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/*
    Stub the parent classes that H3Listener.php's classes extend.
    WebSite.php normally provides these; loading it just to reach
    QuicPacketKeys would drag in the whole framework.
 */
class Connection {}
class Listener
{
    public function __construct(...$a) {}
    public function close() {}
}
abstract class Transport
{
    public function __construct($s) {}
}

require __DIR__ . '/../../src/H3Listener.php';
require __DIR__ . '/measure.php';

/**
 * @var int payload size to seal, in bytes, near the ~1100-byte
 *      protected payload the note measured for a /big packet
 */
const AEAD_PAYLOAD_BYTES = 1100;
/**
 * @var int size of the header bytes passed as AEAD associated data
 */
const AEAD_AAD_BYTES = 30;
/**
 * @var int header-protection sample size, in bytes (RFC 9001
 *      sec 5.4.2 takes a 16-byte sample from the packet)
 */
const AEAD_SAMPLE_BYTES = 16;
/**
 * @var int Destination Connection ID length used to derive the
 *      benchmark's packet keys
 */
const AEAD_DCID_BYTES = 8;
/**
 * @var int a representative packet number, which selects the AEAD
 *      nonce for each call
 */
const AEAD_PACKET_NUMBER = 1234;
/**
 * @var int header-protection mask length in bytes (RFC 9001
 *      sec 5.4.1 masks the low five bytes of the header)
 */
const AEAD_MASK_BYTES = 5;

$keys = QuicPacketKeys::fromInitialDcid(
    random_bytes(AEAD_DCID_BYTES))['server'];
$aad = random_bytes(AEAD_AAD_BYTES);
$plaintext = random_bytes(AEAD_PAYLOAD_BYTES);
$sample = random_bytes(AEAD_SAMPLE_BYTES);
$ciphertext = $keys->seal(AEAD_PACKET_NUMBER, $aad, $plaintext);

/*
    Confirm the inputs form a valid seal/open pair before timing, so
    the open benchmark measures the success path rather than a
    rejected packet, and the header-protection mask is the expected
    length.
 */
if ($keys->open(AEAD_PACKET_NUMBER, $aad, $ciphertext) !== $plaintext) {
    fwrite(STDERR, "seal/open did not round-trip; aborting\n");
    exit(1);
}
if (strlen($keys->headerProtectionMask($sample)) !== AEAD_MASK_BYTES) {
    fwrite(STDERR, "header-protection mask was not 5 bytes; aborting\n");
    exit(1);
}

echo "AEAD hotpath (AES-128-GCM), payload " . AEAD_PAYLOAD_BYTES .
    " bytes\n";
benchHeader();
runBenchmark("(empty-closure overhead)", function () {
});
runBenchmark("QuicPacketKeys::seal",
    function () use ($keys, $aad, $plaintext) {
        $keys->seal(AEAD_PACKET_NUMBER, $aad, $plaintext);
    });
runBenchmark("QuicPacketKeys::open",
    function () use ($keys, $aad, $ciphertext) {
        $keys->open(AEAD_PACKET_NUMBER, $aad, $ciphertext);
    });
runBenchmark("QuicPacketKeys::headerProtectionMask",
    function () use ($keys, $sample) {
        $keys->headerProtectionMask($sample);
    });

/*
    The same hotpath on AES-256-GCM, which seals and opens through
    libsodium rather than OpenSSL. That suite is only offered where
    hardware AES-256-GCM is available, so skip these rows when it is
    not. The keys derive from a 48-byte SHA-384 traffic secret, the
    length that suite's key schedule produces. The default benchmarks
    above use AES-128-GCM Initial keys, so this section is the only
    place the AES-256 seal and open costs show up.
 */
if (function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
    sodium_crypto_aead_aes256gcm_is_available()) {
    $keys_256 = QuicPacketKeys::fromTrafficSecret(
        random_bytes(48),
        Tls13Engine::CIPHER_AES_256_GCM_SHA384);
    $ciphertext_256 = $keys_256->seal(AEAD_PACKET_NUMBER, $aad,
        $plaintext);
    if ($keys_256->open(AEAD_PACKET_NUMBER, $aad, $ciphertext_256)
            !== $plaintext) {
        fwrite(STDERR,
            "AES-256 seal/open did not round-trip; aborting\n");
        exit(1);
    }
    echo "\nAEAD hotpath (AES-256-GCM), payload " .
        AEAD_PAYLOAD_BYTES . " bytes\n";
    benchHeader();
    runBenchmark("QuicPacketKeys::seal",
        function () use ($keys_256, $aad, $plaintext) {
            $keys_256->seal(AEAD_PACKET_NUMBER, $aad, $plaintext);
        });
    runBenchmark("QuicPacketKeys::open",
        function () use ($keys_256, $aad, $ciphertext_256) {
            $keys_256->open(AEAD_PACKET_NUMBER, $aad,
                $ciphertext_256);
        });
    runBenchmark("QuicPacketKeys::headerProtectionMask",
        function () use ($keys_256, $sample) {
            $keys_256->headerProtectionMask($sample);
        });
} else {
    echo "\nAES-256-GCM rows skipped: no hardware AES-256-GCM here\n";
}
