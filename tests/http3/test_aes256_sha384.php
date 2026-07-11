<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Tests for the AES-256-GCM / SHA-384 cipher suite (code 0x1302).
 * The suite adds two things to the TLS 1.3 engine: a key schedule
 * keyed on SHA-384 instead of SHA-256, and seal/open on AES-256-GCM
 * through libsodium. These tests check the parts that can be checked
 * without a live handshake against a real client.
 *
 * What is verified:
 *   - The engine's HKDF, once its hash is set to SHA-384 (and, as a
 *     control, SHA-256), matches PHP's own hash_hkdf for the same
 *     inputs, so the hash-agile key schedule is arithmetically right.
 *   - The AES-256-GCM bytes libsodium produces are identical to those
 *     OpenSSL produces for the same key, nonce, additional data, and
 *     plaintext, and each opens what the other sealed. This is the
 *     interop evidence available here: a real client's AES-256-GCM is
 *     the standard one, and our sealed bytes match it exactly.
 *   - The QUIC packet keys for the suite derive at the right lengths
 *     with the SHA-384 hash, and a packet sealed with them opens back
 *     to the same plaintext, rejects a tampered tag, and yields a
 *     five-byte header-protection mask.
 *
 * What these do NOT cover: the full handshake message flow with a
 * real client negotiating 0x1302 end to end. That needs a real QUIC
 * client speaking AES-256-GCM-SHA384 and should be checked against
 * curl or quiche before the suite is relied on.
 *
 * Run from the repo root:
 *     php tests/http3/test_aes256_sha384.php
 *
 * Exits 0 on full pass, 1 on any failure.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

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

$tests = 0;
$pass = 0;

/**
 * Records one check's result.
 *
 * @param string $name what the check verifies
 * @param bool $cond whether it held
 */
function ok($name, $cond)
{
    global $tests, $pass;
    $tests++;
    if ($cond) {
        $pass++;
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n";
    }
}

/**
 * Builds a Tls13Engine with its key-schedule hash set, skipping the
 * constructor so no certificate is needed, and reaching the two
 * protected HKDF steps for the checks below.
 *
 * @param string $hash_alg the hash to set ("sha256" or "sha384")
 * @param int $hash_len that hash's output length in bytes
 * @return Tls13Engine the engine with those fields set
 */
function engineWithHash($hash_alg, $hash_len)
{
    $reflection = new \ReflectionClass(Tls13Engine::class);
    $engine = $reflection->newInstanceWithoutConstructor();
    $alg = new \ReflectionProperty(Tls13Engine::class, 'hash_alg');
    $alg->setValue($engine, $hash_alg);
    $len = new \ReflectionProperty(Tls13Engine::class, 'hash_len');
    $len->setValue($engine, $hash_len);
    return $engine;
}

/**
 * Calls a protected method by reflection.
 *
 * @param object $object the object to call on
 * @param string $method the method name
 * @param array $args the arguments
 * @return mixed the method's return value
 */
function callProtected($object, $method, $args)
{
    $reflection = new \ReflectionMethod($object, $method);
    return $reflection->invokeArgs($object, $args);
}

/*
    HKDF hash agility: extract-then-expand must match PHP's hash_hkdf,
    which does the same, for both hashes.
 */
foreach ([['sha256', 32], ['sha384', 48]] as $suite_hash) {
    list($hash_alg, $hash_len) = $suite_hash;
    $engine = engineWithHash($hash_alg, $hash_len);
    $ikm = random_bytes(32);
    $salt = random_bytes(16);
    $info = random_bytes(11);
    $prk = callProtected($engine, 'hkdfExtract', [$salt, $ikm]);
    $mine = callProtected($engine, 'hkdfExpand',
        [$prk, $info, $hash_len]);
    $reference = hash_hkdf($hash_alg, $ikm, $hash_len, $info, $salt);
    ok("HKDF $hash_alg extract is one hash block",
        strlen($prk) === $hash_len);
    ok("HKDF $hash_alg matches PHP hash_hkdf", $mine === $reference);
}

/*
    AEAD interop: libsodium's AES-256-GCM output must be byte-for-byte
    what OpenSSL produces, and each must open the other's, so a real
    client using standard AES-256-GCM interoperates with our seal.
 */
if (function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
    sodium_crypto_aead_aes256gcm_is_available()) {
    $key = random_bytes(32);
    $nonce = random_bytes(12);
    $aad = random_bytes(20);
    $plaintext = random_bytes(300);
    $by_sodium = sodium_crypto_aead_aes256gcm_encrypt(
        $plaintext, $aad, $nonce, $key);
    $tag = '';
    $by_openssl = openssl_encrypt($plaintext, 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    $by_openssl .= $tag;
    ok("sodium AES-256-GCM bytes equal OpenSSL's",
        $by_sodium === $by_openssl);
    $openssl_opens = openssl_decrypt(
        substr($by_sodium, 0, -16), 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, $nonce, substr($by_sodium, -16), $aad);
    ok("OpenSSL opens sodium-sealed AES-256-GCM",
        $openssl_opens === $plaintext);
    $sodium_opens = sodium_crypto_aead_aes256gcm_decrypt(
        $by_openssl, $aad, $nonce, $key);
    ok("sodium opens OpenSSL-sealed AES-256-GCM",
        $sodium_opens === $plaintext);
} else {
    echo "SKIP AES-256-GCM AEAD checks (no hardware AES here)\n";
}

/*
    QUIC packet keys for the suite: right lengths, SHA-384 derivation,
    and a working seal/open plus header-protection mask.
 */
$suite = Tls13Engine::CIPHER_AES_256_GCM_SHA384;
$traffic_secret = random_bytes(48);
$keys = QuicPacketKeys::fromTrafficSecret($traffic_secret, $suite);
ok("AES-256 packet key is 32 bytes", strlen($keys->key) === 32);
ok("AES-256 packet iv is 12 bytes", strlen($keys->iv) === 12);
ok("AES-256 header-protection key is 32 bytes",
    strlen($keys->hp_key) === 32);

/*
    The packet key must come from a SHA-384 expand-label of the
    traffic secret. Rebuild it the long way and compare.
 */
$expected_key = referenceExpandLabel($traffic_secret, 'quic key', '',
    32, 'sha384');
ok("AES-256 packet key uses the SHA-384 schedule",
    $keys->key === $expected_key);

if (function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
    sodium_crypto_aead_aes256gcm_is_available()) {
    $aad = random_bytes(18);
    $payload = random_bytes(500);
    $sealed = $keys->seal(42, $aad, $payload);
    ok("AES-256 QUIC seal then open round-trips",
        $keys->open(42, $aad, $sealed) === $payload);
    ok("AES-256 QUIC open rejects a tampered tag",
        $keys->open(42, $aad, substr($sealed, 0, -1) . "\x00")
            === false);
    ok("AES-256 QUIC open rejects the wrong packet number",
        $keys->open(43, $aad, $sealed) === false);
    $mask = $keys->headerProtectionMask(random_bytes(16));
    ok("AES-256 header-protection mask is 5 bytes",
        is_string($mask) && strlen($mask) === 5);
}

/**
 * Rebuilds a TLS 1.3 HKDF-Expand-Label the long way for the check
 * above, so the packet key can be compared against an independent
 * computation. The expand step itself is the one hash_hkdf validated
 * earlier.
 *
 * @param string $secret the secret to expand
 * @param string $label the label, without the "tls13 " prefix
 * @param string $context the context bytes
 * @param int $length how many bytes to produce
 * @param string $hash_alg the hash to key on
 * @return string the derived bytes
 */
function referenceExpandLabel($secret, $label, $context, $length,
    $hash_alg)
{
    $full = "tls13 " . $label;
    $info = chr(($length >> 8) & 0xFF) . chr($length & 0xFF) .
        chr(strlen($full)) . $full .
        chr(strlen($context)) . $context;
    $out = '';
    $block = '';
    $counter = 1;
    while (strlen($out) < $length) {
        $block = hash_hmac($hash_alg,
            $block . $info . chr($counter), $secret, true);
        $out .= $block;
        $counter++;
    }
    return substr($out, 0, $length);
}

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
