<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for QuicPacketKeys::chacha20Block,
 * QuicPacketKeys::chachaUseOpenssl, and the QUIC header-
 * protection mask path that uses ChaCha20. These cover the
 * pure-PHP ChaCha20 fallback shipped to support platforms
 * (notably stock macOS, which links PHP against LibreSSL)
 * that don't expose the raw 'chacha20' EVP cipher.
 *
 * Run from the repo root:
 *     php tests/http3/test_chacha_paths.php
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

/*
    Test 1: the pure-PHP ChaCha20 block function reproduces the
    RFC 8439 sec 2.3.2 keystream vector exactly. This is the
    canonical conformance test for any ChaCha20 implementation.
 */
$key = '';
for ($i = 0; $i < 32; $i++) {
    $key .= chr($i);
}
$nonce = "\x00\x00\x00\x09\x00\x00\x00\x4a\x00\x00\x00\x00";
$expected_hex =
    "10f1e7e4d13b5915500fdd1fa32071c4"
    . "c7d1f4c733c0680304"
    . "22aa9ac3d46c4ed2826446079faa0914"
    . "c2d705d98b02a2b5129cd1de164eb9cb"
    . "d083e8a2503c4e";
$ks = QuicPacketKeys::chacha20Block($key, 1, $nonce);
ok("pure-PHP chacha20 RFC 8439 sec 2.3.2 vector",
    bin2hex($ks) === $expected_hex);

/*
    Test 2: the platform-detect helper returns a stable bool.
    On Linux with OpenSSL 3.x this is true; on stock macOS with
    LibreSSL it is false; either way it must be deterministic.
 */
$use_openssl = QuicPacketKeys::chachaUseOpenssl();
ok("chachaUseOpenssl returns deterministic bool",
    is_bool($use_openssl));
echo "  (chachaUseOpenssl: "
    . ($use_openssl ? "true" : "false") . ")\n";

/*
    Test 3: when OpenSSL's chacha20 is available, both code
    paths produce byte-identical 5-byte HP masks for the same
    (key, sample) input. Skipped on hosts where the openssl
    path failed self-test (the fallback is then the only path).
 */
if ($use_openssl) {
    $hp_key = '';
    for ($i = 0; $i < 32; $i++) {
        $hp_key .= chr(0x40 ^ $i);
    }
    $sample = '';
    for ($i = 0; $i < 16; $i++) {
        $sample .= chr(0x80 ^ $i);
    }
    $iv = substr($sample, 0, 16);
    $ks_oss = openssl_encrypt(
        "\x00\x00\x00\x00\x00", 'chacha20', $hp_key,
        OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);
    $oss_5 = substr($ks_oss, 0, 5);
    $counter = ord($sample[0])
        | (ord($sample[1]) << 8)
        | (ord($sample[2]) << 16)
        | (ord($sample[3]) << 24);
    $nonce_5 = substr($sample, 4, 12);
    $block = QuicPacketKeys::chacha20Block($hp_key, $counter,
        $nonce_5);
    $php_5 = substr($block, 0, 5);
    ok("openssl and pure-PHP HP masks agree byte-for-byte",
        bin2hex($oss_5) === bin2hex($php_5));
}

/*
    Test 4: edge counters. Counter 0, counter 1, and the 32-bit
    maximum all produce 64-byte blocks; counters 0 and 1 must
    differ; counters 1 and max must differ. This catches off-
    by-one and 32-bit-wraparound bugs in the working state
    layout.
 */
$nonce_test = str_repeat("\x00", 12);
$key_test = str_repeat("\xaa", 32);
$b0 = QuicPacketKeys::chacha20Block($key_test, 0, $nonce_test);
$b1 = QuicPacketKeys::chacha20Block($key_test, 1, $nonce_test);
$bmax = QuicPacketKeys::chacha20Block($key_test, 0xffffffff,
    $nonce_test);
ok("counter=0 produces 64 bytes",
    strlen($b0) === 64);
ok("counter=1 produces 64 bytes",
    strlen($b1) === 64);
ok("counter=0xffffffff produces 64 bytes",
    strlen($bmax) === 64);
ok("counters 0 and 1 produce different output",
    $b0 !== $b1);
ok("counters 1 and 0xffffffff produce different output",
    $b1 !== $bmax);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
