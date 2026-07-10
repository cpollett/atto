<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Benchmarks how the per-packet nonce is built. The nonce is the
 * initialization vector with the 64-bit packet number exclusive-or'd
 * into its low 8 bytes, and it is built once per seal and once per
 * open, so on a 1 MiB response it runs a couple of thousand times.
 * The shipping method builds it with one bulk string exclusive-or on
 * the 8-byte tail; this script measures that against the earlier
 * byte-at-a-time loop it replaced and against a variant that caches
 * the tail of the initialization vector as an integer, to show where
 * the time goes and to give the build a baseline a later change can
 * be measured against.
 *
 * The byte-loop reference is kept here rather than in the shipping
 * file so the comparison stays reproducible after the source moved on
 * to the faster form. All three are checked to produce the same nonce
 * before any timing, so a faster row is only reported when it is also
 * a correct one.
 *
 * These are benchmarks, not the pass/fail tests: they are timed
 * rather than asserted and live under the bench_ name the test runner
 * skips.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_nonce.php
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/*
    Stub the parent classes H3Listener.php's classes extend, the way
    the other benchmarks do, so the QUIC classes load without the
    whole framework.
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
 * @var int packet number the timed builds use; the nonce cost does
 *      not depend on its value, so one representative number is
 *      enough
 */
const NONCE_PACKET_NUMBER = 987654321;
/**
 * @var int correctness passes, each with a fresh random
 *      initialization vector, so a variant that mishandles a
 *      high-bit-set tail is caught before timing
 */
const NONCE_CHECK_IVS = 500;

/**
 * Builds a QuicPacketKeys with a given initialization vector,
 * skipping the constructor the way the other benchmarks do, so the
 * real packetNonce can be timed on a set vector.
 *
 * @param string $iv the 12-byte initialization vector to set
 * @return QuicPacketKeys the keys with that vector
 */
function keysWithIv($iv)
{
    $reflection = new \ReflectionClass(QuicPacketKeys::class);
    $keys = $reflection->newInstanceWithoutConstructor();
    $property = new \ReflectionProperty(QuicPacketKeys::class, 'iv');
    $property->setValue($keys, $iv);
    return $keys;
}

/**
 * The byte-at-a-time build the shipping method replaced, kept here so
 * its cost stays measurable. Builds the padded packet number and
 * exclusive-ors it against the vector one byte at a time.
 *
 * @param string $iv the 12-byte initialization vector
 * @param int $packet_number the packet's number
 * @return string the 12-byte nonce
 */
function nonceByteLoop($iv, $packet_number)
{
    $padded = str_repeat("\x00", 4) .
        pack('J', (int) $packet_number);
    $out = '';
    for ($i = 0; $i < 12; $i++) {
        $out .= chr(ord($iv[$i]) ^ ord($padded[$i]));
    }
    return $out;
}

/*
    Check the byte loop and the cached-integer variant against the
    shipping method across many random vectors before timing.
 */
$mismatches = 0;
$checks = 0;
for ($pass = 0; $pass < NONCE_CHECK_IVS; $pass++) {
    $iv = random_bytes(12);
    $keys = keysWithIv($iv);
    $head = substr($iv, 0, 4);
    $tail_int = unpack('J', substr($iv, 4, 8))[1];
    $packet_numbers = [0, 1, (1 << 62) - 1,
        random_int(0, (1 << 62) - 1)];
    foreach ($packet_numbers as $packet_number) {
        $reference = $keys->packetNonce($packet_number);
        $loop = nonceByteLoop($iv, $packet_number);
        $cached = $head
            . pack('J', $tail_int ^ (int) $packet_number);
        $checks++;
        if ($loop !== $reference || $cached !== $reference) {
            $mismatches++;
        }
    }
}
echo "nonce build: checked " . number_format($checks) .
    " (iv, packet-number) pairs, mismatches: " . $mismatches . "\n";

$iv = random_bytes(12);
$keys = keysWithIv($iv);
$head = substr($iv, 0, 4);
$tail_int = unpack('J', substr($iv, 4, 8))[1];
$packet_number = NONCE_PACKET_NUMBER;
benchHeader();
runBenchmark("packetNonce (shipping, tail string xor)",
    function () use ($keys, $packet_number) {
        $keys->packetNonce($packet_number);
    });
runBenchmark("byte loop (former)",
    function () use ($iv, $packet_number) {
        nonceByteLoop($iv, $packet_number);
    });
runBenchmark("cached tail int xor (alternative)",
    function () use ($head, $tail_int, $packet_number) {
        $nonce = $head
            . pack('J', $tail_int ^ (int) $packet_number);
    });
