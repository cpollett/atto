<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the batched header-protection path that emit()
 * uses on the 1-RTT send hotpath: QuicPacketKeys::headerProtectionMasks,
 * QuicPacket::encodeShortSealed, and QuicPacket::applyShortHeaderProtection.
 * The point of the batch is to pay one openssl_encrypt call for a
 * whole emit()'s worth of packets instead of one per packet, so
 * these tests check the batch produces byte-for-byte the same wire
 * as the per-packet encodeShort, that the packets still decode, and
 * that the ChaCha20 loop branch (which cannot share one call)
 * agrees with the single-sample method. AES-128 and, where the
 * platform exposes it, ChaCha20 are both covered.
 *
 * Run from the repo root:
 *     php tests/http3/test_hp_batch.php
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

/*
    Stub the parent classes that H3Listener.php's classes extend.
    WebSite.php normally provides these; loading it just to run the
    unit tests would drag in the whole framework.
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
    Builds a set of short-header packets with a shared destination
    connection id and varying payload sizes, and returns them along
    with the send keys for the given cipher.
 */
function buildBatch($cipher, $count)
{
    $dcid = random_bytes(8);
    $keys = QuicPacketKeys::fromTrafficSecret(random_bytes(32),
        $cipher);
    $packets = [];
    for ($i = 0; $i < $count; $i++) {
        $packet = new QuicPacket();
        $packet->destination_cid = $dcid;
        $packets[] = [$packet, 1000 + $i,
            random_bytes(40 + $i * 11)];
    }
    return [$dcid, $keys, $packets];
}

/*
    Encodes a batch the batched way: seal each packet, mask all the
    samples in one headerProtectionMasks call, then apply each mask.
 */
function batchEncode($keys, $packets)
{
    $unprotected = [];
    $samples = [];
    $header_lengths = [];
    foreach ($packets as $entry) {
        list($bytes, $sample, $hdr_len) =
            $entry[0]->encodeShortSealed($keys, $entry[1],
                $entry[2]);
        $unprotected[] = $bytes;
        $samples[] = $sample;
        $header_lengths[] = $hdr_len;
    }
    $masks = $keys->headerProtectionMasks($samples);
    if ($masks === false) {
        return false;
    }
    $wire = [];
    foreach ($unprotected as $i => $bytes) {
        $wire[] = QuicPacket::applyShortHeaderProtection($bytes,
            $masks[$i], $header_lengths[$i]);
    }
    return $wire;
}

/* AES-128-GCM: the masks match the per-packet method exactly. */
list($dcid, $keys, $packets) =
    buildBatch(Tls13Engine::CIPHER_AES_128_GCM_SHA256, 6);
$samples = [];
$per_packet = [];
foreach ($packets as $entry) {
    list($_u, $sample, $_h) = $entry[0]->encodeShortSealed($keys,
        $entry[1], $entry[2]);
    $samples[] = $sample;
    $per_packet[] = $keys->headerProtectionMask($sample);
}
$batched_masks = $keys->headerProtectionMasks($samples);
ok("aes masks match per-packet masks",
    $batched_masks === $per_packet);

/* AES-128-GCM: batched wire is byte-for-byte the one-shot wire. */
$one_shot = [];
foreach ($packets as $entry) {
    $one_shot[] = $entry[0]->encodeShort($keys, $entry[1],
        $entry[2]);
}
$batched_wire = batchEncode($keys, $packets);
ok("aes batched wire equals one-shot encodeShort",
    $batched_wire === $one_shot);

/* AES-128-GCM: each batched packet still decodes to its payload. */
$decoded_ok = ($batched_wire !== false);
if ($decoded_ok) {
    foreach ($batched_wire as $i => $bytes) {
        list($packet, $_off) = QuicPacket::decodeShort($bytes, 0,
            $keys, strlen($dcid), 999 + $i);
        if ($packet === false
            || $packet->payload !== $packets[$i][2]
            || $packet->packet_number !== 1000 + $i) {
            $decoded_ok = false;
        }
    }
}
ok("aes batched packets decode to their payloads", $decoded_ok);

/* A single-packet batch and an empty batch behave. */
list($_d1, $keys1, $packets1) =
    buildBatch(Tls13Engine::CIPHER_AES_128_GCM_SHA256, 1);
$single_batched = batchEncode($keys1, $packets1);
$single_one_shot = [$packets1[0][0]->encodeShort($keys1,
    $packets1[0][1], $packets1[0][2])];
ok("aes single-packet batch equals one-shot",
    $single_batched === $single_one_shot);
ok("empty batch returns empty masks",
    $keys1->headerProtectionMasks([]) === []);

/* A too-short sample makes the batch report failure, not guess. */
ok("short sample returns false",
    $keys1->headerProtectionMasks([str_repeat("\x00", 8)])
        === false);

/*
    ChaCha20-Poly1305: the batch cannot share one call, so
    headerProtectionMasks loops the single-sample method. Check the
    loop agrees with per-packet masks and that the packets decode.
    The single-sample method self-tests its OpenSSL chacha20 path
    and falls back to pure PHP, so this exercises whichever the
    platform provides.
 */
list($dcid_c, $keys_c, $packets_c) =
    buildBatch(Tls13Engine::CIPHER_CHACHA20_POLY1305_SHA256, 4);
$samples_c = [];
$per_packet_c = [];
foreach ($packets_c as $entry) {
    list($_u, $sample, $_h) = $entry[0]->encodeShortSealed($keys_c,
        $entry[1], $entry[2]);
    $samples_c[] = $sample;
    $per_packet_c[] = $keys_c->headerProtectionMask($sample);
}
$batched_masks_c = $keys_c->headerProtectionMasks($samples_c);
ok("chacha masks match per-packet masks",
    $batched_masks_c === $per_packet_c);
$batched_wire_c = batchEncode($keys_c, $packets_c);
$chacha_decode_ok = ($batched_wire_c !== false);
if ($chacha_decode_ok) {
    foreach ($batched_wire_c as $i => $bytes) {
        list($packet, $_off) = QuicPacket::decodeShort($bytes, 0,
            $keys_c, strlen($dcid_c), 999 + $i);
        if ($packet === false
            || $packet->payload !== $packets_c[$i][2]) {
            $chacha_decode_ok = false;
        }
    }
}
ok("chacha batched packets decode to their payloads",
    $chacha_decode_ok);

echo "\n$pass / $tests passed\n";
exit($pass === $tests ? 0 : 1);
