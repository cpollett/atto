<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Benchmarks for the frame and packet codec methods the bottlenecks
 * note calls out: QuicFrame::encode and its hot STREAM case
 * encodeStream, QuicFrame::decodeAll, and the short-header packet
 * pair QuicPacket::encodeShort and decodeShort. Each is timed on its
 * own over many calls with representative inputs, so its per-call
 * cost can be inspected and a later tweak measured against it.
 *
 * The note suggests inlining encodeStream into the flush loop to
 * skip the type switch in encode, saving about a microsecond per
 * packet. To make that claim measurable, encode (which runs the
 * switch) and encodeStream (reached directly through a reflection
 * closure, which does not) are both timed on the same STREAM frame;
 * the gap between them is the dispatch cost the note is talking
 * about. decodeAll is timed on the small inbound frame set an ACK
 * packet carries, since the note says decodeAll runs on the ACK
 * stream. encodeShort and decodeShort use the same real AES-128-GCM
 * key set as the AEAD benchmark, so the seal, mask, and open steps
 * they call are exercised as in the running server. No connection or
 * socket is stood up.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_codec.php
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
    WebSite.php normally provides these; loading it just to reach the
    QUIC codec classes would drag in the whole framework.
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
 * @var int STREAM frame payload size, in bytes, near the ~1100-byte
 *      chunk a /big response sends per STREAM frame
 */
const CODEC_STREAM_DATA_BYTES = 1100;
/**
 * @var int short-header packet payload size, in bytes
 */
const CODEC_PACKET_PAYLOAD_BYTES = 1100;
/**
 * @var int stream identifier used for the STREAM frame
 */
const CODEC_STREAM_ID = 0;
/**
 * @var int byte offset used for the STREAM frame
 */
const CODEC_STREAM_OFFSET = 0;
/**
 * @var int Destination Connection ID length for the packet keys and
 *      the short-header packet
 */
const CODEC_DCID_BYTES = 8;
/**
 * @var int a representative packet number for the packet benchmarks
 */
const CODEC_PACKET_NUMBER = 1234;
/**
 * @var int largest packet number an ACK frame acknowledges, for the
 *      decodeAll input
 */
const CODEC_ACK_LARGEST_PN = 1000;
/**
 * @var int ACK delay field for the decodeAll input
 */
const CODEC_ACK_DELAY = 100;
/**
 * @var int first-range field of the ACK frame for the decodeAll
 *      input, the count of packets below the largest also acked
 */
const CODEC_ACK_FIRST_RANGE = 10;

$stream_frame = [
    'type' => QuicFrame::F_STREAM_BASE,
    'stream_id' => CODEC_STREAM_ID,
    'offset' => CODEC_STREAM_OFFSET,
    'data' => random_bytes(CODEC_STREAM_DATA_BYTES),
    'fin' => false,
];

/*
    A reflection closure onto the protected static encodeStream, so
    it can be timed directly, without the type switch encode runs and
    without per-call reflection-invoke overhead.
 */
$encode_stream_method = new \ReflectionMethod(
    QuicFrame::class, 'encodeStream');
$encode_stream = $encode_stream_method->getClosure();

/*
    The inbound frame set an ACK packet carries: one ACK frame and a
    PING, the small buffer the note says decodeAll runs on.
 */
$ack_frame = [
    'type' => QuicFrame::F_ACK,
    'largest' => CODEC_ACK_LARGEST_PN,
    'delay' => CODEC_ACK_DELAY,
    'ranges' => [],
    'first_range' => CODEC_ACK_FIRST_RANGE,
];
$inbound_frames = QuicFrame::encode($ack_frame) .
    QuicFrame::encode(['type' => QuicFrame::F_PING]);

$keys = QuicPacketKeys::fromInitialDcid(
    random_bytes(CODEC_DCID_BYTES))['server'];
$packet = new QuicPacket();
$packet->destination_cid = random_bytes(CODEC_DCID_BYTES);
$packet_payload = random_bytes(CODEC_PACKET_PAYLOAD_BYTES);
$sealed_packet = $packet->encodeShort($keys, CODEC_PACKET_NUMBER,
    $packet_payload);

/*
    Confirm each input is valid before timing, so the benchmarks
    measure the working paths rather than early error returns.
 */
if (QuicFrame::encode($stream_frame) === false) {
    fwrite(STDERR, "STREAM frame did not encode; aborting\n");
    exit(1);
}
list($decoded_frames, $decode_error) = QuicFrame::decodeAll(
    $inbound_frames);
if ($decode_error !== '') {
    fwrite(STDERR, "inbound frames did not decode; aborting\n");
    exit(1);
}
list($decoded_packet, $decoded_off) = QuicPacket::decodeShort(
    $sealed_packet, 0, $keys, CODEC_DCID_BYTES,
    CODEC_PACKET_NUMBER - 1);
if ($decoded_packet === false ||
    $decoded_packet->payload !== $packet_payload) {
    fwrite(STDERR, "short packet did not round-trip; aborting\n");
    exit(1);
}

echo "frame and packet codec\n";
benchHeader();
runBenchmark("(empty-closure overhead)", function () {
});
runBenchmark("QuicFrame::encode (STREAM, switch)",
    function () use ($stream_frame) {
        QuicFrame::encode($stream_frame);
    });
runBenchmark("QuicFrame::encodeStream (no switch)",
    function () use ($encode_stream, $stream_frame) {
        $encode_stream($stream_frame);
    });
runBenchmark("QuicFrame::decodeAll (ACK + PING)",
    function () use ($inbound_frames) {
        QuicFrame::decodeAll($inbound_frames);
    });
runBenchmark("QuicPacket::encodeShort",
    function () use ($packet, $keys, $packet_payload) {
        $packet->encodeShort($keys, CODEC_PACKET_NUMBER,
            $packet_payload);
    });
runBenchmark("QuicPacket::decodeShort",
    function () use ($sealed_packet, $keys) {
        QuicPacket::decodeShort($sealed_packet, 0, $keys,
            CODEC_DCID_BYTES, CODEC_PACKET_NUMBER - 1);
    });
