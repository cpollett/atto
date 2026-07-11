<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Benchmarks for the three whole-connection hotpath methods the
 * bottlenecks note names: QuicConnection::emit, the per-packet loop
 * that seals each queued 1-RTT payload into a wire packet;
 * setLossDetectionTimer, the walk over in-flight packets that arms
 * the loss timer; and processAck, the inbound cost of retiring
 * acknowledged packets. All three read the same whole-connection
 * state, so one set-up serves all three. Two smaller rows sit
 * alongside them: header protection for one emit()'s worth of
 * packets done per packet, and the same done in one batched
 * headerProtectionMasks call, which is what emit() now uses.
 *
 * The connection is built the way the http3 tests build one, through
 * ReflectionClass without the constructor, with the fields each
 * method reads set directly (they are public). This needs no
 * certificate and opens no socket. Protected methods (processAck)
 * are reached through reflection, which since PHP 8.1 needs no
 * setAccessible call.
 *
 * emit and processAck both mutate connection state as they run
 * (emit drains the send queue and records sent packets; processAck
 * removes acked packets), so each timed call first restores the
 * starting state from a snapshot. The restore is a plain assignment
 * of an already-built array, so it stays cheap next to the work
 * being timed. emit's single call is heavy -- it seals a whole 1 MiB
 * response's worth of packets -- so it runs with a smaller warm-up
 * and iteration count.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_emit.php
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
    QUIC classes would drag in the whole framework.
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
 * @var int size of the response emit ships, in bytes, the 1 MiB
 *      /big transfer the note measured
 */
const EMIT_RESPONSE_BYTES = 1048576;
/**
 * @var int request stream identifier carrying the response
 */
const EMIT_STREAM_ID = 0;
/**
 * @var int Destination Connection ID length for the packet keys and
 *      the peer connection id
 */
const EMIT_DCID_BYTES = 8;
/**
 * @var int timed iterations for the whole-response emit, smaller
 *      than the default because one call already seals ~950 packets
 */
const EMIT_HEAVY_ITERATIONS = 80;
/**
 * @var int in-flight packet count for the loss-timer and ACK
 *      benchmarks, the number a 1 MiB response leaves outstanding
 */
const EMIT_INFLIGHT_PACKETS = 950;
/**
 * @var int largest acknowledged packet number for the loss-scan
 *      benchmark, set low so only a few packets sit at or below it
 *      and the scan breaks past the rest of the in-flight set
 */
const SCAN_LARGEST_ACKED = 2;
/**
 * @var float seconds to place the loss-scan packets' send time in
 *      the future, so they never age past the loss threshold while
 *      the benchmark runs and the scan removes nothing
 */
const SCAN_FUTURE_OFFSET_SEC = 3600.0;

/**
 * Builds a QuicConnection in the established state with just the
 * fields emit, setLossDetectionTimer, and processAck read, skipping
 * the real constructor the way the http3 tests do.
 *
 * @param QuicPacketKeys $keys transmit keys emit seals packets with
 * @param QuicStream $stream the request stream to attach
 * @return QuicConnection connection ready for the benchmarks
 */
function buildEmitConnection($keys, $stream)
{
    $app = QuicConnection::LEVEL_APPLICATION;
    $initial = QuicConnection::LEVEL_INITIAL;
    $handshake = QuicConnection::LEVEL_HANDSHAKE;
    $reflection = new \ReflectionClass(QuicConnection::class);
    $conn = $reflection->newInstanceWithoutConstructor();
    $conn->state = QuicConnection::ST_ESTABLISHED;
    $conn->handshake_done_sent = true;
    $conn->new_cids_pending = [];
    $conn->path_responses_pending = [];
    $conn->ack_pending = [$initial => false, $handshake => false,
        $app => false];
    $conn->keys = [$app => ['tx' => $keys]];
    $conn->congestion_window = PHP_INT_MAX;
    $conn->bytes_in_flight = 0;
    $conn->next_pn = [$initial => 0, $handshake => 0, $app => 0];
    $conn->peer_cid = random_bytes(EMIT_DCID_BYTES);
    $conn->sent_packets = [$initial => [], $handshake => [],
        $app => []];
    $conn->loss_time = [$initial => null, $handshake => null,
        $app => null];
    $conn->largest_acked_pn = [$initial => -1, $handshake => -1,
        $app => -1];
    $conn->latest_rtt = null;
    $conn->smoothed_rtt = null;
    $conn->rttvar = null;
    $conn->min_rtt = null;
    $conn->pto_count = 0;
    $conn->loss_detection_timer = null;
    $conn->streams = [$stream->id => $stream];
    $conn->send_queue = [];
    $conn->conn_data_sent = 0;
    $conn->stats_bytes_sent = 0;
    $conn->stats_bytes_received = 0;
    $conn->stats_packets_sent = 0;
    return $conn;
}

/**
 * Builds a set of in-flight sent-packet records of the shape
 * processAck and setLossDetectionTimer read, numbered 0 upward.
 *
 * @param int $count how many records to build
 * @param float|null $time_sent send time to stamp on each record,
 *      or null to use the current time
 * @return array packet-number => record
 */
function buildSentPackets($count, $time_sent = null)
{
    if ($time_sent === null) {
        $time_sent = microtime(true);
    }
    $sent = [];
    for ($i = 0; $i < $count; $i++) {
        $sent[$i] = [
            'pn' => $i,
            'time_sent' => $time_sent,
            'ack_eliciting' => true,
            'in_flight' => true,
            'sent_bytes' => QuicConnection::CC_MAX_DATAGRAM_BYTES,
            'frames' => [],
        ];
    }
    return $sent;
}

$app_level = QuicConnection::LEVEL_APPLICATION;
$response = random_bytes(EMIT_RESPONSE_BYTES);
$keys = QuicPacketKeys::fromInitialDcid(
    random_bytes(EMIT_DCID_BYTES))['server'];

/* emit set-up: queue a whole response, then snapshot the queue. */
$emit_stream = new QuicStream(EMIT_STREAM_ID, EMIT_RESPONSE_BYTES,
    EMIT_RESPONSE_BYTES);
$emit_conn = buildEmitConnection($keys, $emit_stream);
$emit_stream->send_buf = $response;
$emit_conn->flushStreams(EMIT_RESPONSE_BYTES);
$queued = $emit_conn->send_queue;
$packets_per_emit = count($queued);

/* loss-timer set-up: a full in-flight set, no earlier loss time. */
$timer_conn = buildEmitConnection($keys,
    new QuicStream(EMIT_STREAM_ID));
$timer_conn->sent_packets[$app_level] = buildSentPackets(
    EMIT_INFLIGHT_PACKETS);

/* processAck set-up: a full in-flight set and an ACK of all of it. */
$ack_conn = buildEmitConnection($keys, new QuicStream(EMIT_STREAM_ID));
$ack_sent = buildSentPackets(EMIT_INFLIGHT_PACKETS);
$ack_frame = [
    'type' => QuicFrame::F_ACK,
    'largest' => EMIT_INFLIGHT_PACKETS - 1,
    'delay' => 0,
    'first_range' => EMIT_INFLIGHT_PACKETS - 1,
    'ranges' => [],
];
$process_ack = new \ReflectionMethod(
    QuicConnection::class, 'processAck');

/*
    Confirm each path does its work before timing: emit produces
    packets, the timer walk arms a deadline, and the ACK retires the
    in-flight set.
 */
$sanity_out = $emit_conn->emit();
if (count($sanity_out) < 1) {
    fwrite(STDERR, "emit produced no packets; aborting\n");
    exit(1);
}
$timer_conn->setLossDetectionTimer();
if ($timer_conn->loss_detection_timer === null) {
    fwrite(STDERR, "loss timer did not arm; aborting\n");
    exit(1);
}
$ack_conn->sent_packets[$app_level] = $ack_sent;
$process_ack->invokeArgs($ack_conn, [$app_level, $ack_frame]);
if (count($ack_conn->sent_packets[$app_level]) !== 0) {
    fwrite(STDERR, "processAck left packets in flight; aborting\n");
    exit(1);
}

echo "emit loop, loss timer, and ACK, " . EMIT_RESPONSE_BYTES .
    "-byte response, " . EMIT_INFLIGHT_PACKETS . " in flight\n";
benchHeader();
$emit_median = runBenchmark("QuicConnection::emit 1 MiB (seal loop)",
    function () use ($emit_conn, $queued, $app_level) {
        $emit_conn->send_queue = $queued;
        $emit_conn->next_pn[$app_level] = 0;
        $emit_conn->bytes_in_flight = 0;
        $emit_conn->sent_packets[$app_level] = [];
        $emit_conn->earliest_eliciting_send = null;
        $emit_conn->loss_timer_cache_dirty = true;
        $emit_conn->emit();
    }, EMIT_HEAVY_ITERATIONS, BENCH_DEFAULT_REPEATS,
    BENCH_HEAVY_WARMUP_ITERATIONS);
printf("    %d packets per emit; %.3f us/packet\n", $packets_per_emit,
    $emit_median / $packets_per_emit / BENCH_NS_PER_US);
/*
    Header protection for one emit()'s worth of 1-RTT packets: the
    per-packet way the send path used before, against the single
    batched call it uses now. headerProtectionMasks concatenates the
    samples into one aes-128-ecb call (ECB blocks are independent),
    so a whole batch costs about one call rather than N. The batch
    is sized to the packets one flush budget yields, since that is
    what a single emit() masks in one call; the samples are the
    16-byte ciphertext samples emit() takes from each sealed packet,
    with random bytes standing in, as ECB timing does not depend on
    their content.
 */
$hp_batch_size = (int) max(1, ceil(
    QuicConnection::DEFAULT_FLUSH_BUDGET
    / QuicConnection::MAX_STREAM_FRAME_BYTES));
$hp_keys = QuicPacketKeys::fromTrafficSecret(random_bytes(32),
    Tls13Engine::CIPHER_AES_128_GCM_SHA256);
$hp_samples = [];
for ($hp_i = 0; $hp_i < $hp_batch_size; $hp_i++) {
    $hp_samples[] = random_bytes(16);
}
runBenchmark(
    "header protection per packet ($hp_batch_size calls)",
    function () use ($hp_keys, $hp_samples) {
        foreach ($hp_samples as $hp_sample) {
            $hp_keys->headerProtectionMask($hp_sample);
        }
    });
runBenchmark("QuicPacketKeys::headerProtectionMasks (batch)",
    function () use ($hp_keys, $hp_samples) {
        $hp_keys->headerProtectionMasks($hp_samples);
    });
runBenchmark("setLossDetectionTimer (cold walk, 950)",
    function () use ($timer_conn) {
        $timer_conn->loss_timer_cache_dirty = true;
        $timer_conn->setLossDetectionTimer();
    });
runBenchmark("setLossDetectionTimer (cached)",
    function () use ($timer_conn) {
        $timer_conn->setLossDetectionTimer();
    });
runBenchmark("QuicConnection::processAck (950 acked)",
    function () use ($process_ack, $ack_conn, $ack_sent, $ack_frame,
        $app_level) {
        $ack_conn->sent_packets[$app_level] = $ack_sent;
        $ack_conn->loss_timer_cache_dirty = true;
        $process_ack->invokeArgs($ack_conn,
            [$app_level, $ack_frame]);
    });

/*
    Loss-scan set-up. detectAndRemoveLostPackets walks the in-flight
    packets to declare losses, skipping any whose packet number is
    above largest_acked. Because sent_packets is in packet-number
    order, it now breaks at the first such packet rather than scanning
    the rest of the tail. With a full in-flight set and a low
    largest_acked, only a handful of packets sit at or below it, so
    the scan does little; computeEarliestElicitingSend over the same
    set is the cost of walking all of it, the reference for what the
    break skips. Send times are placed in the future so no packet
    ages into a loss and the scan stays side-effect-free.
 */
$scan_conn = buildEmitConnection($keys, new QuicStream(EMIT_STREAM_ID));
$scan_conn->sent_packets[$app_level] = buildSentPackets(
    EMIT_INFLIGHT_PACKETS,
    microtime(true) + SCAN_FUTURE_OFFSET_SEC);
$scan_conn->largest_acked_pn[$app_level] = SCAN_LARGEST_ACKED;
$detect_lost = new \ReflectionMethod(
    QuicConnection::class, 'detectAndRemoveLostPackets');
$full_walk = new \ReflectionMethod(
    QuicConnection::class, 'computeEarliestElicitingSend');
$detect_lost->invokeArgs($scan_conn, [$app_level]);
if (count($scan_conn->sent_packets[$app_level])
    !== EMIT_INFLIGHT_PACKETS) {
    fwrite(STDERR, "loss scan removed packets; aborting\n");
    exit(1);
}
runBenchmark("detectAndRemoveLostPackets (break)",
    function () use ($detect_lost, $scan_conn, $app_level) {
        $detect_lost->invokeArgs($scan_conn, [$app_level]);
    });
runBenchmark("full in-flight walk (reference)",
    function () use ($full_walk, $scan_conn) {
        $full_walk->invoke($scan_conn);
    });
