<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Benchmarks for the stream send-buffer chunking and the flush loop:
 * QuicStream::takeForFrame, which hands out one frame-sized chunk of
 * a stream's send buffer at a time, and QuicConnection::flushStreams,
 * which drains a whole response out of its streams into STREAM frames
 * queued for emit. These are the methods the bottlenecks note ties to
 * the per-response chunking cost.
 *
 * takeForFrame is timed two ways: one chunk on its own, and a full
 * drain of a 1 MiB response in ~1100-byte frames. The full drain is
 * the one that matters for the note's history here, since its send
 * buffer used to shift on every drained frame, making a single 1 MiB
 * response O(n^2); the buffer now advances an offset instead, so this
 * measures whether the drain is back to linear. flushStreams is timed
 * draining the same 1 MiB response in one call.
 *
 * The connection is built the way the http3 tests build one: through
 * ReflectionClass without the constructor, with only the fields the
 * method reads set (its application keys and its stream map). That
 * keeps the set-up to what flushStreams actually touches and needs no
 * certificate. No socket is opened.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_flush.php
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
 * @var int size of the response drained through the stream, in
 *      bytes, the 1 MiB /big transfer the note measured
 */
const FLUSH_RESPONSE_BYTES = 1048576;
/**
 * @var int stream identifier for the request stream carrying the
 *      response
 */
const FLUSH_STREAM_ID = 0;
/**
 * @var int Destination Connection ID length used to derive the
 *      application keys placed on the connection
 */
const FLUSH_DCID_BYTES = 8;
/**
 * @var int timed iterations for the whole-response drain and flush;
 *      smaller than the default because each iteration already makes
 *      roughly a thousand takeForFrame calls
 */
const FLUSH_HEAVY_ITERATIONS = 300;

/**
 * Builds a QuicConnection with only the state flushStreams reads,
 * skipping the real constructor the way the http3 tests do.
 *
 * @param array $keys application-level packet keys, which flushStreams
 *      checks are present before draining
 * @param QuicStream $stream the one request stream to drain
 * @return QuicConnection connection ready for a flushStreams call
 */
function buildFlushConnection($keys, $stream)
{
    $reflection = new \ReflectionClass(QuicConnection::class);
    $conn = $reflection->newInstanceWithoutConstructor();
    $conn->keys = [QuicConnection::LEVEL_APPLICATION => $keys];
    $conn->streams = [$stream->id => $stream];
    return $conn;
}

$response = random_bytes(FLUSH_RESPONSE_BYTES);
$chunk_bytes = QuicConnection::MAX_STREAM_FRAME_BYTES;
$frames_per_response = (int) ceil(
    FLUSH_RESPONSE_BYTES / $chunk_bytes);
$keys = QuicPacketKeys::fromInitialDcid(
    random_bytes(FLUSH_DCID_BYTES))['server'];

$single_stream = new QuicStream(FLUSH_STREAM_ID, FLUSH_RESPONSE_BYTES,
    FLUSH_RESPONSE_BYTES);
$single_stream->send_buf = $response;

$drain_stream = new QuicStream(FLUSH_STREAM_ID, FLUSH_RESPONSE_BYTES,
    FLUSH_RESPONSE_BYTES);

$flush_stream = new QuicStream(FLUSH_STREAM_ID, FLUSH_RESPONSE_BYTES,
    FLUSH_RESPONSE_BYTES);
$flush_conn = buildFlushConnection($keys, $flush_stream);

/*
    Confirm the stream yields a chunk and the flush queues frames
    before timing, so the benchmarks measure the working paths.
 */
if ($single_stream->takeForFrame($chunk_bytes) === null) {
    fwrite(STDERR, "takeForFrame yielded nothing; aborting\n");
    exit(1);
}
$single_stream->send_buf_off = 0;
$single_stream->send_next_offset = 0;
$flush_stream->send_buf = $response;
$flush_conn->flushStreams(FLUSH_RESPONSE_BYTES);
if (count($flush_conn->send_queue) < 1) {
    fwrite(STDERR, "flushStreams queued nothing; aborting\n");
    exit(1);
}

echo "stream chunking and flush loop, " .
    FLUSH_RESPONSE_BYTES . "-byte response in " .
    $chunk_bytes . "-byte frames\n";
benchHeader();
runBenchmark("(empty-closure overhead)", function () {
});
runBenchmark("QuicStream::takeForFrame (one chunk)",
    function () use ($single_stream, $chunk_bytes) {
        $single_stream->send_buf_off = 0;
        $single_stream->send_next_offset = 0;
        $single_stream->takeForFrame($chunk_bytes);
    });
$drain_median = runBenchmark("QuicStream drain 1 MiB (full)",
    function () use ($drain_stream, $response, $chunk_bytes) {
        $drain_stream->send_buf = $response;
        $drain_stream->send_buf_off = 0;
        $drain_stream->send_next_offset = 0;
        while ($drain_stream->takeForFrame($chunk_bytes) !== null) {
        }
    }, FLUSH_HEAVY_ITERATIONS);
printf("    %d frames per drain; %.3f us/frame\n",
    $frames_per_response,
    $drain_median / $frames_per_response / BENCH_NS_PER_US);
$flush_median = runBenchmark("QuicConnection::flushStreams 1 MiB",
    function () use ($flush_conn, $flush_stream, $response) {
        $flush_stream->send_buf = $response;
        $flush_stream->send_buf_off = 0;
        $flush_stream->send_next_offset = 0;
        $flush_conn->conn_data_sent = 0;
        $flush_conn->send_queue = [];
        $flush_conn->flushStreams(FLUSH_RESPONSE_BYTES);
    }, FLUSH_HEAVY_ITERATIONS);
printf("    %d frames per flush; %.3f us/frame\n",
    $frames_per_response,
    $flush_median / $frames_per_response / BENCH_NS_PER_US);
