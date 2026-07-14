<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Ties the per-method H3 hotpath timings to real request shapes.
 * The other bench_ scripts measure how long one call to each hotpath
 * method takes; this one measures how many times each of those
 * methods runs while the pure-PHP H3 listener handles each case of
 * the example-21 HTTP benchmark, and multiplies the two. The result,
 * per method and per case, is an estimate of how much of that case's
 * server-side time that one method accounts for.
 *
 * The case shapes are taken from example 21's index.php: a two-byte
 * /small body, a 1 MiB /big body, the same 1 MiB streamed as /stream,
 * a ~200-byte /asset body, a /headers response of a hundred header
 * fields, a keep-alive repeat of /small, a 64 KiB POST echo, and a
 * small /defer body. Each is counted for one representative request,
 * matching how the runner reports a per-request median, so the
 * product here lines up with that median.
 *
 * How the counts are gathered. The response is turned into real
 * HTTP/3 bytes (a QPACK-encoded HEADERS frame and a DATA frame) and
 * driven out through the connection's real flush-and-emit loop, one
 * flush budget per pass the way the event loop paces it, so the seal,
 * header-protection, take-for-frame, flush, and emit counts are the
 * real ones for that many bytes. On the send side header protection
 * is now one batched headerProtectionMasks call per emit rather than
 * one mask per packet; the per-packet headerProtectionMask count is
 * the receive side, one per inbound packet decoded. The request and
 * the client's acknowledgements are driven back in as real short
 * packets decoded with the matching keys, so the open,
 * header-protection, and process-ack counts are real too. The
 * counting comes from the shared subclasses in counting.php, which
 * override the object methods; the few methods the code calls
 * statically (encodeShortSealed, decodeShort, QuicFrame::encode,
 * encodeStream, decodeAll) cannot be overridden, so their counts are
 * derived from the counted ones by the one-to-one relationships the
 * code makes plain: one encodeShortSealed per sealed packet, one
 * decodeShort and one frame decode per received packet, one
 * encodeStream per stream chunk framed.
 *
 * The single-call microsecond figures are read from the other bench_
 * scripts' own output, so the timings multiplied here are exactly the
 * ones those scripts report, measured on this machine.
 *
 * How the tables read. The methods are printed as a call tree rather
 * than a flat list, because several of them invoke others in the
 * list: emit seals through encodeShortSealed, which calls seal;
 * decodeShort opens and header-protects; and QuicFrame::encode's
 * switch dispatches to encodeStream. An indented row is called by the
 * row above it, so its time is part of that row's; only the
 * un-indented rows are free of overlap, and those are the ones the
 * total sums.
 *
 * These are benchmarks, not the pass/fail tests: they are timed and
 * estimated rather than asserted, and live under the bench_ name the
 * test runner skips.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_workload.php
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
    public function __construct(...$arguments) {}
    public function close() {}
}
abstract class Transport
{
    public function __construct($site) {}
}

require __DIR__ . '/../../src/H3Listener.php';
require __DIR__ . '/measure.php';
require __DIR__ . '/counting.php';

/**
 * @var int connection-id length used for the keys and headers here
 */
const WL_DCID_BYTES = 8;
/**
 * @var int acknowledgements arrive for every this-many response
 *      packets, the usual delayed-acknowledgement cadence, so the
 *      inbound ACK-packet count is the response packet count divided
 *      by this
 */
const WL_ACK_EVERY = 2;
/**
 * @var int how many times each case is driven, whose per-method
 *      counts are averaged; the counts are near-deterministic, so a
 *      few passes are enough to absorb any rounding at flush edges
 */
const WL_RUNS = 3;

/**
 * Builds a counting connection in the established state carrying one
 * counting stream, with counting transmit keys, skipping the real
 * constructor the way the other benchmarks do.
 *
 * @param CountingQuicPacketKeys $tx_keys transmit keys to seal with
 * @param CountingQuicStream $stream the response stream to attach
 * @return CountingQuicConnection the connection ready to drive
 */
function buildWorkloadConnection($tx_keys, $stream)
{
    $app = QuicConnection::LEVEL_APPLICATION;
    $initial = QuicConnection::LEVEL_INITIAL;
    $handshake = QuicConnection::LEVEL_HANDSHAKE;
    $reflection = new \ReflectionClass(CountingQuicConnection::class);
    $conn = $reflection->newInstanceWithoutConstructor();
    $conn->state = QuicConnection::ST_ESTABLISHED;
    $conn->handshake_done_sent = true;
    $conn->new_cids_pending = [];
    $conn->path_responses_pending = [];
    $conn->ack_pending = [$initial => false, $handshake => false,
        $app => false];
    $conn->keys = [$app => ['tx' => $tx_keys]];
    $conn->congestion_window = PHP_INT_MAX;
    $conn->bytes_in_flight = 0;
    $conn->next_pn = [$initial => 0, $handshake => 0, $app => 0];
    $conn->peer_cid = random_bytes(WL_DCID_BYTES);
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
 * Turns a set of header fields and a body into the HTTP/3 response
 * bytes a stream would carry: a QPACK-encoded HEADERS frame followed
 * by a DATA frame. Using the real encoders makes the response size,
 * and so the packet count, the real one for that response.
 *
 * @param array $header_pairs list of [name, value] header fields
 * @param string $body the response body
 * @return string the HTTP/3 frames for the response
 */
function buildResponseBytes($header_pairs, $body)
{
    $headers_block = Qpack::encode($header_pairs);
    $out = H3FrameCodec::encode(H3FrameCodec::H3_HEADERS,
        $headers_block);
    if ($body !== '') {
        $out .= H3FrameCodec::encode(H3FrameCodec::H3_DATA, $body);
    }
    return $out;
}

/**
 * Seals one short packet with the given keys and a set destination
 * connection id, then decodes it back with the matching keys, which
 * runs the real open and header-protection on the receive side. Used
 * to drive inbound request and acknowledgement packets so their
 * receive-side calls are counted for real.
 *
 * @param QuicPacketKeys $seal_keys the sender's keys
 * @param CountingQuicPacketKeys $open_keys the receiver's counting
 *      keys, sharing the same secret
 * @param string $dcid the destination connection id to carry
 * @param int $packet_number the packet's number
 * @param string $payload the frames the packet carries
 * @return bool true if the packet decoded, false otherwise
 */
function driveInboundPacket($seal_keys, $open_keys, $dcid,
    $packet_number, $payload)
{
    $packet = new QuicPacket();
    $packet->destination_cid = $dcid;
    $wire = $packet->encodeShort($seal_keys, $packet_number,
        $payload);
    if ($wire === false) {
        return false;
    }
    $result = QuicPacket::decodeShort($wire, 0, $open_keys,
        strlen($dcid), $packet_number - 1);
    return is_array($result) && $result[0] !== false;
}

/**
 * Drives one case end to end and returns the real per-method call
 * counts for it. The response goes out through the paced flush-emit
 * loop; the request and the client's acknowledgements come back in as
 * decoded short packets; the acknowledgements are fed to processAck
 * in the usual delayed cadence so the loss-timer and lost-packet
 * scans run as they would in service.
 *
 * @param array $response_pairs the response header fields
 * @param string $response_body the response body
 * @param array $request_pairs the request header fields
 * @param string $request_body the request body (empty for a GET)
 * @return array method label => number of calls for this case
 */
function driveCase($response_pairs, $response_body, $request_pairs,
    $request_body)
{
    $app = QuicConnection::LEVEL_APPLICATION;
    $dcid = random_bytes(WL_DCID_BYTES);
    $key_pair = QuicPacketKeys::fromInitialDcid($dcid);
    $tx_keys = countingKeysFrom($key_pair['server']);
    $rx_keys = countingKeysFrom($key_pair['client']);
    $response = buildResponseBytes($response_pairs, $response_body);
    $stream = new CountingQuicStream(0, strlen($response),
        strlen($response));
    $conn = buildWorkloadConnection($tx_keys, $stream);
    $stream->send_buf = $response;

    CallCounts::reset();

    /*
        Send the response the way the event loop paces it: one flush
        budget of bytes per pass, emitting after each, until the
        stream is drained. This makes the flush and emit counts the
        real per-response ones rather than a single whole-body call.
     */
    $budget = QuicConnection::DEFAULT_FLUSH_BUDGET;
    do {
        $more = $conn->flushStreams($budget);
        $conn->emit();
    } while ($more);
    $response_packets = count($conn->sent_packets[$app]);

    /*
        Bring the request in as decoded short packets: a QPACK
        HEADERS frame, plus the body split across packets for a POST.
        Then hand the in-order bytes up once, as a served request
        does.
     */
    $request = buildResponseBytes($request_pairs, $request_body);
    $frame_limit = QuicConnection::MAX_STREAM_FRAME_BYTES;
    $request_packets = (int) max(1,
        ceil(strlen($request) / $frame_limit));
    for ($i = 0; $i < $request_packets; $i++) {
        driveInboundPacket($key_pair['client'], $rx_keys, $dcid, $i,
            chr(QuicFrame::F_PING));
    }
    $recv_stream = new CountingQuicStream(0);
    $recv_stream->deliverIncoming(0, $request, true);
    $recv_stream->consume();

    /*
        Bring the client's acknowledgements in at the usual delayed
        cadence, one ACK packet per WL_ACK_EVERY response packets.
        Each is a real decoded short packet, and each is fed to
        processAck against the response still in flight, so the
        loss-timer arm and lost-packet scan run per acknowledgement.
     */
    $ack_packets = (int) max(0,
        ceil($response_packets / WL_ACK_EVERY));
    $largest = $response_packets - 1;
    for ($i = 0; $i < $ack_packets; $i++) {
        driveInboundPacket($key_pair['client'], $rx_keys, $dcid,
            1000 + $i, chr(QuicFrame::F_PING));
        $covered = min($largest,
            ($i + 1) * WL_ACK_EVERY - 1);
        $ack_frame = [
            'type' => QuicFrame::F_ACK,
            'largest' => $covered,
            'delay' => 0,
            'first_range' => $covered,
            'ranges' => [],
        ];
        $conn->processAck($app, $ack_frame);
    }

    $counts = CallCounts::all();
    $counts['response_packets'] = $response_packets;
    $counts['inbound_packets'] = $request_packets + $ack_packets;
    return $counts;
}

/**
 * Averages the per-method counts of several drives of one case.
 *
 * @param array $response_pairs the response header fields
 * @param string $response_body the response body
 * @param array $request_pairs the request header fields
 * @param string $request_body the request body
 * @return array method label => average call count for the case
 */
function averageCase($response_pairs, $response_body, $request_pairs,
    $request_body)
{
    $totals = [];
    for ($run = 0; $run < WL_RUNS; $run++) {
        $counts = driveCase($response_pairs, $response_body,
            $request_pairs, $request_body);
        foreach ($counts as $label => $value) {
            if (!isset($totals[$label])) {
                $totals[$label] = 0;
            }
            $totals[$label] += $value;
        }
    }
    $average = [];
    foreach ($totals as $label => $sum) {
        $average[$label] = $sum / WL_RUNS;
    }
    return $average;
}

/**
 * Reads the single-call microsecond figures the other bench_ scripts
 * print, so the numbers multiplied here are exactly the ones those
 * scripts report on this machine. Each row those scripts print is two
 * spaces, a method label, its microseconds per call, then its calls
 * per second; this pulls the label and the microseconds back out.
 *
 * @return array method label => microseconds per single call
 */
function readSingleCallMicros()
{
    $scripts = ['bench_aead.php', 'bench_codec.php', 'bench_emit.php',
        'bench_flush.php'];
    $micros = [];
    foreach ($scripts as $script) {
        fwrite(STDERR, "    " . $script . "...\n");
        $path = __DIR__ . '/' . $script;
        $lines = [];
        exec('php ' . escapeshellarg($path), $lines);
        foreach ($lines as $line) {
            if (!preg_match('/^  (\S.*?)\s{2,}([0-9.]+)\s{2,}[0-9,]+$/',
                    $line, $match)) {
                continue;
            }
            $micros[trim($match[1])] = (float) $match[2];
        }
    }
    return $micros;
}

/**
 * The example-21 cases, each with the response and request shapes
 * index.php gives it. Sizes match that file: /small is two bytes,
 * /big and /stream are a mebibyte, /asset is about two hundred
 * bytes, /headers carries a hundred header fields, keepalive repeats
 * /small, /echo-post round-trips a 64 KiB body, and /defer is small.
 *
 * @return array list of case descriptions
 */
function buildCases()
{
    $mib = str_repeat("X", 1048576);
    $octet = 'application/octet-stream';
    $header_fields = [[':status', '200']];
    for ($i = 0; $i < 100; $i++) {
        $header_fields[] = ["x-bench-header-{$i}", "value-{$i}"];
    }
    $header_fields[] = ['content-type', 'text/plain'];
    return [
        ['key' => 'small', 'label' => '/small 2 B',
            'res' => [[':status', '200'],
                ['content-type', 'text/plain']],
            'body' => 'ok', 'req' => [[':method', 'GET'],
                [':path', '/small']], 'req_body' => ''],
        ['key' => 'big', 'label' => '/big 1 MiB',
            'res' => [[':status', '200'],
                ['content-type', $octet],
                ['content-length', '1048576']],
            'body' => $mib, 'req' => [[':method', 'GET'],
                [':path', '/big']], 'req_body' => ''],
        ['key' => 'stream', 'label' => '/stream 1 MiB',
            'res' => [[':status', '200'],
                ['content-type', $octet],
                ['content-length', '1048576']],
            'body' => $mib, 'req' => [[':method', 'GET'],
                [':path', '/stream']], 'req_body' => ''],
        ['key' => 'asset', 'label' => '/asset ~200 B',
            'res' => [[':status', '200'],
                ['content-type', 'text/plain']],
            'body' => 'asset 1: ' . str_repeat('a', 200),
            'req' => [[':method', 'GET'],
                [':path', '/asset/1']], 'req_body' => ''],
        ['key' => 'headers', 'label' => '/headers 100',
            'res' => $header_fields, 'body' => 'headers',
            'req' => [[':method', 'GET'],
                [':path', '/headers']], 'req_body' => ''],
        ['key' => 'keepA', 'label' => 'keepalive /small',
            'res' => [[':status', '200'],
                ['content-type', 'text/plain']],
            'body' => 'ok', 'req' => [[':method', 'GET'],
                [':path', '/small']], 'req_body' => ''],
        ['key' => 'post', 'label' => 'POST 64 KiB',
            'res' => [[':status', '200'],
                ['content-type', $octet],
                ['content-length', '65536']],
            'body' => str_repeat('x', 65536),
            'req' => [[':method', 'POST'],
                [':path', '/echo-post']],
            'req_body' => str_repeat('x', 65536)],
        ['key' => 'defer', 'label' => '/defer small',
            'res' => [[':status', '200'],
                ['content-type', 'text/plain']],
            'body' => 'deferred response body',
            'req' => [[':method', 'GET'],
                [':path', '/defer']], 'req_body' => ''],
    ];
}

/**
 * @var int width of the first column, wide enough for the deepest
 *      indented label in WL_CALL_TREE
 */
const WL_LABEL_WIDTH = 48;
/**
 * @var array the call tree the count and estimate tables print, in
 *      the order the rows appear. Each node is:
 *        label   what to print. For a timed row this is the label the
 *                bench_ script prints, so its single-call
 *                microseconds can be looked up by it; for a subtotal
 *                row it is just the method name.
 *        key     the counts key holding this row's per-case call
 *                count
 *        depth   0 for a row that nothing else in the tree calls;
 *                deeper for a row its parent invokes, so the row's
 *                time is part of its parent's
 *        derived true when the count is taken one-to-one from a
 *                counted method because this one is called
 *                statically and so cannot be counted by subclassing
 *        timed   true when the bench_ scripts report a per-call cost,
 *                so cost times count is a meaningful estimate. False
 *                for a row whose only benchmarked figure is a whole
 *                1 MiB response: multiplying that by a paced call
 *                count would double count, so the row's estimate is
 *                the sum of the rows beneath it instead, which leaves
 *                out the row's own loop overhead.
 *      Depth-0 rows do not overlap, so their estimates add up to the
 *      case total. setLossDetectionTimer and decodeAll sit at depth 0
 *      rather than under emit because emit, processAck, and
 *      queuePacket all call them, and nesting them under one caller
 *      would attribute the other callers' time to it.
 */
const WL_CALL_TREE = [
    ['label' => 'QuicConnection::flushStreams',
        'key' => 'QuicConnection::flushStreams', 'depth' => 0,
        'derived' => false, 'timed' => false],
    ['label' => 'QuicStream::takeForFrame (one chunk)',
        'key' => 'QuicStream::takeForFrame', 'depth' => 1,
        'derived' => false, 'timed' => true],
    ['label' => 'QuicFrame::encode (STREAM, switch)',
        'key' => 'response_packets', 'depth' => 1,
        'derived' => true, 'timed' => true],
    ['label' => 'QuicFrame::encodeStream (no switch)',
        'key' => 'response_packets', 'depth' => 2,
        'derived' => true, 'timed' => true],
    ['label' => 'QuicConnection::emit', 'key' => 'QuicConnection::emit',
        'depth' => 0, 'derived' => false, 'timed' => false],
    ['label' => 'QuicPacket::encodeShortSealed',
        'key' => 'QuicPacketKeys::seal', 'depth' => 1,
        'derived' => true, 'timed' => true],
    ['label' => 'QuicPacketKeys::seal', 'key' => 'QuicPacketKeys::seal',
        'depth' => 2, 'derived' => false, 'timed' => true],
    ['label' => 'QuicPacketKeys::headerProtectionMasks (batch)',
        'key' => 'QuicPacketKeys::headerProtectionMasks', 'depth' => 1,
        'derived' => false, 'timed' => true],
    ['label' => 'QuicPacket::decodeShort', 'key' => 'inbound_packets',
        'depth' => 0, 'derived' => true, 'timed' => true],
    ['label' => 'QuicPacketKeys::headerProtectionMask',
        'key' => 'QuicPacketKeys::headerProtectionMask', 'depth' => 1,
        'derived' => false, 'timed' => true],
    ['label' => 'QuicPacketKeys::open', 'key' => 'QuicPacketKeys::open',
        'depth' => 1, 'derived' => false, 'timed' => true],
    ['label' => 'QuicFrame::decodeAll (ACK + PING)',
        'key' => 'inbound_packets', 'depth' => 0,
        'derived' => true, 'timed' => true],
    ['label' => 'setLossDetectionTimer (cached)',
        'key' => 'setLossDetectionTimer', 'depth' => 0,
        'derived' => false, 'timed' => true],
];
/**
 * @var array the whole-operation rows: [bench label, counts key].
 *      Their benchmarked cost is for an entire mebibyte response or a
 *      950-packet acknowledgement, so it is already the sum of the
 *      primitives above for that size. Multiplying it by the paced
 *      per-case call count would double count, so only the call count
 *      is reported for these.
 */
const WL_WHOLE_ROWS = [
    ['QuicConnection::emit 1 MiB (seal loop)', 'QuicConnection::emit'],
    ['QuicConnection::flushStreams 1 MiB',
        'QuicConnection::flushStreams'],
    ['QuicStream drain 1 MiB (full)', 'QuicStream::consume'],
    ['QuicConnection::processAck (950 acked)',
        'QuicConnection::processAck'],
    ['setLossDetectionTimer (cold walk, 950)',
        'setLossDetectionTimer'],
    ['detectAndRemoveLostPackets (break)',
        'detectAndRemoveLostPackets'],
];

/**
 * Returns the call count for a counts key in one case's averaged
 * counts, or zero if the case never invoked it.
 *
 * @param array $counts one case's averaged counts
 * @param string $key the counts key to read
 * @return float the call count, or zero
 */
function caseCount($counts, $key)
{
    return isset($counts[$key]) ? $counts[$key] : 0.0;
}

/**
 * Returns the printable first-column text for a tree node: indented
 * by its depth, and marked with a plus when its count is derived.
 *
 * @param array $node one WL_CALL_TREE node
 * @return string the label to print
 */
function treeLabel($node)
{
    return str_repeat('  ', $node['depth']) . $node['label']
        . ($node['derived'] ? ' +' : '');
}

/**
 * Returns the positions of a node's direct children: the rows below
 * it that sit exactly one level deeper, stopping at the next row at
 * the node's own level or shallower. Grandchildren are left out
 * because their time is already inside a child's.
 *
 * @param array $tree the whole call tree
 * @param int $index the position of the parent node
 * @return array list of positions of the direct children
 */
function childIndexes($tree, $index)
{
    $depth = $tree[$index]['depth'];
    $children = [];
    $total = count($tree);
    for ($i = $index + 1; $i < $total; $i++) {
        if ($tree[$i]['depth'] <= $depth) {
            break;
        }
        if ($tree[$i]['depth'] === $depth + 1) {
            $children[] = $i;
        }
    }
    return $children;
}

/**
 * Estimates the microseconds one case spends in each tree row. A
 * timed row is its single-call cost times its call count for the
 * case; a row with no per-call cost is the sum of its direct
 * children, which leaves out that row's own loop overhead. Walks
 * from the bottom up so a parent's children are already estimated
 * when it is reached.
 *
 * @param array $tree the call tree
 * @param array $counts one case's averaged call counts
 * @param array $micros bench label => microseconds per single call
 * @return array tree position => estimated microseconds
 */
function treeEstimates($tree, $counts, $micros)
{
    $estimates = [];
    for ($i = count($tree) - 1; $i >= 0; $i--) {
        $node = $tree[$i];
        if ($node['timed']) {
            $us = isset($micros[$node['label']])
                ? $micros[$node['label']] : 0.0;
            $estimates[$i] = $us * caseCount($counts, $node['key']);
            continue;
        }
        $sum = 0.0;
        foreach (childIndexes($tree, $i) as $child) {
            $sum += $estimates[$child];
        }
        $estimates[$i] = $sum;
    }
    return $estimates;
}

/**
 * Prints a header row of case labels for a table whose first column
 * is a method name.
 *
 * @param array $cases the case list
 * @param string $first the first column's heading
 */
function printCaseHeader($cases, $first)
{
    printf("  %-" . WL_LABEL_WIDTH . "s", $first);
    foreach ($cases as $case) {
        printf(" %9s", $case['key']);
    }
    echo "\n";
    printf("  %-" . WL_LABEL_WIDTH . "s",
        str_repeat('-', WL_LABEL_WIDTH));
    foreach ($cases as $case) {
        printf(" %9s", str_repeat('-', 9));
    }
    echo "\n";
}

$cases = buildCases();
$counts_by_case = [];
fwrite(STDERR, "counting per-case call counts " .
    "(AES-128-GCM Initial keys)...\n");
foreach ($cases as $case) {
    fwrite(STDERR, "  case " . $case['key'] . " (" .
        $case['label'] . ")...\n");
    $counts_by_case[$case['key']] = averageCase($case['res'],
        $case['body'], $case['req'], $case['req_body']);
}
fwrite(STDERR, "timing single calls: running the micro-benchmarks " .
    "(this is the slow part)...\n");
$micros = readSingleCallMicros();
fwrite(STDERR, "done; writing tables.\n");

echo "note: driven with AES-128-GCM Initial keys, so the seal, open,\n" .
    "and header-protection rows are the OpenSSL AES-128 path; the\n" .
    "AES-256-GCM (sodium) path is a different suite and is measured\n" .
    "separately in bench_aead.php.\n\n";
echo "example-21 cases: response packets and inbound packets\n";
printCaseHeader($cases, 'quantity');
foreach (['response_packets', 'inbound_packets'] as $quantity) {
    printf("  %-" . WL_LABEL_WIDTH . "s", $quantity);
    foreach ($cases as $case) {
        printf(" %9s", number_format(
            caseCount($counts_by_case[$case['key']], $quantity)));
    }
    echo "\n";
}

echo "\nper-primitive call counts per case\n";
printCaseHeader($cases, 'method (+ = derived count)');
foreach (WL_CALL_TREE as $node) {
    printf("  %-" . WL_LABEL_WIDTH . "s", treeLabel($node));
    foreach ($cases as $case) {
        printf(" %9s", number_format(
            caseCount($counts_by_case[$case['key']],
                $node['key'])));
    }
    echo "\n";
}

echo "\nestimated microseconds per case " .
    "(single-call us times call count)\n";
printCaseHeader($cases, 'method');
$estimates_by_case = [];
foreach ($cases as $case) {
    $estimates_by_case[$case['key']] = treeEstimates(WL_CALL_TREE,
        $counts_by_case[$case['key']], $micros);
}
foreach (WL_CALL_TREE as $index => $node) {
    printf("  %-" . WL_LABEL_WIDTH . "s", treeLabel($node));
    foreach ($cases as $case) {
        printf(" %9.1f", $estimates_by_case[$case['key']][$index]);
    }
    echo "\n";
}
printf("  %-" . WL_LABEL_WIDTH . "s", 'total (un-indented rows)');
foreach ($cases as $case) {
    $total = 0.0;
    foreach (WL_CALL_TREE as $index => $node) {
        if ($node['depth'] === 0) {
            $total += $estimates_by_case[$case['key']][$index];
        }
    }
    printf(" %9.1f", $total);
}
echo "\n";

echo "\nreading the tree: an indented row is called by the row above " .
    "it, and\nits time is part of that row's, so only the un-indented " .
    "rows add up.\nA row with no time of its own listed " .
    "(flushStreams, emit) has only a\nwhole-1-MiB benchmark, which " .
    "cannot be multiplied by a paced call\ncount without double " .
    "counting; its figure is the sum of the rows\nbeneath it, so it " .
    "leaves out its own loop overhead and is a floor.\n" .
    "setLossDetectionTimer and decodeAll are un-indented because emit,\n" .
    "processAck, and queuePacket all call them, so nesting them under " .
    "one\ncaller would charge that caller for the others' calls.\n";
echo "\nwhole-operation call counts per case (not multiplied; " .
    "their\ntimed cost is a whole-1-MiB / 950-acked figure that " .
    "already\nsums the primitives above)\n";
printCaseHeader($cases, 'method');
foreach (WL_WHOLE_ROWS as $row) {
    list($label, $key) = $row;
    printf("  %-" . WL_LABEL_WIDTH . "s", $label);
    foreach ($cases as $case) {
        printf(" %9s", number_format(
            caseCount($counts_by_case[$case['key']], $key)));
    }
    echo "\n";
}
echo "\n+ derived count: taken one-to-one from a counted method " .
    "because\nthe method itself is called statically and cannot be " .
    "counted by\nsubclassing (encodeShortSealed per sealed packet, " .
    "decodeShort and\nframe decode per received packet, encodeStream " .
    "per framed chunk).\n";
