<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for QuicConnection::processAck and the surrounding
 * sent-packet bookkeeping. Covers single-range ACKs, gapped
 * ACKs, multi-range ACKs, ACKs that name unknown packet
 * numbers, and the RFC 9002 sec 5.1 rule that latest_rtt is
 * only updated when the largest ACKed packet was ack-eliciting.
 *
 * Run from the repo root:
 *     php tests/http3/test_ack_processing.php
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
    Stub the parent classes that H3NativeListener.php's classes
    extend. WebSite.php normally provides these; loading it just
    to run the unit tests would drag in the whole framework.
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

require __DIR__ . '/../../src/H3NativeListener.php';

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
    Helper to add a fake sent-packet entry. processAck only
    reads pn / time_sent / ack_eliciting from the entry, so we
    leave in_flight / sent_bytes / frames as no-op fillers --
    those fields are exercised by the congestion-accounting
    and retransmission test files.
 */
function addSent($conn, $level, $pn, $ack_eliciting, $time_sent)
{
    $conn->sent_packets[$level][$pn] = [
        'pn' => $pn,
        'time_sent' => $time_sent,
        'ack_eliciting' => $ack_eliciting,
        'in_flight' => true,
        'sent_bytes' => 50,
        'frames' => [],
    ];
}

/*
    Build a fresh QuicConnection without invoking the real
    constructor. Each test gets its own instance so RTT
    samples and largest_acked_pn from one case can't leak
    into the next and trigger spurious loss declarations.
 */
function makeConn()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
    $conn = $rc->newInstanceWithoutConstructor();
    $conn->sent_packets = [
        QuicConnection::LEVEL_INITIAL => [],
        QuicConnection::LEVEL_HANDSHAKE => [],
        QuicConnection::LEVEL_APPLICATION => [],
    ];
    $conn->loss_time = [
        QuicConnection::LEVEL_INITIAL => null,
        QuicConnection::LEVEL_HANDSHAKE => null,
        QuicConnection::LEVEL_APPLICATION => null,
    ];
    $conn->largest_acked_pn = [
        QuicConnection::LEVEL_INITIAL => -1,
        QuicConnection::LEVEL_HANDSHAKE => -1,
        QuicConnection::LEVEL_APPLICATION => -1,
    ];
    $conn->latest_rtt = null;
    $conn->smoothed_rtt = null;
    $conn->rttvar = null;
    $conn->min_rtt = null;
    $conn->pto_count = 0;
    $conn->loss_detection_timer = null;
    return $conn;
}

function callProcessAck($conn, $level, $frame)
{
    $rm = new \ReflectionMethod(
        'seekquarry\\atto\\QuicConnection', 'processAck');
    return $rm->invokeArgs($conn, [$level, $frame]);
}

$L = QuicConnection::LEVEL_APPLICATION;

/* Test 1: simple ACK, single range, removes packets. */
$conn = makeConn();
$now = microtime(true);
addSent($conn, $L, 0, true, $now - 0.010);
addSent($conn, $L, 1, true, $now - 0.009);
addSent($conn, $L, 2, true, $now - 0.008);
$frame = [
    'type' => 0x02,
    'largest' => 2,
    'delay' => 0,
    'first_range' => 2,
    'ranges' => [],
];
callProcessAck($conn, $L, $frame);
ok("simple ACK removes all 3 packets",
    count($conn->sent_packets[$L]) === 0);
ok("latest_rtt is recorded",
    $conn->latest_rtt !== null
        && $conn->latest_rtt > 0.005
        && $conn->latest_rtt < 0.020);

/*
    Test 2: ACK with gap. ACK frame says largest=3 with
    first_range=1 (covers 2-3), then one (gap=0, ack_len=0)
    range that skips pn 1 and acks pn 0. Result: 0,2,3 removed,
    1 still in flight. Sub-millisecond age differences keep
    everything well under any plausible loss-time threshold so
    only the ACK ranges drive removal.
 */
$conn = makeConn();
$now = microtime(true);
addSent($conn, $L, 0, true, $now - 0.0004);
addSent($conn, $L, 1, true, $now - 0.0003);
addSent($conn, $L, 2, true, $now - 0.0002);
addSent($conn, $L, 3, true, $now - 0.0001);
$frame = [
    'type' => 0x02,
    'largest' => 3,
    'delay' => 0,
    'first_range' => 1,
    'ranges' => [[0, 0]],
];
callProcessAck($conn, $L, $frame);
ok("gapped ACK removes pn 0,2,3",
    !isset($conn->sent_packets[$L][0]) &&
    !isset($conn->sent_packets[$L][2]) &&
    !isset($conn->sent_packets[$L][3]));
ok("gapped ACK leaves pn 1",
    isset($conn->sent_packets[$L][1]));

/* Test 3: ACK of unknown PN is harmless. */
$conn = makeConn();
$now = microtime(true);
addSent($conn, $L, 0, true, $now);
$frame = [
    'type' => 0x02,
    'largest' => 99,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [],
];
callProcessAck($conn, $L, $frame);
ok("ACK of unknown PN does not crash",
    count($conn->sent_packets[$L]) === 1);

/*
    Test 4: latest_rtt is only updated when the largest acked
    packet was ack-eliciting (RFC 9002 sec 5.1). Here pn 5 is
    flagged ack_eliciting=false, so even though it's the
    largest acked, it must not produce an RTT sample.
 */
$conn = makeConn();
$now = microtime(true);
addSent($conn, $L, 5, false, $now - 0.020);
addSent($conn, $L, 6, true, $now - 0.015);
$frame = [
    'type' => 0x02,
    'largest' => 5,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [],
];
callProcessAck($conn, $L, $frame);
ok("non-eliciting largest does not update latest_rtt",
    $conn->latest_rtt === null);

/*
    Test 5: large multi-range ACK. Wire-format layout:
        largest=19, first_range=0    → only pn 19
        [gap=1, ack_len=2]           → skip 17-18, ack 14-16
        [gap=2, ack_len=5]           → skip 11-13, ack 5-10
    Expected: 19, 14-16, 5-10 removed by the ACK ranges.
    Phase 11c will additionally declare 0-4 lost via the
    reordering threshold (largest_acked - pn >= 3) and 11-13,
    17-18 likewise once the time threshold kicks in. To
    isolate ACK-range parsing from loss detection, this test
    keeps every packet's time_sent very recent (< 1 ms ago)
    so the time threshold can't fire, and treats packets
    0-4 as "expected lost" rather than "expected kept" --
    they fall to the reordering threshold, which is the
    correct RFC 9002 behaviour we want to exercise.
 */
$conn = makeConn();
$now = microtime(true);
for ($i = 0; $i < 20; $i++) {
    /* All sent within the last 1ms so the time threshold
       cannot fire even with whatever RTT sample test 5
       happens to produce. */
    addSent($conn, $L, $i, true,
        $now - 0.0005 + 0.00001 * $i);
}
$frame = [
    'type' => 0x02,
    'largest' => 19,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [[1, 2], [2, 5]],
];
callProcessAck($conn, $L, $frame);
/*
    Removed by ACK ranges: 19, 14-16, 5-10.
    Removed by reordering threshold: 0-4 (largest_acked - pn
    >= 3 means pn 0-16 qualify, but 5-10 and 14-16 are
    already ACKed; that leaves 0-4 and 11-13).
    Kept: 17, 18 (delta 1, 2 -- below threshold).
 */
$expected_acked = [19, 14, 15, 16, 5, 6, 7, 8, 9, 10];
$expected_lost = [0, 1, 2, 3, 4, 11, 12, 13];
$expected_kept = [17, 18];
$all_acked_removed = true;
foreach ($expected_acked as $p) {
    if (isset($conn->sent_packets[$L][$p])) {
        $all_acked_removed = false;
        break;
    }
}
$all_lost_removed = true;
foreach ($expected_lost as $p) {
    if (isset($conn->sent_packets[$L][$p])) {
        $all_lost_removed = false;
        break;
    }
}
$all_kept = true;
foreach ($expected_kept as $p) {
    if (!isset($conn->sent_packets[$L][$p])) {
        $all_kept = false;
        break;
    }
}
ok("multi-range ACK removes ACKed packets",
    $all_acked_removed);
ok("multi-range ACK declares reordered packets lost",
    $all_lost_removed);
ok("multi-range ACK keeps near-largest packets",
    $all_kept);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
