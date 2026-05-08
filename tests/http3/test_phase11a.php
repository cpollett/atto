<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Phase 11a unit tests for H3NativeListener -- exercises
 * QuicConnection::processAck and the surrounding sent-packet
 * bookkeeping introduced in commit "phase 11a (h3-native):
 * sent-packet tracking + ACK processing". Covers single-range
 * ACKs, gapped ACKs, multi-range ACKs, ACKs of unknown packet
 * numbers, and the rule that latest_rtt is only updated when
 * the largest ACKed packet was ack-eliciting (RFC 9002 sec
 * 5.1).
 *
 * Run from the repo root:
 *     php "examples/18 HTTP Benchmarks/test_phase11a.php"
 *
 * Exits 0 on full pass, 1 on any failure -- usable as a CI
 * step.
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
    leave in_flight / sent_bytes / frames as no-op fillers that
    later phases (11d congestion accounting, 11c retransmission)
    will exercise.
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
    Set up a QuicConnection without running its constructor --
    a real one wants a TLS engine, certs, and a handshake state
    machine that we don't need for ACK tests. Reflection lets us
    poke the few fields processAck reads.
 */
$rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
$conn = $rc->newInstanceWithoutConstructor();
$conn->sent_packets = [
    QuicConnection::LEVEL_INITIAL => [],
    QuicConnection::LEVEL_HANDSHAKE => [],
    QuicConnection::LEVEL_APPLICATION => [],
];
$conn->latest_rtt = null;

$rm = $rc->getMethod('processAck');

$L = QuicConnection::LEVEL_APPLICATION;

/* Test 1: simple ACK, single range, removes packets. */
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
$rm->invoke($conn, $L, $frame);
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
    1 still in flight.
 */
$conn->sent_packets[$L] = [];
$conn->latest_rtt = null;
addSent($conn, $L, 0, true, $now - 0.010);
addSent($conn, $L, 1, true, $now - 0.009);
addSent($conn, $L, 2, true, $now - 0.008);
addSent($conn, $L, 3, true, $now - 0.007);
$frame = [
    'type' => 0x02,
    'largest' => 3,
    'delay' => 0,
    'first_range' => 1,
    'ranges' => [[0, 0]],
];
$rm->invoke($conn, $L, $frame);
ok("gapped ACK removes pn 0,2,3",
    !isset($conn->sent_packets[$L][0]) &&
    !isset($conn->sent_packets[$L][2]) &&
    !isset($conn->sent_packets[$L][3]));
ok("gapped ACK leaves pn 1",
    isset($conn->sent_packets[$L][1]));

/* Test 3: ACK of unknown PN is harmless. */
$conn->sent_packets[$L] = [];
addSent($conn, $L, 0, true, $now);
$frame = [
    'type' => 0x02,
    'largest' => 99,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [],
];
$rm->invoke($conn, $L, $frame);
ok("ACK of unknown PN does not crash",
    count($conn->sent_packets[$L]) === 1);

/*
    Test 4: latest_rtt is only updated when the largest acked
    packet was ack-eliciting (RFC 9002 sec 5.1). Here pn 5 is
    flagged ack_eliciting=false, so even though it's the
    largest acked, it must not produce an RTT sample.
 */
$conn->sent_packets[$L] = [];
$conn->latest_rtt = null;
addSent($conn, $L, 5, false, $now - 0.020);
addSent($conn, $L, 6, true, $now - 0.015);
$frame = [
    'type' => 0x02,
    'largest' => 5,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [],
];
$rm->invoke($conn, $L, $frame);
ok("non-eliciting largest does not update latest_rtt",
    $conn->latest_rtt === null);

/*
    Test 5: large multi-range ACK. Wire-format layout:
        largest=19, first_range=0    → only pn 19
        [gap=1, ack_len=2]           → skip 17-18, ack 14-16
        [gap=2, ack_len=5]           → skip 11-13, ack 5-10
    Expected: 19, 14-16, 5-10 removed; 0-4, 11-13, 17-18 kept.
 */
$conn->sent_packets[$L] = [];
for ($i = 0; $i < 20; $i++) {
    addSent($conn, $L, $i, true, $now - 0.001 * (20 - $i));
}
$frame = [
    'type' => 0x02,
    'largest' => 19,
    'delay' => 0,
    'first_range' => 0,
    'ranges' => [[1, 2], [2, 5]],
];
$rm->invoke($conn, $L, $frame);
$expected_acked = [19, 14, 15, 16, 5, 6, 7, 8, 9, 10];
$expected_unacked = [0, 1, 2, 3, 4, 11, 12, 13, 17, 18];
$all_acked_removed = true;
foreach ($expected_acked as $p) {
    if (isset($conn->sent_packets[$L][$p])) {
        $all_acked_removed = false;
        break;
    }
}
$all_unacked_kept = true;
foreach ($expected_unacked as $p) {
    if (!isset($conn->sent_packets[$L][$p])) {
        $all_unacked_kept = false;
        break;
    }
}
ok("multi-range ACK removes correct packets",
    $all_acked_removed);
ok("multi-range ACK keeps correct packets",
    $all_unacked_kept);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
