<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9002 sec 7 NewReno congestion-
 * controller hooks on QuicConnection: bytes_in_flight
 * accounting, slow-start vs congestion-avoidance cwnd
 * growth, the loss-event reduction, and the recovery-period
 * filter that prevents repeated halvings within one RTT.
 *
 * Run from the repo root:
 *     php tests/http3/test_newreno_cwnd.php
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
    $conn->bytes_in_flight = 0;
    $conn->congestion_window =
        QuicConnection::CC_INITIAL_WINDOW_BYTES;
    $conn->ssthresh = PHP_INT_MAX;
    $conn->congestion_recovery_start = null;
    $conn->send_queue = [];
    $conn->keys = [
        QuicConnection::LEVEL_APPLICATION => [
            'tx' => 'fake', 'rx' => 'fake',
        ],
    ];
    return $conn;
}

function call($conn, $method, ...$args)
{
    $rm = new \ReflectionMethod(
        'seekquarry\\atto\\QuicConnection', $method);
    return $rm->invokeArgs($conn, $args);
}

function makeSentEntry($pn, $time_sent, $sent_bytes,
    $ack_eliciting = true, $in_flight = true)
{
    return [
        'pn' => $pn,
        'time_sent' => $time_sent,
        'ack_eliciting' => $ack_eliciting,
        'in_flight' => $in_flight,
        'sent_bytes' => $sent_bytes,
        'frames' => [],
    ];
}

$L = QuicConnection::LEVEL_APPLICATION;

/*
    -----------------------------------------------------------
    Initial state
    -----------------------------------------------------------
 */

/* Test 1: cwnd starts at CC_INITIAL_WINDOW_BYTES. */
$conn = makeConn();
ok("cwnd starts at CC_INITIAL_WINDOW_BYTES",
    $conn->congestion_window
    === QuicConnection::CC_INITIAL_WINDOW_BYTES);

/* Test 2: ssthresh starts at PHP_INT_MAX (slow-start mode). */
ok("ssthresh starts at PHP_INT_MAX",
    $conn->ssthresh === PHP_INT_MAX);

/* Test 3: bytes_in_flight starts at 0. */
ok("bytes_in_flight starts at 0",
    $conn->bytes_in_flight === 0);

/*
    -----------------------------------------------------------
    bytes_in_flight bookkeeping
    -----------------------------------------------------------
 */

/* Test 4: addToBytesInFlight accumulates. */
$conn = makeConn();
call($conn, 'addToBytesInFlight', 1200);
call($conn, 'addToBytesInFlight', 1200);
ok("addToBytesInFlight accumulates",
    $conn->bytes_in_flight === 2400);

/* Test 5: removeFromBytesInFlight subtracts and floors at 0. */
call($conn, 'removeFromBytesInFlight', 1200);
ok("removeFromBytesInFlight subtracts",
    $conn->bytes_in_flight === 1200);
call($conn, 'removeFromBytesInFlight', 99999);
ok("removeFromBytesInFlight floors at 0 on underflow",
    $conn->bytes_in_flight === 0);

/*
    -----------------------------------------------------------
    Slow-start cwnd growth
    -----------------------------------------------------------
 */

/* Test 6: ACK in slow-start grows cwnd by exactly bytes acked.
   ssthresh stays at PHP_INT_MAX so we're in slow-start. */
$conn = makeConn();
$conn->bytes_in_flight = 12000;
$entry = makeSentEntry(0, microtime(true) - 0.005, 1200);
call($conn, 'onPacketAckedForCwnd', $entry);
ok("slow-start grows cwnd by exactly sent_bytes",
    $conn->congestion_window
    === QuicConnection::CC_INITIAL_WINDOW_BYTES + 1200);

/*
    -----------------------------------------------------------
    Congestion event: cwnd halves, ssthresh = halved cwnd
    -----------------------------------------------------------
 */

/* Test 7: onCongestionEvent halves cwnd and sets ssthresh. */
$conn = makeConn();
$now = microtime(true);
$conn->congestion_window = 16000;
call($conn, 'onCongestionEvent', $now);
ok("loss event halves cwnd",
    $conn->congestion_window === 8000);
ok("loss event sets ssthresh = new cwnd",
    $conn->ssthresh === 8000);
ok("loss event records recovery start",
    $conn->congestion_recovery_start !== null);

/* Test 8: cwnd never falls below CC_MINIMUM_WINDOW_BYTES. */
$conn = makeConn();
$conn->congestion_window = 3000;
call($conn, 'onCongestionEvent', microtime(true));
ok("cwnd floors at CC_MINIMUM_WINDOW_BYTES",
    $conn->congestion_window
    === QuicConnection::CC_MINIMUM_WINDOW_BYTES);

/*
    -----------------------------------------------------------
    Recovery period filters duplicate loss reactions
    -----------------------------------------------------------
 */

/* Test 9: a second loss event for a packet sent before
   recovery_start should not halve cwnd again. */
$conn = makeConn();
$conn->congestion_window = 16000;
$old_send_time = microtime(true) - 0.010;
call($conn, 'onCongestionEvent', $old_send_time);
$cwnd_after_first = $conn->congestion_window;
/* Same time_sent (or older) -- already in recovery for it. */
call($conn, 'onCongestionEvent', $old_send_time);
ok("repeat loss in recovery does not halve cwnd again",
    $conn->congestion_window === $cwnd_after_first);

/* Test 10: a fresh loss for a packet sent AFTER recovery
   start triggers another halving (RFC 9002 sec 7.6.2). */
$new_send_time = microtime(true) + 0.001;
call($conn, 'onCongestionEvent', $new_send_time);
ok("loss after recovery start halves cwnd again",
    $conn->congestion_window === intdiv($cwnd_after_first, 2)
    || $conn->congestion_window
        === QuicConnection::CC_MINIMUM_WINDOW_BYTES);

/*
    -----------------------------------------------------------
    Recovery period filters cwnd growth
    -----------------------------------------------------------
 */

/* Test 11: ACK for a packet sent BEFORE recovery_start
   does not grow cwnd. */
$conn = makeConn();
$now = microtime(true);
$conn->congestion_recovery_start = $now;
$conn->congestion_window = 8000;
$conn->ssthresh = 8000;
$old_entry = makeSentEntry(0, $now - 0.001, 1200);
$cwnd_before = $conn->congestion_window;
call($conn, 'onPacketAckedForCwnd', $old_entry);
ok("ACK in recovery for pre-recovery packet leaves cwnd alone",
    $conn->congestion_window === $cwnd_before);

/* Test 12: ACK for a packet sent AFTER recovery_start grows
   cwnd. */
$new_entry = makeSentEntry(1, $now + 0.001, 1200);
call($conn, 'onPacketAckedForCwnd', $new_entry);
ok("ACK for post-recovery packet grows cwnd again",
    $conn->congestion_window > $cwnd_before);

/*
    -----------------------------------------------------------
    Congestion-avoidance arithmetic
    -----------------------------------------------------------
 */

/* Test 13: when cwnd >= ssthresh, growth is roughly MSS per
   RTT. With cwnd = 12000 and acked = 1200, increment is
   1200 * 1200 / 12000 = 120. */
$conn = makeConn();
$conn->congestion_window = 12000;
$conn->ssthresh = 8000; /* CA mode */
$entry = makeSentEntry(0, microtime(true) - 0.005, 1200);
call($conn, 'onPacketAckedForCwnd', $entry);
ok("CA growth uses MSS * acked / cwnd formula",
    $conn->congestion_window === 12120);

/*
    -----------------------------------------------------------
    Integration: processAck + congestion accounting
    -----------------------------------------------------------
 */

/* Test 14: processAck removes bytes_in_flight for acked
   packets. */
$conn = makeConn();
$now = microtime(true);
$conn->sent_packets[$L][0] = makeSentEntry(0,
    $now - 0.005, 1200);
$conn->sent_packets[$L][1] = makeSentEntry(1,
    $now - 0.004, 1200);
$conn->bytes_in_flight = 2400;
$frame = [
    'type' => 0x02,
    'largest' => 1,
    'delay' => 0,
    'first_range' => 1,
    'ranges' => [],
];
call($conn, 'processAck', $L, $frame);
ok("processAck subtracts bytes for acked packets",
    $conn->bytes_in_flight === 0);

/* Test 15: processAck grows cwnd while in slow start. */
ok("processAck grows cwnd in slow-start",
    $conn->congestion_window
    > QuicConnection::CC_INITIAL_WINDOW_BYTES);

/*
    -----------------------------------------------------------
    Integration: loss path triggers cwnd halving
    -----------------------------------------------------------
 */

/* Test 16: a packet far behind largest_acked is declared lost
   via the reordering threshold; cwnd halves. */
$conn = makeConn();
$conn->congestion_window = 16000;
$now = microtime(true);
$conn->sent_packets[$L][0] = makeSentEntry(0,
    $now - 0.001, 1200);
$conn->bytes_in_flight = 1200;
$conn->largest_acked_pn[$L] = 5;
call($conn, 'detectAndRemoveLostPackets', $L);
ok("loss event removes bytes_in_flight",
    $conn->bytes_in_flight === 0);
ok("loss event halves cwnd",
    $conn->congestion_window === 8000);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
