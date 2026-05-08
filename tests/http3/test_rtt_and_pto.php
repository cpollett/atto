<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9002 RTT estimator (smoothed_rtt,
 * rttvar, min_rtt) and the QuicConnection probe-timeout
 * machinery (basePto, setLossDetectionTimer,
 * onLossDetectionTimeout). Covers the first-sample seed, the
 * EWMA blend on subsequent samples, the min_rtt floor against
 * a misreported ack_delay, the kInitialRtt fallback before any
 * sample exists, exponential backoff on pto_count, and the
 * PING-on-timeout behaviour.
 *
 * Run from the repo root:
 *     php tests/http3/test_rtt_and_pto.php
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

function approx($a, $b, $epsilon = 0.0001)
{
    return abs($a - $b) < $epsilon;
}

/*
    Build a fresh QuicConnection without invoking the real
    constructor (which wants TLS engine + certs we don't have
    here). For this test we only need the RTT/PTO state and the
    sent_packets map.
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
    $conn->latest_rtt = null;
    $conn->smoothed_rtt = null;
    $conn->rttvar = null;
    $conn->min_rtt = null;
    $conn->pto_count = 0;
    $conn->loss_detection_timer = null;
    return $conn;
}

/*
    Helper: invoke a protected method via reflection without
    setAccessible (deprecated in PHP 8.5 / no-op since 8.1).
 */
function call($conn, $method, ...$args)
{
    $rm = new \ReflectionMethod(
        'seekquarry\\atto\\QuicConnection', $method);
    return $rm->invokeArgs($conn, $args);
}

/*
    -----------------------------------------------------------
    RTT smoothing (RFC 9002 sec 5.3)
    -----------------------------------------------------------
 */

/* Test 1: first sample seeds smoothed_rtt = latest_rtt and
   rttvar = latest_rtt / 2. ack_delay = 0 keeps the math
   simple. */
$conn = makeConn();
$conn->latest_rtt = 0.020;
call($conn, 'updateRtt', 0);
ok("first sample seeds smoothed_rtt",
    approx($conn->smoothed_rtt, 0.020));
ok("first sample seeds rttvar = latest_rtt / 2",
    approx($conn->rttvar, 0.010));
ok("first sample seeds min_rtt",
    approx($conn->min_rtt, 0.020));

/* Test 2: second sample blends at 7/8 vs 1/8 weights.
   smoothed_rtt = 0.875 * 0.020 + 0.125 * 0.030 = 0.02125
   diff = |0.020 - 0.030| = 0.010
   rttvar = 0.75 * 0.010 + 0.25 * 0.010 = 0.010 */
$conn->latest_rtt = 0.030;
call($conn, 'updateRtt', 0);
ok("EWMA smoothed_rtt after second sample",
    approx($conn->smoothed_rtt, 0.02125));
ok("EWMA rttvar after second sample",
    approx($conn->rttvar, 0.010));

/* Test 3: min_rtt only decreases. */
$conn->latest_rtt = 0.005;
call($conn, 'updateRtt', 0);
ok("min_rtt drops on lower sample",
    approx($conn->min_rtt, 0.005));
$conn->latest_rtt = 0.050;
call($conn, 'updateRtt', 0);
ok("min_rtt does not increase on higher sample",
    approx($conn->min_rtt, 0.005));

/* Test 4: ack_delay subtraction is clamped against min_rtt.
   If subtracting ack_delay would push the adjusted RTT below
   min_rtt, we keep latest_rtt as-is. The wire ack_delay is in
   units of 8 microseconds (default ack_delay_exponent=3); so
   ack_delay_raw = 1000 means 1000 * 8us = 8ms. With
   latest_rtt = 0.010 and min_rtt = 0.005, adjusted = 0.010 -
   0.008 = 0.002 < min_rtt -> keep 0.010. */
$conn = makeConn();
/* Seed min_rtt to 5ms with a clean first sample */
$conn->latest_rtt = 0.005;
call($conn, 'updateRtt', 0);
$prior_smoothed = $conn->smoothed_rtt;
/* Now feed latest_rtt = 10ms with bogus 8ms ack_delay */
$conn->latest_rtt = 0.010;
call($conn, 'updateRtt', 1000);
/* Adjusted should have fallen back to 0.010 (no subtraction).
   smoothed_rtt = 0.875 * 0.005 + 0.125 * 0.010 = 0.005625 */
ok("ack_delay clamped against min_rtt",
    approx($conn->smoothed_rtt, 0.005625));

/*
    -----------------------------------------------------------
    basePto and timer arming (RFC 9002 sec 6.2)
    -----------------------------------------------------------
 */

/* Test 5: basePto returns kInitialRtt + max_ack_delay before
   any RTT sample exists. kInitialRtt = 0.333, max_ack_delay
   default = 0.025, so basePto = 0.358. */
$conn = makeConn();
$base = call($conn, 'basePto');
ok("basePto uses kInitialRtt before first sample",
    approx($base, 0.358));

/* Test 6: basePto = smoothed_rtt + 4*rttvar + max_ack_delay
   once sampled. With smoothed = 0.020 and rttvar = 0.010:
   0.020 + 0.040 + 0.025 = 0.085. */
$conn = makeConn();
$conn->latest_rtt = 0.020;
call($conn, 'updateRtt', 0);
$base = call($conn, 'basePto');
ok("basePto uses smoothed_rtt + 4*rttvar + max_ack_delay",
    approx($base, 0.085));

/* Test 7: basePto floors 4*rttvar at kGranularity (1ms). With
   smoothed = 0.020 and rttvar = 0.0001 (so 4*rttvar = 0.0004
   < 0.001), the floor kicks in: basePto = 0.020 + 0.001 +
   0.025 = 0.046. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.0001;
$base = call($conn, 'basePto');
ok("basePto floors 4*rttvar at kGranularity",
    approx($base, 0.046));

/* Test 8: setLossDetectionTimer disarms when no ack-eliciting
   packets are in flight. */
$conn = makeConn();
call($conn, 'setLossDetectionTimer');
ok("timer disarms with no ack-eliciting packets",
    $conn->loss_detection_timer === null);

/* Test 9: setLossDetectionTimer ignores non-eliciting
   packets. */
$conn = makeConn();
$now = microtime(true);
$conn->sent_packets[QuicConnection::LEVEL_APPLICATION][0] = [
    'pn' => 0,
    'time_sent' => $now,
    'ack_eliciting' => false,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [],
];
call($conn, 'setLossDetectionTimer');
ok("timer disarms with only non-eliciting packets",
    $conn->loss_detection_timer === null);

/* Test 10: setLossDetectionTimer arms relative to oldest
   ack-eliciting send. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.010;
$old = microtime(true) - 0.005; /* sent 5ms ago */
$conn->sent_packets[QuicConnection::LEVEL_APPLICATION][0] = [
    'pn' => 0,
    'time_sent' => $old,
    'ack_eliciting' => true,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [],
];
call($conn, 'setLossDetectionTimer');
$expected = $old + 0.085; /* basePto computed above */
ok("timer arms at oldest_send + basePto",
    approx($conn->loss_detection_timer, $expected, 0.001));

/* Test 11: pto_count doubles the timer interval. */
$conn->pto_count = 2;
call($conn, 'setLossDetectionTimer');
$expected = $old + 0.085 * 4; /* 1 << 2 = 4 */
ok("timer applies pto_count backoff",
    approx($conn->loss_detection_timer, $expected, 0.001));

/*
    -----------------------------------------------------------
    onLossDetectionTimeout (RFC 9002 sec 6.2.4)
    -----------------------------------------------------------
 */

/* Test 12: onLossDetectionTimeout queues a PING frame in 1-RTT
   space, increments pto_count, and rearms the timer. We have
   to fake APPLICATION-level keys so queue1Rtt does not bail
   on the missing-key guard. */
$conn = makeConn();
$conn->keys[QuicConnection::LEVEL_APPLICATION] = [
    'tx' => 'fake', 'rx' => 'fake'];
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.010;
$conn->sent_packets[QuicConnection::LEVEL_APPLICATION][0] = [
    'pn' => 0,
    'time_sent' => microtime(true) - 0.100,
    'ack_eliciting' => true,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [],
];
call($conn, 'setLossDetectionTimer');
$prior_pto_count = $conn->pto_count;
$prior_send_queue_size = count($conn->send_queue);
$conn->onLossDetectionTimeout();
ok("PING queued on timeout",
    count($conn->send_queue) === $prior_send_queue_size + 1);
ok("PING is in 1-RTT (LEVEL_APPLICATION) space",
    end($conn->send_queue)[0] ===
        QuicConnection::LEVEL_APPLICATION);
ok("PING payload is exactly the F_PING byte",
    end($conn->send_queue)[1] === chr(QuicFrame::F_PING));
ok("pto_count incremented",
    $conn->pto_count === $prior_pto_count + 1);
ok("timer rearmed (not null)",
    $conn->loss_detection_timer !== null);

/*
    -----------------------------------------------------------
    processAck integration: PTO state resets on progress
    -----------------------------------------------------------
 */

/* Test 13: an ACK that newly acknowledges a packet resets
   pto_count to 0 and rearms the timer. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.010;
$conn->pto_count = 3;
$now = microtime(true);
$conn->sent_packets[QuicConnection::LEVEL_APPLICATION][0] = [
    'pn' => 0,
    'time_sent' => $now - 0.005,
    'ack_eliciting' => true,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [],
];
$conn->sent_packets[QuicConnection::LEVEL_APPLICATION][1] = [
    'pn' => 1,
    'time_sent' => $now - 0.001,
    'ack_eliciting' => true,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [],
];
call($conn, 'processAck',
    QuicConnection::LEVEL_APPLICATION,
    [
        'type' => 0x02,
        'largest' => 0,
        'delay' => 0,
        'first_range' => 0,
        'ranges' => [],
    ]);
ok("processAck resets pto_count on progress",
    $conn->pto_count === 0);
ok("processAck rearms timer when packets remain",
    $conn->loss_detection_timer !== null);

/* Test 14: an ACK that drains the last in-flight packet
   disarms the timer. */
call($conn, 'processAck',
    QuicConnection::LEVEL_APPLICATION,
    [
        'type' => 0x02,
        'largest' => 1,
        'delay' => 0,
        'first_range' => 0,
        'ranges' => [],
    ]);
ok("processAck disarms timer when no packets remain",
    $conn->loss_detection_timer === null);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
