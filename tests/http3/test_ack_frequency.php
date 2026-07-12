<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the QUIC ACK-Frequency extension (draft-ietf-quic-
 * ack-frequency): the min_ack_delay transport parameter, the
 * ACK_FREQUENCY and IMMEDIATE_ACK frame codec, honoring a received
 * ACK_FREQUENCY frame (the shouldSendAppAck decision), and
 * originating an ACK_FREQUENCY frame toward a peer that advertised
 * the extension.
 *
 * Run from the repo root:
 *     php tests/http3/test_ack_frequency.php
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
    Stub the parent classes H3Listener.php's classes extend, so the
    unit tests run without loading the whole framework.
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

/* Builds a QuicConnection without running its constructor. */
function makeConn()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
    $conn = $rc->newInstanceWithoutConstructor();
    $conn->send_queue = [];
    return $conn;
}

/* Invokes a protected/static method by name. */
function call($target, $method, $args = [])
{
    $rm = new \ReflectionMethod('seekquarry\\atto\\QuicConnection',
        $method);
    return $rm->invokeArgs(is_object($target) ? $target : null,
        $args);
}

/* Encodes one transport parameter as id, length, value. */
function tp($id, $value)
{
    $val = QuicVarint::write($value);
    return QuicVarint::write($id)
        . QuicVarint::write(strlen($val)) . $val;
}

$app = QuicConnection::LEVEL_APPLICATION;

/* The local transport parameters advertise the extension. */
$local = call(null, 'buildLocalTransportParams');
$has_min = false;
$has_max = false;
$off = 0;
while ($off < strlen($local)) {
    list($id, $off) = QuicVarint::read($local, $off);
    list($len, $off) = QuicVarint::read($local, $off);
    $val = substr($local, $off, $len);
    $off += $len;
    list($param_value, ) = QuicVarint::read($val, 0);
    if ($id === 0xff04de1b) {
        $has_min = ($param_value
            === QuicConnection::AF_LOCAL_MIN_ACK_DELAY);
    }
    if ($id === 0x0b) {
        $has_max = ($param_value === 25);
    }
}
ok("local params advertise min_ack_delay", $has_min);
ok("local params advertise max_ack_delay", $has_max);

/* A peer's min_ack_delay is parsed when it does not exceed max. */
$conn = makeConn();
$conn->peer_transport_params = tp(0x0b, 25) . tp(0xff04de1b, 2000);
call($conn, 'parsePeerTransportParams');
ok("peer min_ack_delay parsed",
    $conn->peer_min_ack_delay === 2000
    && $conn->peer_max_ack_delay === 25);

/* A peer min_ack_delay greater than its max_ack_delay is declined. */
$conn = makeConn();
/* max_ack_delay 1 ms, min_ack_delay 5000 us = 5 ms > 1 ms. */
$conn->peer_transport_params = tp(0x0b, 1) . tp(0xff04de1b, 5000);
call($conn, 'parsePeerTransportParams');
ok("peer min_ack_delay above max is declined",
    $conn->peer_min_ack_delay === null);

/* ACK_FREQUENCY and IMMEDIATE_ACK round-trip through the codec. */
$wire = QuicFrame::encode([
    'type' => QuicFrame::F_ACK_FREQUENCY,
    'sequence' => 7,
    'ack_eliciting_threshold' => 10,
    'requested_max_ack_delay' => 25000,
    'reordering_threshold' => 1,
]) . QuicFrame::encode(['type' => QuicFrame::F_IMMEDIATE_ACK]);
list($frames, $err) = QuicFrame::decodeAll($wire);
ok("ack-frequency frames decode",
    $err === '' && count($frames) === 2
    && $frames[0]['type'] === QuicFrame::F_ACK_FREQUENCY
    && $frames[0]['sequence'] === 7
    && $frames[0]['ack_eliciting_threshold'] === 10
    && $frames[0]['requested_max_ack_delay'] === 25000
    && $frames[0]['reordering_threshold'] === 1
    && $frames[1]['type'] === QuicFrame::F_IMMEDIATE_ACK);
ok("ACK_FREQUENCY type is two-byte varint on the wire",
    substr(bin2hex($wire), 0, 4) === '40af');

/* onAckFrequency applies a newer frame and clamps a tiny delay. */
$conn = makeConn();
call($conn, 'onAckFrequency', [[
    'sequence' => 1,
    'ack_eliciting_threshold' => 10,
    'requested_max_ack_delay' => 50,
    'reordering_threshold' => 1,
]]);
ok("onAckFrequency applies newer frame and floors the delay",
    $conn->af_recv_largest_seq === 1
    && $conn->af_ack_eliciting_threshold === 10
    && $conn->af_max_ack_delay
        === QuicConnection::AF_LOCAL_MIN_ACK_DELAY);

/* An older sequence number is ignored. */
call($conn, 'onAckFrequency', [[
    'sequence' => 0,
    'ack_eliciting_threshold' => 2,
    'requested_max_ack_delay' => 9000,
    'reordering_threshold' => 5,
]]);
ok("onAckFrequency ignores an older sequence",
    $conn->af_ack_eliciting_threshold === 10
    && $conn->af_recv_largest_seq === 1);

/* Before any frame, an app ack is sent whenever one is pending. */
$conn = makeConn();
ok("no ack when nothing pending",
    call($conn, 'shouldSendAppAck') === false);
$conn->ack_pending[$app] = true;
ok("default cadence acks when pending",
    call($conn, 'shouldSendAppAck') === true);

/* After a frame, the threshold and delay gate the ack. */
$conn = makeConn();
$conn->ack_pending[$app] = true;
call($conn, 'onAckFrequency', [[
    'sequence' => 1,
    'ack_eliciting_threshold' => 3,
    'requested_max_ack_delay' => 20000,
    'reordering_threshold' => 1,
]]);
$conn->af_ack_eliciting_since_ack = 2;
$conn->af_first_unacked_at = microtime(true);
ok("held below threshold and within delay",
    call($conn, 'shouldSendAppAck') === false);
$conn->af_ack_eliciting_since_ack = 4;
ok("ack once past the threshold",
    call($conn, 'shouldSendAppAck') === true);
$conn->af_ack_eliciting_since_ack = 1;
$conn->af_first_unacked_at = microtime(true) - 1.0;
ok("ack once the requested delay elapses",
    call($conn, 'shouldSendAppAck') === true);
$conn->af_first_unacked_at = microtime(true);
$conn->af_immediate_ack = true;
ok("IMMEDIATE_ACK forces an ack",
    call($conn, 'shouldSendAppAck') === true);

/* The send side stays silent when the peer omitted the parameter. */
$conn = makeConn();
$conn->keys = [$app => ['tx' => null]];
call($conn, 'maybeQueueAckFrequency');
ok("no ACK_FREQUENCY sent without peer support",
    count($conn->send_queue) === 0 && $conn->af_sent === false);

/* With peer support it sends one frame carrying the policy. */
$conn = makeConn();
$conn->keys = [$app => ['tx' => null]];
$conn->peer_min_ack_delay = 1000;
$conn->smoothed_rtt = 0.02;
call($conn, 'maybeQueueAckFrequency');
$sent_frame = null;
if (count($conn->send_queue) === 1) {
    list($sf, $serr) = QuicFrame::decodeAll(
        $conn->send_queue[0][1]);
    if ($serr === '' && count($sf) === 1) {
        $sent_frame = $sf[0];
    }
}
ok("sends one ACK_FREQUENCY with the policy",
    $sent_frame !== null
    && $sent_frame['type'] === QuicFrame::F_ACK_FREQUENCY
    && $sent_frame['ack_eliciting_threshold']
        === QuicConnection::AF_SEND_THRESHOLD
    && $sent_frame['requested_max_ack_delay'] === 20000
    && $sent_frame['reordering_threshold'] === 1
    && $conn->af_sent === true);

/* It is sent only once. */
call($conn, 'maybeQueueAckFrequency');
ok("ACK_FREQUENCY is sent only once",
    count($conn->send_queue) === 1);
ok("the requested delay is recorded for observability",
    $conn->af_sent_delay === 20000);

/* stats() surfaces the negotiation and the peer's ack cadence. */
$conn = makeConn();
$conn->streams = [];
$conn->peer_min_ack_delay = 1000;
$conn->af_sent = true;
$conn->af_sent_delay = 20000;
$conn->stats_ack_packets_received = 5;
$conn->stats_packets_sent = 50;
$stats = $conn->stats();
$af = $stats['ack_frequency'];
ok("stats reports ack-frequency negotiation and cadence",
    $af['peer_advertised'] === true
    && $af['peer_min_ack_delay'] === 1000
    && $af['sent'] === true
    && $af['sent_threshold'] === QuicConnection::AF_SEND_THRESHOLD
    && $af['sent_max_ack_delay'] === 20000
    && $af['ack_packets_received'] === 5);

echo "\n$pass / $tests passed\n";
exit($pass === $tests ? 0 : 1);
