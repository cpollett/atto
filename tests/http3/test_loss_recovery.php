<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9002 sec 6.1 loss-detection logic
 * (detectAndRemoveLostPackets, onPacketsLost) and the
 * combined loss / PTO timer arming. Covers the packet-
 * number reordering threshold, the time-based threshold,
 * the requeue paths for CRYPTO / STREAM / HANDSHAKE_DONE
 * frames, and the dispatch decision in
 * onLossDetectionTimeout between a loss event and a PTO
 * event.
 *
 * Run from the repo root:
 *     php tests/http3/test_loss_recovery.php
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
    Build a fresh QuicConnection without invoking the real
    constructor. The tests only need the loss-detection state
    plus enough of send_queue / keys / handshake_done_sent for
    onPacketsLost to do its thing.
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
    $conn->send_queue = [];
    $conn->handshake_done_sent = false;
    $conn->keys = [
        QuicConnection::LEVEL_APPLICATION => [
            'tx' => 'fake',
            'rx' => 'fake',
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

function makeSentEntry($pn, $ack_eliciting, $time_sent,
    $frames = [])
{
    return [
        'pn' => $pn,
        'time_sent' => $time_sent,
        'ack_eliciting' => $ack_eliciting,
        'in_flight' => true,
        'sent_bytes' => 50,
        'frames' => $frames,
    ];
}

$L = QuicConnection::LEVEL_APPLICATION;

/*
    -----------------------------------------------------------
    Reordering threshold (RFC 9002 sec 6.1.1)
    -----------------------------------------------------------
 */

/* Test 1: pn 0 declared lost when largest_acked is 3 (delta of
   3 == LOSS_PKT_THRESHOLD). */
$conn = makeConn();
$now = microtime(true);
$conn->sent_packets[$L][0] = makeSentEntry(0, true, $now);
$conn->sent_packets[$L][3] = makeSentEntry(3, true, $now);
$conn->largest_acked_pn[$L] = 3;
unset($conn->sent_packets[$L][3]); /* simulate 3 acked */
$lost = call($conn, 'detectAndRemoveLostPackets', $L);
ok("pn 0 declared lost when delta == kPacketThreshold",
    $lost === 1);
ok("pn 0 removed from sent_packets",
    !isset($conn->sent_packets[$L][0]));

/* Test 2: pn 1 NOT declared lost when delta is 2 (below
   threshold). */
$conn = makeConn();
$conn->sent_packets[$L][1] = makeSentEntry(1, true, $now);
$conn->largest_acked_pn[$L] = 2;
$lost = call($conn, 'detectAndRemoveLostPackets', $L);
ok("delta below kPacketThreshold not declared lost",
    $lost === 0);
ok("pn 1 still in sent_packets",
    isset($conn->sent_packets[$L][1]));

/*
    -----------------------------------------------------------
    Time threshold (RFC 9002 sec 6.1.2)
    -----------------------------------------------------------
 */

/* Test 3: a packet sent long ago, with smoothed_rtt low enough
   that loss_delay = 9/8 * 0.020 = 0.0225 sec, gets declared
   lost when the largest acked is the next-higher PN. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 1.0); /* sent a full second ago */
$conn->largest_acked_pn[$L] = 1;
$lost = call($conn, 'detectAndRemoveLostPackets', $L);
ok("ancient packet below largest_acked declared lost",
    $lost === 1);

/* Test 4: a fresh packet (not yet over loss_delay) is NOT
   declared lost even if its pn is below largest_acked. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 0.001);
$conn->largest_acked_pn[$L] = 1;
$lost = call($conn, 'detectAndRemoveLostPackets', $L);
ok("recent packet below largest_acked not yet lost",
    $lost === 0);

/* Test 5: a still-in-flight packet sets loss_time so the
   timer can fire when it crosses the threshold. */
ok("loss_time set after non-firing detection",
    $conn->loss_time[$L] !== null
    && $conn->loss_time[$L] > $now);

/*
    -----------------------------------------------------------
    onPacketsLost requeues frames
    -----------------------------------------------------------
 */

/* Test 6: a lost packet carrying a STREAM frame requeues
   that frame's bytes onto the send_queue. */
$conn = makeConn();
$now = microtime(true);
$stream_frame = [
    'type' => QuicFrame::F_STREAM_BASE,
    'stream_id' => 0,
    'offset' => 0,
    'data' => 'hello, world',
    'fin' => true,
    'wire_type' => QuicFrame::F_STREAM_BASE
        | QuicFrame::F_STREAM_LEN
        | QuicFrame::F_STREAM_OFF
        | QuicFrame::F_STREAM_FIN,
];
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 1.0, [$stream_frame]);
$conn->largest_acked_pn[$L] = 1;
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
$prev_q_size = count($conn->send_queue);
call($conn, 'detectAndRemoveLostPackets', $L);
ok("STREAM frame retransmit appended to send_queue",
    count($conn->send_queue) > $prev_q_size);

/* Test 7: the requeued payload re-encodes the STREAM frame
   round-trippably (re-decoding it gives back the same
   stream_id, offset, data, fin). */
$entry = end($conn->send_queue);
ok("requeued entry is at LEVEL_APPLICATION",
    $entry[0] === QuicConnection::LEVEL_APPLICATION);
$payload = $entry[1];
list($frames, $err) = QuicFrame::decodeAll($payload);
$decoded = $frames[0] ?? null;
ok("requeued STREAM frame decodes",
    $decoded !== null
    && $decoded['type'] === QuicFrame::F_STREAM_BASE);
ok("requeued STREAM frame preserves stream_id",
    $decoded['stream_id'] === 0);
ok("requeued STREAM frame preserves offset",
    $decoded['offset'] === 0);
ok("requeued STREAM frame preserves data",
    $decoded['data'] === 'hello, world');
ok("requeued STREAM frame preserves FIN",
    $decoded['fin'] === true);

/* Test 8: a lost packet carrying HANDSHAKE_DONE re-arms the
   one-shot send flag. */
$conn = makeConn();
$conn->handshake_done_sent = true;
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 1.0, [['type' => QuicFrame::F_HANDSHAKE_DONE]]);
$conn->largest_acked_pn[$L] = 1;
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
call($conn, 'detectAndRemoveLostPackets', $L);
ok("lost HANDSHAKE_DONE re-arms handshake_done_sent",
    $conn->handshake_done_sent === false);

/* Test 9: a lost packet carrying a CRYPTO frame requeues at
   the original offset. */
$conn = makeConn();
$conn->keys[QuicConnection::LEVEL_HANDSHAKE] = [
    'tx' => 'fake', 'rx' => 'fake'];
$crypto_frame = [
    'type' => QuicFrame::F_CRYPTO,
    'offset' => 1234,
    'data' => "\x01\x02\x03\x04\x05",
];
$conn->sent_packets[QuicConnection::LEVEL_HANDSHAKE][0] =
    makeSentEntry(0, true, $now - 1.0, [$crypto_frame]);
$conn->largest_acked_pn[QuicConnection::LEVEL_HANDSHAKE] = 1;
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
call($conn, 'detectAndRemoveLostPackets',
    QuicConnection::LEVEL_HANDSHAKE);
$entry = end($conn->send_queue);
ok("requeued CRYPTO entry is at LEVEL_HANDSHAKE",
    $entry[0] === QuicConnection::LEVEL_HANDSHAKE);
list($crypto_frames, $cerr) = QuicFrame::decodeAll($entry[1]);
ok("requeued CRYPTO frame decodes",
    isset($crypto_frames[0])
    && $crypto_frames[0]['type'] === QuicFrame::F_CRYPTO);
ok("requeued CRYPTO frame preserves offset",
    $crypto_frames[0]['offset'] === 1234);
ok("requeued CRYPTO frame preserves data",
    $crypto_frames[0]['data'] === "\x01\x02\x03\x04\x05");

/*
    -----------------------------------------------------------
    setLossDetectionTimer prefers loss_time over PTO
    -----------------------------------------------------------
 */

/* Test 10: when loss_time is set on any level, the timer
   fires at that time rather than at oldest_send + PTO. */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.010;
$now = microtime(true);
$conn->sent_packets[$L][0] = makeSentEntry(0, true, $now);
$conn->loss_time[$L] = $now + 0.005; /* 5ms from now */
call($conn, 'setLossDetectionTimer');
ok("timer prefers loss_time when set",
    abs($conn->loss_detection_timer - ($now + 0.005))
    < 0.001);

/*
    -----------------------------------------------------------
    onLossDetectionTimeout dispatches loss vs PTO
    -----------------------------------------------------------
 */

/* Test 11: when loss_time is set, timeout runs loss detection
   (no PING queued, pto_count stays at 0). */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->latest_rtt = 0.020;
$now = microtime(true);
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 1.0);
$conn->largest_acked_pn[$L] = 1;
$conn->loss_time[$L] = $now - 0.001; /* already past */
$conn->loss_detection_timer = $now - 0.001;
$prev_pto = $conn->pto_count;
$prev_q = count($conn->send_queue);
$conn->onLossDetectionTimeout();
ok("loss-event timeout doesn't increment pto_count",
    $conn->pto_count === $prev_pto);
ok("loss-event timeout removes lost packet",
    !isset($conn->sent_packets[$L][0]));

/* Test 12: when no loss_time is set but the timer fires, it
   was a PTO event (PING queued, pto_count incremented). */
$conn = makeConn();
$conn->smoothed_rtt = 0.020;
$conn->rttvar = 0.010;
$conn->sent_packets[$L][0] = makeSentEntry(0, true,
    $now - 0.001);
$conn->loss_detection_timer = $now;
foreach ($conn->loss_time as $lev => $_) {
    $conn->loss_time[$lev] = null;
}
$prev_pto = $conn->pto_count;
$prev_q = count($conn->send_queue);
$conn->onLossDetectionTimeout();
ok("PTO-event timeout queues a PING",
    count($conn->send_queue) === $prev_q + 1
    && end($conn->send_queue)[1] === chr(QuicFrame::F_PING));
ok("PTO-event timeout increments pto_count",
    $conn->pto_count === $prev_pto + 1);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
