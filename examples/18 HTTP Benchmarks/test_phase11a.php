<?php
namespace seekquarry\atto;
class Connection {} 
class Listener { public function __construct(...$a){} public function close(){} }
abstract class Transport { public function __construct($s){} }
require '/home/claude/atto/src/H3NativeListener.php.work';

$tests = 0; $pass = 0;
function ok($name, $cond) {
    global $tests, $pass;
    $tests++;
    if ($cond) { $pass++; echo "PASS $name\n"; }
    else { echo "FAIL $name\n"; }
}

/* ---- Helpers to drive the QuicConnection ACK code in
   isolation. We can't easily instantiate a real
   QuicConnection without a TLS engine, so we use
   reflection to flip the relevant fields and invoke
   processAck directly. */
$rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
$ctor = $rc->getConstructor();
$conn = $rc->newInstanceWithoutConstructor();
/* Initialize the few fields processAck consumes. */
$conn->sent_packets = [
    QuicConnection::LEVEL_INITIAL => [],
    QuicConnection::LEVEL_HANDSHAKE => [],
    QuicConnection::LEVEL_APPLICATION => [],
];
$conn->latest_rtt = null;

/* Helper to add a fake sent-packet entry. */
function addSent($conn, $level, $pn, $ack_eliciting,
    $time_sent)
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

$rm = $rc->getMethod('processAck');
$rm->setAccessible(true);

/* Test 1: simple ACK, single range, removes packets */
$L = QuicConnection::LEVEL_APPLICATION;
$now = microtime(true);
addSent($conn, $L, 0, true, $now - 0.010);
addSent($conn, $L, 1, true, $now - 0.009);
addSent($conn, $L, 2, true, $now - 0.008);
$frame = ['type' => 0x02, 'largest' => 2, 'delay' => 0,
    'first_range' => 2, 'ranges' => []];
$rm->invoke($conn, $L, $frame);
ok("simple ACK removes all 3 packets",
    count($conn->sent_packets[$L]) === 0);
ok("latest_rtt is recorded",
    $conn->latest_rtt !== null && $conn->latest_rtt > 0.005
    && $conn->latest_rtt < 0.020);

/* Test 2: ACK with gap. PNs 0,2,3 acked, 1 NOT acked. */
$conn->sent_packets[$L] = [];
$conn->latest_rtt = null;
addSent($conn, $L, 0, true, $now - 0.010);
addSent($conn, $L, 1, true, $now - 0.009);
addSent($conn, $L, 2, true, $now - 0.008);
addSent($conn, $L, 3, true, $now - 0.007);
/* ACK frame: largest=3, first_range=1 (covers 2-3),
   then one range with gap=0 (skip pn 1) and ack_len=0
   (covers just pn 0). */
$frame = ['type' => 0x02, 'largest' => 3, 'delay' => 0,
    'first_range' => 1,
    'ranges' => [[0, 0]]];
$rm->invoke($conn, $L, $frame);
ok("gapped ACK removes pn 0,2,3",
    !isset($conn->sent_packets[$L][0]) &&
    !isset($conn->sent_packets[$L][2]) &&
    !isset($conn->sent_packets[$L][3]));
ok("gapped ACK leaves pn 1",
    isset($conn->sent_packets[$L][1]));

/* Test 3: ACK of unknown PN is harmless */
$conn->sent_packets[$L] = [];
addSent($conn, $L, 0, true, $now);
$frame = ['type' => 0x02, 'largest' => 99, 'delay' => 0,
    'first_range' => 0, 'ranges' => []];
$rm->invoke($conn, $L, $frame);
ok("ACK of unknown PN does not crash",
    count($conn->sent_packets[$L]) === 1);

/* Test 4: latest_rtt only updated when largest is
   ack-eliciting. */
$conn->sent_packets[$L] = [];
$conn->latest_rtt = null;
addSent($conn, $L, 5, false, $now - 0.020); /* NOT eliciting */
addSent($conn, $L, 6, true, $now - 0.015);
$frame = ['type' => 0x02, 'largest' => 5, 'delay' => 0,
    'first_range' => 0, 'ranges' => []];
$rm->invoke($conn, $L, $frame);
ok("non-eliciting largest does not update latest_rtt",
    $conn->latest_rtt === null);

/* Test 5: large multi-range ACK */
$conn->sent_packets[$L] = [];
for ($i = 0; $i < 20; $i++) {
    addSent($conn, $L, $i, true, $now - 0.001 * (20 - $i));
}
/* ACK 19, then gap 17-18, ack 14-16, gap 11-13, ack 5-10 */
/* In wire order: largest=19, first_range=0 (only 19),
                  then [gap=1, ack=2] = skip 17-18, ack 14-16
                  then [gap=2, ack=5] = skip 11-13, ack 5-10 */
$frame = ['type' => 0x02, 'largest' => 19, 'delay' => 0,
    'first_range' => 0,
    'ranges' => [[1, 2], [2, 5]]];
$rm->invoke($conn, $L, $frame);
$expected_acked = [19, 14, 15, 16, 5, 6, 7, 8, 9, 10];
$expected_unacked = [0, 1, 2, 3, 4, 11, 12, 13, 17, 18];
$all_acked_removed = true;
foreach ($expected_acked as $p) {
    if (isset($conn->sent_packets[$L][$p])) {
        $all_acked_removed = false; break;
    }
}
$all_unacked_kept = true;
foreach ($expected_unacked as $p) {
    if (!isset($conn->sent_packets[$L][$p])) {
        $all_unacked_kept = false; break;
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
