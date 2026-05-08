<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9000 sec 8.1 anti-amplification cap.
 * Before the path is validated (handshake-level packet
 * authenticates -> ST_ESTABLISHED), the server may send at
 * most ANTI_AMP_FACTOR (3) times the bytes it has received
 * from the peer. After ST_ESTABLISHED the cap lifts.
 *
 * The gate uses (payload_len + ANTI_AMP_PACKET_OVERHEAD) as
 * the per-packet bound at gate time; the budget then
 * decrements by the actual encoded length once the packet is
 * committed.
 *
 * Tests drive QuicConnection::emit() directly with
 * controlled stats_bytes_received / stats_bytes_sent and
 * pre-built ack-only payloads of varied size so the gate
 * fires at realistic boundaries. Real keys + real headers
 * are used so the encrypt path runs end-to-end.
 *
 * Run from the repo root:
 *     php tests/http3/test_anti_amplification.php
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

/*
    Build a QuicConnection ready to call emit() on. Real
    1-RTT keys derived from a deterministic dummy traffic
    secret so the encrypt path runs end-to-end. State is
    left at ST_HANDSHAKING; tests bump it to ST_ESTABLISHED
    to verify the cap lifts there.
 */
function makeConn()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
    $conn = $rc->newInstanceWithoutConstructor();
    $conn->state = QuicConnection::ST_HANDSHAKING;
    $conn->stats_bytes_received = 0;
    $conn->stats_bytes_sent = 0;
    $conn->stats_packets_received = 0;
    $conn->stats_packets_sent = 0;
    $conn->bytes_in_flight = 0;
    $conn->congestion_window = PHP_INT_MAX;
    $conn->ssthresh = PHP_INT_MAX;
    $conn->recovery_start_time = 0.0;
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
    $conn->handshake_done_sent = true;
    $conn->ack_pending = [
        QuicConnection::LEVEL_INITIAL => false,
        QuicConnection::LEVEL_HANDSHAKE => false,
        QuicConnection::LEVEL_APPLICATION => false,
    ];
    $conn->next_pn = [
        QuicConnection::LEVEL_INITIAL => 0,
        QuicConnection::LEVEL_HANDSHAKE => 0,
        QuicConnection::LEVEL_APPLICATION => 0,
    ];
    $conn->local_cid = "\x01\x02\x03\x04\x05\x06\x07\x08";
    $conn->peer_cid = "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
    $secret = str_repeat("\x42", 32);
    $tx = QuicPacketKeys::fromTrafficSecret($secret,
        Tls13Engine::CIPHER_AES_128_GCM_SHA256);
    $rx = QuicPacketKeys::fromTrafficSecret($secret,
        Tls13Engine::CIPHER_AES_128_GCM_SHA256);
    $conn->keys = [
        QuicConnection::LEVEL_APPLICATION => [
            'tx' => $tx,
            'rx' => $rx,
        ],
    ];
    return $conn;
}

/*
    Build a queue1Rtt-style entry whose unencrypted payload
    is $size bytes. Padded with PADDING frames (single-byte
    0x00 frames). The amp gate looks at strlen(payload) only;
    the hint marks it in_flight=true so the cwnd path also
    runs to ensure realistic accounting.
 */
function paddedEntry($size)
{
    return [
        QuicConnection::LEVEL_APPLICATION,
        str_repeat(chr(QuicFrame::F_PADDING), $size),
        'pending',
        [
            'ack_eliciting' => false,
            'in_flight' => true,
            'frames' => [['type' => QuicFrame::F_PADDING]],
        ],
    ];
}

/*
    Test 1: pre-ESTABLISHED with zero bytes received -> the
    amp budget is zero. Every entry's gate-bound (size+80)
    exceeds 0; the queue retains both.
 */
$conn = makeConn();
$conn->stats_bytes_received = 0;
$conn->send_queue = [paddedEntry(100), paddedEntry(100)];
$out = $conn->emit();
ok("zero recv: emit produces no datagrams",
    $out === []);
ok("zero recv: queue retained for retry",
    count($conn->send_queue) === 2);

/*
    Test 2: budget tight enough to fit one but not two
    100-byte entries. recv=80 -> budget=240; first
    entry's gate-bound 180 <= 240 ships; the actual
    encoded packet is ~115 bytes (100 payload + ~15
    short-header overhead + 16 AEAD tag), decrementing
    budget to ~125. Second entry's gate-bound 180 > 125
    so it defers.
 */
$conn = makeConn();
$conn->stats_bytes_received = 80;
$conn->send_queue = [paddedEntry(100), paddedEntry(100)];
$out = $conn->emit();
ok("tight budget: emits exactly 1 datagram",
    count($out) === 1);
ok("tight budget: 1 entry retained",
    count($conn->send_queue) === 1);

/*
    Test 3: ample budget lets all entries through.
    recv=10000 -> budget=30000.
 */
$conn = makeConn();
$conn->stats_bytes_received = 10000;
for ($i = 0; $i < 5; $i++) {
    $conn->send_queue[] = paddedEntry(100);
}
$out = $conn->emit();
ok("ample budget: all 5 ship",
    count($out) === 5);
ok("ample budget: queue empty",
    count($conn->send_queue) === 0);

/*
    Test 4: ST_ESTABLISHED bypasses the cap entirely.
 */
$conn = makeConn();
$conn->state = QuicConnection::ST_ESTABLISHED;
$conn->stats_bytes_received = 0;
for ($i = 0; $i < 5; $i++) {
    $conn->send_queue[] = paddedEntry(100);
}
$out = $conn->emit();
ok("established: cap lifts, all 5 ship",
    count($out) === 5);
ok("established: queue empty",
    count($conn->send_queue) === 0);

/*
    Test 5: existing stats_bytes_sent counts against the
    budget. recv=200 -> raw budget=600; sent already=400
    -> remaining=200. First 100-byte entry's gate-bound
    180 <= 200, ships once; second entry sees decremented
    budget below 180 and defers.
 */
$conn = makeConn();
$conn->stats_bytes_received = 200;
$conn->stats_bytes_sent = 400;
$conn->send_queue = [paddedEntry(100), paddedEntry(100)];
$out = $conn->emit();
ok("budget after prior sends: emits 1 datagram",
    count($out) === 1);
ok("budget after prior sends: 1 entry retained",
    count($conn->send_queue) === 1);

/*
    Test 6: factor is exactly 3. A single 100-byte payload
    has gate-bound 180. recv=60 -> budget=180 exactly meets
    the > test (180 > 180 is false -> ships). recv=59 ->
    budget=177 < 180 -> defers.
 */
$conn = makeConn();
$conn->stats_bytes_received = 60;
$conn->send_queue = [paddedEntry(100)];
$out = $conn->emit();
ok("factor=3: budget=180 fits 100B+overhead exactly",
    count($out) === 1);

$conn = makeConn();
$conn->stats_bytes_received = 59;
$conn->send_queue = [paddedEntry(100)];
$out = $conn->emit();
ok("factor=3: budget=177 just below bound, defer",
    count($out) === 0
    && count($conn->send_queue) === 1);

/*
    Test 7: queue order preserved across cap deferrals.
    recv=80 -> budget=240; first 100-byte entry ships,
    remaining 4 defer in original order.
 */
$conn = makeConn();
$conn->stats_bytes_received = 80;
$entries = [];
for ($i = 0; $i < 5; $i++) {
    $entries[] = paddedEntry(100);
    /*
        Tag each entry's payload with a unique trailing
        byte to identify it post-defer. 99 leading PADDING
        bytes plus tag is still 100 bytes total payload.
     */
    $entries[$i][1] = str_repeat(chr(QuicFrame::F_PADDING),
        99) . chr($i);
}
$conn->send_queue = $entries;
$out = $conn->emit();
ok("reorder: 1 datagram emitted",
    count($out) === 1);
ok("reorder: 4 entries retained",
    count($conn->send_queue) === 4);
$retained = $conn->send_queue;
ok("reorder: 2nd entry kept first after deferral",
    $retained[0][1] === str_repeat(chr(QuicFrame::F_PADDING),
        99) . chr(1));
ok("reorder: 5th entry kept last after deferral",
    $retained[3][1] === str_repeat(chr(QuicFrame::F_PADDING),
        99) . chr(4));

/*
    Test 8: budget stable across multiple emit() calls
    with no new bytes received.
 */
$conn = makeConn();
$conn->stats_bytes_received = 80;
$conn->send_queue = [paddedEntry(100), paddedEntry(100)];
$out1 = $conn->emit();
$out2 = $conn->emit();
ok("multi-emit no new recv: total datagrams = 1",
    count($out1) + count($out2) === 1);
ok("multi-emit no new recv: queue stable at 1",
    count($conn->send_queue) === 1);

/*
    Test 9: budget grows when new bytes arrive between
    emit() calls.
 */
$conn = makeConn();
$conn->stats_bytes_received = 80;
$conn->send_queue = [paddedEntry(100), paddedEntry(100)];
$conn->emit();
$conn->stats_bytes_received += 1200;
$conn->emit();
ok("budget grows after new recv: queue drains",
    count($conn->send_queue) === 0);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
