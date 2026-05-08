<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9000 sec 5.1 connection-ID
 * management state machine: NEW_CONNECTION_ID issuance after
 * handshake, the issued_cids book-keeping, RETIRE_CONNECTION
 * _ID handling with pool top-up, the listener's on_cid_-
 * retired callback, the stateless-reset-token derivation,
 * and the loss-retransmission path that re-queues a
 * NEW_CONNECTION_ID frame whose carrier packet was declared
 * lost (RFC 9000 sec 13.3).
 *
 * Run from the repo root:
 *     php tests/http3/test_connection_id_management.php
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
    Build a QuicConnection in just enough of an established
    state to exercise the CID-management surface. Sets a
    deterministic stateless_reset_secret so the token
    derivation is reproducible.
 */
function makeConn()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
    $conn = $rc->newInstanceWithoutConstructor();
    $conn->local_cid = "\x01\x02\x03\x04\x05\x06\x07\x08";
    $conn->peer_cid = "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
    $conn->issued_cids = [0 => $conn->local_cid];
    $conn->cid_seq_next = 1;
    $conn->active_cid_limit_peer = 4;
    $conn->new_cids_pending = [];
    $conn->stateless_reset_secret = str_repeat("\x42", 32);
    $conn->on_cid_retired = null;
    return $conn;
}

/*
    Test 1: fillCidPool tops the pool to active_cid_limit_-
    peer. With seq 0 already present and limit=4, three new
    CIDs should be minted (seq 1, 2, 3).
 */
$conn = makeConn();
$queued = $conn->fillCidPool();
ok("fillCidPool: 3 fresh CIDs queued",
    $queued === 3);
ok("fillCidPool: issued_cids has 4 entries (0..3)",
    count($conn->issued_cids) === 4
    && isset($conn->issued_cids[0])
    && isset($conn->issued_cids[1])
    && isset($conn->issued_cids[2])
    && isset($conn->issued_cids[3]));
ok("fillCidPool: cid_seq_next advances to 4",
    $conn->cid_seq_next === 4);
ok("fillCidPool: new_cids_pending has 3 entries",
    count($conn->new_cids_pending) === 3);

/*
    Test 2: each pending entry has the right shape and
    carries a 16-byte stateless reset token.
 */
$entry = $conn->new_cids_pending[0];
ok("pending entry: has 'sequence'",
    isset($entry['sequence']) && $entry['sequence'] === 1);
ok("pending entry: has 'cid' of 8 bytes",
    isset($entry['cid']) && strlen($entry['cid']) === 8);
ok("pending entry: has 16-byte token",
    isset($entry['token']) && strlen($entry['token']) === 16);

/*
    Test 3: each minted CID is unique.
 */
$cids = [];
foreach ($conn->issued_cids as $cid) {
    $cids[bin2hex($cid)] = true;
}
ok("issued CIDs are pairwise distinct",
    count($cids) === count($conn->issued_cids));

/*
    Test 4: fillCidPool is idempotent when pool is already
    full. Second call should queue zero new entries.
 */
$conn = makeConn();
$conn->fillCidPool();
$queued2 = $conn->fillCidPool();
ok("fillCidPool: second call is a no-op",
    $queued2 === 0);

/*
    Test 5: statelessResetToken is deterministic given the
    same CID and secret, distinct for distinct CIDs.
 */
$conn = makeConn();
$cid_a = "\xaa\xbb\xcc\xdd\xee\xff\x11\x22";
$cid_b = "\x33\x44\x55\x66\x77\x88\x99\x00";
$tok_a1 = $conn->statelessResetToken($cid_a);
$tok_a2 = $conn->statelessResetToken($cid_a);
$tok_b = $conn->statelessResetToken($cid_b);
ok("statelessResetToken: deterministic for same CID",
    $tok_a1 === $tok_a2);
ok("statelessResetToken: distinct for distinct CIDs",
    $tok_a1 !== $tok_b);
ok("statelessResetToken: 16 bytes",
    strlen($tok_a1) === 16);

/*
    Test 6: when no secret is set, statelessResetToken
    returns a 16-byte random fallback.
 */
$conn = makeConn();
$conn->stateless_reset_secret = "";
$tok_r1 = $conn->statelessResetToken("anything");
$tok_r2 = $conn->statelessResetToken("anything");
ok("no secret: token is 16 bytes",
    strlen($tok_r1) === 16);
ok("no secret: each call is a fresh random",
    $tok_r1 !== $tok_r2);

/*
    Test 7: retireLocalCid removes the entry, returns the
    CID bytes, and tops the pool back up.
 */
$conn = makeConn();
$conn->fillCidPool();
$cid_seq2 = $conn->issued_cids[2];
$conn->new_cids_pending = [];  /* simulate emit() flushed */
$retired = $conn->retireLocalCid(2);
ok("retire: returns retired CID bytes",
    $retired === $cid_seq2);
ok("retire: removes seq from issued_cids",
    !isset($conn->issued_cids[2]));
ok("retire: tops pool back up",
    count($conn->issued_cids) === 4);
ok("retire: new replacement queued in pending",
    count($conn->new_cids_pending) === 1
    && $conn->new_cids_pending[0]['sequence'] === 4);

/*
    Test 8: retireLocalCid on an unknown sequence is a
    no-op (idempotent), per docblock.
 */
$conn = makeConn();
$conn->fillCidPool();
$initial_count = count($conn->issued_cids);
$retired = $conn->retireLocalCid(99);
ok("retire unknown: returns empty string",
    $retired === '');
ok("retire unknown: pool unchanged",
    count($conn->issued_cids) === $initial_count);

/*
    Test 9: on_cid_retired callback is fired when a real
    sequence is retired. Used by the listener to drop its
    cid_index entry.
 */
$conn = makeConn();
$conn->fillCidPool();
$conn->new_cids_pending = [];
$callback_arg = null;
$conn->on_cid_retired = function ($cid) use (&$callback_arg) {
    $callback_arg = $cid;
};
$cid_to_retire = $conn->issued_cids[1];
/*
    Drive the call the same way QuicConnection's
    F_RETIRE_CONNECTION_ID dispatch does.
 */
$retired = $conn->retireLocalCid(1);
if ($retired !== '' && $conn->on_cid_retired !== null) {
    call_user_func($conn->on_cid_retired, $retired);
}
ok("retire callback: fired with retired CID",
    $callback_arg === $cid_to_retire);

/*
    Test 10: factor=peer_limit. fillCidPool honors the
    peer's advertised active_connection_id_limit. Drop the
    limit to 2 -> only 1 new CID should be queued (seq 0
    is the original local_cid).
 */
$conn = makeConn();
$conn->active_cid_limit_peer = 2;
$queued = $conn->fillCidPool();
ok("limit=2: 1 fresh CID queued",
    $queued === 1);
ok("limit=2: issued_cids has 2 entries",
    count($conn->issued_cids) === 2);

/*
    Test 11: limit=8 yields a larger pool.
 */
$conn = makeConn();
$conn->active_cid_limit_peer = 8;
$queued = $conn->fillCidPool();
ok("limit=8: 7 fresh CIDs queued",
    $queued === 7);
ok("limit=8: issued_cids has 8 entries",
    count($conn->issued_cids) === 8);

/*
    Test 12: loss retransmission. When a packet carrying a
    NEW_CONNECTION_ID frame is declared lost, onPacketsLost
    re-queues an identical frame on the 1-RTT send queue
    per RFC 9000 sec 13.3.
 */
$rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
$conn = $rc->newInstanceWithoutConstructor();
$conn->state = QuicConnection::ST_HANDSHAKING;
$conn->bytes_in_flight = 1200;
$conn->congestion_window = 16800;
$conn->ssthresh = PHP_INT_MAX;
$conn->recovery_start_time = 0.0;
$conn->send_queue = [];
$conn->stats_bytes_sent = 0;
$conn->stats_bytes_received = 0;
/*
    Build a "lost packet" entry mirroring the shape
    sent_packets carries. Frame content is the
    NEW_CONNECTION_ID we want re-queued.
 */
$frame = [
    'type' => QuicFrame::F_NEW_CONNECTION_ID,
    'sequence' => 1,
    'retire_prior_to' => 0,
    'cid' => "\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
    'stateless_reset_token' => str_repeat("\x77", 16),
];
$lost = [[
    'pn' => 5,
    'time_sent' => microtime(true),
    'ack_eliciting' => true,
    'in_flight' => true,
    'sent_bytes' => 50,
    'frames' => [$frame],
]];
$rm = new \ReflectionMethod('seekquarry\\atto\\QuicConnection',
    'onPacketsLost');
$rm->invokeArgs($conn,
    [QuicConnection::LEVEL_APPLICATION, $lost]);

ok("loss retx: 1 entry on send_queue after replay",
    count($conn->send_queue) === 1);
$replayed = $conn->send_queue[0];
ok("loss retx: replayed at LEVEL_APPLICATION",
    $replayed[0] === QuicConnection::LEVEL_APPLICATION);
$decoded = QuicFrame::decodeAll($replayed[1]);
list($frames, $err) = $decoded;
ok("loss retx: payload decodes to one frame",
    $err === '' && count($frames) === 1);
$got = $frames[0];
ok("loss retx: same frame type",
    $got['type'] === QuicFrame::F_NEW_CONNECTION_ID);
ok("loss retx: same sequence",
    $got['sequence'] === 1);
ok("loss retx: same CID bytes",
    $got['cid'] === $frame['cid']);
ok("loss retx: same stateless reset token",
    $got['stateless_reset_token']
    === $frame['stateless_reset_token']);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
