<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the QuicStream send-side buffer's head-
 * pointer drain. Verifies that draining a buffer of size N
 * in fixed-size chunks runs in O(N) total time rather than
 * O(N^2), which the pre-head-pointer implementation
 * exhibited (each takeForFrame() did a substr-shift of the
 * remaining tail). Also covers the periodic compaction
 * threshold so memory does not grow unboundedly across long-
 * lived streams, and the basic offset / FIN bookkeeping
 * around bufferedLength().
 *
 * Run from the repo root:
 *     php tests/http3/test_stream_send_buffer.php
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
    -----------------------------------------------------------
    Basic invariants
    -----------------------------------------------------------
 */

/* Test 1: a fresh stream reports 0 buffered. */
$s = new QuicStream(0);
ok("fresh stream bufferedLength == 0",
    $s->bufferedLength() === 0);
ok("fresh stream takeForFrame returns null",
    $s->takeForFrame(1100) === null);

/* Test 2: write + bufferedLength tracks the append. */
$s = new QuicStream(0);
$s->write(str_repeat('a', 5000));
ok("after write, bufferedLength == bytes written",
    $s->bufferedLength() === 5000);

/* Test 3: takeForFrame returns the right offset / data, and
   bufferedLength shrinks accordingly. */
$tup = $s->takeForFrame(1100);
ok("takeForFrame returns 3-tuple",
    is_array($tup) && count($tup) === 3);
list($off, $data, $fin) = $tup;
ok("first frame offset == 0",
    $off === 0);
ok("first frame data length == 1100",
    strlen($data) === 1100);
ok("first frame fin == false (no finish() called)",
    $fin === false);
ok("after first take, bufferedLength == 5000 - 1100",
    $s->bufferedLength() === 3900);

/* Test 4: subsequent takes advance correctly. */
list($off2, $data2, $fin2) = $s->takeForFrame(1100);
ok("second frame offset == 1100",
    $off2 === 1100);
ok("second frame data is the next 1100 bytes",
    $data2 === substr(str_repeat('a', 5000), 1100, 1100));
ok("after second take, bufferedLength == 2800",
    $s->bufferedLength() === 2800);

/* Test 5: hasPendingSend reflects the buffered remainder. */
ok("hasPendingSend true while bytes remain",
    $s->hasPendingSend());

/* Test 6: drain to empty, then takeForFrame returns null. */
while ($s->bufferedLength() > 0) {
    $s->takeForFrame(1100);
}
ok("after full drain, bufferedLength == 0",
    $s->bufferedLength() === 0);
ok("after full drain, takeForFrame returns null",
    $s->takeForFrame(1100) === null);
ok("after full drain, hasPendingSend false",
    !$s->hasPendingSend());

/* Test 7: finish() then drain emits FIN on the last frame. */
$s = new QuicStream(0);
$s->write("hello");
$s->finish();
list($off, $data, $fin) = $s->takeForFrame(1100);
ok("FIN frame carries the payload",
    $data === "hello");
ok("FIN frame has fin == true",
    $fin === true);
ok("after FIN, takeForFrame returns null",
    $s->takeForFrame(1100) === null);

/*
    -----------------------------------------------------------
    Compaction
    -----------------------------------------------------------
 */

/* Test 8: small drains never trigger compaction (threshold
   is 64 KiB). After draining 32 KiB worth in 1100-byte chunks
   the underlying $send_buf is still the original size. */
$s = new QuicStream(0);
$s->write(str_repeat('x', 200000));
$initial_buf_len = strlen($s->send_buf);
for ($i = 0; $i < 30; $i++) {
    /* 30 * 1100 = 33000 bytes drained, well below the 65536
       compaction threshold. */
    $s->takeForFrame(1100);
}
ok("no compaction below SEND_BUF_COMPACT_THRESHOLD",
    strlen($s->send_buf) === $initial_buf_len
    && $s->send_buf_off === 33000);

/* Test 9: once draining crosses the threshold, the buffer
   compacts in place. Specifically, after compaction the
   underlying $send_buf shrinks (the consumed prefix has been
   dropped) and the head pointer must remain consistent --
   strlen(send_buf) - send_buf_off must equal the unconsumed
   remainder. The exact post-loop value of $send_buf_off
   depends on whether takeForFrame ran additional iterations
   after the compaction step itself; only the post-condition
   on bufferedLength is invariant. */
$s = new QuicStream(0);
$s->write(str_repeat('y', 200000));
$drained = 0;
while ($drained < 110000) {
    $tup = $s->takeForFrame(1100);
    if ($tup === null) {
        break;
    }
    $drained += strlen($tup[1]);
}
ok("compaction shrinks send_buf below original size",
    strlen($s->send_buf) < 200000);
ok("post-compaction state is internally consistent",
    strlen($s->send_buf) - $s->send_buf_off
    === 200000 - $drained);
ok("post-compaction bufferedLength is correct",
    $s->bufferedLength() === 200000 - $drained);

/* Test 10: post-compaction, takeForFrame still returns the
   correct contiguous offset (head pointer reset must not
   confuse send_next_offset). */
$tup = $s->takeForFrame(1100);
list($off, $data, $fin) = $tup;
ok("post-compaction frame offset is the cumulative drained",
    $off === $drained);
ok("post-compaction frame data is from the right slice",
    $data === substr(str_repeat('y', 200000),
        $drained, 1100));

/*
    -----------------------------------------------------------
    Linear-time drain (the original bug)
    -----------------------------------------------------------
 */

/*
    Test 11: timing test. Drain 1 MiB in 1100-byte frames and
    record the wall time. Without the head pointer this loop
    was O(n^2) and observably took >40 ms in PHP 8.x (each
    substr-shift copying ~1MB on average across ~950 calls).
    With the head pointer it should comfortably run in under
    20 ms. We pick a generous 100 ms ceiling so the assertion
    survives slow CI runners; the regression we are guarding
    against was multi-hundred-ms for larger payloads.

    The drain loop here mirrors flushStreams' own break
    condition: once takeForFrame returns either null or an
    empty payload, no more data can leave this tick.
 */
$s = new QuicStream(0);
$s->write(str_repeat('z', 1024 * 1024));
$frames = 0;
$start = microtime(true);
while (true) {
    $tup = $s->takeForFrame(1100);
    if ($tup === null) {
        break;
    }
    list($_o, $_d, $_f) = $tup;
    if ($_d === '' && !$_f) {
        break;
    }
    $frames++;
}
$elapsed_ms = (microtime(true) - $start) * 1000;
ok("1 MiB drains to >900 frames",
    $frames > 900);
ok(sprintf("1 MiB drain runs in <100ms (got %.1fms)",
    $elapsed_ms),
    $elapsed_ms < 100.0);

/*
    Test 12: scaling check. Drain 4 MiB and confirm wall time
    is roughly linear vs the 1 MiB case (within ~6x, generous
    margin for PHP startup noise). The pre-head-pointer
    quadratic would show ~16x scaling on this comparison.

    NOTE: the default send_window on a QuicStream is 1 MiB
    (the peer's initial_max_stream_data, set by transport
    parameters). To drain 4 MiB without congestion-driven
    pauses the test bumps send_window to 8 MiB up front. In
    real use a peer would advertise a larger window via
    MAX_STREAM_DATA before the response approaches 1 MiB.
 */
$s = new QuicStream(0);
$s->send_window = 8 * 1024 * 1024;
$s->write(str_repeat('z', 4 * 1024 * 1024));
$start = microtime(true);
while (true) {
    $tup = $s->takeForFrame(1100);
    if ($tup === null) {
        break;
    }
    list($_o, $_d, $_f) = $tup;
    if ($_d === '' && !$_f) {
        break;
    }
}
$elapsed_4mb_ms = (microtime(true) - $start) * 1000;
$ratio = $elapsed_ms > 0 ? $elapsed_4mb_ms / $elapsed_ms : 0;
ok(sprintf(
    "4 MiB / 1 MiB ratio is sub-quadratic (got %.1fx, "
    . "quadratic would be ~16x)", $ratio),
    $ratio < 8.0);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
