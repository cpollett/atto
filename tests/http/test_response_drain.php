<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the WebSite::processResponseStreams head-
 * pointer drain. Verifies that draining a buffer of size N
 * across multiple partial-write cycles (the typical pattern
 * when a kernel TCP send buffer is smaller than the response
 * body) runs in O(N) total time rather than O(N^2). Also
 * covers the periodic compaction of the consumed prefix and
 * the integrity of the byte stream observed by the receiver.
 *
 * Run from the repo root:
 *     php tests/http/test_response_drain.php
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

require __DIR__ . '/../../src/WebSite.php';

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
    Build a WebSite instance without invoking its constructor
    (which expects to be inside a CLI request lifecycle and
    sets up signal handlers, server globals, etc that we
    don't need for an offline drain test).
 */
function makeWebSite()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\WebSite');
    $ws = $rc->newInstanceWithoutConstructor();
    $rp = $rc->getProperty('out_streams');
    $rp->setValue($ws, [
        WebSite::CONNECTION => [],
        WebSite::DATA => [],
        WebSite::DATA_OFFSET => [],
        WebSite::CONTEXT => [],
        WebSite::MODIFIED_TIME => [],
    ]);
    $rp = $rc->getProperty('in_streams');
    $rp->setValue($ws, [
        WebSite::CONNECTION => [],
        WebSite::DATA => [],
    ]);
    $rp = $rc->getProperty('connections');
    $rp->setValue($ws, []);
    $rp = $rc->getProperty('default_server_globals');
    $rp->setValue($ws, []);
    return [$ws, $rc];
}

function getOutStreams($rc, $ws)
{
    $rp = $rc->getProperty('out_streams');
    return $rp->getValue($ws);
}

function setOutStreams($rc, $ws, $val)
{
    $rp = $rc->getProperty('out_streams');
    $rp->setValue($ws, $val);
}

/*
    Drain the entire buffer for $key. Returns the bytes the
    receiver observed plus the number of drain iterations and
    the wall time. The drain loop calls processResponseStreams
    in a tight cycle and reads from the receiver socket until
    the entry vanishes from out_streams.
 */
function drainAll($ws, $rc, $write_end, $read_end, $key,
    $max_iter = 10000)
{
    $rm = new \ReflectionMethod(
        'seekquarry\\atto\\WebSite', 'processResponseStreams');
    $received = '';
    $iter = 0;
    $start = microtime(true);
    while ($iter < $max_iter) {
        $os = getOutStreams($rc, $ws);
        if (!isset($os[WebSite::DATA][$key])) {
            break;
        }
        $rm->invoke($ws, [$write_end]);
        while (($chunk = @fread($read_end, 65536)) !== false
            && strlen($chunk) > 0) {
            $received .= $chunk;
        }
        $iter++;
    }
    /*
        After processResponseStreams unsets the DATA entry the
        kernel may still hold buffered bytes for one more
        select(). Drain those before returning.
     */
    $deadline = microtime(true) + 0.1;
    while (microtime(true) < $deadline) {
        $chunk = @fread($read_end, 65536);
        if ($chunk === false || strlen($chunk) === 0) {
            usleep(1000);
            continue;
        }
        $received .= $chunk;
        $deadline = microtime(true) + 0.05;
    }
    $elapsed_ms = (microtime(true) - $start) * 1000;
    return [$received, $iter, $elapsed_ms];
}

/*
    Stage a response of the given size into out_streams as if
    a CLI HTTP/1.0 request had just dispatched. Returns the
    receiver socket so the caller can read what fwrite emits.
 */
function stageResponse($ws, $rc, $size, &$write_end_out,
    &$read_end_out)
{
    $pair = stream_socket_pair(STREAM_PF_UNIX,
        STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    list($read_end, $write_end) = $pair;
    stream_set_blocking($read_end, false);
    stream_set_blocking($write_end, false);
    $key = (int) $write_end;
    $payload = str_repeat('z', $size);
    $os = getOutStreams($rc, $ws);
    $os[WebSite::CONNECTION][$key] = $write_end;
    $os[WebSite::DATA][$key] = $payload;
    $os[WebSite::DATA_OFFSET][$key] = 0;
    $os[WebSite::CONTEXT][$key] =
        ['SERVER_PROTOCOL' => 'HTTP/1.0'];
    $os[WebSite::MODIFIED_TIME][$key] = time();
    setOutStreams($rc, $ws, $os);
    $write_end_out = $write_end;
    $read_end_out = $read_end;
    return [$key, $payload];
}

/*
    -----------------------------------------------------------
    Functional correctness
    -----------------------------------------------------------
 */

/* Test 1: a small response drains in one or two cycles and
   the receiver sees the exact bytes. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 4096,
    $write_end, $read_end);
list($received, $iter, $elapsed) = drainAll($ws, $rc,
    $write_end, $read_end, $key);
ok("4 KiB response drains correctly",
    $received === $payload);
ok("4 KiB response drained quickly",
    $iter < 5);
fclose($write_end); fclose($read_end);

/* Test 2: a 1 MiB response drains and matches byte-for-byte.
   This is the regression case for the substr-shift bug --
   under the old code the drain loop was correct but slow;
   here we just confirm correctness. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 1024 * 1024,
    $write_end, $read_end);
list($received, $iter, $elapsed_1mb) = drainAll($ws, $rc,
    $write_end, $read_end, $key);
ok("1 MiB response drains correctly",
    $received === $payload);
ok(sprintf("1 MiB drain runs in <500ms (got %.1fms)",
    $elapsed_1mb),
    $elapsed_1mb < 500.0);
fclose($write_end); fclose($read_end);

/*
    -----------------------------------------------------------
    Compaction
    -----------------------------------------------------------
 */

/* Test 3: a partial drain that doesn't finish leaves the
   buffer in a state where DATA_OFFSET tracks the position.
   We need the payload to be larger than the kernel sendbuf
   so that fwrite returns partial bytes; on Linux that's
   typically ~200 KiB but can be more. 8 MiB is large enough
   to be confident we'll get at least one partial write
   before the kernel buffer drains. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 8 * 1024 * 1024,
    $write_end, $read_end);
$rm = new \ReflectionMethod('seekquarry\\atto\\WebSite',
    'processResponseStreams');
/* One drain cycle fills the kernel sendbuf without exhausting
   the response. */
$rm->invoke($ws, [$write_end]);
$os = getOutStreams($rc, $ws);
$first_offset = $os[WebSite::DATA_OFFSET][$key] ?? 0;
ok("partial drain advances DATA_OFFSET",
    $first_offset > 0
    && $first_offset < 8 * 1024 * 1024);
ok("partial drain leaves DATA buffer untouched (no shift)",
    isset($os[WebSite::DATA][$key])
    && strlen($os[WebSite::DATA][$key]) === 8 * 1024 * 1024);
/* Drain the rest so the next test gets a clean slate. */
drainAll($ws, $rc, $write_end, $read_end, $key, 50000);
fclose($write_end); fclose($read_end);

/* Test 4: when DATA_OFFSET crosses the compaction threshold
   the underlying buffer shrinks. Use an 8 MiB payload so
   compaction definitely fires before the buffer drains. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 8 * 1024 * 1024,
    $write_end, $read_end);
$compaction_seen = false;
for ($i = 0; $i < 1000; $i++) {
    $os = getOutStreams($rc, $ws);
    if (!isset($os[WebSite::DATA][$key])) {
        break;
    }
    $rm->invoke($ws, [$write_end]);
    /* Drain the receiver so the kernel sendbuf can keep
       absorbing fresh writes -- otherwise the loop stalls
       at "remaining_bytes > 0 but fwrite returns 0". */
    while (($chunk = @fread($read_end, 65536)) !== false
        && strlen($chunk) > 0) {
        /* discard */
    }
    $os = getOutStreams($rc, $ws);
    if (isset($os[WebSite::DATA][$key])
        && strlen($os[WebSite::DATA][$key])
            < 8 * 1024 * 1024) {
        $compaction_seen = true;
        break;
    }
}
ok("compaction shrinks DATA below original size",
    $compaction_seen);
/* Drain remainder to clean up. */
drainAll($ws, $rc, $write_end, $read_end, $key, 50000);
fclose($write_end); fclose($read_end);

/*
    -----------------------------------------------------------
    Linear-time drain (the regression we're guarding against)
    -----------------------------------------------------------
 */

/* Test 5: scaling. A 4 MiB drain should not show quadratic
   blow-up vs the 1 MiB case above. Quadratic would be 16x;
   linear-with-syscall-overhead is closer to 4x; we accept
   anything below 8x. Note that the kernel sendbuf gates the
   per-cycle bytes-emitted, so total syscall count scales
   linearly with size and so does iter count. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 4 * 1024 * 1024,
    $write_end, $read_end);
list($received, $iter, $elapsed_4mb) = drainAll($ws, $rc,
    $write_end, $read_end, $key, 50000);
ok("4 MiB response drains correctly",
    strlen($received) === 4 * 1024 * 1024);
$ratio = $elapsed_1mb > 0 ? $elapsed_4mb / $elapsed_1mb : 0;
ok(sprintf(
    "4 MiB / 1 MiB ratio is sub-quadratic (got %.1fx, "
    . "quadratic would be ~16x)", $ratio),
    $ratio < 8.0);
fclose($write_end); fclose($read_end);

/*
    -----------------------------------------------------------
    Lifecycle: cleanup unsets DATA_OFFSET
    -----------------------------------------------------------
 */

/* Test 6: after the buffer drains to 0 and the H1.0 close
   path runs, the entry must be fully gone -- not just from
   DATA but also from DATA_OFFSET. A leaked DATA_OFFSET would
   eventually accumulate stale keys for connections long
   since closed. */
list($ws, $rc) = makeWebSite();
list($key, $payload) = stageResponse($ws, $rc, 4096,
    $write_end, $read_end);
drainAll($ws, $rc, $write_end, $read_end, $key);
$os = getOutStreams($rc, $ws);
ok("cleanup removes DATA entry",
    !isset($os[WebSite::DATA][$key]));
ok("cleanup removes DATA_OFFSET entry",
    !isset($os[WebSite::DATA_OFFSET][$key]));
fclose($write_end); fclose($read_end);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
