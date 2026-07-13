<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for H3Listener's reaped-connection stats ring: the
 * short history of connections that have left the live table so a
 * /h3stats?keep=1 or benchmark read landing just after a peer
 * closed can still see the connection's final counters (including
 * its ack-frequency cadence). Covers capturing an entry, tagging
 * it with a reason and reaped_at, preserving the ack_frequency
 * block, and bounding the ring at REAPED_STATS_RING.
 *
 * Run from the repo root:
 *     php tests/http3/test_reaped_stats.php
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
    Stub the parent classes H3Listener.php's classes extend, so
    the tests run without loading the whole framework.
 */
class Connection {}
class Listener
{
    public function __construct(...$arguments) {}
    public function close() {}
}
abstract class Transport
{
    public function __construct($site) {}
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
    A minimal stand-in for the QUIC layer: captureReapedStats only
    calls quic->stats(), so a stats() returning a fixed array is
    enough to exercise the ring without a live connection.
 */
class ReapedStatsFakeQuic
{
    public $sample;
    public function __construct($sample)
    {
        $this->sample = $sample;
    }
    public function stats()
    {
        return $this->sample;
    }
}

/*
    A minimal stand-in for H3Connection: captureReapedStats reads
    only its quic property.
 */
class ReapedStatsFakeConnection
{
    public $quic;
    public function __construct($sample)
    {
        $this->quic = new ReapedStatsFakeQuic($sample);
    }
}

/* Builds an H3Listener without running its constructor. */
function makeListener()
{
    $reflected = new \ReflectionClass(
        'seekquarry\\atto\\H3Listener');
    $listener = $reflected->newInstanceWithoutConstructor();
    $listener->reaped_stats = [];
    return $listener;
}

/* A single closing connection is captured with its context. */
$listener = makeListener();
$sample = [
    'packets_sent' => 42,
    'ack_frequency' => [
        'peer_advertised' => false,
        'ack_packets_received' => 4,
    ],
];
$listener->captureReapedStats(
    new ReapedStatsFakeConnection($sample), 'closed');
$reaped = $listener->snapshotReapedStats();
ok("one reaped entry retained", count($reaped) === 1);
ok("reaped entry keeps ack_frequency block",
    isset($reaped[0]['ack_frequency'])
    && $reaped[0]['ack_frequency']['ack_packets_received'] === 4);
ok("reaped entry tagged with reason",
    ($reaped[0]['reason'] ?? null) === 'closed');
ok("reaped entry tagged with reaped_at float",
    is_float($reaped[0]['reaped_at'] ?? null));

/* The reason passed through is the one recorded. */
$listener = makeListener();
$listener->captureReapedStats(
    new ReapedStatsFakeConnection(['packets_sent' => 1]),
    'idle_timeout');
$reaped = $listener->snapshotReapedStats();
ok("idle_timeout reason recorded",
    ($reaped[0]['reason'] ?? null) === 'idle_timeout');

/*
    The ring drops the oldest entries once it exceeds
    REAPED_STATS_RING, keeping the most recent closures.
 */
$listener = makeListener();
$ring = H3Listener::REAPED_STATS_RING;
$total = $ring + 3;
for ($i = 0; $i < $total; $i++) {
    $listener->captureReapedStats(
        new ReapedStatsFakeConnection(['packets_sent' => $i]),
        'closed');
}
$reaped = $listener->snapshotReapedStats();
ok("ring bounded to REAPED_STATS_RING",
    count($reaped) === $ring);
ok("ring keeps newest closures, drops oldest",
    $reaped[0]['packets_sent'] === 3
    && $reaped[$ring - 1]['packets_sent'] === $total - 1);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
