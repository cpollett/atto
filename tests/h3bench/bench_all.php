<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Runs every H3 listener benchmark and prints their output in one
 * place. It finds the bench_*.php scripts beside it, skips itself,
 * and runs each in its own PHP process so one benchmark's warmed
 * state cannot color another's numbers. Each script is also runnable
 * on its own; this is just the convenience that runs them all.
 *
 * These are benchmarks, not the pass/fail tests: they are timed
 * rather than asserted, so they are kept out of tests/run_all.php,
 * which runs the test_*.php scripts and reads their exit status.
 *
 * Run from the repo root:
 *     php tests/h3bench/bench_all.php
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

$self = basename(__FILE__);
$scripts = glob(__DIR__ . '/bench_*.php');
sort($scripts);
foreach ($scripts as $script) {
    if (basename($script) === $self) {
        continue;
    }
    echo "=== " . basename($script) . " ===\n";
    $lines = [];
    exec('php ' . escapeshellarg($script), $lines);
    echo implode("\n", $lines) . "\n\n";
}
