<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Shared measurement helper for the H3 listener hotpath benchmarks.
 * It times one method call over many iterations and reports the
 * per-call cost, so a benchmark script only has to describe the
 * call and its inputs. This is deliberately not one of the pass/fail
 * tests: it measures time rather than asserting a result, and it is
 * slow by design, so it lives under a bench_ name the test runner
 * does not pick up.
 *
 * The recipe is the usual one for a micro-benchmark. Each call is
 * wrapped in a closure so the setup stays outside the timed loop;
 * the loop is warmed first so the opcode cache and any one-shot
 * self-tests inside the method are paid before timing starts; the
 * call is then timed over a fixed number of iterations, repeated a
 * few times, and the median per-call time is reported to smooth out
 * scheduler noise. The closure wrapper adds a small fixed overhead
 * to every row; a benchmark can print an empty-closure row so that
 * overhead is visible and can be subtracted when reading absolute
 * numbers. Because the overhead is fixed, it cancels when the same
 * method is measured before and after a tweak, which is what these
 * benchmarks are for.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * @var int calls made before timing starts, to warm the opcode
 *      cache and pay any one-shot cost inside the method under test
 */
const BENCH_WARMUP_ITERATIONS = 2000;
/**
 * @var int timed calls per repetition; large enough that the
 *      per-call time is stable against the clock's resolution
 */
const BENCH_DEFAULT_ITERATIONS = 20000;
/**
 * @var int repetitions whose median is reported; odd so the median
 *      is a single middle sample rather than an average of two
 */
const BENCH_DEFAULT_REPEATS = 7;
/**
 * @var int nanoseconds in one second, for the calls-per-second
 *      figure
 */
const BENCH_NS_PER_SECOND = 1000000000;
/**
 * @var int nanoseconds in one microsecond, for reporting in the
 *      microsecond units the bottlenecks note uses
 */
const BENCH_NS_PER_US = 1000;

/**
 * Prints the column header for a run of benchmark rows.
 */
function benchHeader()
{
    printf("  %-38s %10s  %14s\n", "method", "us/call", "calls/sec");
    printf("  %-38s %10s  %14s\n", str_repeat("-", 38),
        str_repeat("-", 10), str_repeat("-", 14));
}

/**
 * Times one call over many iterations and prints a row with its
 * median per-call cost. The setup for the call belongs in the
 * closure's captured variables, not inside the closure body, so only
 * the call itself is timed.
 *
 * @param string $name label for the method being timed
 * @param callable $call a closure that makes the one call to time
 * @param int $iterations timed calls per repetition
 * @param int $repeats repetitions whose median is reported
 * @return float the median nanoseconds per call
 */
function runBenchmark($name, callable $call,
    $iterations = BENCH_DEFAULT_ITERATIONS,
    $repeats = BENCH_DEFAULT_REPEATS)
{
    for ($i = 0; $i < BENCH_WARMUP_ITERATIONS; $i++) {
        $call();
    }
    $per_call = [];
    for ($repeat = 0; $repeat < $repeats; $repeat++) {
        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $call();
        }
        $per_call[] = (hrtime(true) - $start) / $iterations;
    }
    sort($per_call);
    $median = $per_call[intdiv($repeats, 2)];
    $micros = $median / BENCH_NS_PER_US;
    $ops = $median > 0 ? BENCH_NS_PER_SECOND / $median : 0;
    printf("  %-38s %10.3f  %14s\n", $name, $micros,
        number_format($ops));
    return $median;
}
