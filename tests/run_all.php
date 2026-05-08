<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Test runner. Walks tests/<subsystem>/test_*.php and runs
 * each one as a separate PHP process. A test file is
 * considered to pass if its exit status is 0; tests are
 * expected to print a "Tests run:"/"Tests passed:" summary
 * to stdout and exit non-zero on any failure (the existing
 * test files in tests/http3/ already follow this contract).
 *
 * Run from the repo root:
 *     php tests/run_all.php
 *     php tests/run_all.php http3        # filter to subsystem
 *
 * Exits 0 if every test file passed, 1 otherwise.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */

$tests_dir = __DIR__;
$filter = isset($argv[1]) ? $argv[1] : null;

$found = [];
foreach (new \DirectoryIterator($tests_dir) as $entry) {
    if ($entry->isDot() || !$entry->isDir()) {
        continue;
    }
    $subsystem = $entry->getFilename();
    if ($filter !== null && $subsystem !== $filter) {
        continue;
    }
    $sub_path = $entry->getPathname();
    foreach (glob($sub_path . '/test_*.php') as $test_file) {
        $found[] = [$subsystem, $test_file];
    }
}

if (empty($found)) {
    if ($filter !== null) {
        fwrite(STDERR,
            "no tests found under tests/$filter/\n");
    } else {
        fwrite(STDERR, "no tests found under tests/\n");
    }
    exit(1);
}

$passed = 0;
$failed = 0;
$failures = [];
foreach ($found as $entry) {
    list($subsystem, $test_file) = $entry;
    $name = $subsystem . '/' . basename($test_file);
    /*
        Each test runs in a fresh PHP process so namespace /
        symbol collisions between test files (they all stub
        Connection / Listener / Transport classes) cannot
        affect each other.
     */
    $cmd = escapeshellarg(PHP_BINARY) . ' '
        . escapeshellarg($test_file) . ' 2>&1';
    $output = [];
    $exit_code = 0;
    exec($cmd, $output, $exit_code);
    /*
        Pull "Tests run:" / "Tests passed:" out of the test's
        output so the summary is informative without being
        noisy.
     */
    $run = '?';
    $pass = '?';
    foreach ($output as $line) {
        if (preg_match('/^Tests run:\s*(\d+)/', $line, $m)) {
            $run = $m[1];
        }
        if (preg_match('/^Tests passed:\s*(\d+)/', $line, $m)) {
            $pass = $m[1];
        }
    }
    if ($exit_code === 0) {
        echo sprintf("PASS  %-40s  %s/%s\n",
            $name, $pass, $run);
        $passed++;
    } else {
        echo sprintf("FAIL  %-40s  %s/%s\n",
            $name, $pass, $run);
        $failed++;
        $failures[] = [$name, $output];
    }
}

echo "\n";
echo "Test files run:    " . count($found) . "\n";
echo "Test files passed: $passed\n";
echo "Test files failed: $failed\n";

if (!empty($failures)) {
    echo "\n--- failure detail ---\n";
    foreach ($failures as $fail) {
        list($name, $output) = $fail;
        echo "\n[$name]\n";
        foreach ($output as $line) {
            echo "  $line\n";
        }
    }
}

exit($failed === 0 ? 0 : 1);
