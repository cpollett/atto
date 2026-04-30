<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    Atto benchmark dashboard. Pair with bench.php in the same
    folder, which is the runner that hits the test endpoints
    over each available HTTP protocol.

    HOW TO RUN:
        From the repo root:
            php index.php 16
        Then open the URL the server prints (typically
        http://localhost:8080/) in a browser and click
        "Run benchmark". The dashboard polls a status endpoint
        and fills in a results table as each case completes.

        From this folder (after commenting the guard above):
            php index.php
        And separately, for the CLI report:
            php bench.php

    ROUTES:
        /             dashboard with a "Run benchmark" button
                      and a results area populated incrementally
                      as each case completes.
        POST /run     spawn bench.php in a child process; the
                      child writes incrementally to a temp file
                      while running. Returns immediately.
        GET /status   returns the temp-file contents plus a
                      done flag. The dashboard polls this.

    TEST ENDPOINTS (protocol-agnostic; the runner negotiates H1
    or H2 per request based on ALPN):
        /small        2-byte response — per-request overhead
        /big          1 MiB response — sustained throughput
        /asset/{n}    indexed small response — parallel-fetch
        /headers      100 custom headers — HPack vs plaintext

    The server listens on both plain HTTP (8080) and TLS (8443)
    so the runner can compare protocols on the same code path:
    HTTP/1.1 negotiates over either; HTTP/2 needs ALPN over TLS.
    A third "HTTP/1.1+TLS" transport gives an apples-to-apples
    H2 comparison (same TLS overhead, only the protocol differs).
 */

/*
    Single shared output file for the in-flight bench run. One
    bench at a time per server process is fine for this demo.
    Reset on each /run invocation so a fresh poll cycle starts
    clean.
 */
$bench_out_file = sys_get_temp_dir() . "/atto_bench_dashboard_" .
    getmypid() . ".out";

$test->get('/', function () {
    ?><!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Atto Benchmark Dashboard</title>
<style>
    body { font-family: -apple-system, sans-serif; max-width: 900px;
        margin: 2em auto; padding: 0 1em; color: #222; }
    h1 { margin-bottom: 0.2em; }
    .meta { color: #666; font-size: 0.9em; margin-bottom: 1.5em; }
    button { font-size: 1em; padding: 0.6em 1.2em; cursor: pointer;
        background: #06c; color: white; border: 0;
        border-radius: 4px; }
    button:disabled { background: #888; cursor: default; }
    .case { margin: 1.2em 0; padding: 1em;
        border: 1px solid #ddd; border-radius: 6px;
        background: #fafafa; }
    .case h2 { margin: 0 0 0.3em; font-size: 1.1em; }
    .case .desc { color: #666; font-size: 0.85em;
        margin-bottom: 0.6em; }
    .case .status { float: right; font-size: 0.85em;
        font-weight: bold; }
    .case .status.pending { color: #999; }
    .case .status.running { color: #c60; }
    .case .status.done { color: #060; }
    table { width: 100%; border-collapse: collapse;
        font-family: monospace; font-size: 0.9em; }
    th, td { padding: 0.3em 0.6em; text-align: right;
        border-bottom: 1px solid #eee; }
    th { background: #efefef; font-weight: normal;
        color: #555; }
    th:first-child, td:first-child { text-align: left; }
    .raw { font-family: monospace; font-size: 0.8em;
        background: #222; color: #ddd; padding: 1em;
        border-radius: 4px; overflow-x: auto;
        white-space: pre; max-height: 12em; }
    .raw-toggle { color: #06c; cursor: pointer;
        text-decoration: underline; font-size: 0.85em; }
    #global_status { font-weight: bold; margin: 1em 0; }
</style>
</head>
<body>
<h1>Atto Benchmark Dashboard</h1>
<p class="meta">
    Runs a fixed suite over each available HTTP protocol and
    displays a comparison. Numbers are localhost-only and reflect
    Atto's single-threaded event loop &mdash; treat trends, not
    absolutes. <a href="/raw">Plain CLI output also available.</a>
</p>
<div id="controls">
    <button id="start_btn">Run benchmark</button>
    <label style="margin-left: 1em; font-size: 0.9em;
        color: #555;">
        Simulate network latency:
        <select id="latency_sel" style="font-size: 0.9em;
            padding: 0.3em;">
            <option value="0">none (loopback)</option>
            <option value="5">5ms each way (10ms RTT)</option>
            <option value="25">25ms each way (50ms RTT)</option>
            <option value="50">50ms each way (100ms RTT)</option>
            <option value="100">100ms each way (200ms RTT)</option>
        </select>
    </label>
</div>
<div id="global_status"></div>
<div id="results"></div>
<p style="margin-top: 2em;">
    <span class="raw-toggle" onclick="
        document.getElementById('raw_block').style.display =
            document.getElementById('raw_block').style.display
            === 'none' ? 'block' : 'none';
    ">Toggle raw output</span>
</p>
<pre class="raw" id="raw_block" style="display: none;"></pre>

<script>
/*
    The dashboard kicks off bench.php with POST /run, then polls
    GET /status every 300ms. Each poll returns the entire bench
    output produced so far, which the script parses into per-case
    sections. Each section becomes one card in the results area;
    the card transitions pending -> running -> done as new lines
    arrive. This is intentionally simple polling rather than SSE
    because Atto's streaming routes block the event loop while
    they're running, and bench.php hits this same server.
 */

// Seed cards in display order so they appear immediately.
var KNOWN_CASES = [
    {key: 'SMALL',     label: '/small (per-request overhead)'},
    {key: 'BIG',       label: '/big (1 MiB throughput)'},
    {key: 'ASSET',     label: '/asset (parallel multiplex)'},
    {key: 'HEADERS',   label: '/headers (HPack vs plain)'},
    {key: 'KEEPALIVE', label: '/small over one connection'},
];
var raw_el = document.getElementById('raw_block');
var results_el = document.getElementById('results');
var status_el = document.getElementById('global_status');
var btn = document.getElementById('start_btn');

function seedCards() {
    results_el.innerHTML = '';
    KNOWN_CASES.forEach(function (c) {
        var card = document.createElement('div');
        card.className = 'case';
        card.id = 'case_' + c.key;
        card.innerHTML =
            '<span class="status pending" id="status_' + c.key +
            '">pending</span>' +
            '<h2>' + c.key + '</h2>' +
            '<div class="desc" id="desc_' + c.key + '">' + c.label +
            '</div>' +
            '<div id="body_' + c.key + '"></div>';
        results_el.appendChild(card);
    });
}

function setStatus(case_key, status) {
    var s = document.getElementById('status_' + case_key);
    if (s) {
        s.className = 'status ' + status;
        s.textContent = status;
    }
}

function renderCase(case_key, desc, header_cols, rows) {
    document.getElementById('desc_' + case_key).textContent = desc;
    var html = '<table><thead><tr>';
    header_cols.forEach(function (h) {
        html += '<th>' + h + '</th>';
    });
    html += '</tr></thead><tbody>';
    rows.forEach(function (r) {
        html += '<tr>';
        r.forEach(function (c) {
            html += '<td>' + c + '</td>';
        });
        html += '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('body_' + case_key).innerHTML = html;
}

/*
    Parse the full bench output text into per-case sections.
    bench.php emits each case as:

        SMALL
          per-request overhead, 2-byte body
          protocol     iters    min ms    median   ...
          HTTP/1.1     ...
          HTTP/2       ...
        <blank>
        BIG
        ...

    A case is "done" when we've seen the trailing blank line
    after its rows.
 */
function parse(text) {
    var lines = text.split('\n');
    var cases = {};
    var current = null;
    var case_keys = KNOWN_CASES.map(function (c) { return c.key; });
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var stripped = line.trim();
        if (case_keys.indexOf(stripped) >= 0) {
            current = stripped;
            cases[current] = {desc: '', cols: [], rows: [],
                done: false};
            continue;
        }
        if (current === null) continue;
        if (stripped === '') {
            cases[current].done = true;
            current = null;
            continue;
        }
        var c = cases[current];
        if (c.desc === '') {
            c.desc = stripped;
        } else if (c.cols.length === 0) {
            c.cols = stripped.split(/\s+/);
        } else {
            c.rows.push(stripped.split(/\s+/));
        }
    }
    return cases;
}

var poll_handle = null;

function poll() {
    fetch('/status').then(function (r) { return r.json(); })
        .then(function (s) {
            raw_el.textContent = s.text;
            var cases = parse(s.text);
            // Update each known-case card.
            var any_running = false;
            for (var i = 0; i < KNOWN_CASES.length; i++) {
                var key = KNOWN_CASES[i].key;
                var c = cases[key];
                if (!c) {
                    setStatus(key, 'pending');
                    continue;
                }
                if (c.done) {
                    setStatus(key, 'done');
                } else {
                    setStatus(key, 'running');
                    any_running = true;
                }
                if (c.cols.length > 0) {
                    renderCase(key, c.desc, c.cols, c.rows);
                }
            }
            if (s.done) {
                clearInterval(poll_handle);
                poll_handle = null;
                status_el.textContent = 'Benchmark complete.';
                btn.disabled = false;
                btn.textContent = 'Run again';
            } else {
                status_el.textContent =
                    'Benchmark in progress \u2026';
            }
        })
        .catch(function (e) {
            status_el.textContent = 'Status error: ' + e;
        });
}

btn.addEventListener('click', function () {
    btn.disabled = true;
    status_el.textContent = 'Starting benchmark \u2026';
    seedCards();
    raw_el.textContent = '';
    var latency = document.getElementById('latency_sel').value;
    var body = 'latency_ms=' + encodeURIComponent(latency);
    fetch('/run', {
        method: 'POST',
        headers: {'Content-Type':
            'application/x-www-form-urlencoded'},
        body: body
    }).then(function () {
        poll();
        poll_handle = setInterval(poll, 400);
    }).catch(function (e) {
        status_el.textContent = 'Failed to start: ' + e;
        btn.disabled = false;
    });
});
</script>
</body>
</html><?php
});

/*
    Spawn bench.php as a detached child. Pattern is the same
    cross-platform recipe used in CrawlDaemon::execInOwnProcess:
    "start /B" on Windows, "&"-detach on Unix, with
    pclose(popen(...)) so the parent doesn't wait. Output is
    redirected into the shared temp file the /status route tails.
 */
$test->post('/run', function () use (
    $test, $bench_out_file) {
    /*
        is_file check before unlink so we don't poison the
        process-wide error_get_last() with a "No such file"
        warning on first run. PHP's @ operator still updates
        error_get_last even when it suppresses output, and any
        later code paths that call error_get_last for their own
        diagnostics (notably enableTls's old SSL Error reporter)
        would mis-attribute the unlink message as the cause of
        whatever they were trying to report.
     */
    if (is_file($bench_out_file)) {
        unlink($bench_out_file);
    }
    $php = escapeshellarg(PHP_BINARY);
    $script = escapeshellarg(__DIR__ . "/bench.php");
    $out = escapeshellarg($bench_out_file);
    /*
        The dashboard can post a latency value to simulate
        network RTT. We forward it to bench.php via the
        --latency-ms flag; bench will spawn proxy.php in front
        of the plain and TLS ports for the duration of the run.
        Validate the input as a non-negative number to keep
        shell-injection at bay.
     */
    $extra = '';
    $latency = $_POST['latency_ms'] ?? '0';
    if (is_numeric($latency) && (float) $latency > 0) {
        $latency_arg = (float) $latency;
        $extra = ' --latency-ms=' . escapeshellarg(
            (string) $latency_arg);
    }
    if (strstr(PHP_OS, "WIN")) {
        $job = "start /B $php $script$extra > $out 2>&1";
    } else {
        $job = "$php $script$extra < /dev/null > $out 2>&1 &";
    }
    pclose(popen($job, "r"));
    $test->header("Content-Type: application/json");
    echo json_encode(['started' => true]);
});

/*
    Poll target. Returns the bench output written so far plus a
    done flag. Done is true when the file has been written and
    contains the bench-completion sentinel. Browser polls every
    ~400ms.
 */
$test->get('/status', function () use (
    $test, $bench_out_file) {
    $test->header("Content-Type: application/json");
    if (!file_exists($bench_out_file)) {
        echo json_encode(['text' => '', 'done' => false]);
        return;
    }
    $text = @file_get_contents($bench_out_file);
    if ($text === false) {
        $text = '';
    }
    /*
        Strip the BENCH_DONE sentinel (which bench.php emits
        only when ATTO_BENCH_DISPATCH=1 — but here we don't set
        that env var, so the sentinel is absent). Detect
        completion by checking whether the last non-blank line
        is a known final-case row, or simply whether all five
        cases produced their trailing blank.
     */
    $done = preg_match('/KEEPALIVE\s*\n.+?\n\s*\n\s*$/s',
        $text) === 1;
    echo json_encode(['text' => $text, 'done' => $done]);
});

/*
    Convenience: dump the raw bench output as text/plain so a
    user (or a shell script) can curl it. Useful for debugging
    the parser and for non-browser consumers.
 */
$test->get('/raw', function () use (
    $test, $bench_out_file) {
    $test->header("Content-Type: text/plain; charset=utf-8");
    if (!file_exists($bench_out_file)) {
        echo "No benchmark has been run yet. POST /run first.\n";
        return;
    }
    echo @file_get_contents($bench_out_file);
});

$test->get('/small', function () use ($test) {
    $test->header("Content-Type: text/plain");
    echo "ok";
});
$test->get('/big', function () use ($test) {
    /*
        1 MiB response. Generated as 1024 repetitions of a
        1024-byte block so the body is deterministic and the
        client can verify the length.
     */
    $test->header("Content-Type: application/octet-stream");
    $block = str_repeat("X", 1024);
    echo str_repeat($block, 1024);
});
$test->get('/asset/{n}', function () use ($test) {
    /*
        Tiny per-asset response. The runner fetches many of
        these in parallel to exercise H2 multiplexing vs the
        H1 keep-alive concurrency limit. The {n} capture lands
        in $_GET['n'] so each asset has a distinct body the
        caller can verify.
     */
    $n = $_GET['n'] ?? '0';
    $test->header("Content-Type: text/plain");
    echo "asset {$n}: " . str_repeat("a", 200);
});
$test->get('/headers', function () use ($test) {
    /*
        Response with 100 custom headers. On H1 the runner
        sees 100 repeated header lines per response in
        plaintext; on H2 HPack indexes repeated names so the
        wire bytes are dramatically smaller after the first
        request on a connection.
     */
    for ($i = 0; $i < 100; $i++) {
        $test->header("X-Bench-Header-{$i}: value-{$i}");
    }
    $test->header("Content-Type: text/plain");
    echo "headers";
});
if ($test->isCli()) {
    /*
        Reuse the repository's self-signed cert (security/) so
        every example with a TLS listener picks up the same
        SAN-enabled localhost+127.0.0.1 certificate. Generated
        once with security/san.cnf rather than per-run, which
        also avoids the openssl progress dots polluting the
        startup output.
     */
    $cert = __DIR__ . "/../../security/server.crt";
    $key = __DIR__ . "/../../security/server.key";
    if (!file_exists($cert) || !file_exists($key)) {
        echo "Cert not found at $cert / $key.\n";
        echo "Run: cd security && openssl req -x509 -nodes " .
            "-newkey rsa:4096 -keyout server.key -out " .
            "server.crt -days 365 -config san.cnf\n";
        exit(1);
    }
    echo "\n";
    echo "  Atto Benchmark Dashboard ready.\n";
    echo "  Open http://localhost:8080/ in a browser and click\n";
    echo "  'Run benchmark'. Press Ctrl+C to stop.\n";
    echo "\n";
    /*
        Listen on plain HTTP, TLS, and (if libquiche is
        available) QUIC. The TLS listener advertises h2 +
        http/1.1 via ALPN so clients can negotiate either over
        the same TCP port. The H3 listener binds the same port
        number as TLS but on UDP; it is silently skipped when
        libquiche/PHP FFI is unavailable. The runner uses plain
        HTTP for H1-only tests, TLS for H1+TLS / H2 tests, and
        QUIC for H3 tests (the runner probes each protocol's
        endpoint and skips the row when no server answers).
     */
    $test->listen([
        8080,
        ['address' => 8443, 'context' => ['ssl' => [
            'local_cert' => $cert,
            'local_pk' => $key,
            'allow_self_signed' => true,
            'verify_peer' => false,
            'alpn_protocols' => 'h2,http/1.1',
        ]]],
        ['address' => 8443, 'protocol' => 'h3',
            'context' => ['ssl' => [
                'local_cert' => $cert,
                'local_pk' => $key,
            ]]],
    ]);
} else {
    $test->process();
}
