<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

/*
    The RUN guard prevents this file from executing when a web
    server happens to serve the examples directory directly. Atto
    apps run under their own listener, not under another HTTP
    server, so a request that lands here in a web-server context
    is almost always a misconfiguration. CLI invocations are
    permitted unconditionally so plain `php index.php [flags]`
    works without commenting anything out.
 */
if (php_sapi_name() !== 'cli'
    && !defined("seekquarry\\atto\\RUN")) {
    exit();
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
        /stream       1 MiB response via generator stream()
        /asset/{n}    indexed small response — parallel-fetch
        /headers      100 custom headers — HPACK / QPACK vs plain
        /echo-post    echoes POST body — request-body round-trip

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
    /*
        Pre-load H3QuicheListener so we can probe for libquiche
        availability and conditionally render the opt-in
        checkbox below. Idempotent (require_once); if the file
        is missing or the FFI extension isn't there, we just
        skip the checkbox.
     */
    $quiche_path = __DIR__ . '/../../src/H3QuicheListener.php';
    if (is_file($quiche_path)) {
        require_once $quiche_path;
    }
    $libquiche_ok =
        class_exists('\seekquarry\atto\H3FFI')
        && \seekquarry\atto\H3FFI::isAvailable();
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
    .endpoints { margin: 0.5em 0 1.5em; font-size: 0.9em;
        color: #555; }
    .endpoints summary { cursor: pointer; color: #06c; }
    .endpoints ul { margin: 0.5em 0 0 0; padding-left: 1.5em; }
    .endpoints li { margin: 0.3em 0; }
    .endpoints code, .endpoints a { font-family: monospace; }
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
<details class="endpoints">
    <summary>Diagnostic endpoints</summary>
    <ul>
        <li><a href="/raw" target="_blank">/raw</a> &mdash;
            current bench.php text output (what the dashboard
            parses).</li>
        <li><a href="/status" target="_blank">/status</a> &mdash;
            JSON: bench progress + raw output (polled by the
            dashboard while a run is in flight).</li>
        <li><a href="/h3stats" target="_blank">/h3stats</a>
            &mdash; JSON: per-connection counters from atto's
            pure-PHP HTTP/3 listener
            (<code>H3Listener.php</code>, no FFI, no
            libquiche). Each entry reports the local and peer
            connection IDs, handshake state
            (<code>established</code> / <code>closed</code>),
            <code>created_at</code> / <code>last_packet_at</code>
            timestamps, byte and packet totals
            (<code>bytes_sent</code>, <code>bytes_received</code>,
            <code>packets_sent</code>, <code>packets_received</code>),
            and the open-stream count. Empty when the H3
            listener is not bound or no H3 traffic has hit
            the server yet. To populate: open
            <a href="https://localhost:8443/" target="_blank">
            https://localhost:8443/</a> in a browser that
            speaks H3, then refresh /h3stats. Also accepts
            <code>?keep=1</code> and <code>?snapshot=1</code>;
            both are no-ops against the pure-PHP listener
            (it computes stats live from connection state and
            doesn't currently retain a reaped-connection ring
            buffer) but turn into post-mortem and forced-
            snapshot views when the libquiche-FFI row is
            included via the checkbox below.</li>
        <li><a href="/small" target="_blank">/small</a>,
            <a href="/big" target="_blank">/big</a>,
            <a href="/stream" target="_blank">/stream</a>,
            <a href="/headers" target="_blank">/headers</a>,
            <a href="/asset/1" target="_blank">/asset/{n}</a>
            &mdash; the bench test endpoints. Hit them
            directly with curl --http3-only to drive H3
            traffic and watch /h3stats update.</li>
    </ul>
</details>
<h2 style="margin-bottom: 0.2em;">Curl benchmark
    <span style="font-weight: normal; font-size: 0.65em;
        color: #666;">client: curl</span></h2>
<p class="meta" style="margin-bottom: 0.8em;">
    Runs the suite from the server with the <code>curl</code> command
    over each protocol, delaying curl's own connection by the chosen
    latency. Good for a repeatable bot-style baseline. For your actual
    browser's numbers, use the browser benchmark below.
</p>
<div id="controls">
    <button id="start_btn">Run curl benchmark</button>
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
<?php if ($libquiche_ok): ?>
    <label style="margin-left: 1em; font-size: 0.9em;
        color: #555;">
        <input type="checkbox" id="include_quiche">
        Include libquiche (HTTP/3-quiche) row
    </label>
<?php endif; ?>
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

<hr style="margin: 2.5em 0 1.5em;">
<h2 style="margin-bottom: 0.2em;">Browser benchmark
    <span style="font-weight: normal; font-size: 0.65em;
        color: #666;">client: this browser</span></h2>
<p class="meta" style="margin-bottom: 0.8em;">
    Times fetches your browser makes to this same origin and reports,
    per case, which protocol it used, in the same columns as the curl
    benchmark above. Load this page over
    <a href="http://localhost:8080/">http://localhost:8080/</a> to
    measure HTTP/1.1, or over
    <a href="https://localhost:8443/">https://localhost:8443/</a> for
    HTTP/2. atto runs as a single process and serves its own
    from-scratch HTTP/3 on UDP 8444; it advertises that port with an
    <code>Alt-Svc</code> header, so once the cert is trusted the
    browser moves to <code>h3</code> on 8444 by itself. The
    <b>Protocol</b> column shows what the browser really did &mdash; if
    it reads <code>h2</code> where you wanted <code>h3</code>, HTTP/3
    did not engage; see below.
</p>
<details class="endpoints">
    <summary>Getting your browser onto HTTP/3 (self-signed cert)</summary>
    <ul>
        <li>Browsers refuse HTTP/3 to a certificate they do not trust,
            so a plain self-signed cert leaves them on HTTP/2. The
            simplest fix is a locally-trusted cert from
            <code>mkcert</code> for <code>localhost</code>, which
            Firefox and Safari will then trust.</li>
        <li><b>Chrome / Edge:</b> will not use a custom CA for QUIC at
            all, so launch it forcing QUIC at atto's HTTP/3 port and
            open that port directly:
            <code>chrome --origin-to-force-quic-on=localhost:8444
            --ignore-certificate-errors</code>, then load
            <a href="https://localhost:8444/">https://localhost:8444/</a>
            (testing only; use a fresh
            <code>--user-data-dir</code>).</li>
        <li><b>Firefox:</b> visit
            <a href="https://localhost:8443/">https://localhost:8443/</a>
            once and accept the cert. Then in
            <code>about:config</code> set
            <code>network.http.http3.disable_when_third_party_roots_found</code>
            to <code>false</code>. Reload and the Protocol column should
            read <code>h3</code>.</li>
        <li><b>Safari:</b> add the cert to the login keychain and mark
            it Always Trust, then reload. Recent Safari does HTTP/3 by
            default; older versions need it enabled under Develop &rarr;
            Experimental Features.</li>
        <li>atto sends an <code>Alt-Svc: h3=":8444"</code> header, so
            on the trusted-cert path (Firefox / Safari) loading
            <a href="https://localhost:8443/">https://localhost:8443/</a>
            is enough &mdash; the browser moves to atto's HTTP/3 on
            8444 by itself after the first request.</li>
    </ul>
</details>
<div id="browser_controls" style="margin: 0.5em 0 0.5em;">
    <button id="browser_btn">Run browser benchmark</button>
</div>
<div id="browser_status" style="font-weight: bold;
    margin: 1em 0;"></div>
<div id="browser_results"></div>

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

/* Seed cards in display order so they appear immediately. */
var KNOWN_CASES = [
    {key: 'SMALL',     label: '/small (per-request overhead)'},
    {key: 'BIG',       label: '/big (1 MiB throughput)'},
    {key: 'STREAM',    label: '/stream (1 MiB via generator)'},
    {key: 'ASSET',     label: '/asset (parallel multiplex)'},
    {key: 'HEADERS',   label: '/headers (HPACK/QPACK vs plain)'},
    {key: 'KEEPALIVE', label: '/small over one connection'},
    {key: 'POST',      label: '/echo-post (round-trip body)'},
    {key: 'DEFER',     label: '/defer (cooperative overlap)'},
];
var raw_output = document.getElementById('raw_block');
var results_area = document.getElementById('results');
var status_line = document.getElementById('global_status');
var button = document.getElementById('start_btn');

function seedCards()
{
    results_area.innerHTML = '';
    KNOWN_CASES.forEach(function (case_info) {
        var card = document.createElement('div');
        card.className = 'case';
        card.id = 'case_' + case_info.key;
        card.innerHTML =
            '<span class="status pending" id="status_'
            + case_info.key + '">pending</span>'
            + '<h2>' + case_info.key + '</h2>'
            + '<div class="desc" id="desc_' + case_info.key
            + '">' + case_info.label + '</div>'
            + '<div id="body_' + case_info.key + '"></div>';
        results_area.appendChild(card);
    });
}

function setStatus(case_key, status)
{
    var indicator = document.getElementById('status_' + case_key);
    if (indicator) {
        indicator.className = 'status ' + status;
        indicator.textContent = status;
    }
}

function renderCase(case_key, description, header_columns, rows)
{
    document.getElementById('desc_' + case_key).textContent =
        description;
    var html = '<table><thead><tr>';
    header_columns.forEach(function (header) {
        html += '<th>' + header + '</th>';
    });
    html += '</tr></thead><tbody>';
    rows.forEach(function (row) {
        html += '<tr>';
        row.forEach(function (cell) {
            html += '<td>' + cell + '</td>';
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
function parse(text)
{
    var lines = text.split('\n');
    var cases = {};
    var current = null;
    var case_keys = KNOWN_CASES.map(function (case_info) {
        return case_info.key;
    });
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var stripped = line.trim();
        if (case_keys.indexOf(stripped) >= 0) {
            current = stripped;
            cases[current] = {description: '', columns: [],
                rows: [], done: false};
            continue;
        }
        if (current === null) {
            continue;
        }
        if (stripped === '') {
            cases[current].done = true;
            current = null;
            continue;
        }
        var entry = cases[current];
        if (entry.description === '') {
            entry.description = stripped;
        } else if (entry.columns.length === 0) {
            entry.columns = stripped.split(/\s+/);
        } else {
            entry.rows.push(stripped.split(/\s+/));
        }
    }
    return cases;
}

var poll_handle = null;

function poll()
{
    fetch('/status').then(function (response) {
        return response.json();
    }).then(function (progress) {
        raw_output.textContent = progress.text;
        var cases = parse(progress.text);
        /* Update each known-case card. */
        for (var i = 0; i < KNOWN_CASES.length; i++) {
            var key = KNOWN_CASES[i].key;
            var entry = cases[key];
            if (!entry) {
                setStatus(key, 'pending');
                continue;
            }
            if (entry.done) {
                setStatus(key, 'done');
            } else {
                setStatus(key, 'running');
            }
            if (entry.columns.length > 0) {
                renderCase(key, entry.description,
                    entry.columns, entry.rows);
            }
        }
        if (progress.done) {
            clearInterval(poll_handle);
            poll_handle = null;
            status_line.textContent = 'Benchmark complete.';
            button.disabled = false;
            button.textContent = 'Run curl benchmark again';
        } else {
            status_line.textContent =
                'Benchmark in progress \u2026';
        }
    }).catch(function (error) {
        status_line.textContent = 'Status error: ' + error;
    });
}

button.addEventListener('click', function () {
    button.disabled = true;
    status_line.textContent = 'Starting benchmark \u2026';
    seedCards();
    raw_output.textContent = '';
    var latency =
        document.getElementById('latency_sel').value;
    var body = 'latency_ms=' + encodeURIComponent(latency);
    var quiche_checkbox =
        document.getElementById('include_quiche');
    if (quiche_checkbox && quiche_checkbox.checked) {
        body += '&include_quiche=1';
    }
    fetch('/run', {
        method: 'POST',
        headers: {'Content-Type':
            'application/x-www-form-urlencoded'},
        body: body
    }).then(function () {
        poll();
        poll_handle = setInterval(poll, 400);
    }).catch(function (error) {
        status_line.textContent = 'Failed to start: ' + error;
        button.disabled = false;
    });
});

/*
    Browser benchmark: time this browser's own fetches to this
    origin and report which protocol it used, read from the
    Resource Timing entry's nextHopProtocol. Separate from the curl
    benchmark above, which the server runs.
 */
var browser_button = document.getElementById('browser_btn');
var browser_results_area =
    document.getElementById('browser_results');
var browser_status_line =
    document.getElementById('browser_status');

var BROWSER_CASES = [
    {key: 'small', path: '/small',
        label: 'per-request overhead', iterations: 5},
    {key: 'big', path: '/big',
        label: '1 MiB throughput', iterations: 3},
    {key: 'post', path: '/echo-post',
        label: '64 KiB round-trip', iterations: 5, post: true}
];

function median(values)
{
    var sorted = values.slice().sort(function (left, right) {
        return left - right;
    });
    var middle = Math.floor(sorted.length / 2);
    if (sorted.length % 2) {
        return sorted[middle];
    }
    return (sorted[middle - 1] + sorted[middle]) / 2;
}

/*
    Smallest value in a list. The list is never empty here: a case
    always runs at least one iteration.
 */
function minimum(values)
{
    var smallest = values[0];
    for (var i = 1; i < values.length; i++) {
        if (values[i] < smallest) {
            smallest = values[i];
        }
    }
    return smallest;
}

/*
    Value at the given fraction (0..1) of the sorted list, e.g.
    0.95 for the 95th percentile, by nearest-rank.
 */
function percentile(values, fraction)
{
    var sorted = values.slice().sort(function (left, right) {
        return left - right;
    });
    var rank = Math.ceil(fraction * sorted.length) - 1;
    if (rank < 0) {
        rank = 0;
    }
    if (rank >= sorted.length) {
        rank = sorted.length - 1;
    }
    return sorted[rank];
}

/*
    Fetch one URL from this origin, consume the whole body, and
    return the elapsed milliseconds, the byte count, and the
    protocol the browser used. A unique query string gives each
    call its own Resource Timing entry to read nextHopProtocol
    from.
 */
function timeFetch(path, is_post)
{
    var separator = path.indexOf('?') < 0 ? '?' : '&';
    var url = location.origin + path + separator + 'nocache='
        + Date.now() + '_' + Math.random().toString(36).slice(2);
    var options = {cache: 'no-store'};
    if (is_post) {
        options.method = 'POST';
        options.body = new Uint8Array(65536);
    }
    var started = performance.now();
    return fetch(url, options).then(function (response) {
        return response.arrayBuffer().then(function (body) {
            var elapsed = performance.now() - started;
            var protocol = '?';
            var entries = performance.getEntriesByName(url);
            if (entries.length > 0) {
                protocol = entries[entries.length - 1]
                    .nextHopProtocol || '?';
            }
            return {elapsed: elapsed, bytes: body.byteLength,
                protocol: protocol};
        });
    });
}

/*
    Run one case's iterations in sequence so they do not contend,
    and return the median time, the last protocol seen, and the
    body size.
 */
function runBrowserCase(item)
{
    var times = [];
    var protocol = '?';
    var bytes = 0;
    var i = 0;
    function step()
    {
        if (i >= item.iterations) {
            return Promise.resolve();
        }
        i++;
        return timeFetch(item.path, item.post)
            .then(function (result) {
                times.push(result.elapsed);
                protocol = result.protocol;
                bytes = result.bytes;
                return step();
            });
    }
    return step().then(function () {
        return {key: item.key, label: item.label,
            protocol: protocol, iters: times.length,
            min: minimum(times), median: median(times),
            p95: percentile(times, 0.95), bytes: bytes};
    });
}

/*
    Throughput in kilobytes per second as a bare number for the
    kB/s column, or '-' when there is no measurable time.
 */
function formatRate(bytes, elapsed)
{
    if (elapsed <= 0) {
        return '-';
    }
    var kilobytes_per_second =
        (bytes / 1024) / (elapsed / 1000);
    return kilobytes_per_second.toFixed(0);
}

/*
    Render each browser case as its own card using the same column
    header the curl benchmark shows (protocol, iters, min(ms),
    median, p95, req/s, kB/s), with one row for the single
    protocol the browser negotiated, so the two benchmarks read
    the same way.
 */
function renderBrowserResults(results)
{
    var html = '';
    results.forEach(function (row) {
        var requests_per_second = row.median > 0
            ? (1000 / row.median).toFixed(2) : '-';
        html += '<div class="case"><h2>' + row.key + '</h2>'
            + '<div class="desc">' + row.label + '</div>'
            + '<table><thead><tr><th>protocol</th><th>iters</th>'
            + '<th>min(ms)</th><th>median</th><th>p95</th>'
            + '<th>req/s</th><th>kB/s</th></tr></thead><tbody>'
            + '<tr><td>' + row.protocol + '</td><td>' + row.iters
            + '</td><td>' + row.min.toFixed(2) + '</td><td>'
            + row.median.toFixed(2) + '</td><td>'
            + row.p95.toFixed(2) + '</td><td>'
            + requests_per_second + '</td><td>'
            + formatRate(row.bytes, row.median)
            + '</td></tr></tbody></table></div>';
    });
    browser_results_area.innerHTML = html;
}

/*
    After the fetches, read /h3stats and show atto's ack-frequency
    for this browser's connection. keep=1 includes the just-closed
    ring, because a browser often tears down its h3 connection the
    moment the fetches finish; without it a read landing a moment
    later would see nothing. Among live and just-closed
    connections, pick the busiest one carrying an ack_frequency
    block (only atto's own h3 listener reports it). The results
    array carries the protocol each case used, so the fallback
    message can tell an h3 run apart from a non-h3 one.
 */
function showBrowserAckFrequency(results)
{
    var used_h3 = (results || []).some(function (row) {
        return row.protocol === 'h3';
    });
    return fetch('/h3stats?keep=1').then(function (response) {
        return response.json();
    }).then(function (data) {
        var candidates = (data.stats || [])
            .concat(data.reaped || []);
        var best = null;
        candidates.forEach(function (stat) {
            if (!stat.ack_frequency) {
                return;
            }
            if (!best
                || stat.packets_sent > best.packets_sent) {
                best = stat;
            }
        });
        var note = document.createElement('p');
        note.className = 'meta';
        if (best) {
            var ack_frequency = best.ack_frequency;
            var cadence = '-';
            if (best.packets_sent > 0) {
                cadence = (ack_frequency.ack_packets_received
                    / best.packets_sent).toFixed(2);
            }
            note.innerHTML = 'H3 ack-frequency &mdash; browser '
                + 'advertised min_ack_delay: <b>'
                + (ack_frequency.peer_advertised ? 'yes' : 'no')
                + '</b>; asked to ack every '
                + (ack_frequency.sent_threshold || '-')
                + '; browser sent '
                + ack_frequency.ack_packets_received
                + ' acks over ' + best.packets_sent
                + ' packets (<b>' + cadence + '</b> per packet). '
                + 'Near 0.1 means it honored the request; near '
                + '1.0 means it ignored it.';
        } else if (used_h3) {
            note.innerHTML = 'Your browser reported h3, but atto '
                + 'had no matching h3 connection to report on when '
                + 'this read landed. Re-run the benchmark; the '
                + 'just-closed connection is kept briefly, so a '
                + 'second run usually shows the cadence.';
        } else {
            note.innerHTML = 'No h3 connection was used. The '
                + 'Protocol column shows what your browser did; '
                + 'if it is not h3, follow the cert steps above.';
        }
        browser_results_area.appendChild(note);
    }).catch(function () {
        /* /h3stats not reachable or no h3 listener; skip. */
    });
}

function runBrowserBench()
{
    browser_button.disabled = true;
    browser_status_line.textContent =
        'Running in your browser \u2026';
    browser_results_area.innerHTML = '';
    var results = [];
    /*
        Warm-up request so the browser can act on the Alt-Svc
        header and move to HTTP/3 before the timed fetches.
     */
    fetch(location.origin + '/small?warm=' + Date.now(),
        {cache: 'no-store'})
        .then(function (response) {
            return response.arrayBuffer();
        })
        .then(function () {
            var i = 0;
            function next()
            {
                if (i >= BROWSER_CASES.length) {
                    return Promise.resolve();
                }
                var item = BROWSER_CASES[i];
                i++;
                browser_status_line.textContent =
                    'Running ' + item.label + ' \u2026';
                return runBrowserCase(item)
                    .then(function (result) {
                        results.push(result);
                        renderBrowserResults(results);
                        return next();
                    });
            }
            return next();
        })
        .then(function () {
            return showBrowserAckFrequency(results);
        })
        .then(function () {
            browser_status_line.textContent =
                'Browser benchmark complete.';
            browser_button.disabled = false;
            browser_button.textContent =
                'Run browser benchmark again';
        })
        .catch(function (error) {
            browser_status_line.textContent =
                'Browser benchmark error: ' + error;
            browser_button.disabled = false;
        });
}

browser_button.addEventListener('click', runBrowserBench);
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
        shell-injection at bay. The dashboard can also post
        include_quiche=1 to add the libquiche-FFI row to the
        run; off by default.
     */
    $extra = '';
    $latency = $_POST['latency_ms'] ?? '0';
    if (is_numeric($latency) && (float) $latency > 0) {
        $latency_arg = (float) $latency;
        $extra = ' --latency-ms=' . escapeshellarg(
            (string) $latency_arg);
    }
    if (!empty($_POST['include_quiche'])) {
        $extra .= ' --include-quiche';
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
$test->get('/stream', function () use ($test) {
    /*
        1 MiB response, same size as /big, but produced through
        $site->stream() instead of a single echo. The route hands
        Atto a generator and returns; Atto pulls one block at a
        time from its event loop as the client takes bytes, so the
        body is never assembled in memory whole and, over HTTP/2,
        the send is paced by the peer's flow-control window.
        Benchmarking this against /big shows the overhead (if any)
        of generator-paced delivery versus a buffered body of the
        same size. Content-Length is set up front so the transfer
        is determinate.
     */
    $total_length = 1024 * 1024;
    $block_length = 256 * 1024;
    $test->header("Content-Type: application/octet-stream");
    $test->header("Content-Length: " . $total_length);
    $test->stream(function () use ($total_length, $block_length) {
        $block = str_repeat("X", $block_length);
        $sent = 0;
        while ($sent < $total_length) {
            $remaining = $total_length - $sent;
            if ($remaining < $block_length) {
                $block = str_repeat("X", $remaining);
            }
            yield $block;
            $sent += strlen($block);
        }
    });
});
$test->get('/asset/{n}', function () use ($test) {
    /*
        Tiny per-asset response. The runner fetches many of
        these in parallel to exercise H2 multiplexing vs the
        H1 keep-alive concurrency limit. The {n} capture lands
        in $_GET['n'] so each asset has a distinct body the
        caller can verify.
     */
    $number = $_GET['n'] ?? '0';
    $test->header("Content-Type: text/plain");
    echo "asset {$number}: " . str_repeat("a", 200);
});
$test->get('/headers', function () use ($test) {
    /*
        Response with 100 custom headers. On H1 the runner
        sees 100 repeated header lines per response in
        plaintext; on H2 HPACK and on H3 QPACK index
        repeated names so the wire bytes are dramatically
        smaller after the first request on a connection.
        H3's static and dynamic QPACK tables are similar in
        spirit to H2's HPACK but reorder field handling so
        the per-stream decoder doesn't block the connection
        on out-of-order delivery.
     */
    for ($i = 0; $i < 100; $i++) {
        $test->header("X-Bench-Header-{$i}: value-{$i}");
    }
    $test->header("Content-Type: text/plain");
    echo "headers";
});
$test->post('/echo-post', function () use ($test) {
    /*
        Echoes the raw POST body back. Used by the runner's
        post case to verify request bodies survive intact.
        The runner POSTs a known payload and checks the
        response equals what it sent. Reads from the atto
        convention $_SERVER['CONTENT'] (raw body) rather
        than $_POST so binary payloads work.
     */
    $body = $_SERVER['CONTENT'] ?? '';
    $test->header("Content-Type: application/octet-stream");
    $test->header("Content-Length: " . strlen($body));
    echo $body;
});
$test->get('/defer', function () use ($test) {
    /*
        A request that does its slow work the cooperative way. It
        runs a short child process and waits for that child by
        suspending the request fiber, so the event loop keeps
        serving every other connection in the meantime. Fetch many
        of these at once (the runner's "defer" case) and they
        overlap: the wall time stays near one request's, not the
        sum, because the children run side by side instead of the
        loop blocking on each in turn. Under Apache there is no atto
        loop, so deferResponse runs the work straight through in
        this request's own process and the wait simply blocks here.
     */
    return $test->deferResponse(function () use ($test) {
        $milliseconds = 150;
        $child = 'usleep(' . ($milliseconds * 1000) . '); echo "ok";';
        $command = escapeshellarg(PHP_BINARY) . ' -r ' .
            escapeshellarg($child);
        $process = proc_open($command, [1 => ['pipe', 'w']], $pipes);
        if (is_resource($process)) {
            stream_set_blocking($pipes[1], false);
            while (!feof($pipes[1])) {
                if (\Fiber::getCurrent() !== null) {
                    $ready = [$pipes[1]];
                    $writable = null;
                    $except = null;
                    $count = @stream_select($ready, $writable,
                        $except, 0);
                    if ($count === 0) {
                        \Fiber::suspend(['read' => $pipes[1]]);
                        continue;
                    }
                }
                if (fread($pipes[1], 256) === false) {
                    break;
                }
            }
            fclose($pipes[1]);
            proc_close($process);
        }
        $test->header("Content-Type: text/plain");
        echo "deferred $milliseconds ms\n";
    });
});
$test->get('/h3stats', function () use ($test) {
    /*
        Returns a JSON snapshot of per-connection counters
        from every H3 listener currently bound. The pure-PHP
        listener (H3Listener.php) reports state, local /
        peer CIDs, established / closed flags, created_at /
        last_packet_at timestamps, byte and packet totals,
        and open-stream count -- everything it computes
        live from QuicConnection state. The libquiche-FFI
        listener (H3QuicheListener.php), when included via
        the checkbox in the dashboard, additionally reports
        lost / retransmitted counts, RTT, and cwnd.

        Returns an empty list when no H3 listener is bound
        or no H3 connections are active. This route is GET
        so it can be hit from any browser / curl / dashboard
        fetch.

        Query parameters:
        - ?keep=1: include the listener's ring buffer of
          stats from connections that have already been
          reaped. Implemented by H3QuicheListener (each
          reaped entry carries a 'reason' field for the
          shutdown trigger and a 'reaped_at' microtime
          float). The pure-PHP listener does not currently
          retain a reaped-connection history; this query
          parameter is a no-op against it.
        - ?snapshot=1: before snapshotting, capture every
          live connection's current stats into the ring
          buffer. Useful with the libquiche row for
          inspecting connections that completed their work
          but were kept alive by the client (e.g. curl
          --http3 leaves the QUIC connection in its pool
          and never sends CONNECTION_CLOSE, so the server
          won't reap it until the idle timer fires).
          Implies ?keep=1; also a no-op on the pure-PHP
          listener.
     */
    $test->header("Content-Type: application/json");
    $stats = [];
    $reaped = [];
    $force_snapshot = !empty($_GET['snapshot']);
    $include_reaped = !empty($_GET['keep']) || $force_snapshot;
    foreach ($test->listeners() as $listener) {
        /*
            Both H3Listener (pure-PHP) and H3QuicheListener
            (FFI) expose the same snapshot/forceSnapshot API
            surface, so duck-type by method existence. Plain
            Listener / TcpListener instances don't define
            snapshotAllStats and are skipped.
         */
        if (!method_exists($listener, 'snapshotAllStats')) {
            continue;
        }
        if ($force_snapshot
            && method_exists($listener, 'forceSnapshotAll')) {
            $listener->forceSnapshotAll();
        }
        foreach ($listener->snapshotAllStats() as $row) {
            $stats[] = $row;
        }
        if ($include_reaped
            && method_exists($listener,
                'snapshotReapedStats')) {
            foreach ($listener->snapshotReapedStats()
                    as $row) {
                $reaped[] = $row;
            }
        }
    }
    $out = [
        'connections' => count($stats),
        'stats' => $stats,
    ];
    if ($include_reaped) {
        $out['reaped_count'] = count($reaped);
        $out['reaped'] = $reaped;
    }
    echo json_encode($out, JSON_PRETTY_PRINT);
});

/**
 * Makes sure the shared self-signed TLS certificate the examples
 * use is present and current, regenerating it when it is missing
 * or has expired. The certificate and its key live in the
 * repository's security/ directory and cover localhost with the
 * subject-alternative-name entries in san.cnf, so a browser can
 * reach the TLS and HTTP/3 listeners. Generation shells out to
 * openssl to write a self-signed RSA certificate valid for a
 * year, the same command security/san.cnf documents. Returns
 * true when a usable certificate and key are in place.
 *
 * @param string $certificate path to the certificate file
 * @param string $key path to the private-key file
 * @param string $configuration_path path to the openssl config
 *      (san.cnf) that carries the localhost names
 * @return bool true when the pair is present and current
 */
function ensureBenchmarkCertificate($certificate, $key,
    $configuration_path)
{
    $present = file_exists($certificate) && file_exists($key);
    $current = false;
    if ($present) {
        /*
            openssl x509 -checkend 0 exits non-zero once the
            certificate has expired, so a zero exit means it is
            still inside its validity window.
         */
        $check = "openssl x509 -in "
            . escapeshellarg($certificate) . " -noout -checkend 0";
        exec($check . " 2>/dev/null", $unused, $status);
        $current = ($status === 0);
    }
    if ($present && $current) {
        return true;
    }
    echo "  TLS certificate "
        . ($present ? "expired" : "missing")
        . "; regenerating in security/.\n";
    /*
        A 4096-bit RSA key, self-signed and valid for one year.
        The length is measured in bits and the lifetime in days,
        as the openssl flags below expect.
     */
    $rsa_key_length = 4096;
    $certificate_lifetime = 365;
    $generate = "openssl req -x509 -nodes -newkey rsa:"
        . $rsa_key_length . " -keyout " . escapeshellarg($key)
        . " -out " . escapeshellarg($certificate) . " -days "
        . $certificate_lifetime . " -config "
        . escapeshellarg($configuration_path);
    exec($generate . " 2>&1", $output, $status);
    if ($status !== 0 || !file_exists($certificate)
        || !file_exists($key)) {
        echo "  Could not generate a certificate. Is openssl on "
            . "the PATH?\n";
        return false;
    }
    echo "  Wrote a fresh certificate and key to security/.\n";
    return true;
}

if ($test->isCli()) {
    /*
        Optional --trace=path flag: when present, the H3 listener
        emits a one-line-per-event timing record to the named
        file. Each line is prefixed H3TRACE so it can be grepped
        out of the bench dashboard's stdout if both happen to
        land in the same place. Off by default; the trace check
        is a single isset() per event when off.
     */
    $trace_path = '';
    foreach (array_slice($argv, 1) as $arg) {
        if (strncmp($arg, '--trace=', 8) === 0) {
            $trace_path = substr($arg, 8);
        } else if ($arg === '--help' || $arg === '-h') {
            echo "Usage: php index.php [--trace=path]\n";
            echo "  --trace=path   Append H3 listener trace lines\n";
            echo "                 to the given file. Useful for\n";
            echo "                 diagnosing latency under bench's\n";
            echo "                 --latency-ms run.\n";
            exit(0);
        }
    }
    if ($trace_path !== '') {
        if (!class_exists(
                '\seekquarry\atto\H3Listener', false)) {
            $h3_path = __DIR__ . "/../../src/H3Listener.php";
            if (is_file($h3_path)) {
                require_once $h3_path;
            }
        }
        if (class_exists(
                '\seekquarry\atto\H3Listener', false)
            && seekquarry\atto\H3Listener::traceTo($trace_path)) {
            echo "  H3 trace -> $trace_path\n";
        } else {
            echo "  WARNING: could not open trace file " .
                "$trace_path\n";
        }
    }
    /*
        Use the repository's shared self-signed cert (security/)
        so every example with a TLS listener picks up the same
        SAN-enabled localhost+127.0.0.1 certificate.
        ensureBenchmarkCertificate regenerates it from
        security/san.cnf when it is missing or has expired, so a
        fresh checkout or a stale cert still starts cleanly.
     */
    $certificate = __DIR__ . "/../../security/server.crt";
    $key = __DIR__ . "/../../security/server.key";
    $configuration_path = __DIR__ . "/../../security/san.cnf";
    if (!ensureBenchmarkCertificate($certificate, $key,
        $configuration_path)) {
        exit(1);
    }
    echo "\n";
    echo "  Atto Benchmark Dashboard ready.\n";
    echo "  Open http://localhost:8080/ in a browser and click\n";
    echo "  'Run benchmark'. Press Ctrl+C to stop.\n";
    echo "\n";
    /*
        Listen on plain HTTP, TLS, the pure-PHP HTTP/3 listener
        ('h3' on UDP 8444), and -- if libquiche/PHP-FFI is
        available -- the libquiche-FFI HTTP/3 listener
        ('h3-quiche' on UDP 8443, sharing the TLS port number).
        The TLS listener advertises h2 + http/1.1 via ALPN so
        clients can negotiate either over the same TCP port.
        The runner uses plain HTTP for H1-only tests, TLS for
        H1+TLS / H2 tests, and QUIC for H3 tests; each row is
        probed and silently skipped if no server answers.
     */
    $listen_specs = [
        8080,
        ['address' => 8443, 'context' => ['ssl' => [
            'local_cert' => $certificate,
            'local_pk' => $key,
            'allow_self_signed' => true,
            'verify_peer' => false,
            'alpn_protocols' => 'h2,http/1.1',
        ]]],
        ['address' => 8444, 'protocol' => 'h3',
            'context' => ['ssl' => [
                'local_cert' => $certificate,
                'local_pk' => $key,
            ]]],
    ];
    /*
        Add the libquiche-FFI listener only when its
        dependencies are present. We pre-load
        H3QuicheListener.php so H3FFI is in scope, then ask
        H3FFI::isAvailable() (which probes for the FFI
        extension and a loadable libquiche.{so,dylib,dll}).
        When unavailable the listener spec would print a
        skip message and noise up the startup log; gating it
        here keeps the dashboard quiet on default systems.
     */
    $quiche_path = __DIR__ . '/../../src/H3QuicheListener.php';
    if (is_file($quiche_path)) {
        require_once $quiche_path;
    }
    $libquiche_ok =
        class_exists('\seekquarry\atto\H3FFI')
        && \seekquarry\atto\H3FFI::isAvailable();
    if ($libquiche_ok) {
        $listen_specs[] = ['address' => 8443,
            'protocol' => 'h3-quiche',
            'context' => ['ssl' => [
                'local_cert' => $certificate,
                'local_pk' => $key,
            ]]];
    }
    $test->listen($listen_specs);
} else {
    $test->process();
}
