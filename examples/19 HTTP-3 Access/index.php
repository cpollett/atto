<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Pure-PHP HTTP/3 demo. Boots an atto site listening on UDP
 * 8443 with the pure-PHP H3 listener (no libquiche, no FFI)
 * and serves a single page that displays the QUIC and HTTP/3
 * details of the request that fetched it: which protocol the
 * server saw, the QUIC connection ID and cipher, byte and
 * packet counters, and the request headers as the browser
 * sent them. Reload the page over HTTPS and the counters tick
 * up in front of you.
 *
 * Run from the repo root:
 *     php index.php 17
 * Then open https://localhost:8443/ in a browser that speaks
 * HTTP/3 (recent Chrome / Firefox / Safari all do). The first
 * connection negotiates HTTP/2 over TCP because the browser
 * has to discover the alt-svc; the page surfaces the alt-svc
 * header on that first hit and reloads itself once HTTP/3 is
 * available, so the second view shows a green H3 banner.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (php_sapi_name() !== 'cli'
    && !defined("seekquarry\\atto\\RUN")) {
    exit();
}

$test = new WebSite();
$cert = __DIR__ . '/../../security/server.crt';
$key = __DIR__ . '/../../security/server.key';

/*
    JSON endpoint that surfaces every live H3 connection's
    QUIC stats. The page polls this every two seconds so the
    counters in the live panel update without a full reload.
    Uses the duck-typed snapshotAllStats() method that both
    H3Listener (pure-PHP) and H3QuicheListener (FFI) define;
    here only the pure-PHP listener is bound.
 */
$test->get('/stats', function () use ($test) {
    $test->header('Content-Type: application/json');
    $rows = [];
    foreach ($test->listeners() as $listener) {
        if (!method_exists($listener, 'snapshotAllStats')) {
            continue;
        }
        foreach ($listener->snapshotAllStats() as $row) {
            $rows[] = $row;
        }
    }
    echo json_encode(['connections' => $rows,
        'now' => microtime(true)]);
});

/*
    The main page. Reads $_SERVER fields atto fills in from
    the H3 request env (SERVER_PROTOCOL, REMOTE_ADDR, the
    HTTP_* headers) and renders them inline so the page
    itself is evidence the request went over HTTP/3. We add
    Alt-Svc on every response so that even when the first
    request lands over HTTP/2, the browser learns about the
    UDP/8443 endpoint and switches subsequent requests to H3.
 */
$test->get('/', function () use ($test) {
    $test->header('Alt-Svc: h3=":8443"; ma=86400');
    $proto = $_SERVER['SERVER_PROTOCOL'] ?? 'unknown';
    $is_h3 = ($proto === 'HTTP/3');
    $remote = ($_SERVER['REMOTE_ADDR'] ?? '?')
        . ':' . ($_SERVER['REMOTE_PORT'] ?? '?');
    $authority = $_SERVER['HTTP_HOST'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'] ?? '';
    $request_uri = $_SERVER['REQUEST_URI'] ?? '/';
    $headers = [];
    foreach ($_SERVER as $k => $v) {
        if (strncmp($k, 'HTTP_', 5) === 0) {
            $name = strtolower(str_replace('_', '-',
                substr($k, 5)));
            $headers[$name] = $v;
        }
    }
    ksort($headers);
    $banner_class = $is_h3 ? 'ok' : 'pending';
    $banner_text = $is_h3
        ? 'This page reached you over HTTP/3 (QUIC).'
        : 'This page reached you over ' . htmlspecialchars(
            $proto) . '. The browser will switch to HTTP/3 '
        . 'shortly via the Alt-Svc header advertised on this '
        . 'response. Reload after a few seconds.';
?><!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Atto pure-PHP HTTP/3 demo</title>
<style>
    body { font-family: -apple-system, system-ui, sans-serif;
        max-width: 880px; margin: 2em auto; padding: 0 1em;
        color: #222; line-height: 1.45; }
    h1 { margin-bottom: 0.2em; }
    h2 { margin-top: 1.6em; font-size: 1.1em; }
    .banner { padding: 1em; border-radius: 6px;
        margin: 1em 0; font-weight: bold; }
    .banner.ok { background: #dff5e1; color: #1a5c2a;
        border: 1px solid #6fbf7a; }
    .banner.pending { background: #fff5d6; color: #6a4f00;
        border: 1px solid #d8b347; }
    table { border-collapse: collapse; width: 100%;
        font-size: 0.9em; margin: 0.6em 0; }
    th, td { border: 1px solid #ddd; padding: 0.4em 0.6em;
        text-align: left; vertical-align: top; }
    th { background: #f4f4f4; font-weight: 600; }
    code { font-family: SFMono-Regular, Menlo, monospace;
        font-size: 0.92em; }
    .muted { color: #666; font-size: 0.9em; }
    #conns { font-family: SFMono-Regular, Menlo, monospace;
        font-size: 0.85em; }
</style>
</head>
<body>
<h1>Atto pure-PHP HTTP/3</h1>
<p class="muted">
    This page is served by atto's pure-PHP HTTP/3 listener
    (<code>H3Listener.php</code>, no libquiche, no FFI). The
    HTTP/3 stack is implemented in PHP using only ext-openssl
    and ext-sodium. Everything below is read out of the
    request env and the listener's per-connection stats
    snapshot, so this page is itself evidence the QUIC
    handshake completed and a 1-RTT stream delivered the
    response.
</p>

<div class="banner <?= $banner_class ?>">
    <?= $banner_text ?>
</div>

<h2>What the server saw on this request</h2>
<table>
    <tr><th>Method</th><td><?= htmlspecialchars($method) ?></td></tr>
    <tr><th>URI</th><td><code><?=
        htmlspecialchars($request_uri) ?></code></td></tr>
    <tr><th>Server protocol</th><td><code><?=
        htmlspecialchars($proto) ?></code> (atto reports
        <code>HTTP/3</code> from the H3 request env, plain
        HTTP from H1, etc.)</td></tr>
    <tr><th>Authority</th><td><code><?=
        htmlspecialchars($authority) ?></code></td></tr>
    <tr><th>Remote</th><td><code><?=
        htmlspecialchars($remote) ?></code></td></tr>
</table>

<h2>Request headers as the client encoded them</h2>
<p class="muted">
    On HTTP/3 the browser ships these compressed via QPACK
    (RFC 9204) over a single QUIC stream. Atto's QPACK
    decoder reconstructs them and surfaces each as
    <code>HTTP_*</code> in the request env. Common pseudo-
    headers (<code>:method</code>, <code>:path</code>, etc.)
    are folded into <code>REQUEST_METHOD</code> /
    <code>REQUEST_URI</code> above.
</p>
<table>
    <tr><th>Header</th><th>Value</th></tr>
<?php foreach ($headers as $name => $value): ?>
    <tr><td><code><?= htmlspecialchars($name) ?></code></td>
        <td><code><?= htmlspecialchars($value) ?></code></td>
    </tr>
<?php endforeach; ?>
</table>

<h2>Live QUIC connection stats</h2>
<p class="muted">
    Pulled from <code>H3Listener::snapshotAllStats()</code>
    every two seconds. One row per active QUIC connection
    this listener has accepted; reload the page (or open it
    in another tab) to watch a new row appear and the byte
    counters climb.
</p>
<div id="conns">loading&hellip;</div>

<script>
function fmtAge(now, ts) {
    if (!ts) return '-';
    var s = Math.max(0, now - ts);
    return s.toFixed(2) + 's ago';
}
function render(rows, now) {
    if (!rows.length) {
        return '<em>No active connections.</em>';
    }
    var html = '<table><tr><th>CID</th><th>state</th>' +
        '<th>bytes rx</th><th>bytes tx</th>' +
        '<th>pkts rx</th><th>pkts tx</th>' +
        '<th>streams</th><th>last pkt</th></tr>';
    rows.forEach(function (r) {
        html += '<tr><td>' + r.cid + '</td>' +
            '<td>' + (r.established ? 'established' :
                'handshaking') + '</td>' +
            '<td>' + r.bytes_received + '</td>' +
            '<td>' + r.bytes_sent + '</td>' +
            '<td>' + r.packets_received + '</td>' +
            '<td>' + r.packets_sent + '</td>' +
            '<td>' + r.streams_open + '</td>' +
            '<td>' + fmtAge(now, r.last_packet_at) + '</td>' +
            '</tr>';
    });
    return html + '</table>';
}
function poll() {
    fetch('/stats').then(function (r) {
        return r.json();
    }).then(function (j) {
        document.getElementById('conns').innerHTML =
            render(j.connections, j.now);
    }).catch(function () {
        document.getElementById('conns').innerHTML =
            '<em>stats unavailable</em>';
    });
}
poll();
setInterval(poll, 2000);
</script>

</body>
</html><?php
});

if (php_sapi_name() === 'cli') {
    if (!is_file($cert) || !is_file($key)) {
        fwrite(STDERR, "Cert / key not found at $cert / $key.\n");
        fwrite(STDERR, "Generate them with the script in "
            . "../../security/.\n");
        exit(1);
    }
    echo "\n  Atto pure-PHP HTTP/3 demo.\n";
    echo "  Open https://localhost:8443/ in a browser that\n";
    echo "  speaks HTTP/3 (Chrome, Firefox, Safari all do).\n";
    echo "  The first hit lands over HTTP/2; the page advertises\n";
    echo "  Alt-Svc: h3=\":8443\" so subsequent reloads switch to\n";
    echo "  HTTP/3 and the green banner lights up.\n\n";
    /*
        Listen on plain HTTP/8080 (so the demo is reachable
        without a cert generated, and so curl --http1.1 works
        for a sanity baseline), TLS/8443 for HTTP/2 + HTTP/1.1
        over TCP (browsers need this to learn the Alt-Svc),
        and the pure-PHP H3 listener on UDP/8443. The browser
        upgrades to H3 after the first response.
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
