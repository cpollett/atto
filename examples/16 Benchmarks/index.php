<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    Atto benchmark endpoints. Pair this with bench.php in the
    same folder, which is the runner that hits these endpoints
    over each supported protocol and prints a comparison.

    SERVER ROUTES (protocol-agnostic; Atto picks H1 or H2 per
    request based on ALPN):

        /small        2-byte response. Per-request overhead test
                      (framing, header processing).
        /big          1 MiB response. Sustained-throughput test.
        /asset/{n}    Tiny indexed response. Designed for
                      parallel-fetch tests (mimics a page that
                      loads many small assets). Body length and
                      content depend on n so the runner can
                      verify each asset matches its index.
        /headers      Response with 100 custom X-Bench-* headers.
                      Exercises HPack on H2 and shows the wire-
                      size difference vs H1's repeating
                      plaintext.
        /             Index page summarising the routes.

    The server listens on both plain HTTP (8080) and TLS (8443)
    so the runner can compare protocols on the same code path:
    HTTP/1.1 negotiates over either; HTTP/2 needs ALPN over TLS.

    To run from this folder, you must comment the guard at the
    top of this file. Then:
        php index.php
    Then in another shell:
        php bench.php
    See bench.php --help for runner options.
 */
$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Atto Benchmark Endpoints</title></head>
    <body>
        <h1>Atto Benchmark Endpoints</h1>
        <p>Run <code>php bench.php</code> in this folder to
        compare HTTP/1.1 vs HTTP/2 (and any other protocols
        the runner is configured for).</p>
        <ul>
            <li><a href="/small">/small</a> &mdash; 2 bytes</li>
            <li><a href="/big">/big</a> &mdash; 1 MiB</li>
            <li><a href="/asset/1">/asset/{n}</a> &mdash;
                small indexed asset</li>
            <li><a href="/headers">/headers</a> &mdash;
                100 custom headers</li>
        </ul>
    </body>
    </html>
    <?php
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
        H1 keep-alive concurrency limit. The {n} capture
        lands in $_GET['n'] so each asset has a distinct
        body the caller can verify.
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
    $cert = __DIR__ . "/cert.pem";
    $key = __DIR__ . "/key.pem";
    if (!file_exists($cert) || !file_exists($key)) {
        echo "Generating self-signed cert for benchmarks...\n";
        $cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 30 " .
            "-keyout " . escapeshellarg($key) . " " .
            "-out " . escapeshellarg($cert) . " " .
            "-subj '/CN=localhost' 2>&1";
        passthru($cmd);
    }
    /*
        Listen on both plain HTTP and TLS. The TLS listener
        advertises h2 + http/1.1 via ALPN so clients can
        negotiate either over the same port. The runner uses
        plain HTTP for H1-only tests and TLS for H2 tests
        (since H2 is only widely supported over TLS).
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
    ]);
} else {
    $test->process();
}
