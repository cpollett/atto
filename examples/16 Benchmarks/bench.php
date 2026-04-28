<?php
/*
    Atto benchmark runner. Hits the endpoints in index.php over
    each available HTTP protocol and prints a comparison table.

    USAGE:
        php bench.php
        php bench.php --iterations=200
        php bench.php --host=127.0.0.1 --plain-port=8080 --tls-port=8443
        php bench.php --only=h2
        php bench.php --skip=headers,big

    PREREQ:
        Start the server first in another shell:
            php index.php

        The runner uses curl as the HTTP client, so php-curl must
        be installed and the curl binary (for --http3 detection)
        is consulted to see which protocols are available.

    PROTOCOLS:
        HTTP/1.1   plain TCP, port 8080
        HTTP/2     TLS+ALPN, port 8443 (requires curl built with
                   --enable-http2, libcurl >= 7.43)
        HTTP/3     TLS+QUIC, port 8443+1 by convention (requires
                   curl built with HTTP/3 support and a server
                   that speaks QUIC; Atto does not yet, so this
                   is shown as "unavailable" until added)

    EXTENDING TO NEW PROTOCOLS:
        Add a new entry to $TRANSPORTS below. Each entry is an
        associative array with:

            name         display name in the report
            available    callable returning bool; check curl
                         capability and whether the server
                         responds on this transport
            endpoint     callable mapping a path to a full URL
            curl_opts    extra curl_setopt_array() pairs for
                         this protocol (e.g.
                         CURLOPT_HTTP_VERSION constant)

        The benchmark cases below are protocol-agnostic; they
        only call endpoint() and curl_opts() through Transport
        helpers, so a new transport plugs in without touching
        the cases.

    OUTPUT FORMAT:
        For each (case, protocol) pair the runner reports:
            iters    number of iterations run
            min ms   fastest single iteration
            median   p50
            p95      95th percentile (tail latency)
            req/s    requests per second derived from median
            kB/s     throughput where applicable
                     (single-shot: body / median; parallel:
                     total bytes / wall-clock)

    INTERPRETING RESULTS:
        On localhost with a single-threaded server (Atto), TLS
        handshake cost dominates short H2 single-shot tests so
        H1 plain looks faster on /small, /headers, /keepalive.
        H2's advantage shows up where TLS cost amortises across
        many streams on one connection — in real-world remote
        scenarios with RTT, the picture flips. The /asset
        parallel test demonstrates multiplexing: at low
        concurrency H2 wins on Atto because all streams share
        one connection, but at high concurrency H1 catches up
        because libcurl opens a connection pool while H2 still
        serialises through one connection (and Atto's H2 path
        is single-threaded).
 */

if (php_sapi_name() !== 'cli') {
    /*
        Guardrail: bench.php is a CLI runner, never useful (or
        safe) under a web server. Refuse to execute under any
        non-CLI SAPI so a misconfigured webroot can't expose it.
     */
    exit();
}

$opts = parseArgs($argv);
if (!empty($opts['help'])) {
    echo trim(<<<'TXT'
Usage: php bench.php [options]

Options:
    --host=HOST           default 127.0.0.1
    --plain-port=PORT     default 8080
    --tls-port=PORT       default 8443
    --quic-port=PORT      default 8444 (HTTP/3, when available)
    --iterations=N        per single-shot case (default 100)
    --concurrency=N       parallel requests for asset case
                          (default 50)
    --only=h1,h2,h3       run only the listed protocols
    --skip=case,case      skip the listed cases
                          (small,big,asset,headers,keepalive)
    --help                this message
TXT);
    echo "\n";
    exit(0);
}
$host = $opts['host'] ?? '127.0.0.1';
$plain_port = (int) ($opts['plain-port'] ?? 8080);
$tls_port = (int) ($opts['tls-port'] ?? 8443);
$quic_port = (int) ($opts['quic-port'] ?? 8444);
$iterations = (int) ($opts['iterations'] ?? 100);
$concurrency = (int) ($opts['concurrency'] ?? 50);
$only = isset($opts['only'])
    ? array_map('trim', explode(',', $opts['only'])) : [];
$skip = isset($opts['skip'])
    ? array_map('trim', explode(',', $opts['skip'])) : [];
if (!extension_loaded('curl')) {
    fwrite(STDERR, "php-curl extension is required.\n");
    exit(1);
}
/*
    Transport definitions. Each transport is what the runner
    asks for protocol-specific behavior (URL scheme, port, curl
    options). Adding a new transport (e.g. HTTP/3 once Atto
    supports it) is a matter of appending another entry here
    and writing its available() probe.
 */
$TRANSPORTS = [
    'h1' => [
        'name' => 'HTTP/1.1',
        'available' => function () use ($host, $plain_port) {
            return probe("http://{$host}:{$plain_port}/small",
                CURL_HTTP_VERSION_1_1);
        },
        'endpoint' => function ($path)
            use ($host, $plain_port) {
            return "http://{$host}:{$plain_port}{$path}";
        },
        'curl_opts' => [
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        ],
    ],
    'h1s' => [
        /*
            HTTP/1.1 over TLS. Same TLS port as H2; ALPN selects
            http/1.1 because we ask curl for HTTP/1.1
            specifically. This is the apples-to-apples comparison
            for H2: both pay TLS encryption + handshake cost,
            so the remaining difference reflects the protocol
            itself rather than transport security.
         */
        'name' => 'HTTP/1.1+TLS',
        'available' => function () use ($host, $tls_port) {
            return probe("https://{$host}:{$tls_port}/small",
                CURL_HTTP_VERSION_1_1);
        },
        'endpoint' => function ($path) use ($host, $tls_port) {
            return "https://{$host}:{$tls_port}{$path}";
        },
        'curl_opts' => [
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ],
    ],
    'h2' => [
        'name' => 'HTTP/2',
        'available' => function () use ($host, $tls_port) {
            if (!defined('CURL_HTTP_VERSION_2_0')) {
                return false;
            }
            return probe("https://{$host}:{$tls_port}/small",
                CURL_HTTP_VERSION_2_0);
        },
        'endpoint' => function ($path) use ($host, $tls_port) {
            return "https://{$host}:{$tls_port}{$path}";
        },
        'curl_opts' => [
            CURLOPT_HTTP_VERSION => defined('CURL_HTTP_VERSION_2_0')
                ? CURL_HTTP_VERSION_2_0 : 0,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ],
    ],
    'h3' => [
        'name' => 'HTTP/3',
        'available' => function () use ($host, $quic_port) {
            /*
                Probe both: that libcurl knows about HTTP/3,
                and that something is actually answering on the
                QUIC port. Atto does not yet speak QUIC so this
                will normally report unavailable; the entry is
                kept so the report layout stays stable when H3
                is added.
             */
            if (!defined('CURL_HTTP_VERSION_3')) {
                return false;
            }
            return probe("https://{$host}:{$quic_port}/small",
                CURL_HTTP_VERSION_3, true);
        },
        'endpoint' => function ($path) use ($host, $quic_port) {
            return "https://{$host}:{$quic_port}{$path}";
        },
        'curl_opts' => [
            CURLOPT_HTTP_VERSION => defined('CURL_HTTP_VERSION_3')
                ? CURL_HTTP_VERSION_3 : 0,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ],
    ],
];
if (!empty($only)) {
    $TRANSPORTS = array_intersect_key(
        $TRANSPORTS, array_flip($only));
}
$active = [];
foreach ($TRANSPORTS as $key => $t) {
    if (($t['available'])()) {
        $active[$key] = $t;
        echo sprintf("  %-12s available\n", $t['name']);
    } else {
        echo sprintf("  %-12s unavailable (skipping)\n",
            $t['name']);
    }
}
if (empty($active)) {
    fwrite(STDERR, "\nNo HTTP protocols available. Is the " .
        "server running on ports {$plain_port}/{$tls_port}?\n");
    exit(1);
}
echo "\n";
/*
    Benchmark cases. Each case is protocol-agnostic — it
    receives a transport descriptor and runs against
    transport endpoints. To add a new case, append to $cases
    below.
 */
$cases = [];
$cases['small'] = function ($t) use ($iterations) {
    $url = ($t['endpoint'])('/small');
    return singleShot($url, $t['curl_opts'], $iterations,
        'per-request overhead, 2-byte body');
};
$cases['big'] = function ($t) use ($iterations) {
    $url = ($t['endpoint'])('/big');
    return singleShot($url, $t['curl_opts'],
        max(10, intdiv($iterations, 10)),
        'sustained throughput, 1 MiB body');
};
$cases['asset'] = function ($t) use ($concurrency) {
    /*
        Parallel-fetch test. With H2 multiplexing all
        $concurrency assets share one connection; with H1.1
        curl will open multiple connections (default 6) so
        the wall-clock time should differ noticeably.
     */
    $urls = [];
    for ($i = 1; $i <= $concurrency; $i++) {
        $urls[] = ($t['endpoint'])('/asset/' . $i);
    }
    return parallelShot($urls, $t['curl_opts'],
        "{$concurrency} parallel asset fetches");
};
$cases['headers'] = function ($t) use ($iterations) {
    $url = ($t['endpoint'])('/headers');
    return singleShot($url, $t['curl_opts'], $iterations,
        '100 custom headers per response');
};
$cases['keepalive'] = function ($t) use ($iterations) {
    /*
        N sequential requests on ONE curl handle so keep-alive
        is exercised. H1 keep-alive vs H2 stream reuse should
        both be fast; cold-connect-per-request would not be.
     */
    $url = ($t['endpoint'])('/small');
    return keepAliveShot($url, $t['curl_opts'], $iterations,
        "{$iterations} sequential requests on one connection");
};
foreach ($skip as $s) {
    unset($cases[$s]);
}
foreach ($cases as $case_name => $case_fn) {
    echo strtoupper($case_name) . "\n";
    $first = true;
    foreach ($active as $key => $t) {
        $result = $case_fn($t);
        if ($first) {
            echo "  " . $result['desc'] . "\n";
            printf("  %-12s  %6s  %8s  %8s  %8s  %8s  %10s\n",
                'protocol', 'iters', 'min(ms)', 'median',
                'p95', 'req/s', 'kB/s');
            $first = false;
        }
        $rps = ($result['median'] > 0)
            ? 1.0 / $result['median'] : 0.0;
        printf("  %-12s  %6d  %8.2f  %8.2f  %8.2f  %8.0f  %10s\n",
            $t['name'],
            $result['iters'],
            $result['min'] * 1000,
            $result['median'] * 1000,
            $result['p95'] * 1000,
            $rps,
            $result['kbps'] === null ? '-'
                : number_format($result['kbps'], 1));
    }
    echo "\n";
}
/*
    Sentinel marker for the dispatcher mode. Only emitted when
    bench.php is invoked by index.php's auto-launch path (which
    sets ATTO_BENCH_DISPATCH=1 in the child's environment).
    Standalone "php bench.php" runs leave it off so the user
    doesn't see noise after the report.
 */
if (getenv('ATTO_BENCH_DISPATCH')) {
    echo "===BENCH_DONE===\n";
}
exit(0);

// -------- helpers --------

/**
 * Parses --key=value style argv into an associative array.
 * Bare --key entries become ['key' => true].
 */
function parseArgs($argv)
{
    $out = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (strpos($arg, '--') !== 0) {
            continue;
        }
        $arg = substr($arg, 2);
        if (strpos($arg, '=') === false) {
            $out[$arg] = true;
        } else {
            list($k, $v) = explode('=', $arg, 2);
            $out[$k] = $v;
        }
    }
    return $out;
}
/**
 * Runs a single GET against $url and returns true if the
 * server answered with a 2xx response. Used by transport
 * available() probes. $strict means the connection must
 * succeed without falling back to a different version.
 */
function probe($url, $http_version, $strict = false)
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => false,
        CURLOPT_TIMEOUT => 2,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTP_VERSION => $http_version,
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $negotiated = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
    curl_close($ch);
    if ($code < 200 || $code >= 400) {
        return false;
    }
    if ($strict && $negotiated !== $http_version) {
        return false;
    }
    return true;
}
/**
 * Runs $iters requests in serial against $url and returns
 * timing statistics. New curl handle per iteration so the
 * connection setup cost is included.
 */
function singleShot($url, $opts, $iters, $desc)
{
    $times = [];
    $bytes = 0;
    for ($i = 0; $i < $iters; $i++) {
        $ch = curl_init();
        curl_setopt_array($ch, $opts + [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ]);
        $body = curl_exec($ch);
        $time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $size = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
        curl_close($ch);
        if ($body === false) {
            continue;
        }
        $times[] = $time;
        $bytes = $size;
    }
    $stats = stats($times);
    $stats['desc'] = $desc;
    $stats['kbps'] = ($bytes > 0 && $stats['median'] > 0)
        ? ($bytes / 1024) / $stats['median']
        : null;
    return $stats;
}
/**
 * Runs N requests on ONE persistent curl handle so the
 * underlying TCP/TLS connection (and HTTP/2 connection
 * with stream reuse) is reused across iterations.
 */
function keepAliveShot($url, $opts, $iters, $desc)
{
    $ch = curl_init();
    curl_setopt_array($ch, $opts + [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_FORBID_REUSE => false,
        CURLOPT_FRESH_CONNECT => false,
    ]);
    $times = [];
    $bytes = 0;
    for ($i = 0; $i < $iters; $i++) {
        $body = curl_exec($ch);
        if ($body === false) {
            continue;
        }
        $time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $bytes = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
        $times[] = $time;
    }
    curl_close($ch);
    $stats = stats($times);
    $stats['desc'] = $desc;
    $stats['kbps'] = ($bytes > 0 && $stats['median'] > 0)
        ? ($bytes / 1024) / $stats['median']
        : null;
    return $stats;
}
/**
 * Issues all $urls in parallel using curl_multi and reports
 * total wall-clock time. With H2 these all multiplex over a
 * single connection; with H1.1 curl opens multiple
 * connections (default ~6) and then queues the rest.
 */
function parallelShot($urls, $opts, $desc)
{
    $mh = curl_multi_init();
    if (defined('CURLPIPE_MULTIPLEX')) {
        /*
            Tells curl to multiplex requests over a single
            connection on H2 instead of opening a fresh
            connection per URL. Critical for the H2 advantage
            to be visible.
         */
        curl_multi_setopt($mh, CURLMOPT_PIPELINING,
            CURLPIPE_MULTIPLEX);
    }
    $handles = [];
    foreach ($urls as $i => $url) {
        $ch = curl_init();
        $per_opts = $opts + [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ];
        /*
            CURLOPT_PIPEWAIT tells libcurl that it's OK to
            wait for an existing H2 connection to finish its
            handshake before deciding whether to open another
            connection. Without this, curl_multi opens a fresh
            TCP+TLS connection per handle and H2 multiplexing
            never kicks in.
         */
        if (defined('CURLOPT_PIPEWAIT')) {
            $per_opts[CURLOPT_PIPEWAIT] = true;
        }
        curl_setopt_array($ch, $per_opts);
        curl_multi_add_handle($mh, $ch);
        $handles[$i] = $ch;
    }
    $start = microtime(true);
    do {
        $status = curl_multi_exec($mh, $running);
        if ($running) {
            curl_multi_select($mh, 0.5);
        }
    } while ($running && $status === CURLM_OK);
    $elapsed = microtime(true) - $start;
    $bytes = 0;
    foreach ($handles as $ch) {
        $bytes += (int) curl_getinfo($ch,
            CURLINFO_SIZE_DOWNLOAD);
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return [
        'desc' => $desc,
        'iters' => count($urls),
        'min' => $elapsed,
        'median' => $elapsed,
        'mean' => $elapsed,
        'p95' => $elapsed,
        'max' => $elapsed,
        'kbps' => ($bytes > 0 && $elapsed > 0)
            ? ($bytes / 1024) / $elapsed : null,
    ];
}
/**
 * Computes min, median, mean, p95, max for an array of times
 * (each in seconds). Returns zeros for an empty input.
 */
function stats($times)
{
    if (empty($times)) {
        return ['iters' => 0, 'min' => 0, 'median' => 0,
            'mean' => 0, 'p95' => 0, 'max' => 0];
    }
    sort($times);
    $n = count($times);
    return [
        'iters' => $n,
        'min' => $times[0],
        'median' => $times[intdiv($n, 2)],
        'mean' => array_sum($times) / $n,
        'p95' => $times[(int) min($n - 1, ceil($n * 0.95) - 1)],
        'max' => $times[$n - 1],
    ];
}
