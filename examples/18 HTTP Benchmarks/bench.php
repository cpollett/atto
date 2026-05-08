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

    DEBUGGING SLOW OR EMPTY ROWS:
        Set ATTO_BENCH_DEBUG=1 to log per-iteration curl errors
        for any row reporting fewer successful iters than the
        target. Useful when an H3 row appears to "hang" -- the
        debug output shows whether each iteration is timing
        out (errno=28 CURLE_OPERATION_TIMEDOUT), failing to
        connect (errno=7), or some other curl-level error,
        plus the negotiated HTTP version per success so you
        can see if libcurl is silently falling back to H2.
            ATTO_BENCH_DEBUG=1 php bench.php --only=h3

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
        HTTP/3     TLS+QUIC, port 8443/UDP (same port as H2 but
                   over UDP; requires curl built with HTTP/3
                   support and atto's H3 listener which is opt-in
                   via libquiche/PHP FFI; reported as
                   "unavailable" if either piece is missing)

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

/*
    Silence deprecation notices so bench output stays clean for
    the dashboard parser. PHP 8.5 deprecates a number of curl
    functions that have been no-ops since 8.0; we don't call them
    anymore but third-party extensions may.
 */
error_reporting(E_ALL & ~E_DEPRECATED);

$opts = parseArgs($argv);
if (!empty($opts['help'])) {
    echo trim(<<<'TXT'
Usage: php bench.php [options]

Options:
    --host=HOST           default 127.0.0.1
    --plain-port=PORT     default 8080
    --tls-port=PORT       default 8443
    --quic-port=PORT      default 8444 (pure-PHP HTTP/3 listener,
                          'h3' protocol code in atto's listen
                          spec, bound on UDP)
    --quiche-port=PORT    default 8443 (libquiche-FFI listener,
                          'h3-quiche' protocol code, shares the
                          TLS port number but on UDP)
    --include-quiche      include the libquiche-FFI 'h3-quiche'
                          row in the run. Default off because
                          libquiche/PHP-FFI is an optional
                          dependency that most users will not
                          have. The dashboard renders a checkbox
                          when libquiche is detected and forwards
                          this flag through.
    --iterations=N        per single-shot case (default 100)
    --concurrency=N       parallel requests for asset case
                          (default 50)
    --latency-ms=N        simulate one-way network latency by
                          spawning a proxy in front of each
                          port (TCP for H1/H1+TLS/H2, UDP for
                          H3); round-trip is 2*N.
    --only=h1,h1s,h2,h3,h3-quiche
                          run only the listed protocols
    --skip=case,case      skip the listed cases
                          (small,big,asset,headers,keepalive,post)
    --help                this message
TXT);
    echo "\n";
    exit(0);
}
$host = $opts['host'] ?? '127.0.0.1';
$plain_port = (int) ($opts['plain-port'] ?? 8080);
$tls_port = (int) ($opts['tls-port'] ?? 8443);
/*
    Pure-PHP HTTP/3 listener (atto's 'h3' protocol code) binds a
    UDP-only port that's separate from the TLS port -- by default
    8444. The FFI libquiche listener ('h3-quiche'), when included,
    shares the TLS port number on UDP. index.php in this directory
    uses these defaults; override if you've moved them.
 */
$quic_port = (int) ($opts['quic-port'] ?? 8444);
$quiche_port = (int) ($opts['quiche-port'] ?? $tls_port);
$include_quiche = !empty($opts['include-quiche']);
$iterations = (int) ($opts['iterations'] ?? 100);
$concurrency = (int) ($opts['concurrency'] ?? 50);
$latency_ms = (float) ($opts['latency-ms'] ?? 0);
$only = isset($opts['only'])
    ? array_map('trim', explode(',', $opts['only'])) : [];
$skip = isset($opts['skip'])
    ? array_map('trim', explode(',', $opts['skip'])) : [];
if (!extension_loaded('curl')) {
    fwrite(STDERR, "php-curl extension is required.\n");
    exit(1);
}
/*
    --latency-ms support. Spawn a pair of proxy.php children that
    sit in front of the plain and TLS ports and add a delay
    each way. The transports below get rewritten to point at the
    proxy ports instead of the original ports. Children are
    detached (yioop's CrawlDaemon::execInOwnProcess pattern) so
    the bench process doesn't have to manage them; they exit
    automatically when the bench process exits because their
    listening sockets close. We pick high random ports for the
    proxy listeners so they don't collide with the real services.
 */
$proxy_children = [];
if ($latency_ms > 0) {
    $proxy_plain_port = $plain_port + 10000;
    $proxy_tls_port = $tls_port + 10000;
    /*
        H3 proxy uses a separate offset (+20000 instead of
        +10000) because QUIC reuses the same port number as
        H2/TLS but on UDP. Without the different offset, both
        proxies would try to advertise the same listen port to
        the bench client even though TCP/UDP namespaces are
        independent at the kernel level. The bench client
        cannot reach two services on the same port with
        different protocols transparently because curl picks
        URL host:port first and decides protocol by ALPN /
        --http3 flag separately, and our --quic-port option is
        a single integer. Different ports keep the wiring
        unambiguous.
     */
    $proxy_quic_port = $quic_port + 20000;
    /*
        FFI libquiche listener gets its own proxy port. Same
        +20000 offset (UDP) but applied to the libquiche's UDP
        port (default 8443, shares with the TLS port number) so
        when --include-quiche is set the two can run in parallel
        without clashing.
     */
    $proxy_quiche_port = $quiche_port + 20000;
    $php = escapeshellarg(PHP_BINARY);
    $script = escapeshellarg(__DIR__ . "/proxy.php");
    $proxy_specs = [
        [$proxy_plain_port, $host, $plain_port, 'tcp'],
        [$proxy_tls_port, $host, $tls_port, 'tcp'],
        [$proxy_quic_port, $host, $quic_port, 'udp'],
    ];
    if ($include_quiche) {
        $proxy_specs[] = [$proxy_quiche_port, $host,
            $quiche_port, 'udp'];
    }
    foreach ($proxy_specs as $proxy_spec) {
        list($listen, $thost, $tport, $proto) = $proxy_spec;
        $cmd = "$php $script $listen " . escapeshellarg($thost) .
            " $tport " . escapeshellarg((string) $latency_ms) .
            " " . escapeshellarg($proto);
        if (strstr(PHP_OS, "WIN")) {
            $job = "start /B $cmd > NUL 2>&1";
            pclose(popen($job, "r"));
            /*
                Windows: no straightforward way to capture the
                child PID via popen. Proxies will linger after
                bench exits; user can close the cmd window or
                kill via Task Manager.
             */
        } else {
            /*
                Unix: wrap in a brace+exec so the shell's $!
                refers to the proxy itself (not a transient
                subshell), and echo it back through popen so
                we can capture the PID for cleanup. The full
                idiom { exec CMD; } & echo $! gives us a PID
                that survives bench's exit.
             */
            $job = "{ exec $cmd; } < /dev/null > /dev/null " .
                "2>&1 & echo PID=\$!";
            $h = popen($job, "r");
            if ($h) {
                $line = stream_get_contents($h);
                pclose($h);
                if (preg_match('/PID=(\d+)/', $line, $m)) {
                    $proxy_children[] = (int) $m[1];
                }
            }
        }
    }
    /*
        Register a shutdown handler to kill the proxy children
        whether the bench finishes normally or aborts.
        register_shutdown_function fires for normal completion,
        die(), uncaught exceptions, and pcntl signals once we
        bind them. Without this, repeated --latency-ms runs
        would leak proxy processes.
     */
    register_shutdown_function(function () use (&$proxy_children) {
        foreach ($proxy_children as $pid) {
            if (function_exists('posix_kill')) {
                @posix_kill($pid, 15);  // SIGTERM
            }
        }
    });
    if (function_exists('pcntl_signal')) {
        pcntl_async_signals(true);
        $sigh = function ($sig) use (&$proxy_children) {
            foreach ($proxy_children as $pid) {
                @posix_kill($pid, 15);
            }
            exit(128 + $sig);
        };
        pcntl_signal(SIGINT, $sigh);
        pcntl_signal(SIGTERM, $sigh);
    }
    /*
        Wait for the proxy listeners to be ready. A bare usleep
        is racy when the host is loaded; instead poll by
        attempting a short TCP connect to each TCP proxy port
        until both succeed or we time out. The UDP proxy can't
        be probed the same way (UDP has no connect handshake)
        so we just wait for it via a short fixed sleep after
        the TCP probes complete. 2-second budget is plenty for
        three PHP children to bind a socket.
     */
    $deadline = microtime(true) + 2.0;
    foreach ([$proxy_plain_port, $proxy_tls_port] as $port) {
        while (microtime(true) < $deadline) {
            $probe = @stream_socket_client(
                "tcp://{$host}:{$port}",
                $perr, $pmsg, 0.5);
            if ($probe) {
                fclose($probe);
                break;
            }
            usleep(50 * 1000);
        }
    }
    /*
        Brief grace period for the UDP proxy to bind. We can't
        usefully probe it (a UDP recvfrom that times out vs. an
        unbound port look the same from PHP) so a short sleep
        is the simplest reliable wait.
     */
    usleep(100 * 1000);
    $plain_port = $proxy_plain_port;
    $tls_port = $proxy_tls_port;
    $quic_port = $proxy_quic_port;
    if ($include_quiche) {
        $quiche_port = $proxy_quiche_port;
    }
    fwrite(STDERR, "  latency: " . $latency_ms .
        "ms each way (RTT " . (2 * $latency_ms) . "ms)\n");
}
/*
    Transport definitions. Each transport is what the runner
    asks for protocol-specific behavior (URL scheme, port, curl
    options). Adding a new transport is a matter of appending
    another entry here and writing its available() probe.
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
        /*
            Pure-PHP HTTP/3 listener. No libquiche, no FFI --
            ext-openssl + ext-sodium are the only requirements,
            both of which ship with stock PHP. Runs by default
            whenever atto's index.php has bound an h3:// listener
            (default UDP port 8444). If curl supports HTTP/3 the
            row probes successfully; if not, the row is skipped.
         */
        'name' => 'HTTP/3',
        'available' => function () use (
            $host, $quic_port, $latency_ms) {
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
            /*
                Use CURL_HTTP_VERSION_3ONLY when available
                (libcurl >= 7.88.0). Plain CURL_HTTP_VERSION_3
                lets libcurl silently fall back to HTTP/2 over
                TCP if QUIC fails, which masks H3-specific
                bugs and inflates per-iteration latency on
                hosts where the UDP port has no TCP listener.
                _3ONLY pins the row to true HTTP/3.
             */
            CURLOPT_HTTP_VERSION =>
                defined('CURL_HTTP_VERSION_3ONLY')
                    ? CURL_HTTP_VERSION_3ONLY
                    : (defined('CURL_HTTP_VERSION_3')
                        ? CURL_HTTP_VERSION_3 : 0),
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ],
    ],
];
if ($include_quiche) {
    /*
        libquiche-FFI HTTP/3 listener. Opt-in because libquiche
        and PHP-FFI are not stock dependencies; the dashboard
        renders a checkbox when libquiche is detected and
        forwards --include-quiche when checked. Endpoint mirrors
        the 'h3' transport above but points at the libquiche
        listener's UDP port (default 8443, shared with TLS).
     */
    $TRANSPORTS['h3-quiche'] = [
        'name' => 'HTTP/3-quiche',
        'available' => function () use (
            $host, $quiche_port, $latency_ms) {
            if (!defined('CURL_HTTP_VERSION_3')) {
                return false;
            }
            return probe(
                "https://{$host}:{$quiche_port}/small",
                CURL_HTTP_VERSION_3, true);
        },
        'endpoint' => function ($path)
            use ($host, $quiche_port) {
            return "https://{$host}:{$quiche_port}{$path}";
        },
        'curl_opts' => [
            CURLOPT_HTTP_VERSION =>
                defined('CURL_HTTP_VERSION_3ONLY')
                    ? CURL_HTTP_VERSION_3ONLY
                    : (defined('CURL_HTTP_VERSION_3')
                        ? CURL_HTTP_VERSION_3 : 0),
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ],
    ];
}
if (!empty($only)) {
    $TRANSPORTS = array_intersect_key(
        $TRANSPORTS, array_flip($only));
}
$active = [];
foreach ($TRANSPORTS as $key => $t) {
    if (($t['available'])()) {
        $active[$key] = $t;
        echo sprintf("  %-13s available\n", $t['name']);
    } else {
        echo sprintf("  %-13s unavailable (skipping)\n",
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
$cases['post'] = function ($t) use ($iterations) {
    /*
        Round-trip POST with a 64 KiB payload. The runner
        verifies the response body matches the request body
        byte-for-byte; iterations that mismatch are dropped
        so a silently-truncating server reports zero iters
        rather than a bogus throughput number.
     */
    $url = ($t['endpoint'])('/echo-post');
    $body = str_repeat('x', 65536);
    return postShot($url, $t['curl_opts'], $body, $iterations,
        '64 KiB POST round-trip with body verification');
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
            printf("  %-13s  %6s  %8s  %8s  %8s  %8s  %10s\n",
                'protocol', 'iters', 'min(ms)', 'median',
                'p95', 'req/s', 'kB/s');
            $first = false;
        }
        $rps = ($result['median'] > 0)
            ? 1.0 / $result['median'] : 0.0;
        printf("  %-13s  %6d  %8.2f  %8.2f  %8.2f  %8.0f  %10s\n",
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
    /*
        Probe timeout is generous (5s) so it tolerates the
        proxy used by --latency-ms without false negatives.
        Real cold connection on localhost is sub-millisecond;
        the timeout only matters when something is actually
        wrong.
     */
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => false,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_HTTP_VERSION => $http_version,
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $negotiated = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
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
    $debug = (bool) getenv('ATTO_BENCH_DEBUG');
    $times = [];
    $bytes = 0;
    $first_err = null;
    $err_codes = [];
    $http_versions = [];
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
        $errno = curl_errno($ch);
        $err = curl_error($ch);
        $hv = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
        if ($body === false) {
            if ($debug) {
                /*
                    Print only the first 5 failures per row
                    so 100-iter rows with everything failing
                    don't drown the report.
                 */
                if (count($err_codes) < 5) {
                    fwrite(STDERR, sprintf(
                        "    [debug] iter=%d errno=%d "
                        . "err=%s elapsed=%.3fs hv=%d\n",
                        $i, $errno, $err, $time, $hv));
                }
                $err_codes[$errno] =
                    ($err_codes[$errno] ?? 0) + 1;
            }
            if ($first_err === null) {
                $first_err = "errno=$errno $err";
            }
            continue;
        }
        if ($debug) {
            $http_versions[$hv] = ($http_versions[$hv] ?? 0) + 1;
        }
        $times[] = $time;
        $bytes = $size;
    }
    if ($debug && !empty($err_codes)) {
        fwrite(STDERR, "    [debug] err code counts: "
            . json_encode($err_codes) . "\n");
    }
    if ($debug && !empty($http_versions)) {
        fwrite(STDERR, "    [debug] http_version counts: "
            . json_encode($http_versions) . "\n");
    }
    $stats = stats($times);
    $stats['desc'] = $desc;
    $stats['kbps'] = ($bytes > 0 && $stats['median'] > 0)
        ? ($bytes / 1024) / $stats['median']
        : null;
    return $stats;
}
/**
 * Runs N POST requests with a fixed body, verifying the
 * response equals the request body byte-for-byte each
 * iteration. Mismatches are dropped (treated like errors)
 * so the timing stats only reflect successful round-trips.
 * The kbps figure is computed from upload + download bytes
 * since the test exercises both directions.
 */
function postShot($url, $opts, $body, $iters, $desc)
{
    $body_len = strlen($body);
    $times = [];
    for ($i = 0; $i < $iters; $i++) {
        $ch = curl_init();
        curl_setopt_array($ch, $opts + [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/octet-stream',
                'Content-Length: ' . $body_len,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ]);
        $resp = curl_exec($ch);
        $time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        if ($resp === false || $resp !== $body) {
            continue;
        }
        $times[] = $time;
    }
    $stats = stats($times);
    $stats['desc'] = $desc;
    /*
        kB/s reported here is one-way (download) since that is
        what the other cases also report; the bench is comparing
        protocols on the same metric. Upload bytes are roughly
        equal in this case.
     */
    $stats['kbps'] = ($body_len > 0 && $stats['median'] > 0)
        ? ($body_len / 1024) / $stats['median']
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
