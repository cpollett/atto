<?php
/**
 * AttoDNS demo: a click-through tour of authoritative DNS.
 * Visitors land on the demo UI and exercise the running DNS
 * server through three modes:
 *
 *   1. Click-through scenarios that show the wire query, the
 *      wire response, and a human-readable interpretation
 *      side by side -- A, AAAA, MX with glue, TXT, CNAME
 *      chasing, NXDOMAIN with SOA in authority, wildcard,
 *      truncation forcing TCP, EDNS0, and DNS-over-TLS.
 *   2. A dig-style raw query box: type a name, pick a type,
 *      pick a transport (UDP, TCP, DoT), see the actual
 *      bytes go out and come back.
 *   3. A zone editor that reads the .zone master file,
 *      lets you make changes, writes them back, and reloads
 *      the FileDnsAuthority so the next query reflects them.
 *
 * Demonstrates:
 *   - DnsSite: the authoritative server itself, binding
 *     UDP, TCP, and (when a TLS context is configured) DoT
 *   - FileDnsAuthority: zone storage backed by RFC 1035
 *     master-format files
 *   - DnsMessage: the wire-format codec, exposed publicly
 *     so the demo can decode raw bytes for display
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * The demo binds:
 *
 *      UDP 5353    -- standard DNS over UDP
 *      TCP 5353    -- standard DNS over TCP (large responses,
 *                     truncation fallback)
 *      TCP 8853    -- DNS-over-TLS (DoT) when a SERVER_CONTEXT
 *                     ssl block is configured below
 *
 * High ports are used so the demo runs without root. A real
 * deployment would bind UDP 53 and TCP 53 (privileged) and
 * TCP 853 for DoT.
 *
 * The companion web UI is spawned automatically and lives at
 *
 *      http://localhost:8080/
 *
 *
 * --- TESTING WITH dig ---
 *
 *      dig @127.0.0.1 -p 5353 www.example.test A
 *      dig @127.0.0.1 -p 5353 example.test MX
 *      dig @127.0.0.1 -p 5353 ftp.example.test A
 *      dig @127.0.0.1 -p 5353 +tcp example.test ANY
 *
 *
 * --- A REAL DEPLOYMENT WOULD ALSO ---
 *
 *   - Bind to the privileged ports 53 and 853
 *   - Add DNSSEC signing (a future framework phase)
 *   - Run two instances on separate hosts and configure each
 *     as a slave of the other for redundancy
 *   - Front the public listener with a rate-limiter to
 *     dampen reflection-amplification abuse
 *
 * The demo skips all of that to keep the example readable.
 */
require '../../src/DnsSite.php';
use seekquarry\atto\DnsSite;
use seekquarry\atto\FileDnsAuthority;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$zone_dir = __DIR__ . DIRECTORY_SEPARATOR . 'zones';
if (!is_dir($zone_dir)) {
    mkdir($zone_dir, 0755, true);
}
$authority = new FileDnsAuthority($zone_dir);
$dns = new DnsSite($authority);
/*
    Spawn the companion web UI exactly like example 21.
    Detached child so killing the DNS server cleans up the
    UI; UI URL is the conventional http://localhost:8080/.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . "webui.php");
if (strstr(PHP_OS, "WIN")) {
    $job = "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows; close cmd window to stop)\n";
} else {
    $job = "{ exec $php $webui ; } < /dev/null > /dev/null " .
        "2>&1 & echo PID=\$!";
    $h = popen($job, "r");
    $webui_pid = 0;
    if ($h) {
        $line = stream_get_contents($h);
        pclose($h);
        if (preg_match('/PID=(\d+)/', $line, $m)) {
            $webui_pid = (int) $m[1];
        }
    }
    if ($webui_pid > 0) {
        echo "Spawned webui.php (pid $webui_pid). " .
            "Open http://localhost:8080/\n";
        register_shutdown_function(function () use ($webui_pid) {
            @posix_kill($webui_pid, 15);
        });
    } else {
        echo "Warning: failed to capture webui pid; " .
            "you may need to kill it manually.\n";
    }
}
$config = [
    'BIND' => '127.0.0.1',
    'DNS_UDP_PORT' => 5353,
    'DNS_TCP_PORT' => 5353,
    'DNS_TLS_PORT' => 8853,
    'SERVER_NAME' => 'atto-dns-demo',
];
/*
    DNS-over-TLS (RFC 7858) needs a server certificate. We
    read it from cert/ if present; absence means DoT is
    silently skipped. The cert and key files are not shipped
    with atto -- generate a self-signed pair like:
        openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem
            -out cert.pem -days 365 -subj "/CN=atto-dns-demo"
    and drop them in this directory next to index.php.
 */
$cert = __DIR__ . DIRECTORY_SEPARATOR . 'cert.pem';
$key = __DIR__ . DIRECTORY_SEPARATOR . 'key.pem';
if (is_file($cert) && is_file($key)) {
    $config['SERVER_CONTEXT'] = ['ssl' => [
        'local_cert' => $cert,
        'local_pk' => $key,
        'allow_self_signed' => true,
        'verify_peer' => false,
    ]];
}
$dns->listen($config);
