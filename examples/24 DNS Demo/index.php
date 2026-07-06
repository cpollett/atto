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
 *      UDP 15353    -- standard DNS over UDP
 *      TCP 15353    -- standard DNS over TCP (large responses,
 *                     truncation fallback)
 *      TCP 18853    -- DNS-over-TLS (DoT), served with the
 *                     self-signed cert from atto's security/
 *                     folder
 *
 * High ports are used so the demo runs without root. We pick
 * 15353 / 18853 specifically because UDP 5353 is camped by
 * mDNSResponder on macOS (used for multicast DNS / Bonjour),
 * and binding to it can either fail outright or silently
 * have packets stolen by the system resolver. The "1" prefix
 * keeps the mnemonic ("port 53" -> "port 5353" -> "port
 * 15353") while staying clear of every well-known service.
 * A real deployment would bind UDP 53 and TCP 53 (privileged)
 * and TCP 853 for DoT.
 *
 * The companion web UI is spawned automatically and lives at
 *
 *      http://localhost:8080/
 *
 *
 * --- TESTING WITH dig (macOS / Linux / WSL) ---
 *
 *      dig @127.0.0.1 -p 15353 www.example.test A
 *      dig @127.0.0.1 -p 15353 mail-heavy.test MX
 *      dig @127.0.0.1 -p 15353 ipv6-only.v6.test AAAA
 *      dig @127.0.0.1 -p 15353 1.2.0.192.in-addr.arpa PTR
 *      dig @127.0.0.1 -p 15353 ftp.example.test A
 *      dig @127.0.0.1 -p 15353 +tcp example.test ANY
 *
 *
 * --- TESTING ON WINDOWS ---
 *
 * Windows ships nslookup by default. The non-standard port
 * is set with -port= as the first argument, the server IP
 * is the trailing argument:
 *
 *      nslookup -port=15353 -type=A www.example.test 127.0.0.1
 *      nslookup -port=15353 -type=MX mail-heavy.test 127.0.0.1
 *      nslookup -port=15353 -type=AAAA ipv6-only.v6.test 127.0.0.1
 *      nslookup -port=15353 -type=PTR 1.2.0.192.in-addr.arpa 127.0.0.1
 *
 * Or the equivalent interactively (better for several
 * lookups in a row, since it skips the per-query startup):
 *
 *      C:\> nslookup
 *      > server 127.0.0.1
 *      > set port=15353
 *      > set type=MX
 *      > mail-heavy.test
 *
 * Note: Windows PowerShell's Resolve-DnsName cmdlet does
 * NOT support a -Port parameter, so it can only hit the
 * standard port 53. Use nslookup for non-standard ports.
 *
 * If you have installed BIND tools on Windows, the dig
 * commands above work identically.
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
    Spawn the companion web UI exactly like example 23.
    Detached child so the parent process is free to run the
    DNS event loop. On Unix we capture the child PID and
    kill it on shutdown via register_shutdown_function. On
    Windows, "start /B" does not surface the PID, so the
    user has to close the cmd window (or kill php.exe via
    Task Manager) to stop the webui after stopping the DNS
    server. UI URL is http://localhost:8080/.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . "webui.php");
if (strstr(PHP_OS, "WIN")) {
    $job = "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows). Open " .
        "http://localhost:8080/\n";
    echo "  To stop, close this cmd window or end php.exe " .
        "in Task Manager.\n";
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
    'DNS_UDP_PORT' => 15353,
    'DNS_TCP_PORT' => 15353,
    'DNS_TLS_PORT' => 18853,
    'SERVER_NAME' => 'atto-dns-demo',
];
/*
    DNS-over-TLS (RFC 7858) uses the self-signed server cert
    that ships under atto's security/ folder. The same pair
    powers examples 09 (HTTPS), 12 (Virtual Hosting), 16
    (Server Push), 17 (HTTP/3), and 23 (FTPS), so trusting
    it once in your client suffices for the whole repo.
 */
$cert = __DIR__ . DIRECTORY_SEPARATOR . '..' .
    DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .
    'security' . DIRECTORY_SEPARATOR . 'server.crt';
$key = __DIR__ . DIRECTORY_SEPARATOR . '..' .
    DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .
    'security' . DIRECTORY_SEPARATOR . 'server.key';
if (is_file($cert) && is_file($key)) {
    $config['SERVER_CONTEXT'] = ['ssl' => [
        'local_cert' => $cert,
        'local_pk' => $key,
        'allow_self_signed' => true,
        'verify_peer' => false,
    ]];
}
$dns->listen($config);
