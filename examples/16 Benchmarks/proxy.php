<?php
/*
    Latency-injecting TCP proxy for the Atto benchmark suite.

    Listens on $listen_port, forwards to $target_host:$target_port,
    adds $delay_ms one-way delay (so round-trip latency is 2x).
    Used by bench.php's --latency-ms option to simulate the
    real-world cost of network RTT, where TLS handshakes and
    H1's connection-per-request pattern stop being free.

    USAGE
        php proxy.php <listen_port> <target_host> <target_port>
                      <delay_ms>

    DESIGN
        Single-threaded stream_select loop. Forwards bytes
        verbatim with no protocol awareness, so it works for
        plain HTTP, TLS, and any other byte-stream protocol on
        top of TCP.  Each direction (client->upstream and
        upstream->client) is queued with a delivery deadline of
        now + delay_ms; the main loop drains the queue every
        ~1ms.  The proxy buffers in memory; a single bench run's
        peak buffer is bounded by the bench body size times
        concurrency.
 */

if (php_sapi_name() !== 'cli') {
    /*
        Guardrail: the proxy is a CLI helper for bench.php and
        is never useful or safe under a web server.
     */
    exit();
}

$listen_port = (int) ($argv[1] ?? 9090);
$target_host = $argv[2] ?? '127.0.0.1';
$target_port = (int) ($argv[3] ?? 8443);
$delay_ms    = (float) ($argv[4] ?? 25);
$delay_s     = $delay_ms / 1000.0;

$server = stream_socket_server("tcp://0.0.0.0:$listen_port",
    $errno, $errstr);
if (!$server) {
    fwrite(STDERR, "proxy: listen on $listen_port failed: " .
        "$errstr\n");
    exit(1);
}
stream_set_blocking($server, false);
fwrite(STDERR, "proxy: 0.0.0.0:$listen_port -> " .
    "$target_host:$target_port (delay {$delay_ms}ms each way)\n");

/*
    Connection bookkeeping. A "pair" consists of a peer-facing
    socket (in $client) and a target-facing socket (in $upstream).
    $partner maps each socket id to the id of the other end so a
    read on either side can route into the correct delivery
    queue, and so closing one end can tear down both.
 */
$client = [];
$upstream = [];
$partner = [];
$pending = [];

function close_pair($id, &$client, &$upstream, &$partner)
{
    if (!isset($partner[$id])) {
        return;
    }
    $other = $partner[$id];
    foreach ([$id, $other] as $x) {
        if (isset($client[$x])) {
            @fclose($client[$x]);
            unset($client[$x]);
        }
        if (isset($upstream[$x])) {
            @fclose($upstream[$x]);
            unset($upstream[$x]);
        }
        unset($partner[$x]);
    }
}

while (true) {
    $reads = [$server];
    foreach ($client as $r) {
        $reads[] = $r;
    }
    foreach ($upstream as $r) {
        $reads[] = $r;
    }
    $w = [];
    $e = [];
    @stream_select($reads, $w, $e, 0, 1000);
    foreach ($reads as $sock) {
        if ($sock === $server) {
            $c = @stream_socket_accept($server, 0);
            if (!$c) {
                continue;
            }
            $u = @stream_socket_client(
                "tcp://$target_host:$target_port",
                $u_errno, $u_errstr, 1);
            if (!$u) {
                fclose($c);
                continue;
            }
            stream_set_blocking($c, false);
            stream_set_blocking($u, false);
            $cid = (int) $c;
            $uid = (int) $u;
            $client[$cid] = $c;
            $upstream[$uid] = $u;
            $partner[$cid] = $uid;
            $partner[$uid] = $cid;
            continue;
        }
        $sid = (int) $sock;
        if (!isset($partner[$sid])) {
            continue;
        }
        $data = @fread($sock, 65536);
        if ($data === false || $data === '') {
            close_pair($sid, $client, $upstream, $partner);
            continue;
        }
        $pending[] = [
            microtime(true) + $delay_s,
            $partner[$sid],
            $data
        ];
    }
    /*
        Drain pending deliveries that have aged past their
        deadline. Items targeting closed connections are
        dropped silently; the source side has already torn
        down the pair so the data is genuinely unwanted.
     */
    $now = microtime(true);
    $still = [];
    foreach ($pending as $p) {
        [$when, $dst_id, $data] = $p;
        if ($when > $now) {
            $still[] = $p;
            continue;
        }
        $dst = $client[$dst_id] ?? $upstream[$dst_id] ?? null;
        if ($dst !== null) {
            @fwrite($dst, $data);
        }
    }
    $pending = $still;
}
