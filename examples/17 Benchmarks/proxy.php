<?php
/*
    Latency-injecting proxy for the Atto benchmark suite.

    Listens on $listen_port, forwards to $target_host:$target_port,
    adds $delay_ms one-way delay (so round-trip latency is 2x).
    Used by bench.php's --latency-ms option to simulate the
    real-world cost of network RTT, where TLS handshakes and
    H1's connection-per-request pattern stop being free.

    USAGE
        php proxy.php <listen_port> <target_host> <target_port>
                      <delay_ms> [<protocol>]

        <protocol> is 'tcp' (default) or 'udp'. UDP mode is needed
        for QUIC/HTTP-3, which rides UDP and would otherwise
        bypass a TCP proxy.

    DESIGN
        Single-threaded stream_select loop. Forwards bytes
        verbatim with no protocol awareness, so it works for
        plain HTTP, TLS, QUIC, and any byte-stream or datagram
        protocol on top of TCP/UDP. Each direction (client to
        upstream and upstream to client) is queued with a
        delivery deadline of now + delay_ms; the main loop
        drains the queue every ~1ms.

    TCP MODE
        For each accepted client connection, opens a fresh TCP
        connection to the upstream and forwards bytes both ways
        with the configured delay.

    UDP MODE
        Maintains a flow table keyed by client address
        ("host:port"). When the proxy receives a datagram from a
        new client address, it opens a fresh UDP socket bound to
        an ephemeral local port and connect()s it to the
        upstream so reply datagrams from the upstream arrive on
        that socket. Each subsequent inbound datagram from that
        client is forwarded out the same upstream socket;
        replies from the upstream are routed back to the
        client's original address. Idle flows time out after
        UDP_FLOW_IDLE_SECS seconds and the upstream socket is
        closed.

        UDP mode preserves QUIC connection IDs by passing
        datagrams verbatim. The proxy never inspects or rewrites
        payload bytes; QUIC's encrypted header survives intact.
        TLS for HTTP/3 doesn't bind to port number (only to SNI
        hostname), so curl with verify-peer disabled traverses
        the proxy without certificate complaints.
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
$protocol    = strtolower($argv[5] ?? 'tcp');
$delay_s     = $delay_ms / 1000.0;

if ($protocol === 'udp') {
    runUdpProxy($listen_port, $target_host, $target_port, $delay_s,
        $delay_ms);
} else {
    runTcpProxy($listen_port, $target_host, $target_port, $delay_s,
        $delay_ms);
}

function runTcpProxy($listen_port, $target_host, $target_port,
    $delay_s, $delay_ms)
{
    $server = stream_socket_server("tcp://0.0.0.0:$listen_port",
        $errno, $errstr);
    if (!$server) {
        fwrite(STDERR, "proxy: listen on $listen_port failed: " .
            "$errstr\n");
        exit(1);
    }
    stream_set_blocking($server, false);
    fwrite(STDERR, "proxy: tcp 0.0.0.0:$listen_port -> " .
        "$target_host:$target_port (delay {$delay_ms}ms each way)\n");
    /*
        Connection bookkeeping. A "pair" consists of a peer-facing
        socket (in $client) and a target-facing socket (in
        $upstream). $partner maps each socket id to the id of the
        other end so a read on either side can route into the
        correct delivery queue, and so closing one end can tear
        down both.
     */
    $client = [];
    $upstream = [];
    $partner = [];
    $pending = [];
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
                tcpClosePair($sid, $client, $upstream, $partner);
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
            list($when, $dst_id, $data) = $p;
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
}

function tcpClosePair($id, &$client, &$upstream, &$partner)
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

function runUdpProxy($listen_port, $target_host, $target_port,
    $delay_s, $delay_ms)
{
    $server = stream_socket_server("udp://0.0.0.0:$listen_port",
        $errno, $errstr, STREAM_SERVER_BIND);
    if (!$server) {
        fwrite(STDERR, "proxy: udp listen on $listen_port " .
            "failed: $errstr\n");
        exit(1);
    }
    stream_set_blocking($server, false);
    fwrite(STDERR, "proxy: udp 0.0.0.0:$listen_port -> " .
        "$target_host:$target_port (delay {$delay_ms}ms each way)\n");
    /*
        Flow table. For each unique client peer address we
        maintain one upstream UDP socket (connect()ed to the
        target via stream_socket_client). When the upstream
        replies, the reply comes back on that socket and we
        route it to the client's original peer address.

        Schema:
            $flow_by_peer["host:port"] = [
                'upstream' => stream resource,
                'last_seen' => microtime float,
            ];
            $flow_by_upstream[(int)resource] = "host:port";

        Idle flows are reaped after UDP_FLOW_IDLE_SECS seconds
        of silence to bound memory and FD usage on long bench
        runs. Picking the same value as atto's QUIC idle
        timeout (30s) keeps the proxy from killing flows the
        server still considers live.
     */
    if (!defined('UDP_FLOW_IDLE_SECS')) {
        define('UDP_FLOW_IDLE_SECS', 30.0);
    }
    $flow_by_peer = [];
    $flow_by_upstream = [];
    $pending = [];
    $last_reap = microtime(true);
    while (true) {
        $reads = [$server];
        foreach ($flow_by_peer as $entry) {
            $reads[] = $entry['upstream'];
        }
        $w = [];
        $e = [];
        /*
            Compute a select timeout that wakes us at the next
            queue deadline (or 100 ms if the queue is empty).
            Without this, the select grain is whatever default
            we pick and adds a per-wake-up latency tax to every
            forwarded datagram. For an 800-packet 1 MiB H3
            transfer that tax compounds badly: a 1 ms grain
            inflates a clean 20 ms RTT path to 100+ ms because
            every microbatch of datagrams pays the full tick
            before being forwarded. Driving the select with the
            actual deadline avoids the tax entirely; we wake
            either when packets arrive or precisely when the
            next datagram is due to be forwarded.
         */
        if (!empty($pending)) {
            $now = microtime(true);
            $head_deadline = $pending[0][0];
            foreach ($pending as $p) {
                if ($p[0] < $head_deadline) {
                    $head_deadline = $p[0];
                }
            }
            $wait_s = max(0.0, $head_deadline - $now);
        } else {
            $wait_s = 0.1;
        }
        $sel_secs = (int) floor($wait_s);
        $sel_micro = (int) (($wait_s - $sel_secs) * 1000000);
        @stream_select($reads, $w, $e, $sel_secs, $sel_micro);
        foreach ($reads as $sock) {
            if ($sock === $server) {
                /*
                    Drain every queued client datagram in a
                    tight loop instead of one per outer
                    iteration. UDP recvfrom returns a single
                    datagram per call; when QUIC bursts a few
                    dozen packets, we'd otherwise need that
                    many select wake-ups to consume them all.
                    Tight-loop draining lets one wake-up
                    consume every datagram currently buffered
                    in the kernel, which is the only viable
                    way to keep up with high-rate transfers.
                 */
                while (true) {
                    $peer = '';
                    $data = @stream_socket_recvfrom($server,
                        65535, 0, $peer);
                    if ($data === false || $data === '') {
                        break;
                    }
                    if (!isset($flow_by_peer[$peer])) {
                        $u = @stream_socket_client(
                            "udp://$target_host:$target_port",
                            $u_errno, $u_errstr, 1);
                        if (!$u) {
                            continue;
                        }
                        stream_set_blocking($u, false);
                        $flow_by_peer[$peer] = [
                            'upstream' => $u,
                            'last_seen' => microtime(true),
                        ];
                        $flow_by_upstream[(int) $u] = $peer;
                    } else {
                        $flow_by_peer[$peer]['last_seen']
                            = microtime(true);
                    }
                    $pending[] = [
                        microtime(true) + $delay_s,
                        'upstream',
                        $peer,
                        $data,
                    ];
                }
                continue;
            }
            /*
                Inbound from an upstream socket: this is a
                response datagram. Same tight-loop drain as
                the client side because QUIC's pacer can burst
                dozens of packets at once.
             */
            $sid = (int) $sock;
            if (!isset($flow_by_upstream[$sid])) {
                /*
                    Stale read after the flow was reaped
                    between select() returning and us getting
                    here. Drain whatever is in the kernel and
                    move on.
                 */
                while (@stream_socket_recvfrom($sock, 65535)
                        !== false) {
                    /* discard */
                }
                continue;
            }
            $peer = $flow_by_upstream[$sid];
            while (true) {
                $data = @stream_socket_recvfrom($sock, 65535);
                if ($data === false || $data === '') {
                    break;
                }
                $flow_by_peer[$peer]['last_seen']
                    = microtime(true);
                $pending[] = [
                    microtime(true) + $delay_s,
                    'client',
                    $peer,
                    $data,
                ];
            }
        }
        /*
            Drain pending deliveries that have aged past their
            deadline. Direction tag tells us where to send: an
            'upstream' item is written on the flow's upstream
            socket; a 'client' item is sendto'd on the
            listening socket back to the original peer.
         */
        $now = microtime(true);
        $still = [];
        foreach ($pending as $p) {
            list($when, $dir, $peer, $data) = $p;
            if ($when > $now) {
                $still[] = $p;
                continue;
            }
            if (!isset($flow_by_peer[$peer])) {
                /*
                    Flow reaped before delivery; drop the
                    datagram. The client side either gave up
                    or will retransmit.
                 */
                continue;
            }
            if ($dir === 'upstream') {
                @fwrite($flow_by_peer[$peer]['upstream'], $data);
            } else {
                @stream_socket_sendto($server, $data, 0, $peer);
            }
        }
        $pending = $still;
        /*
            Idle-flow reaping. Walked at most once per second
            so normal benches that finish in seconds don't pay
            the cost. UDP_FLOW_IDLE_SECS of silence in either
            direction means the flow is dead enough to drop.
         */
        if ($now - $last_reap > 1.0) {
            $last_reap = $now;
            foreach ($flow_by_peer as $peer => $entry) {
                if ($now - $entry['last_seen']
                        > UDP_FLOW_IDLE_SECS) {
                    $u = $entry['upstream'];
                    $sid = (int) $u;
                    @fclose($u);
                    unset($flow_by_upstream[$sid]);
                    unset($flow_by_peer[$peer]);
                }
            }
        }
    }
}
