<?php
/**
 * AttoTURN demo: a click-through tour of the STUN / TURN
 * relay protocol (RFC 8489 + RFC 8656). The demo runs a
 * real TURN server on localhost and pairs it with a webui
 * that exercises the protocol in three modes:
 *
 *   1. Click-through scenarios -- pre-built sequences of
 *      STUN/TURN messages (Binding discovery, Allocate with
 *      401 challenge, Send-indication round trip via a
 *      relay peer, ChannelBind + ChannelData, refresh and
 *      teardown) that show the actual on-wire bytes and
 *      decoded structure of every datagram.
 *   2. Raw message builder -- pick a method, attach
 *      attributes, send the message, see the response.
 *   3. Relay live view -- a server-side dashboard of the
 *      current allocations, permissions, and channel
 *      bindings, refreshing every couple of seconds.
 *
 * Demonstrates:
 *
 *   - TurnSite: STUN message framing, attribute encoding,
 *     long-term credential authentication, TURN allocation
 *     lifecycle, permission and channel tables, peer
 *     traffic relay
 *   - StaticTurnAuthenticator: user lookup with cleartext
 *     passwords, suitable for the demo
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * The demo binds:
 *
 *      UDP 13478   -- STUN/TURN control plus the relay
 *                     listener for peer-to-client traffic.
 *      UDP 60000-60100 -- relay-port range; one socket per
 *                     active allocation
 *
 * The high port follows the "decade-shifted" pattern other
 * atto demos use: 13478 is mnemonic for "STUN-on-3478-but-
 * prefixed-with-1". A real deployment binds 3478 (a
 * privileged port) and may also offer 5349 for STUN-over-
 * TLS / TURN-over-TLS, which is not implemented here.
 *
 * The launcher binds on IPv4 by default (127.0.0.1). Use
 * the "Bind" dropdown in the demo's web UI to switch to
 * IPv6 (::1) or to a dual-stack listener (::); the choice
 * is persisted in bind.txt and takes effect on the next
 * launch. RFC 8656 supports IPv4 and IPv6 cleanly because
 * XOR-MAPPED-ADDRESS / XOR-RELAYED-ADDRESS / XOR-PEER-
 * ADDRESS attributes self-describe their address family.
 *
 * The companion web UI is spawned automatically and lives
 * at
 *
 *      http://localhost:8080/
 *
 *
 * --- DEMO CREDENTIALS ---
 *
 * The static credential store is configured with two
 * users out of the box:
 *
 *      alice / hunter2
 *      bob   / sekret
 *
 * The realm advertised in 401 challenges is
 * "atto-turn-demo".
 *
 * --- CONNECTING WITH A REAL TURN CLIENT ---
 *
 * The demo speaks RFC 8656 TURN over UDP. To exercise it
 * with a third-party client (e.g. Pion's turn-cli, the
 * coturn turnutils_uclient binary, or any WebRTC stack
 * configured with a custom TURN server), point the client
 * at:
 *
 *      stun:127.0.0.1:13478          (Binding only)
 *      turn:127.0.0.1:13478?transport=udp
 *
 * with username "alice" and password "hunter2", realm
 * "atto-turn-demo". The relayed-address returned in the
 * Allocate response will be a 127.0.0.1 (or [::1]) port in
 * the 60000-60100 range; permissioned peers can send
 * datagrams to that port and they arrive as Data
 * indications on the client's control socket.
 *
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 *
 * LICENSE:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license http://www.gnu.org/licenses/ GPL-3.0-or-later
 * @link http://www.seekquarry.com/
 * @copyright 2017-2026
 * @filesource
 */
require '../../src/TurnSite.php';
use seekquarry\atto\TurnSite;
use seekquarry\atto\StaticTurnAuthenticator;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$turn = new TurnSite();
$turn->auth(new StaticTurnAuthenticator([
    'alice' => 'hunter2',
    'bob' => 'sekret',
]))->realm('atto-turn-demo')
   ->software('atto-turn-demo 1.0')
   ->relayPortRange(60000, 60100);
/*
    Bind family is selectable at runtime via the dropdown
    in the webui's reset bar. The selection is persisted
    in bind.txt and read here on every launch. Allowed
    values:
        "127.0.0.1" -- IPv4 loopback only (default)
        "::1"       -- IPv6 loopback only
        "0.0.0.0"   -- IPv4 on all interfaces
        "::"        -- IPv6 on all interfaces; on most
                       Linux/BSD this also accepts IPv4
                       through v4-mapped addresses
    Anything else falls back to "127.0.0.1" so a
    corrupted bind.txt cannot ground the demo.
 */
$bind_file = __DIR__ . DIRECTORY_SEPARATOR . 'bind.txt';
$bind_value = is_file($bind_file) ?
    trim((string) file_get_contents($bind_file)) :
    '127.0.0.1';
if (!in_array($bind_value,
    ['127.0.0.1', '::1', '0.0.0.0', '::'], true)) {
    $bind_value = '127.0.0.1';
}
$config = [
    'BIND' => $bind_value,
    'TURN_PORT' => 13478,
];
/*
    Spawn the companion web UI. Same detached-child pattern
    as examples 21-24. We export ATTOTURN_SERVER_PID into
    the spawned webui's environment so the bind-switch
    endpoint can signal index.php (us) to shut down.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR .
    "webui.php");
$self_pid = getmypid();
if (strstr(PHP_OS, "WIN")) {
    $job = "set ATTOTURN_SERVER_PID=$self_pid && " .
        "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows). Open " .
        "http://localhost:8080/\n";
    echo "  To stop, click 'Switch bind' in the UI, or " .
        "close this cmd window, or end php.exe in Task " .
        "Manager.\n";
} else {
    $job = "{ export ATTOTURN_SERVER_PID=$self_pid; " .
        "exec $php $webui ; } < /dev/null > /dev/null " .
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
        register_shutdown_function(
            function () use ($webui_pid) {
                @posix_kill($webui_pid, 15);
            });
    } else {
        echo "Warning: failed to capture webui pid; " .
            "you may need to kill it manually.\n";
    }
}
$turn->listen($config);
