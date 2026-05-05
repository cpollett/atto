<?php
/**
 * AttoTURN demo webui. Companion UI to index.php; see that
 * file for the demo's "how to run" docs and the full
 * configuration. This script is itself an atto WebSite
 * application that uses a thin set of TURN-client helpers
 * to exercise the running TURN server. Three tabs:
 *
 *   1. Scenarios -- click-through canned exchanges. Each
 *      scenario opens a UDP socket, sends a sequence of
 *      STUN messages or ChannelData frames against the
 *      running TURN server, and renders the wire transcript.
 *   2. Raw message builder -- pick a method, attach
 *      attributes, send the message, see the response.
 *   3. Allocations -- a server-side dashboard of the
 *      currently-running allocations, permissions, and
 *      channel bindings.
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 * License: GPL-3.0-or-later
 * @author Chris Pollett chris@pollett.org
 * @copyright 2017-2026
 * @filesource
 */
require '../../src/WebSite.php';
require '../../src/TurnSite.php';
use seekquarry\atto\WebSite;
use seekquarry\atto\TurnSite;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$site = new WebSite(".");
$cfg = [
    'host' => '127.0.0.1',
    'port' => 13478,
    'realm' => 'atto-turn-demo',
    'bind_file' => __DIR__ . DIRECTORY_SEPARATOR .
        'bind.txt',
    /*
        Allowed BIND values for the runtime dropdown.
        Mirrors the choices in index.php's allowlist.
     */
    'bind_choices' => [
        '127.0.0.1' => 'IPv4 loopback (127.0.0.1)',
        '::1' => 'IPv6 loopback (::1)',
        '0.0.0.0' => 'IPv4 all interfaces (0.0.0.0)',
        '::' => 'IPv6 / dual-stack all interfaces (::)',
    ],
    'demo_users' => [
        ['user' => 'alice', 'pass' => 'hunter2'],
        ['user' => 'bob', 'pass' => 'sekret'],
    ],
];
/*
    Derive the dial host from the current bind. Same logic
    as ex23: loopback addresses on the matching family.
 */
$cfg['host'] = turnHostFromBind(
    is_file($cfg['bind_file']) ?
    trim((string) file_get_contents($cfg['bind_file'])) :
    '127.0.0.1');
function turnHostFromBind($bind)
{
    if ($bind === '::1' || $bind === '::') {
        return '::1';
    }
    return '127.0.0.1';
}
/**
 * Bracket-wraps IPv6 hosts for stream_socket_client.
 */
function turnDialUrl($host, $port)
{
    if (strpos($host, ':') !== false) {
        return "udp://[$host]:$port";
    }
    return "udp://$host:$port";
}
/*
    --- TURN client primitives ---

    Most STUN constants we mirror by-name from TurnSite so
    the demo and the server agree on the wire format. We
    reimplement the encode/decode helpers here rather than
    expose the framework's protected methods, to keep the
    educational separation: the demo is a real client
    talking to the server over a real socket.
 */
const TURN_MAGIC = 0x2112A442;
const TURN_M_BINDING = 0x001;
const TURN_M_ALLOCATE = 0x003;
const TURN_M_REFRESH = 0x004;
const TURN_M_SEND = 0x006;
const TURN_M_DATA = 0x007;
const TURN_M_CREATE_PERMISSION = 0x008;
const TURN_M_CHANNEL_BIND = 0x009;
const TURN_C_REQUEST = 0x0000;
const TURN_C_INDICATION = 0x0010;
const TURN_C_SUCCESS = 0x0100;
const TURN_C_ERROR = 0x0110;
const TURN_ATTR_USERNAME = 0x0006;
const TURN_ATTR_MI = 0x0008;
const TURN_ATTR_ERROR = 0x0009;
const TURN_ATTR_REALM = 0x0014;
const TURN_ATTR_NONCE = 0x0015;
const TURN_ATTR_XOR_MAPPED = 0x0020;
const TURN_ATTR_LIFETIME = 0x000D;
const TURN_ATTR_XOR_PEER = 0x0012;
const TURN_ATTR_DATA = 0x0013;
const TURN_ATTR_XOR_RELAYED = 0x0016;
const TURN_ATTR_REQ_TRANSPORT = 0x0019;
const TURN_ATTR_CHAN = 0x000C;
const TURN_ATTR_SOFTWARE = 0x8022;
/**
 * Encodes the 16-bit message-type field from method and
 * class (the bit-spread documented in TurnSite::encode-
 * MessageType). Same algorithm; duplicated here so the
 * webui doesn't reach into the framework's protected
 * surface.
 */
function turnEncType($method, $class)
{
    $low = ($method & 0x000F);
    $mid = ($method & 0x0070) << 1;
    $high = ($method & 0x0F80) << 2;
    return $low | $mid | $high |
        ($class & 0x0010) | ($class & 0x0100);
}
/**
 * Decodes a 16-bit message-type into [method, class].
 */
function turnDecType($t)
{
    $m = ($t & 0x000F) | (($t & 0x00E0) >> 1) |
        (($t & 0x3E00) >> 2);
    $c = ($t & 0x0010) | ($t & 0x0100);
    return [$m, $c];
}
/**
 * Encodes one STUN attribute (type, length, value) with
 * 4-byte padding.
 */
function turnAttr($t, $v)
{
    $L = strlen($v);
    $out = pack('nn', $t, $L) . $v;
    $pad = (4 - ($L % 4)) % 4;
    return $out . str_repeat("\x00", $pad);
}
/**
 * Builds a complete STUN message. If $key is non-empty,
 * appends a MESSAGE-INTEGRITY attribute computed over the
 * header (with provisional length) and body.
 */
function turnBuildMsg($method, $class, $tid, $blocks,
    $key = '')
{
    $body = implode('', $blocks);
    if ($key !== '') {
        $provLen = strlen($body) + 24;
        $hdr = pack('nnN',
            turnEncType($method, $class),
            $provLen, TURN_MAGIC) . $tid;
        $mac = hash_hmac('sha1', $hdr . $body, $key, true);
        $body .= turnAttr(TURN_ATTR_MI, $mac);
    }
    $hdr = pack('nnN',
        turnEncType($method, $class),
        strlen($body), TURN_MAGIC) . $tid;
    return $hdr . $body;
}
/**
 * Parses a STUN message from a byte buffer into a
 * structured array. Returns false on parse error.
 */
function turnParseMsg($buf)
{
    if (strlen($buf) < 20) {
        return false;
    }
    $h = unpack('ntype/nlen/Ncookie', substr($buf, 0, 8));
    if ($h['cookie'] !== TURN_MAGIC) {
        return false;
    }
    $tid = substr($buf, 8, 12);
    list($m, $c) = turnDecType($h['type']);
    $attrs = [];
    $off = 20;
    while ($off + 4 <= 20 + $h['len']) {
        $a = unpack('nt/nl', substr($buf, $off, 4));
        $v = substr($buf, $off + 4, $a['l']);
        $attrs[$a['t']][] = $v;
        $off += 4 + $a['l'];
        $off += (4 - ($a['l'] % 4)) % 4;
    }
    return ['method' => $m, 'class' => $c, 'tid' => $tid,
        'attrs' => $attrs, 'raw' => $buf];
}
/**
 * Returns the first instance of an attribute by type, or
 * null if not present.
 */
function turnAttr1($msg, $type)
{
    return $msg['attrs'][$type][0] ?? null;
}
/**
 * Encodes XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, or
 * XOR-RELAYED-ADDRESS. RFC 8489 sec 14.2.
 */
function turnEncXor($host, $port, $tid)
{
    $is6 = strpos($host, ':') !== false;
    $fam = $is6 ? 0x02 : 0x01;
    $p = $port ^ ((TURN_MAGIC >> 16) & 0xFFFF);
    if ($is6) {
        $a = inet_pton($host) ^
            (pack('N', TURN_MAGIC) . $tid);
    } else {
        $a = inet_pton($host) ^ pack('N', TURN_MAGIC);
    }
    return pack('CCn', 0, $fam, $p) . $a;
}
/**
 * Decodes an XOR-*-ADDRESS attribute back to [host, port].
 */
function turnDecXor($v, $tid)
{
    if (strlen($v) < 8) {
        return [false, 0];
    }
    $h = unpack('Cz/Cf/np', substr($v, 0, 4));
    $port = $h['p'] ^ ((TURN_MAGIC >> 16) & 0xFFFF);
    if ($h['f'] === 0x01) {
        $a = substr($v, 4, 4) ^ pack('N', TURN_MAGIC);
        return [inet_ntop($a), $port];
    } else if ($h['f'] === 0x02) {
        if (strlen($v) < 20) {
            return [false, 0];
        }
        $a = substr($v, 4, 16) ^
            (pack('N', TURN_MAGIC) . $tid);
        return [inet_ntop($a), $port];
    }
    return [false, 0];
}
/**
 * Decodes an ERROR-CODE attribute into [code, reason].
 */
function turnDecErr($v)
{
    if (strlen($v) < 4) {
        return [0, ''];
    }
    $b = unpack('Cr1/Cr2/Cclass/Cnum', substr($v, 0, 4));
    return [$b['class'] * 100 + $b['num'],
        substr($v, 4)];
}
/**
 * Sends one datagram and reads the next reply. Returns
 * the reply bytes (or '' on timeout). If $timeout_ms is
 * 0, doesn't wait for a reply (useful for indications).
 */
function turnRoundTrip($sock, $msg, $timeout_ms = 1500)
{
    @stream_socket_sendto($sock, $msg);
    if ($timeout_ms === 0) {
        return '';
    }
    stream_set_timeout($sock, intdiv($timeout_ms, 1000),
        ($timeout_ms % 1000) * 1000);
    $peer = '';
    $buf = @stream_socket_recvfrom($sock, 65535, 0, $peer);
    return $buf === false ? '' : $buf;
}
/**
 * Renders one STUN message as a multi-line text block for
 * the transcript: a one-line header summary plus one line
 * per attribute. The transcript view is the demo's main
 * pedagogical surface, so we go to some trouble to make
 * each line readable.
 */
function turnRenderMsg($buf, $direction)
{
    $msg = turnParseMsg($buf);
    if ($msg === false) {
        if (strlen($buf) >= 4) {
            $first = ord($buf[0]);
            if (($first & 0xC0) === 0x40) {
                $h = unpack('nchan/nlen',
                    substr($buf, 0, 4));
                $payload = substr($buf, 4, $h['len']);
                return $direction . ' ChannelData chan=0x' .
                    sprintf('%04X', $h['chan']) .
                    ' len=' . $h['len'] . ' data=' .
                    turnPrintable($payload) . "\n";
            }
        }
        return $direction . ' (unparseable, ' .
            strlen($buf) . " bytes)\n";
    }
    $method_names = [
        TURN_M_BINDING => 'Binding',
        TURN_M_ALLOCATE => 'Allocate',
        TURN_M_REFRESH => 'Refresh',
        TURN_M_SEND => 'Send',
        TURN_M_DATA => 'Data',
        TURN_M_CREATE_PERMISSION => 'CreatePermission',
        TURN_M_CHANNEL_BIND => 'ChannelBind',
    ];
    $class_names = [
        TURN_C_REQUEST => 'request',
        TURN_C_INDICATION => 'indication',
        TURN_C_SUCCESS => 'success',
        TURN_C_ERROR => 'error',
    ];
    $mname = $method_names[$msg['method']] ??
        'method-0x' . sprintf('%03X', $msg['method']);
    $cname = $class_names[$msg['class']] ??
        'class-0x' . sprintf('%03X', $msg['class']);
    $out = $direction . " $mname $cname  (tid " .
        substr(bin2hex($msg['tid']), 0, 12) . "...)\n";
    foreach ($msg['attrs'] as $type => $values) {
        foreach ($values as $val) {
            $out .= '    ' .
                turnAttrSummary($type, $val,
                $msg['tid']) . "\n";
        }
    }
    return $out;
}
/**
 * One-line summary of one STUN attribute. Used inside the
 * transcript renderer.
 */
function turnAttrSummary($type, $value, $tid)
{
    switch ($type) {
        case TURN_ATTR_USERNAME:
            return 'USERNAME = ' . $value;
        case TURN_ATTR_REALM:
            return 'REALM = ' . $value;
        case TURN_ATTR_NONCE:
            return 'NONCE = ' . substr($value, 0, 16) .
                (strlen($value) > 16 ? '...' : '');
        case TURN_ATTR_SOFTWARE:
            return 'SOFTWARE = ' . $value;
        case TURN_ATTR_MI:
            return 'MESSAGE-INTEGRITY = ' .
                bin2hex(substr($value, 0, 6)) . '...';
        case TURN_ATTR_LIFETIME:
            $u = unpack('Nv', $value);
            return 'LIFETIME = ' . $u['v'] . 's';
        case TURN_ATTR_REQ_TRANSPORT:
            return 'REQUESTED-TRANSPORT = ' .
                ord($value[0]) . ' (UDP)';
        case TURN_ATTR_XOR_MAPPED:
            list($h, $p) = turnDecXor($value, $tid);
            return 'XOR-MAPPED-ADDRESS = ' .
                turnFormatHostPort($h, $p);
        case TURN_ATTR_XOR_PEER:
            list($h, $p) = turnDecXor($value, $tid);
            return 'XOR-PEER-ADDRESS = ' .
                turnFormatHostPort($h, $p);
        case TURN_ATTR_XOR_RELAYED:
            list($h, $p) = turnDecXor($value, $tid);
            return 'XOR-RELAYED-ADDRESS = ' .
                turnFormatHostPort($h, $p);
        case TURN_ATTR_ERROR:
            list($code, $reason) = turnDecErr($value);
            return 'ERROR-CODE = ' . $code . ' ' . $reason;
        case TURN_ATTR_DATA:
            return 'DATA = ' . turnPrintable($value);
        case TURN_ATTR_CHAN:
            $u = unpack('nchan', $value);
            return 'CHANNEL-NUMBER = 0x' .
                sprintf('%04X', $u['chan']);
    }
    return 'attr-0x' . sprintf('%04X', $type) . ' (' .
        strlen($value) . ' bytes)';
}
/**
 * Formats a host:port pair for transcript display, using
 * brackets for IPv6 hosts so the colon-laden v6 literals
 * are visually grouped.
 */
function turnFormatHostPort($host, $port)
{
    if ($host === false) {
        return '?';
    }
    if (strpos($host, ':') !== false) {
        return "[$host]:$port";
    }
    return "$host:$port";
}
/**
 * Formats raw bytes for transcript display. Pure-ASCII
 * runs print as a quoted string; binary content prints as
 * a length and a short hex prefix.
 */
function turnPrintable($s)
{
    if ($s === '') {
        return '""';
    }
    $printable = true;
    for ($i = 0; $i < strlen($s); $i++) {
        $c = ord($s[$i]);
        if ($c < 0x20 || $c >= 0x7F) {
            $printable = false;
            break;
        }
    }
    if ($printable && strlen($s) <= 64) {
        return '"' . $s . '"';
    }
    return strlen($s) . ' bytes (' .
        bin2hex(substr($s, 0, 8)) .
        (strlen($s) > 8 ? '...' : '') . ')';
}
/*
    --- Stylesheet ---
    Same palette and row layout as ex20/ex23. The toggle-
    button pattern (Run -> Running... -> X) mirrors the
    ex23 scenarios.
 */
$site->get('/style.css', function () use ($site) {
    $site->header("Content-Type: text/css");
    echo <<<'CSS'
body { font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, sans-serif;
    max-width: 920px; margin: 1.5em auto; padding: 0 1em;
    color: #222; }
h1 { margin-bottom: 0.1em; }
.meta { color: #666; font-size: 0.9em; margin-bottom: 1.5em; }
h2 { font-size: 1.05em; margin-top: 1.6em;
    padding-bottom: 0.2em; border-bottom: 1px solid #ddd; }
.note { color: #555; font-size: 0.88em; }
code { background: #eee; padding: 0.1em 0.3em;
    border-radius: 3px; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; }
nav.tabs { display: flex; gap: 4px; margin: 0.5em 0 1em;
    border-bottom: 1px solid #ddd; }
nav.tabs a { padding: 0.5em 1em; text-decoration: none;
    color: #444; border: 1px solid transparent;
    border-bottom: none; border-radius: 4px 4px 0 0; }
nav.tabs a.active { background: #f6f6f6; border-color: #ddd;
    color: #111; font-weight: 600; }
.reset-bar { display: flex; align-items: center; gap: 1em;
    margin: 1em 0 1.5em; padding: 0.7em 0.9em;
    background: #fff8e6; border: 1px solid #f0d890;
    border-radius: 4px; }
.reset-bar button { font: inherit; padding: 0.4em 1em;
    background: #d97706; color: white; border: 0;
    border-radius: 4px; cursor: pointer; flex-shrink: 0; }
.reset-bar button:hover { background: #b85f04; }
.reset-bar button:disabled { background: #888;
    cursor: default; }
.reset-bar .reset-status { color: #555; font-size: 0.9em; }
.bind-bar { display: flex; align-items: center; gap: 1em;
    margin: 0 0 1.5em; padding: 0.7em 0.9em;
    background: #ecf3ff; border: 1px solid #b8c8e8;
    border-radius: 4px; }
.bind-bar label { font-size: 0.9em; color: #234;
    font-weight: 600; }
.bind-bar select { font: inherit; padding: 0.3em 0.5em;
    border-radius: 4px; border: 1px solid #b8c8e8;
    background: #fff; }
.bind-bar .bind-status { color: #555; font-size: 0.9em;
    flex: 1; }
.scenario { margin: 0.6em 0; padding: 0.7em 0.9em;
    background: #f6f6f6; border-radius: 4px; }
.scenario .row { display: flex; align-items: center;
    justify-content: space-between; gap: 1em; }
.scenario .label { font-weight: 600; }
.scenario .desc { color: #555; font-size: 0.92em;
    margin-top: 0.25em; }
.scenario button { font: inherit; padding: 0.35em 0.9em;
    background: #06c; color: white; border: 0;
    border-radius: 4px; cursor: pointer; flex-shrink: 0;
    min-width: 4.5em; text-align: center; }
.scenario button:disabled { background: #888;
    cursor: default; }
.scenario button.close { background: #b33; }
.scenario button.close:hover { background: #c44; }
.scenario .transcript { display: none; margin-top: 0.7em;
    background: #1e1e1e; color: #ddd; padding: 0.8em;
    border-radius: 4px; white-space: pre-wrap;
    font-size: 0.85em; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; max-height: 360px;
    overflow: auto; }
.scenario .transcript.visible { display: block; }
.scenario .note-hint { display: none; margin-top: 0.6em;
    padding: 0.55em 0.8em; background: #fff8e1;
    border-left: 3px solid #f0b400; color: #5a4400;
    font-size: 0.88em; line-height: 1.45;
    border-radius: 0 3px 3px 0; }
.scenario .note-hint.visible { display: block; }
form.raw { background: #f6f6f6; padding: 0.9em;
    border-radius: 4px; margin: 0.6em 0; }
form.raw label { display: block; font-size: 0.85em;
    color: #555; margin-bottom: 0.2em; }
form.raw .row { display: flex; gap: 1em;
    margin-bottom: 0.7em; align-items: end; flex-wrap: wrap; }
form.raw .row > div { flex: 1; min-width: 180px; }
form.raw select, form.raw input[type=text] { font: inherit;
    padding: 0.35em 0.5em; border: 1px solid #bbb;
    border-radius: 3px; width: 100%; }
form.raw button { font: inherit; padding: 0.4em 1em;
    background: #06c; color: white; border: 0;
    border-radius: 4px; cursor: pointer;
    margin-top: 0.5em; }
form.raw button:hover { background: #0050a0; }
#rawResult { margin-top: 0.7em; }
pre.transcript-static { background: #1e1e1e; color: #ddd;
    padding: 0.8em; border-radius: 4px; white-space: pre-wrap;
    font-size: 0.85em; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; max-height: 360px;
    overflow: auto; margin: 0; }
.banner { background: #ecf3ff; color: #234;
    border: 1px solid #b8c8e8; padding: 0.7em 0.9em;
    border-radius: 4px; font-size: 0.9em;
    margin-bottom: 1em; line-height: 1.4; }
.banner code { background: rgba(0,0,0,0.06); }
.alloc-table { width: 100%; border-collapse: collapse;
    background: #fff; border: 1px solid #ddd;
    border-radius: 3px; margin-top: 0.6em; }
.alloc-table th, .alloc-table td { text-align: left;
    padding: 0.45em 0.7em; border-bottom: 1px solid #eee;
    font-size: 0.92em; vertical-align: top; }
.alloc-table th { background: #f4f4f4; font-weight: 600;
    font-size: 0.85em; }
.alloc-table .empty { color: #888; font-style: italic; }
.alloc-table code { font-size: 0.88em; }
.alloc-meta { color: #666; font-size: 0.85em;
    margin-bottom: 0.4em; }
CSS;
});
/*
    --- Page renderer ---
    The shell wrapped around each tab. Includes the bind
    dropdown bar (same shape as ex23). There is no reset
    bar -- the TURN demo's only mutable server state is
    the live allocation table, which has its own dedicated
    "tear down all" action on the Allocations tab.
 */
function turnRenderPage($which, $cfg, $body_fn)
{
    $tabs = [
        'scenarios' => ['/', 'Scenarios'],
        'raw' => ['/raw', 'Raw message builder'],
        'allocs' => ['/allocs', 'Allocations'],
    ];
    echo "<!DOCTYPE html><html lang=\"en\"><head>";
    echo "<meta charset=\"utf-8\">";
    echo "<meta name=\"viewport\" content=\"width=" .
        "device-width, initial-scale=1\">";
    echo "<title>AttoTURN Demo</title>";
    echo "<link rel=\"stylesheet\" href=\"/style.css\">";
    echo "</head><body>";
    echo "<h1>AttoTURN Demo</h1>";
    $display_host = (strpos($cfg['host'], ':') !== false) ?
        '[' . $cfg['host'] . ']' : $cfg['host'];
    echo "<div class=\"meta\">STUN/TURN listener on udp://" .
        htmlspecialchars($display_host) . ":" .
        (int) $cfg['port'] . " &middot; realm <code>" .
        htmlspecialchars($cfg['realm']) . "</code> " .
        "&middot; demo creds <code>alice / hunter2</code>" .
        " and <code>bob / sekret</code>. Companion UI to " .
        "<code>index.php</code>; every transcript on this " .
        "page comes from a real UDP exchange with the " .
        "running server.</div>";
    /*
        Bind bar -- same dropdown pattern as ex23. Switching
        the bind kills both processes; the user relaunches
        from the terminal.
     */
    $current_bind = is_file($cfg['bind_file']) ?
        trim((string) file_get_contents(
        $cfg['bind_file'])) : '127.0.0.1';
    if (!isset($cfg['bind_choices'][$current_bind])) {
        $current_bind = '127.0.0.1';
    }
    echo "<div class=\"bind-bar\">";
    echo "<label for=\"bind-select\">Bind:</label>";
    echo "<select id=\"bind-select\">";
    foreach ($cfg['bind_choices'] as $key => $label) {
        $sel = ($key === $current_bind) ? ' selected' : '';
        echo "<option value=\"" . htmlspecialchars($key) .
            "\"$sel>" . htmlspecialchars($label) .
            "</option>";
    }
    echo "</select>";
    echo "<span class=\"bind-status\" id=\"bind-status\">";
    echo "Switching the bind stops the server. Relaunch " .
        "<code>php index.php</code> in your terminal " .
        "after the switch to see the demo on the new " .
        "family. STUN/TURN attribute encoding is family-" .
        "agnostic so both v4 and v6 exercise the same " .
        "scenarios.";
    echo "</span></div>";
    echo "<nav class=\"tabs\">";
    foreach ($tabs as $key => $info) {
        list($url, $label) = $info;
        $cls = ($key === $which) ? ' class="active"' : '';
        echo "<a href=\"$url\"$cls>" .
            htmlspecialchars($label) . "</a>";
    }
    echo "</nav>";
    $body_fn();
    echo "<script>" . turnBindScript() . "</script>";
    echo "</body></html>";
}
/**
 * Bind-bar dropdown handler. Same shape as ex23: confirm,
 * post the selection, server writes bind.txt and signals
 * both processes to exit, JS swaps the page body for a
 * "relaunch" message.
 */
function turnBindScript()
{
    return <<<'JS'
(function () {
    var sel = document.getElementById('bind-select');
    if (!sel) return;
    var status = document.getElementById('bind-status');
    var current = sel.value;
    sel.addEventListener('change', function () {
        if (sel.value === current) return;
        if (!window.confirm(
            'Switch the listener bind to "' + sel.value +
            '"?\n\nThe server will stop after this ' +
            'request. You will need to run "php ' +
            'index.php" again in the terminal to see the ' +
            'example with the new bind.')) {
            sel.value = current;
            return;
        }
        sel.disabled = true;
        var fd = new FormData();
        fd.append('bind', sel.value);
        fetch('/bind', { method: 'POST', body: fd })
            .then(function (r) { return r.text(); })
            .then(function (msg) {
                document.body.innerHTML =
                    '<h1>Bind switched</h1>' +
                    '<p>The server has been asked to ' +
                    'shut down. Once it exits in your ' +
                    'terminal, run:</p>' +
                    '<pre style="background:#1e1e1e;' +
                    'color:#ddd;padding:1em;' +
                    'border-radius:4px;">php index.php' +
                    '</pre>' +
                    '<p>and reload this page to see the ' +
                    'demo on <code>' +
                    sel.value.replace(/[<>&]/g, '') +
                    '</code>.</p>' +
                    '<p>(Server response: <em>' +
                    msg.replace(/[<>&]/g, '') +
                    '</em>)</p>';
            })
            .catch(function (err) {
                status.textContent = 'ERROR: ' + err;
                sel.value = current;
                sel.disabled = false;
            });
    });
})();
JS;
}
/*
    --- Scenario helpers ---

    Each scenario opens its own UDP socket against the
    running TURN server, runs through a sequence of
    messages, and returns a transcript. The transcript is
    rendered into the dark pre below the card.

    Authenticated requests follow the long-term-credential
    pattern: send the request, expect a 401 with REALM and
    NONCE, retry with USERNAME/REALM/NONCE/MI computed from
    those values plus the user's password. turnAuthSend
    encapsulates that flow.
 */
/**
 * Sends an authenticated request (with USERNAME / REALM /
 * NONCE / MESSAGE-INTEGRITY) and reads the reply. If the
 * server initially returns 401 (because we didn't have a
 * nonce yet), captures realm + nonce and retries. The
 * returned transcript captures both the unauthenticated
 * attempt and the retry, so the demo shows the challenge
 * cycle.
 *
 * @param resource $sock UDP socket
 * @param int $method method constant
 * @param array $extra_blocks attribute blocks beyond
 *     USERNAME/REALM/NONCE/MI
 * @param string $username
 * @param string $password
 * @param string $realm  if empty, we let the server tell us
 * @param string $nonce  if empty, we let the server tell us
 * @return array [transcript_text, response_msg|null,
 *     realm, nonce]  realm/nonce can be reused on the next
 *     auth round to avoid the second 401.
 */
function turnAuthSend($sock, $method, $extra_blocks,
    $username, $password, $realm = '', $nonce = '')
{
    $transcript = '';
    /*
        $extra_blocks may be either an array of pre-built
        attribute blocks (for attributes whose encoding
        does not depend on the message TID, like
        REQUESTED-TRANSPORT, LIFETIME, or CHANNEL-NUMBER)
        OR a callable taking ($tid) and returning the
        block array (for XOR-PEER-ADDRESS and friends,
        whose v6 encoding XORs the address against the
        message TID and so must be recomputed for each
        outgoing message). We resolve the callable form
        once per outgoing message.
     */
    if ($realm === '' || $nonce === '') {
        $tid = random_bytes(12);
        $blocks = is_callable($extra_blocks) ?
            $extra_blocks($tid) : $extra_blocks;
        $req = turnBuildMsg($method, TURN_C_REQUEST, $tid,
            $blocks);
        $transcript .= turnRenderMsg($req, '>');
        $reply = turnRoundTrip($sock, $req);
        if ($reply === '') {
            return [$transcript . "! no reply (timeout)\n",
                null, $realm, $nonce];
        }
        $transcript .= turnRenderMsg($reply, '<');
        $msg = turnParseMsg($reply);
        if ($msg === false || $msg['class'] !==
            TURN_C_ERROR) {
            return [$transcript, $msg, $realm, $nonce];
        }
        $err = turnAttr1($msg, TURN_ATTR_ERROR);
        if ($err !== null) {
            list($code, ) = turnDecErr($err);
            if ($code !== 401 && $code !== 438) {
                /*
                    A non-auth error (e.g. 400 or 442)
                    means the server has rejected the
                    request on its merits. No retry will
                    help.
                 */
                return [$transcript, $msg, $realm, $nonce];
            }
        }
        $r2 = turnAttr1($msg, TURN_ATTR_REALM);
        $n2 = turnAttr1($msg, TURN_ATTR_NONCE);
        if ($r2 === null || $n2 === null) {
            return [$transcript, $msg, $realm, $nonce];
        }
        $realm = $r2;
        $nonce = $n2;
    }
    /*
        Second attempt with creds.
     */
    $key = md5($username . ':' . $realm . ':' . $password,
        true);
    $tid2 = random_bytes(12);
    $extras = is_callable($extra_blocks) ?
        $extra_blocks($tid2) : $extra_blocks;
    $blocks = array_merge($extras, [
        turnAttr(TURN_ATTR_USERNAME, $username),
        turnAttr(TURN_ATTR_REALM, $realm),
        turnAttr(TURN_ATTR_NONCE, $nonce),
    ]);
    $req2 = turnBuildMsg($method, TURN_C_REQUEST, $tid2,
        $blocks, $key);
    $transcript .= turnRenderMsg($req2, '>');
    $reply2 = turnRoundTrip($sock, $req2);
    if ($reply2 === '') {
        return [$transcript . "! no reply (timeout)\n",
            null, $realm, $nonce];
    }
    $transcript .= turnRenderMsg($reply2, '<');
    return [$transcript, turnParseMsg($reply2), $realm,
        $nonce];
}
/**
 * Opens a fresh UDP socket bound to a transient local
 * port, ready for one scenario's worth of traffic against
 * the server. Returns the socket.
 */
function turnOpenSocket($cfg)
{
    $url = turnDialUrl($cfg['host'], $cfg['port']);
    $sock = @stream_socket_client($url, $errno, $errstr, 3);
    if (!$sock) {
        return false;
    }
    stream_set_timeout($sock, 2);
    return $sock;
}
/**
 * Opens a fresh UDP "peer" socket on a transient local
 * port. Used by scenarios that need a non-TURN endpoint
 * to receive relayed datagrams. Returns the socket and
 * its bound (host, port).
 */
function turnOpenPeerSocket($cfg)
{
    $bind_host = $cfg['host'];
    $url = (strpos($bind_host, ':') !== false) ?
        "udp://[$bind_host]:0" : "udp://$bind_host:0";
    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_server($url, $errno, $errstr,
        STREAM_SERVER_BIND);
    if (!$sock) {
        return [false, '', 0];
    }
    stream_set_blocking($sock, 0);
    $name = stream_socket_get_name($sock, false);
    /*
        stream_socket_get_name() returns the bound address
        as either "host:port" or "[host]:port"; reuse the
        same bracket-aware split that TurnSite does so we
        get a clean (host, port) pair on both families.
     */
    if ($name === false || $name === '') {
        @fclose($sock);
        return [false, '', 0];
    }
    if ($name[0] === '[') {
        $end = strpos($name, ']');
        $h = substr($name, 1, $end - 1);
        $p = (int) substr($name, $end + 2);
    } else {
        $colon = strrpos($name, ':');
        $h = substr($name, 0, $colon);
        $p = (int) substr($name, $colon + 1);
    }
    return [$sock, $h, $p];
}
/**
 * Reads one datagram off a peer socket with a small
 * polling loop, since the socket is non-blocking. Returns
 * '' if nothing arrives within $ms milliseconds.
 */
function turnPeerReadOnce($peer_sock, $ms)
{
    $deadline = microtime(true) + $ms / 1000.0;
    while (microtime(true) < $deadline) {
        $from = '';
        $buf = @stream_socket_recvfrom($peer_sock, 65535,
            0, $from);
        if ($buf !== false && $buf !== '') {
            return [$buf, $from];
        }
        usleep(20000);
    }
    return ['', ''];
}
/**
 * Allocate then exchange a Send/Data round trip with a
 * locally-bound peer socket. Demonstrates the full
 * "client -> server relay -> peer -> server relay ->
 * client" loop.
 */
function turnSendDataScenario($cfg)
{
    $sock = turnOpenSocket($cfg);
    if (!$sock) {
        return ['transcript' => "! could not connect\n",
            'note' => null];
    }
    list($peer_sock, $peer_host, $peer_port) =
        turnOpenPeerSocket($cfg);
    if (!$peer_sock) {
        @fclose($sock);
        return ['transcript' =>
            "! could not bind peer socket\n",
            'note' => null];
    }
    $t = "# Allocate (with 401 challenge)\n";
    list($at, $ar, $realm, $nonce) = turnAuthSend($sock,
        TURN_M_ALLOCATE,
        [turnAttr(TURN_ATTR_REQ_TRANSPORT,
            chr(17) . chr(0) . chr(0) . chr(0))],
        'alice', 'hunter2');
    $t .= $at;
    if ($ar === null || $ar['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t,
            'note' => 'Allocate failed; cannot continue.'];
    }
    $relay_attr = turnAttr1($ar, TURN_ATTR_XOR_RELAYED);
    list($relay_host, $relay_port) =
        turnDecXor($relay_attr, $ar['tid']);
    $t .= "\n# CreatePermission for peer " .
        turnFormatHostPort($peer_host, $peer_port) . "\n";
    list($pt, $pr, , ) = turnAuthSend($sock,
        TURN_M_CREATE_PERMISSION,
        function ($tid) use ($peer_host, $peer_port) {
            return [turnAttr(TURN_ATTR_XOR_PEER,
                turnEncXor($peer_host, $peer_port,
                $tid))];
        },
        'alice', 'hunter2', $realm, $nonce);
    $t .= $pt;
    if ($pr === null || $pr['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t,
            'note' => 'CreatePermission failed.'];
    }
    $payload = "ping-from-alice-" . random_int(1000, 9999);
    $tid_send = random_bytes(12);
    $send_msg = turnBuildMsg(TURN_M_SEND,
        TURN_C_INDICATION, $tid_send, [
            turnAttr(TURN_ATTR_XOR_PEER,
                turnEncXor($peer_host, $peer_port,
                $tid_send)),
            turnAttr(TURN_ATTR_DATA, $payload),
        ]);
    $t .= "\n# Send indication (no MI -- allocation is " .
        "the credential)\n";
    $t .= turnRenderMsg($send_msg, '>');
    @stream_socket_sendto($sock, $send_msg);
    /*
        Read the relayed datagram on the peer socket.
        $relay_dest will be the "[host]:port" the server
        relayed from -- we stash it so the peer can
        reply.
     */
    list($peer_recv, $relay_dest) =
        turnPeerReadOnce($peer_sock, 1500);
    if ($peer_recv === '') {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t .
            "\n! peer never received the datagram\n",
            'note' => null];
    }
    $t .= "\n# peer received " . strlen($peer_recv) .
        " bytes from server relay " . $relay_dest . "\n";
    $t .= "    payload = " . turnPrintable($peer_recv) .
        "\n";
    /*
        Have the peer reply through the relay. The server
        wraps it as a Data indication for the client.
     */
    $reply_payload = "pong-from-peer-" .
        random_int(1000, 9999);
    @stream_socket_sendto($peer_sock, $reply_payload, 0,
        $relay_dest);
    $t .= "\n# peer -> server relay (" .
        strlen($reply_payload) . " bytes)\n";
    $t .= "    payload = " . turnPrintable($reply_payload) .
        "\n";
    /*
        Read the resulting Data indication on the client
        socket.
     */
    stream_set_timeout($sock, 1, 500000);
    $from = '';
    $client_buf = @stream_socket_recvfrom($sock, 65535, 0,
        $from);
    if ($client_buf === false || $client_buf === '') {
        $t .= "\n! Data indication did not arrive\n";
    } else {
        $t .= "\n# client side\n";
        $t .= turnRenderMsg($client_buf, '<');
    }
    @fclose($sock);
    @fclose($peer_sock);
    return ['transcript' => $t,
        'note' => 'Send/Data uses one full STUN-message ' .
            'wrapping per datagram in each direction. ' .
            'For peers under heavy use, ChannelBind ' .
            '(next scenario) reduces the framing ' .
            'overhead to 4 bytes per direction.'];
}
/**
 * Allocate, ChannelBind to a peer, exchange traffic via
 * 4-byte ChannelData frames in both directions.
 */
function turnChannelBindScenario($cfg)
{
    $sock = turnOpenSocket($cfg);
    if (!$sock) {
        return ['transcript' => "! could not connect\n",
            'note' => null];
    }
    list($peer_sock, $peer_host, $peer_port) =
        turnOpenPeerSocket($cfg);
    if (!$peer_sock) {
        @fclose($sock);
        return ['transcript' =>
            "! could not bind peer socket\n",
            'note' => null];
    }
    $t = "# Allocate\n";
    list($at, $ar, $realm, $nonce) = turnAuthSend($sock,
        TURN_M_ALLOCATE,
        [turnAttr(TURN_ATTR_REQ_TRANSPORT,
            chr(17) . chr(0) . chr(0) . chr(0))],
        'alice', 'hunter2');
    $t .= $at;
    if ($ar === null || $ar['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t,
            'note' => 'Allocate failed.'];
    }
    $chan = 0x4000;
    $t .= "\n# ChannelBind 0x" . sprintf('%04X', $chan) .
        " -> " . turnFormatHostPort($peer_host,
        $peer_port) . " (implicitly creates a " .
        "permission)\n";
    list($cbt, $cbr, , ) = turnAuthSend($sock,
        TURN_M_CHANNEL_BIND,
        function ($tid) use ($chan, $peer_host,
            $peer_port) {
            return [
                turnAttr(TURN_ATTR_CHAN,
                    pack('nn', $chan, 0)),
                turnAttr(TURN_ATTR_XOR_PEER,
                    turnEncXor($peer_host, $peer_port,
                    $tid)),
            ];
        },
        'alice', 'hunter2', $realm, $nonce);
    $t .= $cbt;
    if ($cbr === null || $cbr['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t,
            'note' => 'ChannelBind failed.'];
    }
    $payload = "via-channel-" . random_int(1000, 9999);
    $frame = pack('nn', $chan, strlen($payload)) .
        $payload;
    $t .= "\n# ChannelData frame client -> server\n";
    $t .= turnRenderMsg($frame, '>');
    @stream_socket_sendto($sock, $frame);
    list($peer_recv, $relay_dest) =
        turnPeerReadOnce($peer_sock, 1500);
    if ($peer_recv === '') {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t .
            "\n! peer never received the channel " .
            "datagram\n", 'note' => null];
    }
    $t .= "\n# peer received " . strlen($peer_recv) .
        " bytes from server relay " . $relay_dest . "\n";
    $t .= "    payload = " . turnPrintable($peer_recv) .
        "\n";
    $reply_payload = "back-via-chan-" .
        random_int(1000, 9999);
    @stream_socket_sendto($peer_sock, $reply_payload, 0,
        $relay_dest);
    $t .= "\n# peer -> server relay (" .
        strlen($reply_payload) . " bytes)\n";
    $t .= "    payload = " . turnPrintable($reply_payload) .
        "\n";
    stream_set_timeout($sock, 1, 500000);
    $from = '';
    $client_buf = @stream_socket_recvfrom($sock, 65535, 0,
        $from);
    if ($client_buf === false || $client_buf === '') {
        $t .= "\n! ChannelData did not arrive\n";
    } else {
        $t .= "\n# client side (back via the same " .
            "channel)\n";
        $t .= turnRenderMsg($client_buf, '<');
    }
    @fclose($sock);
    @fclose($peer_sock);
    return ['transcript' => $t,
        'note' => 'Compare the channel-data framing ' .
            '(4 bytes) to the Send/Data wrapping in the ' .
            'previous scenario (typically 30+ bytes per ' .
            'datagram). For high-rate peer traffic the ' .
            'savings are substantial.'];
}
/**
 * Allocate, then either Refresh with a non-zero lifetime
 * (extend) or Refresh(0) (tear down).
 */
function turnRefreshScenario($cfg, $tear_down)
{
    $sock = turnOpenSocket($cfg);
    if (!$sock) {
        return ['transcript' => "! could not connect\n",
            'note' => null];
    }
    $t = "# Allocate\n";
    list($at, $ar, $realm, $nonce) = turnAuthSend($sock,
        TURN_M_ALLOCATE,
        [turnAttr(TURN_ATTR_REQ_TRANSPORT,
            chr(17) . chr(0) . chr(0) . chr(0))],
        'alice', 'hunter2');
    $t .= $at;
    if ($ar === null || $ar['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        return ['transcript' => $t,
            'note' => 'Allocate failed.'];
    }
    $lifetime = $tear_down ? 0 : 600;
    $t .= "\n# Refresh (lifetime=$lifetime)\n";
    list($rt, $rr, , ) = turnAuthSend($sock,
        TURN_M_REFRESH,
        [turnAttr(TURN_ATTR_LIFETIME,
            pack('N', $lifetime))],
        'alice', 'hunter2', $realm, $nonce);
    $t .= $rt;
    @fclose($sock);
    $note = $tear_down ?
        'After Refresh(0) the server destroys the ' .
        'allocation and closes its relay socket. A ' .
        'subsequent Send or ChannelData against the ' .
        'same allocation would now be silently dropped.' :
        'A non-zero lifetime resets the allocation\'s ' .
        'expiry. Clients usually re-issue Refresh once ' .
        'per minute or two, well before the lifetime ' .
        'runs out.';
    return ['transcript' => $t, 'note' => $note];
}
/**
 * Allocate but skip CreatePermission. An external sender
 * (the peer socket) sends datagrams toward the relayed
 * address; the server silently discards them. The point
 * of the scenario is the *absence* of a Data indication
 * on the client side.
 */
function turnUnpermissionedScenario($cfg)
{
    $sock = turnOpenSocket($cfg);
    if (!$sock) {
        return ['transcript' => "! could not connect\n",
            'note' => null];
    }
    list($peer_sock, $peer_host, $peer_port) =
        turnOpenPeerSocket($cfg);
    if (!$peer_sock) {
        @fclose($sock);
        return ['transcript' =>
            "! could not bind peer socket\n",
            'note' => null];
    }
    $t = "# Allocate (no CreatePermission)\n";
    list($at, $ar, , ) = turnAuthSend($sock,
        TURN_M_ALLOCATE,
        [turnAttr(TURN_ATTR_REQ_TRANSPORT,
            chr(17) . chr(0) . chr(0) . chr(0))],
        'alice', 'hunter2');
    $t .= $at;
    if ($ar === null || $ar['class'] !== TURN_C_SUCCESS) {
        @fclose($sock);
        @fclose($peer_sock);
        return ['transcript' => $t,
            'note' => 'Allocate failed.'];
    }
    $relay_attr = turnAttr1($ar, TURN_ATTR_XOR_RELAYED);
    list($relay_host, $relay_port) =
        turnDecXor($relay_attr, $ar['tid']);
    $t .= "\n# Peer fires a datagram at the relayed " .
        "address " . turnFormatHostPort($relay_host,
        $relay_port) . " WITHOUT a permission in place\n";
    $relay_dest = (strpos($relay_host, ':') !== false) ?
        "[$relay_host]:$relay_port" :
        "$relay_host:$relay_port";
    @stream_socket_sendto($peer_sock,
        "should-be-dropped", 0, $relay_dest);
    /*
        Wait briefly to confirm nothing arrives. The
        absence of any reply is the point. We use
        stream_select rather than a blocking recvfrom so
        the loop is responsive to short timeouts on UDP
        even under fussy timeout-handling builds of PHP.
     */
    $read = [$sock];
    $w = null;
    $e = null;
    $n = @stream_select($read, $w, $e, 1, 0);
    if ($n > 0) {
        $from = '';
        $client_buf = @stream_socket_recvfrom($sock,
            65535, 0, $from);
        $t .= "\n! UNEXPECTED: client received " .
            strlen((string) $client_buf) . " bytes\n";
    } else {
        $t .= "\n# (1 second elapsed; client received " .
            "nothing)\n";
    }
    @fclose($sock);
    @fclose($peer_sock);
    return ['transcript' => $t,
        'note' => 'RFC 8656 sec 11.3: the server MUST ' .
            'silently discard datagrams from peers ' .
            'that are not in the permission list. The ' .
            'silence is the safety property -- it ' .
            'prevents an open TURN allocation from ' .
            'becoming a UDP reflector.'];
}
/**
 * Returns the static list of scenarios. Each entry has:
 *     title -- one-line headline shown on the card
 *     desc  -- a sentence or two of context
 *     run   -- callable that takes ($cfg) and returns
 *              ['transcript' => text, 'note' => string|null]
 */
function turnScenarioList()
{
    return [
        'binding' => [
            'title' => 'Binding discovery (bare STUN)',
            'desc' => 'A Binding request is the bare STUN ' .
                'core: no authentication, no allocation. ' .
                'The server replies with an XOR-MAPPED-' .
                'ADDRESS attribute containing the client\'s ' .
                'reflexive address as seen from the ' .
                'server\'s side. WebRTC stacks use this to ' .
                'discover their own NAT-translated address ' .
                'before they involve a TURN relay.',
            'run' => function ($cfg) {
                $sock = turnOpenSocket($cfg);
                if (!$sock) {
                    return ['transcript' =>
                        "! could not connect\n",
                        'note' => null];
                }
                $tid = random_bytes(12);
                $req = turnBuildMsg(TURN_M_BINDING,
                    TURN_C_REQUEST, $tid, []);
                $t = turnRenderMsg($req, '>');
                $reply = turnRoundTrip($sock, $req);
                $t .= ($reply !== '') ?
                    turnRenderMsg($reply, '<') :
                    "! timeout\n";
                @fclose($sock);
                return ['transcript' => $t, 'note' => null];
            },
        ],
        'allocate-no-auth' => [
            'title' => 'Allocate without credentials -> 401',
            'desc' => 'TURN allocations require long-term ' .
                'credentials. A first Allocate that omits ' .
                'them is rejected with 401 Unauthorized; ' .
                'the server includes REALM and NONCE so ' .
                'the client knows what to put in the ' .
                'retry. RFC 8489 sec 9.2.',
            'run' => function ($cfg) {
                $sock = turnOpenSocket($cfg);
                if (!$sock) {
                    return ['transcript' =>
                        "! could not connect\n",
                        'note' => null];
                }
                $tid = random_bytes(12);
                $blocks = [
                    turnAttr(TURN_ATTR_REQ_TRANSPORT,
                        chr(17) . chr(0) . chr(0) . chr(0)),
                ];
                $req = turnBuildMsg(TURN_M_ALLOCATE,
                    TURN_C_REQUEST, $tid, $blocks);
                $t = turnRenderMsg($req, '>');
                $reply = turnRoundTrip($sock, $req);
                $t .= ($reply !== '') ?
                    turnRenderMsg($reply, '<') :
                    "! timeout\n";
                @fclose($sock);
                return ['transcript' => $t,
                    'note' => 'Notice the server\'s 401 ' .
                        'reply carries the REALM and ' .
                        'NONCE attributes. The client ' .
                        'caches them so the retry only ' .
                        'needs MESSAGE-INTEGRITY appended.'];
            },
        ],
        'allocate-ok' => [
            'title' => 'Allocate with valid credentials',
            'desc' => 'Same Allocate, this time with ' .
                'USERNAME / REALM / NONCE / MESSAGE-' .
                'INTEGRITY computed from the long-term ' .
                'key. The server replies with XOR-' .
                'RELAYED-ADDRESS (a server-side port the ' .
                'client can hand to peers), XOR-MAPPED-' .
                'ADDRESS, and LIFETIME. The transcript ' .
                'shows both the 401 challenge and the ' .
                'follow-up success.',
            'run' => function ($cfg) {
                $sock = turnOpenSocket($cfg);
                if (!$sock) {
                    return ['transcript' =>
                        "! could not connect\n",
                        'note' => null];
                }
                list($t, $msg) = turnAuthSend($sock,
                    TURN_M_ALLOCATE,
                    [turnAttr(TURN_ATTR_REQ_TRANSPORT,
                        chr(17) . chr(0) . chr(0) .
                        chr(0))],
                    'alice', 'hunter2');
                /* free the allocation we just made so
                   nothing lingers */
                if ($msg !== null && $msg['class'] ===
                    TURN_C_SUCCESS) {
                    /* skipped: would need to keep nonce
                       around, the demo's allocation table
                       reaper will clean up shortly */
                }
                @fclose($sock);
                return ['transcript' => $t,
                    'note' => null];
            },
        ],
        'wrong-password' => [
            'title' => 'Wrong password -> 401',
            'desc' => 'Same Allocate flow but with the ' .
                'wrong password. The first round still ' .
                'gets back a 401 with realm + nonce, ' .
                'but the second round fails MESSAGE-' .
                'INTEGRITY verification on the server ' .
                'side and the response carries 401 Bad ' .
                'MESSAGE-INTEGRITY.',
            'run' => function ($cfg) {
                $sock = turnOpenSocket($cfg);
                if (!$sock) {
                    return ['transcript' =>
                        "! could not connect\n",
                        'note' => null];
                }
                list($t, ) = turnAuthSend($sock,
                    TURN_M_ALLOCATE,
                    [turnAttr(TURN_ATTR_REQ_TRANSPORT,
                        chr(17) . chr(0) . chr(0) .
                        chr(0))],
                    'alice', 'WRONG-PASSWORD');
                @fclose($sock);
                return ['transcript' => $t,
                    'note' => null];
            },
        ],
        'send-data' => [
            'title' => 'Send -> peer -> Data round trip',
            'desc' => 'After Allocate and CreatePermission ' .
                'for a peer, the client sends data via ' .
                'a Send indication. The server unwraps it ' .
                'and forwards the payload over the ' .
                'relay socket to the peer. When the peer ' .
                'sends back, the server wraps the ' .
                'response in a Data indication. ' .
                'Indications carry no MESSAGE-INTEGRITY ' .
                '-- the allocation itself is the ' .
                'authentication.',
            'run' => function ($cfg) {
                return turnSendDataScenario($cfg);
            },
        ],
        'channel-bind' => [
            'title' => 'ChannelBind and ChannelData frames',
            'desc' => 'Once a peer is in heavy use, the ' .
                'client can ChannelBind it to a 16-bit ' .
                'channel number (0x4000-0x4FFF). After ' .
                'that, traffic to and from that peer can ' .
                'use compact ChannelData frames -- a 4-' .
                'byte header instead of a full STUN ' .
                'message. The transcript shows the bind ' .
                'request, the success reply, and a ' .
                'channel-framed exchange.',
            'run' => function ($cfg) {
                return turnChannelBindScenario($cfg);
            },
        ],
        'refresh-extend' => [
            'title' => 'Refresh extends an allocation',
            'desc' => 'A Refresh request with a non-zero ' .
                'lifetime extends the allocation\'s ' .
                'expiry. Clients re-issue Refresh ' .
                'periodically (typically with the same ' .
                'lifetime they got back) to keep the ' .
                'allocation alive across the demo\'s ' .
                'default 600-second window.',
            'run' => function ($cfg) {
                return turnRefreshScenario($cfg, false);
            },
        ],
        'refresh-zero' => [
            'title' => 'Refresh(lifetime=0) tears down',
            'desc' => 'A Refresh request with lifetime=0 ' .
                'is the explicit teardown signal. The ' .
                'server destroys the allocation, closes ' .
                'the relay socket, and replies with ' .
                'lifetime=0 confirming the destruction. ' .
                'A polite TURN client sends this on ' .
                'shutdown to free server resources.',
            'run' => function ($cfg) {
                return turnRefreshScenario($cfg, true);
            },
        ],
        'unpermissioned-peer' => [
            'title' => 'Unpermissioned peer is silently ' .
                'dropped',
            'desc' => 'After Allocate but without a ' .
                'CreatePermission for the peer, an ' .
                'unrelated process sending datagrams to ' .
                'the relayed address never reaches the ' .
                'client. RFC 8656 sec 11.3 requires the ' .
                'server to silently discard. The ' .
                'transcript shows the lack of any Data ' .
                'indication arriving on the client side.',
            'run' => function ($cfg) {
                return turnUnpermissionedScenario($cfg);
            },
        ],
        'fingerprint-mismatch' => [
            'title' => 'Allocate without REQUESTED-' .
                'TRANSPORT -> 400',
            'desc' => 'Allocate is required to carry a ' .
                'REQUESTED-TRANSPORT attribute. Omitting ' .
                'it gets a 400 Bad Request. This is a ' .
                'sample of the protocol\'s defensive ' .
                'parsing: required attributes are ' .
                'enforced before authentication is ' .
                'considered.',
            'run' => function ($cfg) {
                $sock = turnOpenSocket($cfg);
                if (!$sock) {
                    return ['transcript' =>
                        "! could not connect\n",
                        'note' => null];
                }
                list($t, ) = turnAuthSend($sock,
                    TURN_M_ALLOCATE, [],
                    'alice', 'hunter2');
                @fclose($sock);
                return ['transcript' => $t,
                    'note' => null];
            },
        ],
    ];
}
/*
    --- Recent-transcripts ring buffer ---

    Per the demo's third tab. Each scenario run appends one
    entry; the file is bounded to MAX_LOG_ENTRIES so it
    doesn't grow forever. JSON-on-disk is fine here -- the
    demo is intentionally single-process and there is no
    concurrent-write contention to worry about.
 */
const TURN_LOG_FILE = 'recent.json';
const TURN_LOG_MAX = 25;
/**
 * Returns the absolute path to the log file in the
 * example directory.
 */
function turnLogPath()
{
    return __DIR__ . DIRECTORY_SEPARATOR . TURN_LOG_FILE;
}
/**
 * Reads the log. Returns an array of entries with shape:
 *
 *     ['ts' => unix_seconds, 'scenario' => key,
 *      'title' => string, 'note' => string|null,
 *      'transcript' => string]
 *
 * Returns [] on missing or malformed file.
 */
function turnLogRead()
{
    $p = turnLogPath();
    if (!is_file($p)) {
        return [];
    }
    $raw = @file_get_contents($p);
    if ($raw === false || $raw === '') {
        return [];
    }
    $data = @json_decode($raw, true);
    if (!is_array($data)) {
        return [];
    }
    return $data;
}
/**
 * Appends one entry, trimming to TURN_LOG_MAX.
 */
function turnLogAppend($entry)
{
    $log = turnLogRead();
    $log[] = $entry;
    if (count($log) > TURN_LOG_MAX) {
        $log = array_slice($log, -TURN_LOG_MAX);
    }
    @file_put_contents(turnLogPath(),
        json_encode($log, JSON_PRETTY_PRINT));
}
/**
 * Wipes the log. Used by the "Clear" button on the
 * Recent-transcripts tab.
 */
function turnLogClear()
{
    @file_put_contents(turnLogPath(), "[]");
}
/*
    --- Tab body renderers ---
 */
/**
 * Scenarios tab body. One card per scenario. Each card has
 * a Run button that, on click, fetches the corresponding
 * server-side runner and folds the transcript out below
 * the card.
 */
function turnRenderScenarios($cfg)
{
    echo '<div class="banner">';
    echo 'Each scenario opens a fresh UDP socket against ' .
        'the running TURN server, runs through a real ' .
        'message exchange, and shows you the on-wire ' .
        'transcript. Click <strong>Run</strong> on any ' .
        'card to expand. The transcripts are also ' .
        'written to the <strong>Recent transcripts</strong>' .
        ' tab so you can scroll through past runs.';
    echo '</div>';
    echo '<h2>Click-through scenarios</h2>';
    foreach (turnScenarioList() as $key => $info) {
        $btn_id = 'btn-' . htmlspecialchars($key);
        $box_id = 'box-' . htmlspecialchars($key);
        $note_id = 'note-' . htmlspecialchars($key);
        echo '<div class="scenario" data-key="' .
            htmlspecialchars($key) . '">';
        echo '<div class="row">';
        echo '<div>';
        echo '<div class="label">' .
            htmlspecialchars($info['title']) . '</div>';
        echo '<div class="desc">' .
            htmlspecialchars($info['desc']) . '</div>';
        echo '</div>';
        echo '<button id="' . $btn_id .
            '" class="run">Run</button>';
        echo '</div>';
        echo '<pre class="transcript" id="' . $box_id .
            '"></pre>';
        echo '<div class="note-hint" id="' . $note_id .
            '"></div>';
        echo '</div>';
    }
    echo '<script>' . turnClientScript() . '</script>';
}
/**
 * Raw message builder tab. Form for picking method,
 * credentials, and a few common attributes; the result
 * pane shows the transcript of the resulting exchange.
 */
function turnRenderRaw($cfg)
{
    echo '<div class="banner">';
    echo 'Build a single STUN/TURN message and send it. ' .
        'The form below covers the common cases ' .
        '(Binding, Allocate, Refresh, CreatePermission, ' .
        'ChannelBind). Pick a user from the dropdown to ' .
        'have the request signed with that user\'s long-' .
        'term key.';
    echo '</div>';
    echo '<h2>Raw message builder</h2>';
    echo '<form class="raw" id="rawForm">';
    echo '<div class="row">';
    echo '<div><label for="rawMethod">Method</label>';
    echo '<select id="rawMethod" name="method">';
    $methods = [
        'binding' => 'Binding (no auth)',
        'allocate' => 'Allocate (with REQUESTED-' .
            'TRANSPORT=UDP)',
        'refresh' => 'Refresh',
        'create-permission' => 'CreatePermission',
        'channel-bind' => 'ChannelBind',
    ];
    foreach ($methods as $k => $v) {
        echo '<option value="' . htmlspecialchars($k) .
            '">' . htmlspecialchars($v) . '</option>';
    }
    echo '</select></div>';
    echo '<div><label for="rawUser">User</label>';
    echo '<select id="rawUser" name="user">';
    echo '<option value="">(no auth)</option>';
    foreach ($cfg['demo_users'] as $u) {
        echo '<option value="' .
            htmlspecialchars($u['user']) . '">' .
            htmlspecialchars($u['user']) . ' / ' .
            htmlspecialchars($u['pass']) .
            '</option>';
    }
    echo '<option value="alice-wrong">alice / WRONG' .
        ' (force MI failure)</option>';
    echo '</select></div>';
    echo '</div>';
    echo '<div class="row">';
    echo '<div><label for="rawPeer">Peer host:port (for ' .
        'CreatePermission / ChannelBind)</label>';
    echo '<input type="text" id="rawPeer" name="peer" ' .
        'value="192.0.2.10:5060" ' .
        'placeholder="192.0.2.10:5060"></div>';
    echo '<div><label for="rawChan">Channel (0x4000-' .
        '0x4FFF, ChannelBind only)</label>';
    echo '<input type="text" id="rawChan" name="chan" ' .
        'value="0x4000" placeholder="0x4000"></div>';
    echo '<div><label for="rawLifetime">Lifetime ' .
        '(Allocate / Refresh, seconds)</label>';
    echo '<input type="text" id="rawLifetime" ' .
        'name="lifetime" value="600" ' .
        'placeholder="600"></div>';
    echo '</div>';
    echo '<button type="button" id="rawSend">Send</button>';
    echo '</form>';
    echo '<div id="rawResult"></div>';
    echo '<script>' . turnRawScript() . '</script>';
}
/**
 * Recent-transcripts tab. Reads the ring buffer and lays
 * out the entries newest-first. Each entry is a
 * collapsible block (open by default for the most recent
 * one).
 */
function turnRenderAllocs($cfg)
{
    $log = turnLogRead();
    echo '<div class="banner">';
    echo 'Every scenario run on the <strong>Scenarios' .
        '</strong> tab and every send from the ' .
        '<strong>Raw message builder</strong> tab is ' .
        'logged here. The most recent ' . TURN_LOG_MAX .
        ' entries are kept; older ones roll off as new ' .
        'ones arrive.';
    echo '</div>';
    echo '<h2>Recent transcripts</h2>';
    echo '<div class="reset-bar">';
    echo '<button id="clearLog" type="button">Clear ' .
        'log</button>';
    echo '<span class="reset-status" id="clearStatus">' .
        count($log) . ' entr' .
        (count($log) === 1 ? 'y' : 'ies') .
        ' on file.</span>';
    echo '</div>';
    if (empty($log)) {
        echo '<p class="note">No transcripts yet. Run a ' .
            'scenario or send a message from the other ' .
            'tabs to populate this list.</p>';
    } else {
        $newest_first = array_reverse($log);
        foreach ($newest_first as $i => $entry) {
            $when = date('Y-m-d H:i:s',
                (int)($entry['ts'] ?? 0));
            $title = $entry['title'] ?? '(untitled)';
            $note = $entry['note'] ?? '';
            $tx = $entry['transcript'] ?? '';
            echo '<div class="scenario">';
            echo '<div class="alloc-meta">' .
                htmlspecialchars($when) . ' &middot; ' .
                htmlspecialchars($title) . '</div>';
            echo '<pre class="transcript-static">' .
                htmlspecialchars($tx) . '</pre>';
            if ($note !== '' && $note !== null) {
                echo '<div class="note-hint visible">' .
                    htmlspecialchars($note) . '</div>';
            }
            echo '</div>';
        }
    }
    echo '<script>' . turnClearScript() . '</script>';
}
/*
    --- Inline JS for the three tabs ---
 */
/**
 * Scenarios tab JS. Handles the Run -> Running... -> X
 * toggle on each card. Same pattern as ex23.
 */
function turnClientScript()
{
    return <<<'JS'
(function () {
    var cards = document.querySelectorAll('.scenario');
    cards.forEach(function (card) {
        var key = card.getAttribute('data-key');
        if (!key) return;
        var btn = document.getElementById('btn-' + key);
        var box = document.getElementById('box-' + key);
        var note = document.getElementById('note-' + key);
        var state = 'idle';
        function reset() {
            btn.textContent = 'Run';
            btn.disabled = false;
            btn.classList.remove('close');
            box.textContent = '';
            box.classList.remove('visible');
            note.textContent = '';
            note.classList.remove('visible');
            state = 'idle';
        }
        function run() {
            btn.disabled = true;
            btn.textContent = 'Running...';
            box.textContent = '';
            box.classList.add('visible');
            note.textContent = '';
            note.classList.remove('visible');
            var fd = new FormData();
            fd.append('scenario', key);
            fetch('/scenario', {
                method: 'POST',
                body: fd,
            }).then(function (r) {
                return r.json();
            }).then(function (j) {
                box.textContent = j.transcript || '';
                if (j.note) {
                    note.textContent = j.note;
                    note.classList.add('visible');
                }
                btn.disabled = false;
                btn.textContent = '\u2715';
                btn.classList.add('close');
                state = 'open';
            }).catch(function (err) {
                box.textContent = 'ERROR: ' + err;
                btn.disabled = false;
                btn.textContent = '\u2715';
                btn.classList.add('close');
                state = 'open';
            });
        }
        btn.addEventListener('click', function () {
            if (state === 'idle') {
                run();
            } else {
                reset();
            }
        });
    });
})();
JS;
}
/**
 * Raw-message tab JS. Submits the form via fetch and
 * renders the transcript inline.
 */
function turnRawScript()
{
    return <<<'JS'
(function () {
    var btn = document.getElementById('rawSend');
    var result = document.getElementById('rawResult');
    if (!btn) return;
    btn.addEventListener('click', function () {
        btn.disabled = true;
        btn.textContent = 'Sending...';
        result.innerHTML = '';
        var form = document.getElementById('rawForm');
        var fd = new FormData(form);
        fetch('/raw', {
            method: 'POST',
            body: fd,
        }).then(function (r) {
            return r.json();
        }).then(function (j) {
            var pre = document.createElement('pre');
            pre.className = 'transcript-static';
            pre.textContent = j.transcript || '(no reply)';
            result.appendChild(pre);
            if (j.note) {
                var n = document.createElement('div');
                n.className = 'note-hint visible';
                n.textContent = j.note;
                result.appendChild(n);
            }
            btn.disabled = false;
            btn.textContent = 'Send';
        }).catch(function (err) {
            result.textContent = 'ERROR: ' + err;
            btn.disabled = false;
            btn.textContent = 'Send';
        });
    });
})();
JS;
}
/**
 * Recent-transcripts tab JS. Just the Clear-log button.
 */
function turnClearScript()
{
    return <<<'JS'
(function () {
    var btn = document.getElementById('clearLog');
    if (!btn) return;
    btn.addEventListener('click', function () {
        if (!window.confirm('Clear the transcripts log?')) {
            return;
        }
        btn.disabled = true;
        fetch('/log/clear', { method: 'POST' })
            .then(function () { window.location.reload(); })
            .catch(function (err) {
                document.getElementById('clearStatus')
                    .textContent = 'ERROR: ' + err;
                btn.disabled = false;
            });
    });
})();
JS;
}
/*
    --- Routes ---
 */
$site->get('/', function () use ($site, $cfg) {
    turnRenderPage('scenarios', $cfg, function () use
        ($cfg) { turnRenderScenarios($cfg); });
});
$site->get('/raw', function () use ($site, $cfg) {
    turnRenderPage('raw', $cfg, function () use ($cfg) {
        turnRenderRaw($cfg);
    });
});
$site->get('/allocs', function () use ($site, $cfg) {
    turnRenderPage('allocs', $cfg, function () use ($cfg) {
        turnRenderAllocs($cfg);
    });
});
/*
    POST /scenario -- runs the named scenario, logs the
    transcript, returns JSON {transcript, note}.
 */
$site->post('/scenario', function () use ($site, $cfg) {
    $site->header('Content-Type: application/json');
    $key = $_POST['scenario'] ?? '';
    $list = turnScenarioList();
    if (!isset($list[$key])) {
        echo json_encode([
            'transcript' => "! unknown scenario: " . $key,
            'note' => null,
        ]);
        return;
    }
    $info = $list[$key];
    $runner = $info['run'];
    $result = $runner($cfg);
    turnLogAppend([
        'ts' => time(),
        'scenario' => $key,
        'title' => $info['title'],
        'transcript' => $result['transcript'],
        'note' => $result['note'] ?? null,
    ]);
    echo json_encode($result);
});
/*
    POST /raw -- runs the user's hand-built message,
    logs the transcript, returns JSON {transcript, note}.
 */
$site->post('/raw', function () use ($site, $cfg) {
    $site->header('Content-Type: application/json');
    $method = $_POST['method'] ?? '';
    $user_choice = $_POST['user'] ?? '';
    $peer_str = $_POST['peer'] ?? '';
    $chan_str = $_POST['chan'] ?? '0x4000';
    $lt_str = $_POST['lifetime'] ?? '600';
    $result = turnRunRaw($cfg, $method, $user_choice,
        $peer_str, $chan_str, $lt_str);
    turnLogAppend([
        'ts' => time(),
        'scenario' => 'raw:' . $method,
        'title' => 'Raw: ' . $method .
            ($user_choice !== '' ?
            ' as ' . $user_choice : ''),
        'transcript' => $result['transcript'],
        'note' => $result['note'] ?? null,
    ]);
    echo json_encode($result);
});
/*
    POST /log/clear -- wipes the transcripts log.
 */
$site->post('/log/clear', function () use ($site) {
    turnLogClear();
    $site->header('Content-Type: text/plain');
    echo 'cleared';
});
/*
    POST /bind -- writes bind.txt and asks both processes
    to exit. Same shape as ex23.
 */
$site->post('/bind', function () use ($site, $cfg) {
    $site->header('Content-Type: text/plain');
    $val = $_POST['bind'] ?? '';
    if (!isset($cfg['bind_choices'][$val])) {
        echo 'invalid bind';
        return;
    }
    @file_put_contents($cfg['bind_file'], $val);
    echo 'bind written; shutting down';
    $server_pid = (int) (getenv('ATTOTURN_SERVER_PID') ?:
        0);
    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    }
    /* a small delay so the response makes it back */
    if (!strstr(PHP_OS, 'WIN')) {
        if ($server_pid > 0) {
            @posix_kill($server_pid, 15);
        }
        @posix_kill(getmypid(), 15);
    } else {
        if ($server_pid > 0) {
            @exec("taskkill /F /PID $server_pid");
        }
        @exec("taskkill /F /PID " . getmypid());
    }
});
/*
    --- Raw-builder runner ---

    Takes the form values and assembles a single STUN
    request, sends it (with the long-term-credential 401
    challenge cycle if a user was selected), and returns
    the transcript.
 */
/**
 * Implements POST /raw. Returns ['transcript' => string,
 * 'note' => string|null].
 */
function turnRunRaw($cfg, $method, $user_choice, $peer_str,
    $chan_str, $lt_str)
{
    $sock = turnOpenSocket($cfg);
    if (!$sock) {
        return ['transcript' => "! could not connect\n",
            'note' => null];
    }
    /*
        Resolve the chosen user into (username, password).
        The literal "alice-wrong" entry forces an MI
        failure by using the wrong password.
     */
    $username = '';
    $password = '';
    if ($user_choice !== '') {
        if ($user_choice === 'alice-wrong') {
            $username = 'alice';
            $password = 'WRONG-PASSWORD';
        } else {
            foreach ($cfg['demo_users'] as $u) {
                if ($u['user'] === $user_choice) {
                    $username = $u['user'];
                    $password = $u['pass'];
                    break;
                }
            }
        }
    }
    /*
        Build the per-method attribute set. Method names
        are the same lowercase-dash form the form sends.
        XOR-PEER-ADDRESS is encoded against the message
        TID (for IPv6) so we hold the peer host/port aside
        and stitch the attribute in once we have the TID.
     */
    $blocks = [];
    $stun_method = TURN_M_BINDING;
    $peer_for_xor = null;
    $chan_for_xor = 0;
    switch ($method) {
        case 'binding':
            $stun_method = TURN_M_BINDING;
            break;
        case 'allocate':
            $stun_method = TURN_M_ALLOCATE;
            $blocks[] = turnAttr(TURN_ATTR_REQ_TRANSPORT,
                chr(17) . chr(0) . chr(0) . chr(0));
            $lt = max(0, (int) $lt_str);
            if ($lt > 0) {
                $blocks[] = turnAttr(TURN_ATTR_LIFETIME,
                    pack('N', $lt));
            }
            break;
        case 'refresh':
            $stun_method = TURN_M_REFRESH;
            $lt = max(0, (int) $lt_str);
            $blocks[] = turnAttr(TURN_ATTR_LIFETIME,
                pack('N', $lt));
            break;
        case 'create-permission':
            $stun_method = TURN_M_CREATE_PERMISSION;
            list($ph, $pp) = turnParsePeerString($peer_str);
            if ($ph === false) {
                @fclose($sock);
                return ['transcript' =>
                    "! unparseable peer address: " .
                    $peer_str . "\n", 'note' => null];
            }
            $peer_for_xor = [$ph, $pp];
            break;
        case 'channel-bind':
            $stun_method = TURN_M_CHANNEL_BIND;
            list($ph, $pp) = turnParsePeerString($peer_str);
            if ($ph === false) {
                @fclose($sock);
                return ['transcript' =>
                    "! unparseable peer address: " .
                    $peer_str . "\n", 'note' => null];
            }
            $chan_for_xor = (int) (substr($chan_str, 0, 2)
                === '0x' ? hexdec(substr($chan_str, 2)) :
                $chan_str);
            $blocks[] = turnAttr(TURN_ATTR_CHAN,
                pack('nn', $chan_for_xor, 0));
            $peer_for_xor = [$ph, $pp];
            break;
        default:
            @fclose($sock);
            return ['transcript' =>
                "! unknown method: " . $method . "\n",
                'note' => null];
    }
    /*
        Bare-STUN methods (Binding) skip the auth cycle.
        Everything else either does the full 401 challenge
        when a user is selected, or sends unauthenticated
        (which will get back 401 and we render that as the
        whole transcript).
     */
    if ($stun_method === TURN_M_BINDING ||
        $username === '') {
        $tid = random_bytes(12);
        $send_blocks = $blocks;
        if ($peer_for_xor !== null) {
            $send_blocks[] = turnAttr(TURN_ATTR_XOR_PEER,
                turnEncXor($peer_for_xor[0],
                $peer_for_xor[1], $tid));
        }
        $req = turnBuildMsg($stun_method, TURN_C_REQUEST,
            $tid, $send_blocks);
        $t = turnRenderMsg($req, '>');
        $reply = turnRoundTrip($sock, $req);
        $t .= ($reply !== '') ?
            turnRenderMsg($reply, '<') :
            "! timeout\n";
        @fclose($sock);
        return ['transcript' => $t, 'note' => null];
    }
    /*
        Authenticated path. The static blocks go straight
        through; XOR-PEER (if any) is inserted via the
        callable form so it gets re-encoded against
        whichever TID turnAuthSend ends up using.
     */
    if ($peer_for_xor === null) {
        $extras = $blocks;
    } else {
        $extras = function ($tid) use ($blocks,
            $peer_for_xor) {
            $b = $blocks;
            $b[] = turnAttr(TURN_ATTR_XOR_PEER,
                turnEncXor($peer_for_xor[0],
                $peer_for_xor[1], $tid));
            return $b;
        };
    }
    list($t, ) = turnAuthSend($sock, $stun_method, $extras,
        $username, $password);
    @fclose($sock);
    return ['transcript' => $t, 'note' => null];
}
/**
 * Parses a "host:port" or "[host]:port" form-input string.
 * Returns [host, port] or [false, 0].
 */
function turnParsePeerString($s)
{
    $s = trim($s);
    if ($s === '') {
        return [false, 0];
    }
    if ($s[0] === '[') {
        $end = strpos($s, ']');
        if ($end === false) {
            return [false, 0];
        }
        $h = substr($s, 1, $end - 1);
        $p = (int) substr($s, $end + 2);
        return [$h, $p];
    }
    $colon = strrpos($s, ':');
    if ($colon === false) {
        return [false, 0];
    }
    return [substr($s, 0, $colon),
        (int) substr($s, $colon + 1)];
}
$site->listen(8080);
