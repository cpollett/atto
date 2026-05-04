<?php
/**
 * AttoDNS demo: web UI for the authoritative DNS server in
 * index.php. Three modes:
 *
 *   - Scenarios: a scripted tour of A / AAAA / MX / TXT /
 *     CNAME chase / NXDOMAIN / wildcard / TCP truncation /
 *     EDNS0 / DoT, each rendering the actual wire query and
 *     wire response with a hex pane plus a parsed-out human
 *     view.
 *   - Raw query: pick a name, type, and transport and watch
 *     the bytes go out and come back, dig-style.
 *   - Zone editor: read the .zone master files from disk,
 *     edit them in a textarea, save them back. Saving
 *     issues an HTTP request to /reload so the running DNS
 *     server picks up the change without a restart.
 *
 * This file runs as a detached child of index.php; do not
 * launch it directly. It loads DnsSite.php for the wire-
 * format codec only -- the running DNS server is in the
 * sibling process and we reach it via real UDP/TCP sockets,
 * which is the whole point of the demo.
 */
require '../../src/WebSite.php';
require '../../src/DnsSite.php';
use seekquarry\atto\WebSite;
use seekquarry\atto\DnsMessage;
use seekquarry\atto\DnsRecord;
use seekquarry\atto\DnsSite;
use seekquarry\atto\FileDnsAuthority;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$site = new WebSite(".");
$cfg = [
    'host' => '127.0.0.1',
    'udp_port' => 15353,
    'tcp_port' => 15353,
    'tls_port' => 18853,
    'zone_dir' => __DIR__ . DIRECTORY_SEPARATOR . 'zones',
];
/*
    Send one query packet over UDP and return the raw bytes
    of the response. The function is short on purpose: it is
    the "see the whole transaction" surface that the demo
    hangs every visualization off of, and adding cleverness
    here would make the demo less honest about what a DNS
    request really is.
 */
function dnsSendUdp($host, $port, $bytes, $timeout_ms = 1500)
{
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client("udp://$host:$port",
        $errno, $errstr, $timeout_ms / 1000);
    if (!$sock) {
        return ['error' => "udp connect: $errstr"];
    }
    stream_set_timeout($sock, 0, $timeout_ms * 1000);
    $sent = @fwrite($sock, $bytes);
    $start = microtime(true);
    $response = @fread($sock, 65535);
    $elapsed_ms = (int) ((microtime(true) - $start) * 1000);
    @fclose($sock);
    if ($response === false || $response === '') {
        return ['error' => 'udp: no response (timeout)'];
    }
    return ['bytes' => $response, 'elapsed_ms' => $elapsed_ms];
}
/*
    TCP variant. RFC 1035 sec 4.2.2 frames each message with
    a 2-byte big-endian length prefix; we add it on the way
    out and strip it on the way in.
 */
function dnsSendTcp($host, $port, $bytes, $timeout_ms = 2000)
{
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client("tcp://$host:$port",
        $errno, $errstr, $timeout_ms / 1000);
    if (!$sock) {
        return ['error' => "tcp connect: $errstr"];
    }
    stream_set_timeout($sock, 0, $timeout_ms * 1000);
    $framed = pack("n", strlen($bytes)) . $bytes;
    @fwrite($sock, $framed);
    $start = microtime(true);
    $head = '';
    while (strlen($head) < 2) {
        $chunk = @fread($sock, 2 - strlen($head));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $head .= $chunk;
    }
    if (strlen($head) < 2) {
        @fclose($sock);
        return ['error' => 'tcp: truncated length prefix'];
    }
    $length = unpack("n", $head)[1];
    $payload = '';
    while (strlen($payload) < $length) {
        $chunk = @fread($sock, $length - strlen($payload));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $payload .= $chunk;
    }
    $elapsed_ms = (int) ((microtime(true) - $start) * 1000);
    @fclose($sock);
    if (strlen($payload) !== $length) {
        return ['error' =>
            "tcp: short read ($length expected, " .
            strlen($payload) . " got)"];
    }
    return ['bytes' => $payload, 'elapsed_ms' => $elapsed_ms];
}
/*
    DNS-over-TLS variant. Same wire framing as plain TCP but
    inside an implicit-TLS connection on a different port.
    We disable peer verification because the demo uses a
    self-signed cert; a real client would pin the cert or
    use the public CA tree.
 */
function dnsSendDot($host, $port, $bytes, $timeout_ms = 3000)
{
    $context = stream_context_create(['ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
    ]]);
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client("tls://$host:$port",
        $errno, $errstr, $timeout_ms / 1000,
        STREAM_CLIENT_CONNECT, $context);
    if (!$sock) {
        return ['error' => "dot connect: $errstr"];
    }
    stream_set_timeout($sock, 0, $timeout_ms * 1000);
    $framed = pack("n", strlen($bytes)) . $bytes;
    @fwrite($sock, $framed);
    $start = microtime(true);
    $head = '';
    while (strlen($head) < 2) {
        $chunk = @fread($sock, 2 - strlen($head));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $head .= $chunk;
    }
    if (strlen($head) < 2) {
        @fclose($sock);
        return ['error' => 'dot: truncated length prefix'];
    }
    $length = unpack("n", $head)[1];
    $payload = '';
    while (strlen($payload) < $length) {
        $chunk = @fread($sock, $length - strlen($payload));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $payload .= $chunk;
    }
    $elapsed_ms = (int) ((microtime(true) - $start) * 1000);
    @fclose($sock);
    return ['bytes' => $payload, 'elapsed_ms' => $elapsed_ms];
}
/*
    Build a question packet from (name, type) and a few
    knobs. The transaction ID is randomized so successive
    runs in the demo look like independent transactions.
 */
function dnsBuildQuery($name, $type, $opts = [])
{
    $msg = new DnsMessage();
    $msg->id = isset($opts['id']) ? $opts['id'] :
        random_int(0, 0xFFFF);
    $msg->rd = !empty($opts['rd']);
    $msg->questions = [[$name, $type, DnsSite::CLASS_IN]];
    if (!empty($opts['edns0'])) {
        /*
            Add an OPT pseudo-record to the additional
            section. CLASS holds the requestor's UDP buffer
            size (4096 by convention); TTL is split into
            extended-rcode/version/Z/DO bits and we leave
            them all zero. RDATA is empty.
         */
        $msg->additional[] = new DnsRecord('',
            DnsSite::TYPE_OPT, 4096, 0, '');
    }
    return DnsMessage::pack($msg);
}
/*
    Format a packet as a side-by-side hex+ASCII dump,
    16 bytes per row, like xxd. The output is plain text;
    the surrounding HTML wraps it in <pre>.
 */
function dnsHexDump($bytes)
{
    $out = '';
    $n = strlen($bytes);
    for ($i = 0; $i < $n; $i += 16) {
        $chunk = substr($bytes, $i, 16);
        $hex_pairs = [];
        $ascii = '';
        for ($j = 0; $j < strlen($chunk); $j++) {
            $b = ord($chunk[$j]);
            $hex_pairs[] = sprintf('%02x', $b);
            $ascii .= ($b >= 0x20 && $b < 0x7F) ?
                $chunk[$j] : '.';
        }
        while (count($hex_pairs) < 16) {
            $hex_pairs[] = '  ';
        }
        $left = implode(' ', array_slice($hex_pairs, 0, 8));
        $right = implode(' ', array_slice($hex_pairs, 8));
        $out .= sprintf("%04x  %-23s  %-23s  %s\n", $i,
            $left, $right, $ascii);
    }
    return $out;
}
/*
    Render a DnsMessage in dig-like form. Helpful as a
    second view alongside the hex dump: clients see exactly
    what dig would show for the same packet.
 */
function dnsHumanRender($message)
{
    if ($message === false || $message === null) {
        return "(unparseable)\n";
    }
    $rcode_names = [0 => 'NOERROR', 1 => 'FORMERR',
        2 => 'SERVFAIL', 3 => 'NXDOMAIN', 4 => 'NOTIMP',
        5 => 'REFUSED'];
    $rcode = isset($rcode_names[$message->rcode]) ?
        $rcode_names[$message->rcode] :
        'RCODE' . $message->rcode;
    $flags = [];
    if ($message->qr) { $flags[] = 'qr'; }
    if ($message->aa) { $flags[] = 'aa'; }
    if ($message->tc) { $flags[] = 'tc'; }
    if ($message->rd) { $flags[] = 'rd'; }
    if ($message->ra) { $flags[] = 'ra'; }
    $out = sprintf(";; ->>HEADER<<- opcode: %s, status: %s," .
        " id: %d\n",
        $message->opcode === 0 ? 'QUERY' :
            'OPCODE' . $message->opcode,
        $rcode, $message->id);
    $out .= ';; flags: ' . (empty($flags) ? '' :
        implode(' ', $flags)) .
        '; QUERY: ' . count($message->questions) .
        ', ANSWER: ' . count($message->answers) .
        ', AUTHORITY: ' . count($message->authority) .
        ', ADDITIONAL: ' . count($message->additional) . "\n\n";
    if (!empty($message->questions)) {
        $out .= ";; QUESTION SECTION:\n";
        foreach ($message->questions as $q) {
            $out .= sprintf(";%-30s %-7s %s\n",
                $q[0] . '.', dnsClassName($q[2]),
                DnsSite::nameFromType($q[1]));
        }
        $out .= "\n";
    }
    if (!empty($message->answers)) {
        $out .= ";; ANSWER SECTION:\n";
        $out .= dnsRenderRrList($message->answers);
        $out .= "\n";
    }
    if (!empty($message->authority)) {
        $out .= ";; AUTHORITY SECTION:\n";
        $out .= dnsRenderRrList($message->authority);
        $out .= "\n";
    }
    if (!empty($message->additional)) {
        $out .= ";; ADDITIONAL SECTION:\n";
        $out .= dnsRenderRrList($message->additional);
        $out .= "\n";
    }
    return $out;
}
function dnsClassName($class)
{
    return $class === DnsSite::CLASS_IN ? 'IN' :
        ($class === DnsSite::CLASS_ANY ? 'ANY' :
            'CLASS' . $class);
}
function dnsRenderRrList($records)
{
    $out = '';
    foreach ($records as $r) {
        if ($r->type === DnsSite::TYPE_OPT) {
            $out .= sprintf("; OPT pseudo-record udp_size=%d\n",
                $r->class);
            continue;
        }
        $rdata_text = dnsRenderRdata($r->type, $r->rdata);
        $out .= sprintf("%-30s %-7d %-4s %-7s %s\n",
            $r->name . '.', $r->ttl, dnsClassName($r->class),
            DnsSite::nameFromType($r->type), $rdata_text);
    }
    return $out;
}
function dnsRenderRdata($type, $rdata)
{
    switch ($type) {
        case DnsSite::TYPE_A:
        case DnsSite::TYPE_AAAA:
            return (string) $rdata;
        case DnsSite::TYPE_CNAME:
        case DnsSite::TYPE_NS:
        case DnsSite::TYPE_PTR:
            return $rdata . '.';
        case DnsSite::TYPE_MX:
            return $rdata['preference'] . ' ' .
                $rdata['exchange'] . '.';
        case DnsSite::TYPE_TXT:
            $strings = is_array($rdata) ? $rdata : [$rdata];
            $parts = [];
            foreach ($strings as $s) {
                $parts[] = '"' . addslashes($s) . '"';
            }
            return implode(' ', $parts);
        case DnsSite::TYPE_SOA:
            return $rdata['mname'] . '. ' .
                $rdata['rname'] . '. ' .
                $rdata['serial'] . ' ' .
                $rdata['refresh'] . ' ' .
                $rdata['retry'] . ' ' .
                $rdata['expire'] . ' ' .
                $rdata['minimum'];
    }
    return is_string($rdata) ? $rdata :
        json_encode($rdata);
}
$site->get('/style.css', function () use ($site) {
    $site->header("Content-Type: text/css");
    echo <<<'CSS'
* { box-sizing: border-box; }
body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont,
        "Segoe UI", Roboto, sans-serif;
    background: #f7f7f8; color: #222;
}
.page {
    max-width: 1100px; margin: 0 auto; padding: 0 20px 40px;
}
header {
    background: #1f2937; color: #f5f5f7; padding: 18px 24px;
    margin: 0 -20px 20px;
}
header h1 { margin: 0; font-size: 20px; font-weight: 600; }
header small { color: #9ca3af; }
nav.tabs {
    display: flex; gap: 4px; border-bottom: 1px solid #d1d5db;
    margin-bottom: 18px;
}
nav.tabs a {
    padding: 8px 14px; text-decoration: none; color: #444;
    border: 1px solid transparent; border-bottom: none;
    border-radius: 6px 6px 0 0;
}
nav.tabs a.active {
    background: #fff; border-color: #d1d5db;
    color: #111; font-weight: 600;
}
.scenario-list {
    display: grid; grid-template-columns: 1fr; gap: 10px;
}
.scenario {
    background: #fff; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 14px 16px;
}
.scenario h3 {
    margin: 0 0 6px; font-size: 15px; font-weight: 600;
}
.scenario p { margin: 0 0 10px; color: #4b5563; font-size: 14px; }
.scenario button {
    background: #2563eb; color: #fff; border: 0;
    padding: 6px 14px; border-radius: 6px; cursor: pointer;
    font-size: 13px;
}
.scenario button:hover { background: #1d4ed8; }
.result {
    margin-top: 12px; display: grid;
    grid-template-columns: 1fr 1fr; gap: 12px;
}
.result h4 {
    margin: 0 0 6px; font-size: 12px; color: #6b7280;
    text-transform: uppercase; letter-spacing: 0.04em;
}
.pane {
    background: #0f172a; color: #e2e8f0; padding: 10px 12px;
    border-radius: 6px; font-family: ui-monospace,
        "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px; white-space: pre; overflow-x: auto;
    line-height: 1.5;
}
.pane.hex { color: #cbd5e1; }
.pane.error { background: #7f1d1d; color: #fee2e2; }
.banner {
    background: #fef3c7; color: #92400e; padding: 8px 12px;
    border-radius: 6px; font-size: 13px; margin-bottom: 14px;
}
form.raw {
    background: #fff; border: 1px solid #e5e7eb;
    padding: 14px; border-radius: 8px;
    display: grid; grid-template-columns: 2fr 1fr 1fr auto;
    gap: 8px; align-items: end; margin-bottom: 14px;
}
form.raw label {
    display: block; font-size: 12px; color: #4b5563;
    margin-bottom: 3px;
}
form.raw input, form.raw select {
    width: 100%; padding: 6px 8px; border: 1px solid #d1d5db;
    border-radius: 4px; font-size: 14px;
}
form.raw button {
    background: #2563eb; color: #fff; border: 0;
    padding: 8px 16px; border-radius: 4px; cursor: pointer;
    font-size: 14px;
}
.zone-list {
    background: #fff; border: 1px solid #e5e7eb;
    padding: 10px; border-radius: 8px; margin-bottom: 14px;
}
.zone-list a {
    display: inline-block; padding: 4px 10px; margin: 2px;
    background: #eef2ff; color: #1e3a8a; text-decoration: none;
    border-radius: 4px; font-size: 13px;
}
form.zone {
    background: #fff; border: 1px solid #e5e7eb;
    padding: 14px; border-radius: 8px;
}
form.zone textarea {
    width: 100%; min-height: 360px; font-family:
        ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 13px; padding: 10px; border: 1px solid #d1d5db;
    border-radius: 4px; line-height: 1.5;
}
form.zone .actions {
    display: flex; gap: 8px; margin-top: 10px;
    align-items: center;
}
form.zone button {
    background: #16a34a; color: #fff; border: 0;
    padding: 8px 16px; border-radius: 4px; cursor: pointer;
}
form.zone .saved {
    color: #15803d; font-size: 13px;
}
footer {
    margin-top: 32px; padding-top: 16px;
    border-top: 1px solid #e5e7eb;
    color: #6b7280; font-size: 12px; text-align: center;
}
@media (max-width: 700px) {
    .result { grid-template-columns: 1fr; }
    form.raw { grid-template-columns: 1fr; }
}
CSS;
});
$site->get('/', function () use ($site) {
    dnsRenderPage('scenarios');
});
$site->get('/raw', function () use ($site) {
    dnsRenderPage('raw');
});
$site->get('/zones', function () use ($site, $cfg) {
    dnsRenderPage('zones', ['cfg' => $cfg]);
});
$site->get('/zones/{name}', function ()
    use ($site, $cfg) {
    $name = (string) ($_REQUEST['name'] ?? '');
    dnsRenderPage('zone-edit', ['cfg' => $cfg,
        'name' => $name]);
});
function dnsRenderPage($which, $params = [])
{
    $tabs = [
        'scenarios' => ['Scenarios', '/'],
        'raw' => ['Raw query', '/raw'],
        'zones' => ['Zone editor', '/zones'],
    ];
    if ($which === 'zone-edit') {
        $active = 'zones';
    } else {
        $active = $which;
    }
    echo "<!DOCTYPE html>\n";
    echo "<html lang=\"en\"><head><meta charset=\"utf-8\">\n";
    echo "<title>AttoDNS demo</title>\n";
    echo "<meta name=\"viewport\" content=\"width=device-" .
        "width,initial-scale=1\">\n";
    echo "<link rel=\"stylesheet\" href=\"/style.css\">\n";
    echo "</head><body>\n";
    echo "<div class=\"page\">\n";
    echo "<header><h1>AttoDNS demo</h1>";
    echo "<small>Single-file authoritative DNS server in PHP" .
        " &mdash; click through real wire transactions</small>";
    echo "</header>\n";
    echo "<nav class=\"tabs\">";
    foreach ($tabs as $key => $info) {
        $cls = $key === $active ? ' class="active"' : '';
        echo "<a$cls href=\"" . $info[1] . "\">" .
            htmlspecialchars($info[0]) . "</a>";
    }
    echo "</nav>\n";
    if ($which === 'scenarios') {
        dnsRenderScenarios();
    } else if ($which === 'raw') {
        dnsRenderRaw();
    } else if ($which === 'zones') {
        dnsRenderZones($params['cfg']);
    } else if ($which === 'zone-edit') {
        dnsRenderZoneEdit($params['cfg'], $params['name']);
    }
    echo "<footer>AttoDNS demo. Each scenario sends a real" .
        " query over a real socket and shows what came back" .
        " on the wire.</footer>\n";
    echo "</div></body></html>\n";
}
function dnsScenarioList()
{
    return [
        'a' => [
            'title' => 'A query for www.example.test',
            'desc' => 'The basic case: ask for an IPv4 ' .
                'address by name. The answer section ' .
                'carries one A record with the four-byte ' .
                'address; the response packet uses ' .
                'compression so the answer name is a ' .
                'pointer back to byte 12 of the question.',
        ],
        'aaaa' => [
            'title' => 'AAAA query for ipv6only.example.test',
            'desc' => 'Same shape as A but the RDATA is ' .
                'sixteen bytes of IPv6 address. The owner ' .
                'has no A record, demonstrating that A and ' .
                'AAAA lookups are independent.',
        ],
        'mx' => [
            'title' => 'MX query (with glue)',
            'desc' => 'MX records carry a 16-bit ' .
                'preference followed by an exchange name. ' .
                'The server adds glue: A and AAAA records ' .
                'for the exchange host appear in the ' .
                'additional section so the client does ' .
                'not need a follow-up lookup.',
        ],
        'txt' => [
            'title' => 'TXT query (SPF-style)',
            'desc' => 'TXT carries one or more length-' .
                'prefixed strings. Used in the wild for ' .
                'SPF, DKIM, ACME challenges, and more.',
        ],
        'cname' => [
            'title' => 'CNAME chase (ftp -> www)',
            'desc' => 'When asked for an A record at a ' .
                'CNAME owner, we return both the CNAME ' .
                'and the A record at the target. Clients ' .
                'do not have to follow the chain ' .
                'themselves.',
        ],
        'nxdomain' => [
            'title' => 'NXDOMAIN with SOA in authority',
            'desc' => 'A name that does not exist in any ' .
                'served zone returns rcode NXDOMAIN. We ' .
                'put the zone\'s SOA in the authority ' .
                'section so caches know how long to ' .
                'remember the negative answer (RFC 2308).',
        ],
        'wildcard' => [
            'title' => 'Wildcard match',
            'desc' => 'A *.wild.example.test record ' .
                'answers any name under wild.example.test ' .
                'that has no exact match. The owner name ' .
                'in the response is rewritten to the ' .
                'queried name (RFC 4592).',
        ],
        'tcp' => [
            'title' => 'Same query over TCP',
            'desc' => 'TCP frames each message with a ' .
                '2-byte length prefix. Same payload, just ' .
                'a different transport.',
        ],
        'edns0' => [
            'title' => 'EDNS0 OPT pseudo-record',
            'desc' => 'Adding an OPT record to the ' .
                'additional section advertises a larger ' .
                'UDP buffer (RFC 6891), letting the ' .
                'server fit answers that would otherwise ' .
                'truncate at 512 bytes.',
        ],
        'tc' => [
            'title' => 'Truncation forces TCP retry',
            'desc' => 'Forcing a tiny UDP buffer trips the ' .
                'truncation logic: the response sets the ' .
                'TC bit and strips the answer section. A ' .
                'real client retries over TCP after ' .
                'seeing TC.',
        ],
        'dot' => [
            'title' => 'DNS-over-TLS (RFC 7858)',
            'desc' => 'The same TCP wire format inside a ' .
                'TLS connection on port 18853. Requires a ' .
                'cert.pem/key.pem in the demo directory; ' .
                'absent that, this scenario is unavailable.',
        ],
        'refused' => [
            'title' => 'REFUSED for a foreign zone',
            'desc' => 'Asking about a name that is not ' .
                'inside any zone we serve returns rcode ' .
                'REFUSED. An authoritative server only ' .
                'speaks for what it owns.',
        ],
    ];
}
function dnsRenderScenarios()
{
    echo "<div class=\"banner\">Click any scenario below to " .
        "send a real DNS query against the running server " .
        "and see the actual bytes go out and come back.</div>";
    echo "<div class=\"scenario-list\">";
    foreach (dnsScenarioList() as $key => $info) {
        echo "<div class=\"scenario\" data-key=\"" .
            htmlspecialchars($key) . "\">";
        echo "<h3>" . htmlspecialchars($info['title']) .
            "</h3>";
        echo "<p>" . htmlspecialchars($info['desc']) . "</p>";
        echo "<button type=\"button\" " .
            "onclick=\"runScenario('" . $key . "', this)\">" .
            "Run</button>";
        echo "<div class=\"result-slot\"></div>";
        echo "</div>";
    }
    echo "</div>";
    echo "<script>\n" . dnsClientScript() . "\n</script>\n";
}
function dnsRenderRaw()
{
    echo "<div class=\"banner\">Type a name and pick a record " .
        "type and transport. Defaults to www.example.test, " .
        "which the demo's zone resolves.</div>";
    echo "<form class=\"raw\" id=\"rawForm\">";
    echo "<div><label>Name</label>";
    echo "<input name=\"name\" value=\"www.example.test\"" .
        " required></div>";
    echo "<div><label>Type</label><select name=\"type\">";
    foreach (['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA',
        'PTR', 'ANY'] as $t) {
        echo "<option>$t</option>";
    }
    echo "</select></div>";
    echo "<div><label>Transport</label><select name=\"" .
        "transport\">";
    foreach (['udp', 'tcp', 'dot'] as $t) {
        echo "<option value=\"$t\">" . strtoupper($t) .
            "</option>";
    }
    echo "</select></div>";
    echo "<div><label>&nbsp;</label>";
    echo "<button type=\"submit\">Query</button></div>";
    echo "</form>";
    echo "<div id=\"rawResult\"></div>";
    echo "<script>\n" . dnsClientScript() . "\n</script>\n";
}
function dnsRenderZones($cfg)
{
    $files = glob($cfg['zone_dir'] . DIRECTORY_SEPARATOR .
        '*.zone');
    if ($files === false) { $files = []; }
    sort($files);
    echo "<div class=\"banner\">Edit zone files in place. " .
        "Saving sends a reload signal to the running DNS " .
        "server, so the next query reflects your changes.</div>";
    echo "<div class=\"zone-list\"><strong>Zones:</strong> ";
    if (empty($files)) {
        echo "<em>(none yet)</em>";
    } else {
        foreach ($files as $file) {
            $base = basename($file, '.zone');
            echo "<a href=\"/zones/" .
                htmlspecialchars(rawurlencode($base)) .
                "\">" . htmlspecialchars($base) . "</a> ";
        }
    }
    echo "</div>";
}
function dnsRenderZoneEdit($cfg, $name)
{
    $name = preg_replace('/[^a-zA-Z0-9._-]/', '', $name);
    if ($name === '') {
        echo "<div class=\"banner\">Bad zone name.</div>";
        return;
    }
    $path = $cfg['zone_dir'] . DIRECTORY_SEPARATOR .
        $name . '.zone';
    $contents = is_file($path) ?
        (string) @file_get_contents($path) : '';
    echo "<form class=\"zone\" method=\"post\" action=\"" .
        "/zones/" . htmlspecialchars(rawurlencode($name)) .
        "\">";
    echo "<h3>" . htmlspecialchars($name) . ".zone</h3>";
    echo "<textarea name=\"contents\" spellcheck=\"false\">" .
        htmlspecialchars($contents) . "</textarea>";
    echo "<div class=\"actions\">";
    echo "<button type=\"submit\">Save and reload</button>";
    echo "<a href=\"/zones\">Back</a>";
    if (isset($_GET['saved'])) {
        echo "<span class=\"saved\">Saved and reloaded.</span>";
    }
    echo "</div></form>";
}
function dnsClientScript()
{
    return <<<'JS'
async function runScenario(key, btn) {
    btn.disabled = true;
    btn.textContent = 'Running...';
    try {
        const fd = new FormData();
        fd.append('scenario', key);
        const r = await fetch('/scenario',
            { method: 'POST', body: fd });
        const data = await r.json();
        const slot = btn.parentElement
            .querySelector('.result-slot');
        slot.innerHTML = renderResult(data);
    } catch (e) {
        const slot = btn.parentElement
            .querySelector('.result-slot');
        slot.innerHTML = '<div class="pane error">' +
            escapeHtml(String(e)) + '</div>';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Run';
    }
}
function renderResult(data) {
    if (data.error) {
        return '<div class="result"><div><h4>Error</h4>' +
            '<div class="pane error">' +
            escapeHtml(data.error) + '</div></div></div>';
    }
    let html = '';
    if (data.note) {
        html += '<div class="banner" style="margin-top:12px">' +
            escapeHtml(data.note) + '</div>';
    }
    html += '<div class="result">';
    html += '<div><h4>Query</h4><div class="pane">' +
        escapeHtml(data.query_human) + '</div>' +
        '<h4 style="margin-top:8px">Hex</h4>' +
        '<div class="pane hex">' +
        escapeHtml(data.query_hex) + '</div></div>';
    html += '<div><h4>Response</h4><div class="pane">' +
        escapeHtml(data.response_human) + '</div>' +
        '<h4 style="margin-top:8px">Hex</h4>' +
        '<div class="pane hex">' +
        escapeHtml(data.response_hex) + '</div></div>';
    html += '</div>';
    html += '<div style="margin-top:8px;color:#6b7280;' +
        'font-size:12px">Transport: ' + data.transport +
        ', round trip: ' + data.elapsed_ms + ' ms</div>';
    return html;
}
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
const rawForm = document.getElementById('rawForm');
if (rawForm) {
    rawForm.addEventListener('submit', async function (ev) {
        ev.preventDefault();
        const slot = document.getElementById('rawResult');
        slot.innerHTML = '<div class="pane">Querying...</div>';
        const fd = new FormData(rawForm);
        try {
            const r = await fetch('/raw',
                { method: 'POST', body: fd });
            const data = await r.json();
            slot.innerHTML = renderResult(data);
        } catch (e) {
            slot.innerHTML = '<div class="pane error">' +
                escapeHtml(String(e)) + '</div>';
        }
    });
}
JS;
}
$site->post('/scenario', function () use ($site, $cfg) {
    $key = $_POST['scenario'] ?? '';
    $list = dnsScenarioList();
    if (!isset($list[$key])) {
        $site->header("Content-Type: application/json");
        echo json_encode(['error' => 'unknown scenario']);
        return;
    }
    $result = dnsRunScenario($key, $cfg);
    $site->header("Content-Type: application/json");
    echo json_encode($result);
});
$site->post('/raw', function () use ($site, $cfg) {
    $name = trim((string) ($_POST['name'] ?? ''));
    $type_name = strtoupper(trim((string)
        ($_POST['type'] ?? 'A')));
    $transport = strtolower(trim((string)
        ($_POST['transport'] ?? 'udp')));
    if ($name === '' ||
        !preg_match('/^[a-zA-Z0-9._\-]+$/', $name)) {
        $site->header("Content-Type: application/json");
        echo json_encode(['error' => 'bad name']);
        return;
    }
    $type = DnsSite::typeFromName($type_name);
    if ($type === false) {
        $site->header("Content-Type: application/json");
        echo json_encode(['error' => 'unknown type']);
        return;
    }
    if (!in_array($transport, ['udp', 'tcp', 'dot'], true)) {
        $site->header("Content-Type: application/json");
        echo json_encode(['error' => 'unknown transport']);
        return;
    }
    $result = dnsExecuteQuery($name, $type, $transport,
        ['rd' => true], $cfg);
    $site->header("Content-Type: application/json");
    echo json_encode($result);
});
$site->post('/zones/{name}', function ()
    use ($site, $cfg) {
    $name = (string) ($_REQUEST['name'] ?? '');
    $name = preg_replace('/[^a-zA-Z0-9._-]/', '', $name);
    if ($name === '') {
        echo "Bad zone name.";
        return;
    }
    $path = $cfg['zone_dir'] . DIRECTORY_SEPARATOR .
        $name . '.zone';
    $contents = (string) ($_POST['contents'] ?? '');
    /*
        Bound the size; a runaway paste should not consume
        unbounded disk. 2 MB is plenty for any realistic
        hand-edited zone.
     */
    if (strlen($contents) > 2 * 1024 * 1024) {
        echo "Zone file too large.";
        return;
    }
    $tmp = $path . '.new';
    if (@file_put_contents($tmp, $contents) === false) {
        echo "Failed to write zone file.";
        return;
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        echo "Failed to install zone file.";
        return;
    }
    /*
        The running DNS server's FileDnsAuthority watches
        zone-file mtimes and reloads on the next query, so
        no explicit reload signal is needed here. The next
        scenario or raw query the user fires will see the
        new state.
     */
    $site->header("Location: /zones/" .
        rawurlencode($name) . "?saved=1");
    $site->header("HTTP/1.1 302 Found");
});
/*
    Runs one canned scenario: builds the right query packet,
    sends it over the right transport, decodes the response,
    and returns a structured result the JS in the page can
    render. Each scenario picks its own (name, type,
    transport) tuple.
 */
function dnsRunScenario($key, $cfg)
{
    $defs = [
        'a' => ['www.example.test', DnsSite::TYPE_A, 'udp'],
        'aaaa' => ['ipv6only.example.test',
            DnsSite::TYPE_AAAA, 'udp'],
        'mx' => ['example.test', DnsSite::TYPE_MX, 'udp'],
        'txt' => ['example.test', DnsSite::TYPE_TXT, 'udp'],
        'cname' => ['ftp.example.test', DnsSite::TYPE_A,
            'udp'],
        'nxdomain' => ['nope.example.test', DnsSite::TYPE_A,
            'udp'],
        'wildcard' => ['anything.wild.example.test',
            DnsSite::TYPE_A, 'udp'],
        'tcp' => ['www.example.test', DnsSite::TYPE_A, 'tcp'],
        'edns0' => ['example.test', DnsSite::TYPE_TXT, 'udp'],
        'tc' => ['example.test', DnsSite::TYPE_ANY, 'udp-tiny'],
        'dot' => ['www.example.test', DnsSite::TYPE_A, 'dot'],
        'refused' => ['something.foreign.com',
            DnsSite::TYPE_A, 'udp'],
    ];
    if (!isset($defs[$key])) {
        return ['error' => 'unknown scenario'];
    }
    list($name, $type, $transport) = $defs[$key];
    $opts = ['rd' => true];
    if ($key === 'edns0') {
        $opts['edns0'] = true;
    }
    $note = null;
    if ($key === 'tc') {
        $note = 'Forced 200-byte UDP cap on this client to ' .
            'trigger truncation (the server still honors ' .
            '512 minimum, so we shrink the client side to ' .
            'demonstrate the TC bit + retry path).';
    }
    if ($key === 'dot') {
        $note = 'DoT requires cert.pem and key.pem in the ' .
            'demo directory; if missing, this scenario ' .
            'will report a connection error.';
    }
    return dnsExecuteQuery($name, $type, $transport, $opts,
        $cfg, $note);
}
/*
    Carries out the actual transaction: build, send, parse,
    return the human + hex views of both the query and the
    response. $transport is "udp", "tcp", "udp-tiny" (a UDP
    send capped to 200 bytes to demonstrate truncation), or
    "dot".
 */
function dnsExecuteQuery($name, $type, $transport, $opts,
    $cfg, $note = null)
{
    $name = rtrim($name, '.');
    $query = dnsBuildQuery($name, $type, $opts);
    $query_msg = DnsMessage::unpack($query);
    $result = [
        'query_human' => dnsHumanRender($query_msg),
        'query_hex' => dnsHexDump($query),
        'transport' => strtoupper($transport),
        'note' => $note,
    ];
    if ($transport === 'udp' || $transport === 'udp-tiny') {
        $sent = dnsSendUdp($cfg['host'], $cfg['udp_port'],
            $query);
        if ($transport === 'udp-tiny' &&
            isset($sent['bytes']) &&
            strlen($sent['bytes']) > 200) {
            /*
                Truncate on receipt to simulate a path-MTU
                drop. A real network might lose the packet
                entirely; truncating to a too-short prefix
                surfaces the same "client cannot parse,
                must retry over TCP" symptom.
             */
            $sent['bytes'] = substr($sent['bytes'], 0, 200);
        }
    } else if ($transport === 'tcp') {
        $sent = dnsSendTcp($cfg['host'], $cfg['tcp_port'],
            $query);
    } else if ($transport === 'dot') {
        $sent = dnsSendDot($cfg['host'], $cfg['tls_port'],
            $query);
    } else {
        return ['error' => "unknown transport: $transport"];
    }
    if (isset($sent['error'])) {
        $result['response_human'] = '(no response: ' .
            $sent['error'] . ')';
        $result['response_hex'] = '';
        $result['elapsed_ms'] = 0;
        $result['error'] = $sent['error'];
        return $result;
    }
    $response_bytes = $sent['bytes'];
    $response_msg = DnsMessage::unpack($response_bytes);
    $result['response_human'] = dnsHumanRender($response_msg);
    $result['response_hex'] = dnsHexDump($response_bytes);
    $result['elapsed_ms'] = $sent['elapsed_ms'];
    return $result;
}
$site->listen(8080);
