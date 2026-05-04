<?php
/**
 * AttoMail demo: webmail front-end for the anonymous mail
 * server in index.php. Acts as a regular IMAP client over
 * loopback (127.0.0.1:1143), authenticating as whichever
 * random local-part the visitor has been assigned via a
 * signed cookie. Read-only by default plus a Burn action
 * that flags-and-expunges every message in the user's
 * INBOX before clearing the cookie.
 *
 * Trust model. The cookie is HMAC-signed so a visitor
 * cannot impersonate someone else's mailbox by typing in a
 * URL or editing a cookie value -- the server only honors
 * cookies it itself signed. The signing key lives in
 * memory only and is regenerated every restart, which
 * matches the "every restart is a clean slate" property
 * of the RAM storage backend. Anyone with the address
 * itself, however, can have mail delivered to it from
 * outside; that is by design (the address is the
 * advertised contact point) and matches every public
 * disposable-mail service.
 *
 * This file is spawned by index.php as a detached child;
 * do not run it directly unless you want to host the UI
 * without the mail server.
 */
require '../../src/WebSite.php';
use seekquarry\atto\WebSite;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$site = new WebSite(".");
/*
    Configuration shared with index.php. The shared password
    is read from the same file index.php writes on startup;
    if the file does not exist (UI started without the
    mail server first) we fall back to a known sentinel,
    which will simply fail IMAP login and surface a clear
    error to the user.
 */
$cfg = [
    'host' => '127.0.0.1',
    'imap' => 1143,
    'domain' => 'anon.test',
];
$shared_pw_file = __DIR__ . '/.shared_password';
$cfg['shared_password'] = is_file($shared_pw_file) ?
    trim((string) file_get_contents($shared_pw_file)) :
    '';
/*
    The HMAC key for cookie signing. Held in memory only;
    every webui.php restart invalidates every existing
    cookie. We do NOT persist this to disk because
    persisting it would let cookies survive a server
    restart and reach a mailbox that no longer exists,
    confusing the user.
 */
$secret_key = random_bytes(32);
/*
    Wordlist for random address generation. Chosen for
    readability and pronounceability when read aloud (the
    user might tell their address to someone). Avoids
    visually-similar pairs (no "il" / "1l") and avoids
    anything that could read as offensive. Two pools and
    a 4-digit suffix gives 60 * 60 * 10000 = 36M slots,
    which is plenty for a demo and for any deployment that
    is not actively gamed.
 */
$adjectives = [
    'quiet', 'happy', 'bright', 'silent', 'gentle', 'curious',
    'brave', 'clever', 'merry', 'tidy', 'noble', 'humble',
    'lively', 'eager', 'kind', 'witty', 'patient', 'mellow',
    'jolly', 'modest', 'polite', 'sturdy', 'snappy', 'cozy',
    'dapper', 'plucky', 'nimble', 'sage', 'tame', 'rapid',
    'spry', 'wise', 'sunny', 'crisp', 'frank', 'genial',
    'vivid', 'bold', 'calm', 'fond', 'glad', 'keen',
    'mild', 'neat', 'pure', 'raw', 'soft', 'true',
    'warm', 'wry', 'fast', 'slow', 'tall', 'short',
    'big', 'small', 'shy', 'proud', 'quick', 'sleek',
];
$nouns = [
    'fox', 'owl', 'hare', 'wren', 'lark', 'finch',
    'otter', 'badger', 'heron', 'crane', 'sparrow', 'thrush',
    'cricket', 'beetle', 'mantis', 'newt', 'frog', 'toad',
    'salmon', 'trout', 'minnow', 'bass', 'perch', 'pike',
    'fern', 'reed', 'oak', 'pine', 'birch', 'maple',
    'rose', 'iris', 'lily', 'daisy', 'poppy', 'thistle',
    'crow', 'raven', 'magpie', 'jay', 'robin', 'swift',
    'lynx', 'mink', 'weasel', 'marmot', 'beaver', 'mole',
    'star', 'moon', 'comet', 'cloud', 'storm', 'frost',
    'river', 'creek', 'pond', 'bay', 'cove', 'glen',
];
/*
    HMAC-signed cookie helpers. Cookie format is
    "<username>.<32-char-hex-truncated-mac>" where the MAC
    is HMAC-SHA256 over the username with $secret_key. We
    truncate to 32 hex chars (128 bits) because that is
    plenty against forgery and keeps the cookie short
    enough to fit comfortably in any User-Agent.
 */
function sign_user($username, $secret_key)
{
    $mac = hash_hmac('sha256', $username, $secret_key);
    return $username . '.' . substr($mac, 0, 32);
}
function verify_user($cookie_value, $secret_key)
{
    if (!is_string($cookie_value)) {
        return false;
    }
    $dot = strrpos($cookie_value, '.');
    if ($dot === false) {
        return false;
    }
    $username = substr($cookie_value, 0, $dot);
    $supplied_mac = substr($cookie_value, $dot + 1);
    $expected = substr(
        hash_hmac('sha256', $username, $secret_key), 0, 32);
    if (!hash_equals($expected, $supplied_mac)) {
        return false;
    }
    /*
        Sanity-check the username: only the local-part
        characters we ever generate (lowercase, digits,
        dash). This prevents a leftover cookie from a
        future code change that allowed something exotic
        from making us send weird IMAP commands.
     */
    if (!preg_match('/^[a-z0-9-]{1,64}$/', $username)) {
        return false;
    }
    return $username;
}
/**
 * Returns the validated username from the request cookie,
 * or false if no valid cookie is present.
 */
function current_user_or_false($secret_key)
{
    if (!isset($_COOKIE['anon_user'])) {
        return false;
    }
    return verify_user($_COOKIE['anon_user'], $secret_key);
}
/**
 * Generates a fresh random local-part of the shape
 * "<adj>-<noun>-<4digits>". Uniqueness is best-effort:
 * collisions are rare (1-in-36M) and the consequence of a
 * collision is just that two visitors share a mailbox,
 * which is exactly what would happen if one of them
 * voluntarily told the other the address. The cookie is
 * still valid; the trust model already permits this.
 */
function generate_address($adjectives, $nouns)
{
    $a = $adjectives[random_int(0, count($adjectives) - 1)];
    $n = $nouns[random_int(0, count($nouns) - 1)];
    $d = sprintf('%04d', random_int(0, 9999));
    return "$a-$n-$d";
}
/**
 * Minimal IMAP client just rich enough to drive our own
 * MailSite. Opens a TCP connection, runs LOGIN/SELECT/
 * FETCH/STORE/EXPUNGE/LOGOUT, and returns parsed message
 * records. Tag generator is a process-monotonic counter
 * so simultaneous in-flight commands cannot collide on
 * tag (we serialize them anyway, but defensive numbering
 * is cheap). Any I/O failure throws RuntimeException so
 * route handlers can render a clean error page.
 */
class ImapClient
{
    protected $socket;
    protected $tag_counter = 0;
    protected $buffer = '';
    public function __construct($host, $port, $timeout = 5)
    {
        $errno = 0;
        $errstr = '';
        $this->socket = @stream_socket_client(
            "tcp://$host:$port", $errno, $errstr, $timeout);
        if (!$this->socket) {
            throw new RuntimeException(
                "IMAP connect failed: $errstr");
        }
        stream_set_timeout($this->socket, $timeout);
        /*
            Drain the server greeting; we do not parse it
            beyond confirming it arrived.
         */
        $greeting = $this->readLine();
        if (substr($greeting, 0, 4) !== '* OK') {
            throw new RuntimeException(
                "Unexpected greeting: $greeting");
        }
    }
    public function __destruct()
    {
        if (is_resource($this->socket)) {
            @fclose($this->socket);
        }
    }
    /**
     * Reads exactly one CRLF-terminated line. Throws if
     * the socket dies mid-line (read returns false / "").
     */
    protected function readLine()
    {
        while (strpos($this->buffer, "\r\n") === false) {
            $chunk = @fread($this->socket, 4096);
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException(
                    "IMAP read failed mid-line");
            }
            $this->buffer .= $chunk;
        }
        $end = strpos($this->buffer, "\r\n");
        $line = substr($this->buffer, 0, $end);
        $this->buffer = substr($this->buffer, $end + 2);
        return $line;
    }
    /**
     * Reads the next $n bytes from the buffer / socket.
     * Used for IMAP literal {N} payloads.
     */
    protected function readBytes($n)
    {
        while (strlen($this->buffer) < $n) {
            $chunk = @fread($this->socket, 4096);
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException(
                    "IMAP read failed mid-literal");
            }
            $this->buffer .= $chunk;
        }
        $payload = substr($this->buffer, 0, $n);
        $this->buffer = substr($this->buffer, $n);
        return $payload;
    }
    /**
     * Sends a tagged command and accumulates every line
     * the server emits until the matching tagged response
     * arrives. Returns ['status' => 'OK'|'NO'|'BAD',
     * 'detail' => string, 'untagged' => array of lines,
     * 'literals' => array of literal payloads keyed by the
     * line index they were attached to].
     */
    public function send($command_text)
    {
        $tag = 'X' . (++$this->tag_counter);
        $line = "$tag $command_text\r\n";
        if (@fwrite($this->socket, $line) === false) {
            throw new RuntimeException(
                "IMAP write failed");
        }
        $untagged = [];
        $literals = [];
        while (true) {
            $line = $this->readLine();
            /*
                If the line ends with "{N}" it announces a
                literal payload of N bytes that follows
                immediately, then the rest of the line as
                a fresh logical continuation. We swallow
                the literal into $literals keyed by the
                untagged-line index, then keep reading.
             */
            if (preg_match('/\{(\d+)\}$/', $line, $m)) {
                $payload = $this->readBytes((int) $m[1]);
                $idx = count($untagged);
                $literals[$idx] = $payload;
                /*
                    The server's next read may include the
                    rest of this logical line as a new
                    physical line (atto's framing puts the
                    literal "right after the close brace
                    on the wire" with no extra CRLF). We
                    treat the announced line as the start
                    and read whatever comes next as a
                    continuation/closing.
                 */
                $continuation = $this->readLine();
                $untagged[] = $line . $payload . $continuation;
                continue;
            }
            if (substr($line, 0, strlen($tag) + 1) ===
                "$tag ") {
                $rest = substr($line, strlen($tag) + 1);
                $space = strpos($rest, ' ');
                if ($space === false) {
                    return ['status' => $rest, 'detail' => '',
                        'untagged' => $untagged,
                        'literals' => $literals];
                }
                return ['status' => substr($rest, 0, $space),
                    'detail' => substr($rest, $space + 1),
                    'untagged' => $untagged,
                    'literals' => $literals];
            }
            $untagged[] = $line;
        }
    }
}
/**
 * Connects, logs in as $username with the shared
 * password, and returns the open client. Throws on any
 * failure so callers can render an error page.
 */
function imap_connect_for($username, $cfg)
{
    $client = new ImapClient($cfg['host'], $cfg['imap']);
    $login_result = $client->send(
        'LOGIN ' . $username . ' ' . $cfg['shared_password']);
    if ($login_result['status'] !== 'OK') {
        throw new RuntimeException("IMAP LOGIN refused: " .
            $login_result['detail']);
    }
    return $client;
}
/**
 * Returns the parsed inbox listing as a list of records:
 * [['uid'=>int, 'size'=>int, 'date'=>int, 'flags'=>array,
 *   'from'=>string, 'subject'=>string], ...] sorted
 * descending by UID (newest first).
 *
 * Uses FETCH 1:* (UID INTERNALDATE FLAGS RFC822.SIZE
 * BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]). PEEK so we
 * do not mark messages \Seen by listing them.
 */
function inbox_listing($client)
{
    $select_result = $client->send('SELECT INBOX');
    if ($select_result['status'] !== 'OK') {
        throw new RuntimeException("SELECT INBOX failed");
    }
    /*
        Empty mailbox? SELECT will have shown "* 0 EXISTS"
        in the untagged lines. Avoid an invalid 1:* fetch
        on zero messages by short-circuiting.
     */
    $exists = 0;
    foreach ($select_result['untagged'] as $line) {
        if (preg_match('/^\* (\d+) EXISTS$/', $line, $m)) {
            $exists = (int) $m[1];
            break;
        }
    }
    if ($exists === 0) {
        return [];
    }
    $fetch_result = $client->send(
        'FETCH 1:* (UID INTERNALDATE FLAGS RFC822.SIZE ' .
        'BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])');
    if ($fetch_result['status'] !== 'OK') {
        throw new RuntimeException("FETCH listing failed");
    }
    $rows = [];
    foreach ($fetch_result['untagged'] as $line) {
        if (substr($line, 0, 2) !== '* ') {
            continue;
        }
        if (strpos($line, ' FETCH (') === false) {
            continue;
        }
        $row = parse_fetch_listing_line($line);
        if ($row !== null) {
            $rows[] = $row;
        }
    }
    /*
        Sort newest-first so the inbox view shows the most
        recent message at the top.
     */
    usort($rows, function ($a, $b) {
        return $b['uid'] - $a['uid'];
    });
    return $rows;
}
/**
 * Parses one untagged FETCH response line of the shape
 *      * <seq> FETCH (UID 7 INTERNALDATE "..." FLAGS (...)
 *      RFC822.SIZE 1234 BODY[HEADER.FIELDS (FROM SUBJECT)]
 *      <header bytes>)
 * Returns the parsed record or null if anything looks
 * malformed.
 */
function parse_fetch_listing_line($line)
{
    $row = [
        'uid' => 0, 'size' => 0, 'date' => 0,
        'flags' => [], 'from' => '', 'subject' => '',
    ];
    if (preg_match('/UID (\d+)/', $line, $m)) {
        $row['uid'] = (int) $m[1];
    }
    if (preg_match('/INTERNALDATE "([^"]+)"/', $line, $m)) {
        $ts = strtotime($m[1]);
        $row['date'] = $ts === false ? 0 : $ts;
    }
    if (preg_match('/FLAGS \(([^)]*)\)/', $line, $m)) {
        $flags = preg_split('/\s+/', trim($m[1]));
        $row['flags'] = array_filter($flags,
            function ($f) { return $f !== ''; });
    }
    if (preg_match('/RFC822\.SIZE (\d+)/', $line, $m)) {
        $row['size'] = (int) $m[1];
    }
    /*
        The header block is delivered after the literal
        marker; our reader has already inlined the
        payload into $line. Parse the From: and Subject:
        out of whatever followed the marker.
     */
    if (preg_match('/From:\s*([^\r\n]+)/i', $line, $m)) {
        $row['from'] = trim($m[1]);
    }
    if (preg_match('/Subject:\s*([^\r\n]+)/i', $line, $m)) {
        $row['subject'] = trim($m[1]);
    }
    if ($row['uid'] === 0) {
        return null;
    }
    return $row;
}
/**
 * Fetches one full message (RFC 822) by UID. Returns the
 * raw bytes or false if not found. Uses UID FETCH so the
 * caller does not have to translate UID -> sequence.
 */
function fetch_message_bytes($client, $uid)
{
    $uid = (int) $uid;
    if ($uid < 1) {
        return false;
    }
    $select_result = $client->send('SELECT INBOX');
    if ($select_result['status'] !== 'OK') {
        return false;
    }
    $fetch_result = $client->send("UID FETCH $uid (RFC822)");
    if ($fetch_result['status'] !== 'OK') {
        return false;
    }
    /*
        The message bytes were captured into $literals
        when our reader saw the {N} announcement. There
        will be exactly one literal for a successful fetch
        of one message; pick the first.
     */
    if (empty($fetch_result['literals'])) {
        return false;
    }
    foreach ($fetch_result['literals'] as $payload) {
        return $payload;
    }
    return false;
}
/**
 * Marks every message in INBOX as \Deleted and expunges.
 * Used by the Burn handler. Returns the count expunged.
 */
function purge_inbox($client)
{
    $select_result = $client->send('SELECT INBOX');
    if ($select_result['status'] !== 'OK') {
        return 0;
    }
    $exists = 0;
    foreach ($select_result['untagged'] as $line) {
        if (preg_match('/^\* (\d+) EXISTS$/', $line, $m)) {
            $exists = (int) $m[1];
            break;
        }
    }
    if ($exists === 0) {
        return 0;
    }
    $client->send('STORE 1:* +FLAGS (\\Deleted)');
    $client->send('EXPUNGE');
    return $exists;
}
/**
 * Splits raw RFC 822 bytes at the header/body boundary
 * (first blank line). Returns ['headers'=>string,
 * 'body'=>string]. Handles both CRLF and bare-LF
 * terminators because mail in the wild is messy.
 */
function split_message($bytes)
{
    $boundary = strpos($bytes, "\r\n\r\n");
    $bsize = 4;
    if ($boundary === false) {
        $boundary = strpos($bytes, "\n\n");
        $bsize = 2;
    }
    if ($boundary === false) {
        return ['headers' => $bytes, 'body' => ''];
    }
    return [
        'headers' => substr($bytes, 0, $boundary),
        'body' => substr($bytes, $boundary + $bsize),
    ];
}
/**
 * Extracts a named header value (case-insensitive). Joins
 * folded continuation lines into a single string.
 */
function header_value($header_block, $name)
{
    $name_lower = strtolower($name);
    $lines = preg_split('/\r\n|\n/', $header_block);
    $output = '';
    $capturing = false;
    foreach ($lines as $line) {
        if ($capturing &&
            ($line === '' ||
             ($line[0] !== ' ' && $line[0] !== "\t"))) {
            return $output;
        }
        if ($capturing) {
            $output .= ' ' . trim($line);
            continue;
        }
        $colon = strpos($line, ':');
        if ($colon === false) {
            continue;
        }
        if (strtolower(substr($line, 0, $colon)) ===
            $name_lower) {
            $output = trim(substr($line, $colon + 1));
            $capturing = true;
        }
    }
    return $output;
}
/*
    HTML helpers. h() escapes with a single sensible default
    (UTF-8, double-encode disabled so we can safely re-render
    user-controlled strings already containing entities).
 */
function h($s)
{
    return htmlspecialchars((string) $s,
        ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', false);
}
function header_layout($title)
{
    $t = h($title);
    return <<<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>$t</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/style.css">
</head><body>
<div class="page">
HTML;
}
function footer_layout()
{
    return <<<HTML
<footer><small>AttoMail anonymous demo. Inboxes evaporate
when the server restarts.</small></footer>
</div></body></html>
HTML;
}
/*
    Routes.
 */
$site->get('/style.css', function () use ($site) {
    $site->header('Content-Type: text/css; charset=utf-8');
    /*
        Minimal stylesheet -- keeps the demo readable on
        mobile and desktop without pulling in a framework.
     */
    echo <<<CSS
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, sans-serif;
       background: #fafaf7; color: #222; }
.page { max-width: 760px; margin: 0 auto; padding: 1.5rem; }
header h1 { margin-top: 0; }
.address-box { background: #fffbe5; border: 1px solid #d8c97e;
               padding: 1rem 1.2rem; border-radius: 6px;
               font-size: 1.15rem; }
.address-box code { font-size: 1.25rem; font-weight: 600;
                    user-select: all; }
nav { margin: 1rem 0; }
nav a { margin-right: 1rem; }
table { border-collapse: collapse; width: 100%;
        background: #fff; }
th, td { padding: 0.5rem 0.75rem; text-align: left;
         border-bottom: 1px solid #eee; vertical-align: top; }
th { background: #f1f0eb; font-size: 0.9rem; }
tr.unread td { font-weight: 600; }
tr:hover td { background: #faf8ee; }
.empty { padding: 2rem; text-align: center; color: #777; }
pre { background: #fff; border: 1px solid #ddd;
      padding: 1rem; border-radius: 4px; overflow: auto;
      white-space: pre-wrap; word-wrap: break-word; }
form.burn { display: inline; }
form.burn button { background: #b1411a; color: #fff;
                   border: 0; padding: 0.5rem 1rem;
                   border-radius: 4px; cursor: pointer; }
form.burn button:hover { background: #8a3414; }
.banner { background: #ffe; border-left: 4px solid #c93;
          padding: 0.75rem 1rem; margin: 1rem 0;
          font-size: 0.9rem; }
details { margin: 1.5rem 0; padding: 0.75rem 1rem;
          background: #fff; border: 1px solid #ddd;
          border-radius: 4px; }
details summary { cursor: pointer; font-weight: 600;
                  color: #336; padding: 0.25rem 0; }
details[open] summary { margin-bottom: 0.75rem;
                        border-bottom: 1px solid #eee; }
details p { margin: 0.5rem 0; line-height: 1.45; }
details code { background: #f1f0eb; padding: 0.05rem 0.3rem;
               border-radius: 3px; font-size: 0.95em; }
details pre { font-size: 0.85rem; }
footer { margin-top: 3rem; color: #888; }
.error { background: #fbe; border: 1px solid #c97;
         padding: 1rem; border-radius: 4px;
         color: #842; }
CSS;
});
$site->get('/', function () use (
    $site, $secret_key, $cfg, $adjectives, $nouns
) {
    $username = current_user_or_false($secret_key);
    if ($username === false) {
        /*
            New visitor. Pick a fresh random address, set
            the cookie, and land on the welcome page.
         */
        $username = generate_address($adjectives, $nouns);
        $cookie_value = sign_user($username, $secret_key);
        /*
            atto's CLI server does not surface PHP's native
            setcookie() output to the wire; we have to use
            the WebSite helper which knows how to emit the
            Set-Cookie header through atto's response
            buffer. Same applies to header() below.
         */
        $site->setCookie('anon_user', $cookie_value, 0,
            '/', '', false, true);
    }
    $address = $username . '@' . $cfg['domain'];
    echo header_layout('Anonymous Inbox');
    echo "<header><h1>Your anonymous inbox</h1></header>\n";
    echo "<div class=\"address-box\">Mail sent to " .
        "<code>" . h($address) . "</code> arrives in your " .
        "inbox below. Use this address anywhere you would " .
        "rather not give out a real email -- one-time " .
        "signups, demo accounts, registration confirmations " .
        "you only need once.</div>\n";
    echo "<nav><a href=\"/inbox\">Open inbox &rarr;</a> " .
        "<form class=\"burn\" method=\"post\" " .
        "action=\"/burn\"><button>Burn this address" .
        "</button></form></nav>\n";
    echo "<div class=\"banner\">This server holds messages " .
        "in memory only. They disappear when the server " .
        "restarts. Do not use for anything you need " .
        "later.</div>\n";
    /*
        How-to-test block: a copy-pasteable nc/telnet
        session that delivers a message to the assigned
        address. Useful both for users smoke-testing the
        demo and for anyone reading the example to see how
        the SMTP wire protocol looks. Wrapped in a
        <details> so non-technical visitors are not
        confronted with raw SMTP on the welcome screen.
     */
    $smtp_host = '127.0.0.1';
    $smtp_port = 2525;
    /*
        Build the SMTP transaction as a single-line printf
        invocation rather than a multi-line nc pipeline.
        Two reasons. First, multi-line shell commands with
        literal CR bytes survive a copy-paste round-trip
        as broken text in many terminals; users in tcsh
        and zsh see the {} brace group execute line-by-line
        with CR-laden input which breaks parsing. Second, a
        single-line form works identically across sh, bash,
        zsh, fish, and tcsh; brace groups do not.

        We escape the angle-brackets and quotes for HTML
        once via h(); the actual \r\n escape sequences
        below are LITERAL backslash-r-backslash-n in the
        rendered output, NOT real CR/LF bytes. printf
        interprets them at run time. This is what makes
        the line copy-paste safe.
     */
    $cmd =
        "printf '" .
        'EHLO test\r\n' .
        "MAIL FROM:<friend@example.com>" . '\r\n' .
        "RCPT TO:<" . $address . ">" . '\r\n' .
        'DATA\r\n' .
        "From: friend@example.com" . '\r\n' .
        "Subject: hello there" . '\r\n' .
        '\r\n' .
        "Just testing this disposable inbox." . '\r\n' .
        '.\r\n' .
        'QUIT\r\n' .
        "' | nc $smtp_host $smtp_port";
    echo "<details>\n";
    echo "<summary>How do I send a test message to this " .
        "address?</summary>\n";
    echo "<p>Paste this into a terminal:</p>\n";
    echo "<pre>" . h($cmd) . "</pre>\n";
    echo "<p>The whole transaction is one line so it " .
        "survives a copy-paste round-trip and works the " .
        "same in sh, bash, zsh, fish, and tcsh. " .
        "<code>printf</code> interprets the " .
        "<code>\\r\\n</code> escapes as CRLF bytes when " .
        "the command runs, which is the line ending SMTP " .
        "requires. After the " .
        "<code>250 2.0.0 Ok: message accepted</code> " .
        "response, refresh your inbox to see it arrive.</p>\n";
    echo "<p>From a real mail client, point the SMTP " .
        "submission settings at <code>$smtp_host:" .
        "$smtp_port</code> with no authentication and no " .
        "TLS, and send to <code>" . h($address) . "</code>. " .
        "Authentication is not required because <code>" .
        h($cfg['domain']) . "</code> is configured as a " .
        "local domain on this server.</p>\n";
    echo "</details>\n";
    echo footer_layout();
});
$site->get('/inbox', function () use (
    $site, $secret_key, $cfg
) {
    $username = current_user_or_false($secret_key);
    if ($username === false) {
        $site->header('Location: /');
        return;
    }
    $address = $username . '@' . $cfg['domain'];
    echo header_layout("Inbox: $address");
    /*
        Auto-refresh the inbox listing every 5 seconds so
        the user does not have to manually reload to see a
        newly-delivered message. Five seconds keeps the
        round-trip cost on the server low (one IMAP
        connect per visible client per 5s) while feeling
        responsive enough.
     */
    echo "<meta http-equiv=\"refresh\" content=\"5\">\n";
    echo "<header><h1>Inbox</h1>\n";
    echo "<p><code>" . h($address) . "</code> &middot; " .
        "<a href=\"/\">home</a></p></header>\n";
    try {
        $client = imap_connect_for($username, $cfg);
        $rows = inbox_listing($client);
    } catch (RuntimeException $e) {
        echo "<div class=\"error\">Could not reach mail " .
            "server: " . h($e->getMessage()) . "</div>\n";
        echo footer_layout();
        return;
    }
    if (empty($rows)) {
        echo "<div class=\"empty\">No mail yet. Send some " .
            "to <code>" . h($address) . "</code> to test " .
            "delivery.</div>\n";
    } else {
        echo "<table>\n<tr><th>From</th><th>Subject</th>" .
            "<th>When</th></tr>\n";
        foreach ($rows as $row) {
            $unread = !in_array('\\Seen', $row['flags']) ?
                ' class="unread"' : '';
            echo "<tr$unread><td>" . h($row['from']) .
                "</td><td><a href=\"/msg/" .
                (int) $row['uid'] . "\">" .
                h($row['subject'] !== '' ?
                    $row['subject'] : '(no subject)') .
                "</a></td><td>" .
                ($row['date'] > 0 ?
                    h(date('Y-m-d H:i', $row['date'])) :
                    '') .
                "</td></tr>\n";
        }
        echo "</table>\n";
    }
    echo "<nav><form class=\"burn\" method=\"post\" " .
        "action=\"/burn\"><button>Burn this address" .
        "</button></form></nav>\n";
    echo footer_layout();
});
$site->get('/msg/{uid}', function () use (
    $site, $secret_key, $cfg
) {
    $username = current_user_or_false($secret_key);
    if ($username === false) {
        $site->header('Location: /');
        return;
    }
    /*
        atto's router places named route placeholders (e.g.
        the {uid} in /msg/{uid}) into $_GET and $_REQUEST
        rather than passing them as closure arguments. Pull
        the uid out of $_GET; cast and validate so a
        request like /msg/abc surfaces a 404 cleanly rather
        than throwing on the IMAP UID FETCH.
     */
    $uid = isset($_GET['uid']) ? (int) $_GET['uid'] : 0;
    if ($uid < 1) {
        $site->header('HTTP/1.1 404 Not Found');
        echo header_layout('Not found');
        echo "<header><h1>Message not found</h1></header>\n";
        echo "<p><a href=\"/inbox\">Back to inbox</a></p>\n";
        echo footer_layout();
        return;
    }
    try {
        $client = imap_connect_for($username, $cfg);
        $bytes = fetch_message_bytes($client, $uid);
    } catch (RuntimeException $e) {
        echo header_layout('Message error');
        echo "<div class=\"error\">Could not load message: " .
            h($e->getMessage()) . "</div>\n";
        echo footer_layout();
        return;
    }
    if ($bytes === false) {
        $site->header('HTTP/1.1 404 Not Found');
        echo header_layout('Not found');
        echo "<header><h1>Message not found</h1></header>\n";
        echo "<p><a href=\"/inbox\">Back to inbox</a></p>\n";
        echo footer_layout();
        return;
    }
    $parts = split_message($bytes);
    $from = header_value($parts['headers'], 'From');
    $to = header_value($parts['headers'], 'To');
    $subject = header_value($parts['headers'], 'Subject');
    $date = header_value($parts['headers'], 'Date');
    echo header_layout('Message: ' .
        ($subject !== '' ? $subject : '(no subject)'));
    echo "<header><h1>" .
        h($subject !== '' ? $subject : '(no subject)') .
        "</h1></header>\n";
    echo "<div class=\"banner\">The From: header below is " .
        "claimed by the sender and is not verified. " .
        "Anonymous mail is by definition unauthenticated; " .
        "treat sender identity as unconfirmed.</div>\n";
    echo "<table>\n";
    echo "<tr><th>From</th><td>" . h($from) . "</td></tr>\n";
    echo "<tr><th>To</th><td>" . h($to) . "</td></tr>\n";
    echo "<tr><th>Date</th><td>" . h($date) . "</td></tr>\n";
    echo "</table>\n";
    echo "<h2>Body</h2>\n";
    echo "<pre>" . h($parts['body']) . "</pre>\n";
    echo "<nav><a href=\"/inbox\">&larr; Back to inbox</a>" .
        "</nav>\n";
    echo footer_layout();
});
$site->post('/burn', function () use ($site, $secret_key, $cfg) {
    $username = current_user_or_false($secret_key);
    if ($username !== false) {
        try {
            $client = imap_connect_for($username, $cfg);
            purge_inbox($client);
        } catch (RuntimeException $e) {
            /*
                Best-effort purge: if the IMAP loopback
                is down we still clear the cookie so the
                user gets a fresh address on next visit.
             */
        }
    }
    $site->setCookie('anon_user', '', time() - 3600, '/');
    $site->header('Location: /');
});
$site->error('default', function () use ($site) {
    $site->header('HTTP/1.1 404 Not Found');
    echo header_layout('Not found');
    echo "<header><h1>Not found</h1></header>\n";
    echo "<p><a href=\"/\">Home</a></p>\n";
    echo footer_layout();
});
$site->listen(8080);
