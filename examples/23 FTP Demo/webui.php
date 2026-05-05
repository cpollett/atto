<?php
/**
 * AttoFTP demo: web UI for the FTP server in index.php.
 * Three tabs:
 *
 *   - Scenarios: scripted tour of common FTP transactions
 *     (anonymous browse, named-user upload, MLSD, REST,
 *     rename, security probes, FTPS upgrade) -- each
 *     scenario opens a real control connection to the
 *     running FTP server and renders the wire transcript.
 *   - Raw command box: pick credentials, type any sequence
 *     of FTP commands, see the responses. Maintains state
 *     across submissions by stashing the FTP session id in
 *     a hidden field.
 *   - File browser: drives the FTP server via real LIST /
 *     RETR / STOR / DELE / RNFR+RNTO / MKD / RMD commands,
 *     so what you see is exactly what Filezilla would see.
 *
 * The webui never touches the filesystem directly; every
 * operation goes over the FTP wire to the server in the
 * sibling process. That is the whole point of the demo --
 * the "browser" tab is really just an FTP client wearing
 * an HTTP costume.
 *
 * Do not launch this file directly; it runs as a detached
 * child of index.php.
 */
require '../../src/WebSite.php';
use seekquarry\atto\WebSite;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$site = new WebSite(".");
$cfg = [
    'host' => '127.0.0.1',
    'port' => 12121,
    'tls_port' => 19990,
    'root_dir' => __DIR__ . DIRECTORY_SEPARATOR . 'root',
    'original_root_dir' => __DIR__ . DIRECTORY_SEPARATOR .
        'original-root',
    'demo_users' => [
        ['user' => 'anonymous', 'pass' => 'guest@example.com',
            'label' => 'Anonymous (read-only, /pub)'],
        ['user' => 'alice', 'pass' => 'hunter2',
            'label' => 'alice (rw, /users/alice)'],
        ['user' => 'bob', 'pass' => 'sekret',
            'label' => 'bob (rw, /users/bob)'],
    ],
];
/*
    --- FTP client primitives ---
    A small set of helpers that open a control connection,
    send commands, read replies, and run a passive-mode data
    transfer. The webui composes these into scenarios and
    file-browser actions; the protocol layer is exercised
    end-to-end on a real socket every time.
 */

/*
    Reads one FTP reply from the control socket. A reply may
    span multiple lines: the multi-line form opens with
    "code-..." and closes with the same code followed by a
    space. Returns the list of lines as received.
 */
function ftpReadReply($sock)
{
    $lines = [];
    while (($line = fgets($sock, 8192)) !== false) {
        $lines[] = rtrim($line, "\r\n");
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }
    return $lines;
}
/*
    Sends one command line and reads the next reply. Records
    both into the supplied transcript so the webui can
    render the conversation.
 */
function ftpSendCmd($sock, $cmd, &$transcript)
{
    @fwrite($sock, $cmd . "\r\n");
    $transcript[] = ['dir' => '>', 'lines' => [$cmd]];
    $reply = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $reply];
    return $reply;
}
/*
    Sends multiple commands in sequence. Returns the
    transcript so the webui can render it. The session is
    closed at the end with QUIT (whether or not the caller
    listed it).
 */
function ftpScript($host, $port, $commands)
{
    $transcript = [];
    $sock = @stream_socket_client("tcp://$host:$port",
        $errno, $errstr, 5);
    if (!$sock) {
        $transcript[] = ['dir' => '!',
            'lines' => ["connect failed: $errstr"]];
        return $transcript;
    }
    stream_set_timeout($sock, 5);
    $banner = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $banner];
    foreach ($commands as $cmd) {
        ftpSendCmd($sock, $cmd, $transcript);
    }
    /*
        Always end with QUIT so the server-side connection
        gets a clean shutdown rather than an idle-timeout
        reap. If the caller already sent QUIT, the second
        one will get a "connection closed" reply or just
        EOF, which we tolerate.
     */
    $last = end($transcript);
    $is_quit_done = false;
    if ($last['dir'] === '>' &&
        strtoupper(trim($last['lines'][0])) === 'QUIT') {
        $is_quit_done = true;
    }
    if (!$is_quit_done) {
        @fwrite($sock, "QUIT\r\n");
        $transcript[] = ['dir' => '>', 'lines' => ['QUIT']];
        $reply = @ftpReadReply($sock);
        if (!empty($reply)) {
            $transcript[] = ['dir' => '<', 'lines' => $reply];
        }
    }
    @fclose($sock);
    return $transcript;
}
/*
    Parses a 227 PASV reply line, returning [host, port] or
    false if the line cannot be parsed.
 */
function ftpParsePasv($line)
{
    if (!preg_match('/\((\d+,\d+,\d+,\d+,\d+,\d+)\)/',
        $line, $m)) {
        return false;
    }
    $parts = explode(',', $m[1]);
    return [
        $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.' .
            $parts[3],
        ((int) $parts[4]) * 256 + (int) $parts[5],
    ];
}
/*
    Runs a passive-mode data transfer: PASV on the control
    channel, open the data socket, send the data command,
    read the 150 open reply, transfer bytes, close, read the
    226 done reply. Direction is 'download' (we read from
    the data socket) or 'upload' (we write upload_body and
    close). Returns ['transcript' => ..., 'body' => ...].
    The transcript captures the control-channel exchange
    only; the data-channel content is in 'body'.
 */
function ftpPasvTransfer($sock, $cmd, $direction,
    &$transcript, $upload_body = '')
{
    $reply = ftpSendCmd($sock, 'PASV', $transcript);
    $addr = false;
    foreach ($reply as $line) {
        $maybe = ftpParsePasv($line);
        if ($maybe !== false) {
            $addr = $maybe;
            break;
        }
    }
    if ($addr === false) {
        return ['body' => '',
            'note' => 'PASV reply not parseable'];
    }
    list($h, $p) = $addr;
    @fwrite($sock, $cmd . "\r\n");
    $transcript[] = ['dir' => '>', 'lines' => [$cmd]];
    $data = @stream_socket_client("tcp://$h:$p",
        $errno, $errstr, 5);
    $open = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $open];
    if (!$data) {
        return ['body' => '',
            'note' => "data connect failed: $errstr"];
    }
    stream_set_timeout($data, 5);
    $body = '';
    if ($direction === 'upload') {
        @fwrite($data, $upload_body);
    } else {
        $body = (string) stream_get_contents($data);
    }
    @fclose($data);
    $done = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $done];
    return ['body' => $body, 'note' => null];
}
/*
    EPSV variant of ftpPasvTransfer. Sends EPSV instead of
    PASV, parses the (|||port|) reply to get the data port,
    then dials whatever host the control connection arrived
    on. The dial address is family-correct automatically:
    stream_socket_get_name returns "[::1]:port" for v6 peers
    and "127.0.0.1:port" for v4, so we just splice the new
    data port onto the host part. This is exactly the
    behavior real FTP clients use over EPSV -- the server's
    omitting the address from the reply is what makes EPSV
    dual-stack-clean.
 */
function ftpEpsvTransfer($sock, $cmd, $direction,
    &$transcript, $upload_body = '')
{
    $reply = ftpSendCmd($sock, 'EPSV', $transcript);
    $port = 0;
    foreach ($reply as $line) {
        if (preg_match('/\(\|\|\|(\d+)\|\)/', $line, $m)) {
            $port = (int) $m[1];
            break;
        }
    }
    if ($port === 0) {
        return ['body' => '',
            'note' => 'EPSV reply not parseable'];
    }
    /*
        Splice the EPSV-supplied port onto the control's
        remote address. The remote name from the server's
        side of the control socket is "host:port" (or
        "[host]:port" for v6) -- we rebuild it with the new
        port so the dial uses the correct family.
     */
    $remote = stream_socket_get_name($sock, true);
    $colon = strrpos($remote, ':');
    $host_part = substr($remote, 0, $colon);
    $addr = "tcp://$host_part:$port";
    @fwrite($sock, $cmd . "\r\n");
    $transcript[] = ['dir' => '>', 'lines' => [$cmd]];
    $data = @stream_socket_client($addr,
        $errno, $errstr, 5);
    $open = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $open];
    if (!$data) {
        return ['body' => '',
            'note' => "data connect failed: $errstr"];
    }
    stream_set_timeout($data, 5);
    $body = '';
    if ($direction === 'upload') {
        @fwrite($data, $upload_body);
    } else {
        $body = (string) stream_get_contents($data);
    }
    @fclose($data);
    $done = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $done];
    return ['body' => $body, 'note' => null];
}
/*
    Convenience: open a connection, log in as the given
    user, run a callback that returns a list of further
    commands (or executes its own transfers), and close.
    Returns the transcript and any extra payload the
    callback recorded under 'body'.
 */
function ftpSession($host, $port, $user, $pass, $body_fn)
{
    $transcript = [];
    $sock = @stream_socket_client("tcp://$host:$port",
        $errno, $errstr, 5);
    if (!$sock) {
        $transcript[] = ['dir' => '!',
            'lines' => ["connect failed: $errstr"]];
        return ['transcript' => $transcript, 'body' => ''];
    }
    stream_set_timeout($sock, 5);
    $banner = ftpReadReply($sock);
    $transcript[] = ['dir' => '<', 'lines' => $banner];
    ftpSendCmd($sock, "USER $user", $transcript);
    ftpSendCmd($sock, "PASS $pass", $transcript);
    $body = '';
    $skip_quit = false;
    if (is_callable($body_fn)) {
        $extra = $body_fn($sock, $transcript);
        if (is_array($extra) && isset($extra['body'])) {
            $body = $extra['body'];
        }
        if (is_array($extra) && !empty($extra['no_quit'])) {
            $skip_quit = true;
        }
    }
    if (!$skip_quit) {
        @fwrite($sock, "QUIT\r\n");
        $transcript[] = ['dir' => '>', 'lines' => ['QUIT']];
        $reply = @ftpReadReply($sock);
        if (!empty($reply)) {
            $transcript[] = ['dir' => '<',
                'lines' => $reply];
        }
    }
    @fclose($sock);
    return ['transcript' => $transcript, 'body' => $body];
}
/*
    Renders an FTP transcript as the dig-style two-column
    block the demo uses. Each entry has a one-character
    direction indicator (">" client, "<" server, "!" error)
    and one or more text lines. Output is plain text wrapped
    in <pre> by the page template.
 */
function ftpRenderTranscript($transcript)
{
    $out = '';
    foreach ($transcript as $entry) {
        $arrow = $entry['dir'];
        foreach ($entry['lines'] as $line) {
            $out .= $arrow . ' ' . $line . "\n";
        }
    }
    return $out;
}
/*
    --- HTTP routing ---
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
.scenario .body-pane { display: none; margin-top: 0.5em;
    background: #fff; padding: 0.8em; border-radius: 4px;
    border: 1px solid #ddd; font-size: 0.85em;
    font-family: ui-monospace, SFMono-Regular, Menlo,
    monospace; white-space: pre-wrap; max-height: 200px;
    overflow: auto; }
.scenario .body-pane.visible { display: block; }
.scenario .body-pane .hint { display: block;
    font-family: -apple-system, BlinkMacSystemFont,
    sans-serif; font-size: 0.85em; color: #666;
    margin-bottom: 0.4em; }
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
form.raw textarea { font: inherit; font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; font-size: 0.9em;
    padding: 0.5em; border: 1px solid #bbb;
    border-radius: 3px; width: 100%; min-height: 7em;
    line-height: 1.4; }
form.raw button { font: inherit; padding: 0.4em 1em;
    background: #06c; color: white; border: 0;
    border-radius: 4px; cursor: pointer;
    margin-top: 0.5em; }
form.raw button:hover { background: #0050a0; }
#rawResult { margin-top: 0.7em; }
.user-pick { background: #ecf3ff; border: 1px solid #b8c8e8;
    padding: 0.7em 0.9em; border-radius: 4px;
    margin-bottom: 1em; }
.user-pick label { font-size: 0.85em; color: #555;
    margin-right: 0.4em; }
.user-pick select { font: inherit; padding: 0.3em 0.5em;
    border: 1px solid #b8c8e8; border-radius: 4px;
    background: #fff; }
.browser { background: #f6f6f6; padding: 0.9em;
    border-radius: 4px; margin: 0.6em 0; }
.browser .crumb { font-family: ui-monospace,
    SFMono-Regular, Menlo, monospace; font-size: 0.9em;
    padding: 0.4em 0.6em; background: #fff;
    border: 1px solid #ddd; border-radius: 3px;
    margin-bottom: 0.6em; }
.browser table { width: 100%; border-collapse: collapse;
    background: #fff; border: 1px solid #ddd;
    border-radius: 3px; }
.browser th, .browser td { text-align: left;
    padding: 0.35em 0.6em; border-bottom: 1px solid #eee;
    font-size: 0.92em; }
.browser th { background: #f4f4f4; font-weight: 600;
    font-size: 0.85em; }
.browser tr:hover { background: #fafafa; }
.browser a { color: #06c; text-decoration: none; }
.browser a:hover { text-decoration: underline; }
.browser .actions { display: flex; gap: 0.3em;
    flex-wrap: wrap; }
.browser .actions form { display: inline; margin: 0; }
.browser .actions button { font: inherit;
    padding: 0.15em 0.6em; background: #fff;
    color: #444; border: 1px solid #bbb; border-radius: 3px;
    cursor: pointer; font-size: 0.85em; }
.browser .actions button:hover { background: #eef; }
.browser .actions button.danger { color: #b33;
    border-color: #f0c0c0; }
.browser .actions button.danger:hover { background: #fee; }
.upload-form { margin-top: 0.8em; padding: 0.7em;
    background: #fff; border: 1px dashed #ccc;
    border-radius: 4px; }
.upload-form label { display: block; font-size: 0.85em;
    color: #555; margin-bottom: 0.2em; }
.upload-form input[type=file], .upload-form input[type=text]
    { font: inherit; padding: 0.3em 0.5em;
    border: 1px solid #bbb; border-radius: 3px;
    margin-right: 0.4em; }
.upload-form button { font: inherit;
    padding: 0.35em 0.9em; background: #06c; color: white;
    border: 0; border-radius: 4px; cursor: pointer; }
.upload-form button:hover { background: #0050a0; }
.upload-form form { display: inline-block;
    margin-right: 1em; margin-bottom: 0.4em; }
.transcript-wrap { margin-top: 1em; }
.transcript-wrap h3 { font-size: 0.92em; color: #555;
    font-weight: 600; margin: 0 0 0.3em; }
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
CSS;
});
/*
    --- Page renderer ---
    Common header/footer wrapped around the active tab's
    content. Mirrors ex22's structure; the active tab is
    highlighted in the nav.
 */
function ftpRenderPage($which, $cfg, $body_fn)
{
    $tabs = [
        'scenarios' => ['/', 'Scenarios'],
        'raw' => ['/raw', 'Raw command box'],
        'browser' => ['/browser', 'File browser'],
    ];
    $reset_msg = '';
    if (isset($_GET['reset']) && $_GET['reset'] !== '') {
        if ($_GET['reset'] === 'ok') {
            $n = isset($_GET['count']) ?
                (int) $_GET['count'] : 0;
            $reset_msg = "Reset complete. Restored $n " .
                "file" . ($n === 1 ? '' : 's') .
                " from original-root/.";
        } else if ($_GET['reset'] === 'err') {
            $reset_msg = "Reset finished with errors -- " .
                "see server console for details.";
        }
    }
    echo "<!DOCTYPE html><html lang=\"en\"><head>";
    echo "<meta charset=\"utf-8\">";
    echo "<meta name=\"viewport\" content=\"width=" .
        "device-width, initial-scale=1\">";
    echo "<title>AttoFTP Demo</title>";
    echo "<link rel=\"stylesheet\" href=\"/style.css\">";
    echo "</head><body>";
    echo "<h1>AttoFTP Demo</h1>";
    echo "<div class=\"meta\">FTP control on tcp://" .
        htmlspecialchars($cfg['host']) . ":" .
        (int) $cfg['port'] . " &middot; implicit FTPS on " .
        "tcp://" . htmlspecialchars($cfg['host']) . ":" .
        (int) $cfg['tls_port'] . ". Companion UI to <code>" .
        "index.php</code>; every transcript on this page " .
        "comes from a real control-channel exchange with " .
        "the running server.</div>";
    /*
        Reset bar -- copies of original-root/ overlay any
        local changes in root/. Same shape and palette as
        ex20's reset-all-stored-mail bar.
     */
    echo "<div class=\"reset-bar\">";
    echo "<button type=\"button\" id=\"reset-btn\">" .
        "Reset root/ from original-root/</button>";
    echo "<span class=\"reset-status\" id=\"reset-status\">";
    if ($reset_msg !== '') {
        echo htmlspecialchars($reset_msg);
    } else {
        echo "Wipes uploads, renames, deletions and " .
            "directory changes under <code>root/</code> " .
            "and overlays the pristine demo content from " .
            "<code>original-root/</code>.";
    }
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
    echo "<script>" . ftpResetScript() . "</script>";
    echo "</body></html>";
}
/*
    Tiny client-side script for the reset bar's confirm-then-
    POST flow. Posts to /reset and reloads the current page
    with status query-parameters that the server-side
    rendering surfaces in the bar.
 */
function ftpResetScript()
{
    return <<<'JS'
(function () {
    var btn = document.getElementById('reset-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
        if (!window.confirm(
            'Wipe root/ and restore from original-root/?\n' +
            'This cannot be undone.')) {
            return;
        }
        btn.disabled = true;
        btn.textContent = 'Resetting...';
        fetch('/reset', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var qs = data.errors && data.errors.length ?
                    '?reset=err' :
                    '?reset=ok&count=' +
                    encodeURIComponent(data.restored || 0);
                window.location.search = qs;
            })
            .catch(function (err) {
                btn.disabled = false;
                btn.textContent = 'Reset root/ from ' +
                    'original-root/';
                alert('Reset failed: ' + err);
            });
    });
})();
JS;
}
/*
    Returns the static list of scenarios. Each entry has:
        title -- one-line description shown on the card
        desc  -- a sentence or two of context
        user  -- USER value to log in with
        pass  -- PASS value
        run   -- callable that takes ($sock, &$transcript)
                 and returns either null or
                 ['body' => string, 'note' => string|null]
    The runner function executes after USER/PASS but before
    QUIT; the page renderer adds those automatically.
 */
function ftpScenarioList()
{
    return [
        'anon-browse' => [
            'title' => 'Anonymous: browse /pub',
            'desc' => 'USER anonymous + any password lands ' .
                'in /pub. PWD reports the cwd; LIST opens ' .
                'a passive data channel and streams the ' .
                'directory listing in ls-l format.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'PWD', $transcript);
                ftpSendCmd($sock, 'TYPE I', $transcript);
                $r = ftpPasvTransfer($sock, 'LIST',
                    'download', $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'mlsd' => [
            'title' => 'Anonymous: machine listing (MLSD)',
            'desc' => 'MLSD returns a parseable format ' .
                'modern clients prefer over LIST. Each ' .
                'line is fact=value pairs (type, size, ' .
                'modify, perm) followed by the filename.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                $r = ftpPasvTransfer($sock, 'MLSD /pub',
                    'download', $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'feat' => [
            'title' => 'Anonymous: FEAT capability probe',
            'desc' => 'FEAT returns a multi-line list of ' .
                'extensions the server supports. Filezilla ' .
                'sends FEAT right after the banner to ' .
                'decide whether to use MLSD, AUTH TLS, etc.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'FEAT', $transcript);
                ftpSendCmd($sock, 'SYST', $transcript);
                ftpSendCmd($sock, 'OPTS UTF8 ON',
                    $transcript);
                return null;
            },
        ],
        'retr' => [
            'title' => 'Anonymous: download a file (RETR)',
            'desc' => 'Sets binary mode, opens a passive ' .
                'data channel, and streams /pub/hello.txt ' .
                'to the client. The file body is shown ' .
                'below the transcript.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                ftpSendCmd($sock, 'SIZE /pub/hello.txt',
                    $transcript);
                $r = ftpPasvTransfer($sock,
                    'RETR /pub/hello.txt', 'download',
                    $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'anon-stor-rejected' => [
            'title' => 'Anonymous: STOR (denied)',
            'desc' => 'Anonymous accounts are read-only by ' .
                'convention. STOR returns 550 even before ' .
                'the data channel is opened. The same ' .
                'rejection happens for DELE, MKD, RMD, ' .
                'and RNFR.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                /* Note: we send STOR without setting up
                   PASV first, because the server should
                   reject STOR before any data channel
                   is needed -- the read-only check fires
                   in requireWrite() ahead of the data
                   channel handshake. */
                ftpSendCmd($sock, 'STOR newfile.txt',
                    $transcript);
                return null;
            },
        ],
        'cwd-escape' => [
            'title' => 'Path-traversal probe (denied)',
            'desc' => 'Tries to escape the configured ' .
                'root via .. and via absolute paths. The ' .
                'storage layers resolveSafe() check ' .
                'rejects both (550). After the rejection ' .
                'PWD confirms the cwd was not changed.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'PWD', $transcript);
                ftpSendCmd($sock, 'CWD ../../etc',
                    $transcript);
                ftpSendCmd($sock, 'CWD /etc/passwd',
                    $transcript);
                ftpSendCmd($sock, 'PWD', $transcript);
                return null;
            },
        ],
        'alice-login' => [
            'title' => 'alice: login lands in /users/alice',
            'desc' => 'Static-list users carry a ' .
                'login_folder field; alice lands in her ' .
                'own writable subdirectory. PWD confirms ' .
                'the cwd was set on login.',
            'user' => 'alice',
            'pass' => 'hunter2',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'PWD', $transcript);
                ftpSendCmd($sock, 'TYPE I', $transcript);
                $r = ftpPasvTransfer($sock, 'LIST',
                    'download', $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'alice-stor' => [
            'title' => 'alice: upload (STOR)',
            'desc' => 'STOR scratch.txt opens a passive ' .
                'data channel; the client streams the ' .
                'file contents into it; the server saves ' .
                'and returns 226. The follow-up LIST ' .
                'shows the new file.',
            'user' => 'alice',
            'pass' => 'hunter2',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                $payload = "Demo upload from the " .
                    "scenarios tab\nTime: " . date('c') .
                    "\n";
                $r = ftpPasvTransfer($sock,
                    'STOR scratch.txt', 'upload',
                    $transcript, $payload);
                $list = ftpPasvTransfer($sock, 'LIST',
                    'download', $transcript);
                return ['body' => $list['body'],
                    'note' => 'Uploaded ' .
                        strlen($payload) . ' bytes; ' .
                        'directory listing shown below.'];
            },
        ],
        'alice-rename-delete' => [
            'title' => 'alice: rename + delete',
            'desc' => 'RNFR captures the source path; ' .
                'RNTO moves it. Then DELE removes it. ' .
                'The follow-up LIST confirms the file is ' .
                'gone. (If the previous scenario created ' .
                'scratch.txt, this scenario cleans it up.)',
            'user' => 'alice',
            'pass' => 'hunter2',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                ftpSendCmd($sock, 'RNFR scratch.txt',
                    $transcript);
                ftpSendCmd($sock, 'RNTO renamed.txt',
                    $transcript);
                ftpSendCmd($sock, 'DELE renamed.txt',
                    $transcript);
                $r = ftpPasvTransfer($sock, 'LIST',
                    'download', $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'wrong-password' => [
            'title' => 'Wrong password (denied)',
            'desc' => 'CompositeAuthenticator tries the ' .
                'static list first. A USER named alice ' .
                'with the wrong password is rejected ' .
                'outright with 530, rather than silently ' .
                'falling back to anonymous.',
            'user' => 'alice',
            'pass' => 'wrong-password',
            'run' => function ($sock, &$transcript) {
                /* USER/PASS already sent by the wrapper;
                   this scenario simply tries one more
                   command after the failure to show that
                   subsequent commands return 530 too. */
                ftpSendCmd($sock, 'PWD', $transcript);
                return null;
            },
        ],
        'epsv' => [
            'title' => 'EPSV: dual-stack passive mode',
            'desc' => 'EPSV (RFC 2428) is the IPv6-aware ' .
                'replacement for PASV. Where PASV embeds a ' .
                'four-byte IPv4 address in its reply, EPSV ' .
                'elides the address entirely -- the reply ' .
                'shape is just (|||port|), telling the ' .
                'client "use whatever family you opened the ' .
                'control connection on, this port". That ' .
                'design means a single command works ' .
                'unchanged over IPv4 and IPv6. The ' .
                'demonstration here runs over the v4 control ' .
                'channel; if you switch the launcher\'s BIND ' .
                'to "::", the same scenario runs unchanged ' .
                'over IPv6.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'TYPE I', $transcript);
                $r = ftpEpsvTransfer($sock, 'LIST /pub',
                    'download', $transcript);
                return ['body' => $r['body'],
                    'note' => $r['note']];
            },
        ],
        'epsv-all' => [
            'title' => 'EPSV ALL: latch the session to ' .
                'extended mode',
            'desc' => 'A client that knows it will only use ' .
                'EPSV can send "EPSV ALL" once after login. ' .
                'The server records the commitment and ' .
                'refuses PASV / PORT / EPRT for the rest of ' .
                'the session (with 503 Bad sequence). This ' .
                'protects against NAT boxes that try to ' .
                'rewrite PASV/PORT addresses on the fly: if ' .
                'the address can\'t even be in the message, ' .
                'the NAT has nothing to break.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'EPSV ALL', $transcript);
                ftpSendCmd($sock, 'PASV', $transcript);
                ftpSendCmd($sock, 'PORT 192,0,2,1,0,21',
                    $transcript);
                ftpSendCmd($sock, 'EPRT |1|192.0.2.1|21|',
                    $transcript);
                ftpSendCmd($sock, 'EPSV', $transcript);
                return null;
            },
        ],
        'auth-tls' => [
            'title' => 'AUTH TLS (FTPS upgrade)',
            'desc' => 'AUTH TLS asks the server to start ' .
                'TLS on the control channel. The demo ' .
                'serves the self-signed cert from atto\'s ' .
                'security/ folder, so the server returns ' .
                '234 and is ready for the handshake. The ' .
                'scenario stops there: from the 234 ' .
                'onward the wire would carry TLS records, ' .
                'not readable FTP, so continuing would ' .
                'just produce gibberish in the transcript. ' .
                'A real client would now do the TLS ' .
                'handshake on the same socket and resume ' .
                'with USER/PASS over the encrypted channel.',
            'user' => 'anonymous',
            'pass' => 'guest@example.com',
            'run' => function ($sock, &$transcript) {
                ftpSendCmd($sock, 'AUTH TLS', $transcript);
                /* Stop here. PBSZ/PROT belong to the
                   encrypted side of the upgrade. Sending
                   anything in cleartext after the 234 (even
                   the wrapper's automatic QUIT) would
                   confuse the server's TLS layer, which is
                   now waiting for a TLS ClientHello -- so we
                   set no_quit and let the connection close
                   when fclose() runs. */
                return ['no_quit' => true];
            },
        ],
    ];
}
/*
    Renders the scenarios tab. Each card has a title, a
    paragraph of context, and a Run button that fires off
    a fetch POST to /scenario; the JS replaces the .result-
    slot with the rendered transcript and optional body
    pane.
 */
function ftpRenderScenarios($cfg)
{
    echo "<div class=\"banner\">Click any scenario below " .
        "to open a real control connection to the FTP " .
        "server, run a scripted sequence of FTP commands, " .
        "and see the wire transcript. Greater-than (&gt;) " .
        "lines are sent by the client; less-than (&lt;) " .
        "lines are server responses. Click the <strong>" .
        "&times;</strong> button to hide a transcript again." .
        "<br><br><strong>Try this:</strong> run " .
        "<em>alice: upload</em>, then run " .
        "<em>alice: rename + delete</em> to round-trip the " .
        "upload through rename and delete and verify the " .
        "file is gone.</div>";
    foreach (ftpScenarioList() as $key => $info) {
        echo "<div class=\"scenario\" data-key=\"" .
            htmlspecialchars($key) . "\">";
        echo "<div class=\"row\">";
        echo "<div>";
        echo "<div class=\"label\">" .
            htmlspecialchars($info['title']) . "</div>";
        echo "<div class=\"desc\">" .
            htmlspecialchars($info['desc']) . "</div>";
        echo "</div>";
        echo "<button type=\"button\">Run</button>";
        echo "</div>";
        echo "<pre class=\"transcript\"></pre>";
        echo "<div class=\"body-pane\"></div>";
        echo "</div>";
    }
    echo "<script>\n" . ftpClientScript() . "\n</script>\n";
}
/*
    Renders the raw command box. The user picks a username
    + password from the demo list (or types arbitrary ones)
    and types a multi-line script of FTP commands. We send
    them sequentially and render the transcript.
 */
function ftpRenderRaw($cfg)
{
    echo "<div class=\"banner\">Type any sequence of FTP " .
        "commands. They are sent over a fresh control " .
        "connection in the order shown, with USER/PASS " .
        "prepended automatically. Empty lines are " .
        "skipped. Note that data commands (LIST, RETR, " .
        "STOR, MLSD) need a PASV before them, but PASV " .
        "is also sent automatically for any line that " .
        "looks like a data command. Add your own PASV " .
        "explicitly if you want to see it in the " .
        "transcript. A few suggestions:<br>" .
        "<code>FEAT</code> &middot; " .
        "<code>SYST</code> &middot; " .
        "<code>PWD</code> &middot; " .
        "<code>CWD /pub</code> &middot; " .
        "<code>SIZE /pub/changelog.txt</code> &middot; " .
        "<code>MDTM /pub/hello.txt</code> &middot; " .
        "<code>STAT /pub</code> &middot; " .
        "<code>HELP</code></div>";
    echo "<form class=\"raw\" id=\"rawForm\">";
    echo "<div class=\"row\">";
    echo "<div><label>User</label>";
    echo "<select name=\"who\" id=\"whoPick\" " .
        "onchange=\"ftpUserPicked(this)\">";
    foreach ($cfg['demo_users'] as $i => $u) {
        echo "<option value=\"" . htmlspecialchars($i) .
            "\">" . htmlspecialchars($u['label']) .
            "</option>";
    }
    echo "<option value=\"custom\">Custom...</option>";
    echo "</select></div>";
    echo "<div><label>Username</label>";
    echo "<input type=\"text\" name=\"user\" " .
        "id=\"userField\" value=\"anonymous\"></div>";
    echo "<div><label>Password</label>";
    echo "<input type=\"text\" name=\"pass\" " .
        "id=\"passField\" value=\"guest@example.com\">" .
        "</div>";
    echo "</div>";
    echo "<label>Commands (one per line; QUIT is sent " .
        "automatically at the end)</label>";
    echo "<textarea name=\"commands\" rows=\"6\">PWD\n" .
        "TYPE I\nLIST\n</textarea>";
    echo "<button type=\"submit\">Send</button>";
    echo "</form>";
    echo "<div id=\"rawResult\"></div>";
    echo "<script>\n" .
        "var demoUsers = " . json_encode(array_values(
        $cfg['demo_users'])) . ";\n" .
        ftpClientScript() . "\n</script>\n";
}
/*
    Renders the file browser tab. Server-side, this opens
    a control connection as the active demo user, runs a
    LIST against the supplied path, and renders the result
    as an HTML table with action links (download, rename,
    delete). It also exposes upload (STOR) and mkdir (MKD)
    forms underneath.
 */
function ftpRenderBrowser($cfg, $params)
{
    $who = isset($params['who']) ?
        (int) $params['who'] : 1; /* default to alice */
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    /* Determine cwd: default to login folder for the
       active user. */
    $defaults = [0 => '/pub', 1 => '/users/alice',
        2 => '/users/bob'];
    $cwd = isset($params['cwd']) && $params['cwd'] !== '' ?
        $params['cwd'] :
        (isset($defaults[$who]) ? $defaults[$who] : '/');
    /* Banner + user picker. */
    echo "<div class=\"banner\">This tab is a small FTP " .
        "client. Every navigation, upload, download, " .
        "rename, and delete sends a real FTP command to " .
        "the running server. Switch the active user to " .
        "see how permissions and login folders differ. " .
        "Anonymous is read-only; alice and bob have " .
        "write access in their own subdirs.</div>";
    echo "<form class=\"session\" method=\"get\" " .
        "action=\"/browser\">";
    echo "<div class=\"user-pick\">";
    echo "<strong>Acting as:</strong> ";
    echo "<select name=\"who\" onchange=\"this.form." .
        "submit()\">";
    foreach ($cfg['demo_users'] as $i => $du) {
        $sel = ($i === $who) ? ' selected' : '';
        echo "<option value=\"$i\"$sel>" .
            htmlspecialchars($du['label']) . "</option>";
    }
    echo "</select>";
    echo "</div>";
    echo "</form>";
    /* Open a session, list cwd, render. */
    $session = ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($cwd) {
            ftpSendCmd($sock, 'TYPE I', $transcript);
            $cmd = 'MLSD ' . $cwd;
            $r = ftpPasvTransfer($sock, $cmd, 'download',
                $transcript);
            return ['body' => $r['body']];
        });
    $entries = ftpParseMlsd($session['body']);
    echo "<div class=\"browser\">";
    echo "<div class=\"crumb\">Path: " .
        htmlspecialchars($cwd) . "</div>";
    echo "<table>";
    echo "<thead><tr><th>Name</th><th>Type</th>" .
        "<th>Size</th><th>Modified</th>" .
        "<th>Actions</th></tr></thead><tbody>";
    /* Add a parent-dir row if not at root and cwd has
       a parent we can reach. */
    if ($cwd !== '/' && $cwd !== '') {
        $parent = ftpParentPath($cwd);
        echo "<tr><td><a href=\"/browser?who=$who&cwd=" .
            urlencode($parent) . "\">.. (parent)</a></td>";
        echo "<td>dir</td><td>-</td><td>-</td><td></td></tr>";
    }
    foreach ($entries as $e) {
        echo "<tr>";
        $name = $e['name'];
        $is_dir = ($e['type'] === 'dir');
        if ($is_dir) {
            $sub = $cwd === '/' ? '/' . $name :
                rtrim($cwd, '/') . '/' . $name;
            echo "<td><a href=\"/browser?who=$who&cwd=" .
                urlencode($sub) . "\">" .
                htmlspecialchars($name) . "/</a></td>";
            echo "<td>dir</td><td>-</td>";
        } else {
            echo "<td>" . htmlspecialchars($name) . "</td>";
            echo "<td>file</td><td>" .
                (int) $e['size'] . "</td>";
        }
        echo "<td>" . htmlspecialchars(
            isset($e['modify']) ?
                ftpFormatModify($e['modify']) : '-') .
            "</td>";
        echo "<td class=\"actions\">";
        if (!$is_dir) {
            echo "<form method=\"post\" action=\"" .
                "/browser/download\">";
            echo "<input type=\"hidden\" name=\"who\" " .
                "value=\"$who\">";
            echo "<input type=\"hidden\" name=\"cwd\" " .
                "value=\"" . htmlspecialchars($cwd) .
                "\">";
            echo "<input type=\"hidden\" name=\"name\" " .
                "value=\"" . htmlspecialchars($name) .
                "\">";
            echo "<button type=\"submit\">Download" .
                "</button></form>";
        }
        if (empty($u['user']) || $u['user'] !==
            'anonymous') {
            echo "<form method=\"post\" action=\"" .
                "/browser/rename\" onsubmit=\"return " .
                "ftpRenamePrompt(this)\">";
            echo "<input type=\"hidden\" name=\"who\" " .
                "value=\"$who\">";
            echo "<input type=\"hidden\" name=\"cwd\" " .
                "value=\"" . htmlspecialchars($cwd) .
                "\">";
            echo "<input type=\"hidden\" name=\"name\" " .
                "value=\"" . htmlspecialchars($name) .
                "\">";
            echo "<input type=\"hidden\" name=\"to\" " .
                "value=\"\">";
            echo "<button type=\"submit\">Rename" .
                "</button></form>";
            echo "<form method=\"post\" action=\"" .
                "/browser/delete\" onsubmit=\"return " .
                "confirm('Delete ' + " .
                json_encode($name) . " + '?')\">";
            echo "<input type=\"hidden\" name=\"who\" " .
                "value=\"$who\">";
            echo "<input type=\"hidden\" name=\"cwd\" " .
                "value=\"" . htmlspecialchars($cwd) .
                "\">";
            echo "<input type=\"hidden\" name=\"name\" " .
                "value=\"" . htmlspecialchars($name) .
                "\">";
            echo "<button type=\"submit\" " .
                "class=\"danger\">Delete</button>" .
                "</form>";
        }
        echo "</td></tr>";
    }
    if (empty($entries) && ($cwd === '/' || $cwd === '')) {
        /* Show nothing extra. */
    }
    echo "</tbody></table>";
    /* Show the upload + mkdir forms only when the active
       user has write access. */
    if ($u['user'] !== 'anonymous') {
        echo "<div class=\"upload-form\">";
        echo "<form method=\"post\" action=\"" .
            "/browser/upload\" enctype=\"multipart/" .
            "form-data\">";
        echo "<input type=\"hidden\" name=\"who\" " .
            "value=\"$who\">";
        echo "<input type=\"hidden\" name=\"cwd\" " .
            "value=\"" . htmlspecialchars($cwd) . "\">";
        echo "<label>Upload a file (STOR)</label>";
        echo "<input type=\"file\" name=\"file\" " .
            "required>";
        echo "<button type=\"submit\">Upload</button>";
        echo "</form>";
        echo "<form method=\"post\" action=\"" .
            "/browser/mkdir\">";
        echo "<input type=\"hidden\" name=\"who\" " .
            "value=\"$who\">";
        echo "<input type=\"hidden\" name=\"cwd\" " .
            "value=\"" . htmlspecialchars($cwd) . "\">";
        echo "<label>Make directory (MKD)</label>";
        echo "<input type=\"text\" name=\"name\" " .
            "placeholder=\"new-folder\" required>";
        echo "<button type=\"submit\">Create</button>";
        echo "</form>";
        echo "</div>";
    } else {
        echo "<div class=\"note\">Anonymous accounts " .
            "are read-only. Switch to alice or bob " .
            "to upload, rename, delete, or mkdir.</div>";
    }
    echo "</div>";
    /*
        Always show the transcript of the listing call so
        the educational point is reinforced even on the
        browser tab.
     */
    echo "<div class=\"transcript-wrap\">";
    echo "<h3>FTP transcript (MLSD listing)</h3>";
    echo "<pre class=\"transcript-static\">" .
        htmlspecialchars(ftpRenderTranscript(
        $session['transcript'])) . "</pre>";
    echo "</div>";
    echo "<script>\n" .
        "function ftpRenamePrompt(form) {\n" .
        "  var current = form.querySelector(\n" .
        "    'input[name=\"name\"]').value;\n" .
        "  var to = prompt('Rename ' + current + ' to:'," .
        " current);\n" .
        "  if (!to) return false;\n" .
        "  form.querySelector('input[name=\"to\"]')." .
        "value = to;\n" .
        "  return true;\n" .
        "}\n</script>\n";
}
/*
    Parses a server's MLSD output into an array of entries.
    Each line looks like:
        type=file;size=129;modify=20260504215057;perm=r; name
 */
function ftpParseMlsd($body)
{
    $out = [];
    foreach (preg_split('/\r?\n/', $body) as $line) {
        if ($line === '') {
            continue;
        }
        $sp = strpos($line, ' ');
        if ($sp === false) {
            continue;
        }
        $facts_str = substr($line, 0, $sp);
        $name = substr($line, $sp + 1);
        $entry = ['name' => $name];
        foreach (explode(';', $facts_str) as $fact) {
            if ($fact === '') {
                continue;
            }
            $eq = strpos($fact, '=');
            if ($eq === false) {
                continue;
            }
            $entry[strtolower(substr($fact, 0, $eq))] =
                substr($fact, $eq + 1);
        }
        $out[] = $entry;
    }
    /* Show directories first, then files; alphabetical
       within each group. */
    usort($out, function ($a, $b) {
        $ad = ($a['type'] ?? '') === 'dir';
        $bd = ($b['type'] ?? '') === 'dir';
        if ($ad !== $bd) {
            return $ad ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });
    return $out;
}
/*
    Reformats an MLSD modify timestamp (YYYYMMDDhhmmss) as
    a human-readable date.
 */
function ftpFormatModify($modify)
{
    if (!preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})' .
        '(\d{2})(\d{2})$/', $modify, $m)) {
        return $modify;
    }
    return "$m[1]-$m[2]-$m[3] $m[4]:$m[5]:$m[6] UTC";
}
/*
    Returns the FTP-space parent of a path. "/pub" -> "/",
    "/users/alice" -> "/users", "/" -> "/".
 */
function ftpParentPath($path)
{
    if ($path === '/' || $path === '') {
        return '/';
    }
    $trim = rtrim($path, '/');
    $slash = strrpos($trim, '/');
    if ($slash === false || $slash === 0) {
        return '/';
    }
    return substr($trim, 0, $slash);
}
/*
    Returns the JS used by the scenarios tab and the raw
    tab. Both the scenarios runner and the raw form post
    to a JSON endpoint and replace a result slot with the
    rendered transcript.
 */
function ftpClientScript()
{
    return <<<'JS'
/*
    Each scenario card binds its button to a tri-state toggle:
        Run        -> click sends the request, fills the
                      transcript pane, switches button to X.
        X          -> click hides the pane, restores Run.
        Running... -> in-flight; button disabled.
 */
document.querySelectorAll('.scenario').forEach(function (el) {
    var btn = el.querySelector('button');
    var key = el.dataset.key;
    var pre = el.querySelector('.transcript');
    var body = el.querySelector('.body-pane');
    function showRun() {
        btn.textContent = 'Run';
        btn.classList.remove('close');
        btn.disabled = false;
    }
    function showClose() {
        btn.textContent = '\u2715';
        btn.classList.add('close');
        btn.disabled = false;
    }
    function showBusy() {
        btn.textContent = 'Running...';
        btn.classList.remove('close');
        btn.disabled = true;
    }
    function hideAll() {
        pre.classList.remove('visible');
        pre.textContent = '';
        body.classList.remove('visible');
        body.innerHTML = '';
    }
    btn.addEventListener('click', function () {
        if (btn.classList.contains('close')) {
            hideAll();
            showRun();
            return;
        }
        showBusy();
        hideAll();
        pre.classList.add('visible');
        pre.textContent = '(running...)';
        var fd = new FormData();
        fd.append('scenario', key);
        fetch('/scenario', { method: 'POST', body: fd })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) {
                    pre.textContent = 'ERROR: ' + data.error;
                } else {
                    pre.textContent = data.transcript ||
                        '(empty transcript)';
                    if (data.body && data.body.length > 0) {
                        body.innerHTML = '<span class="hint">' +
                            'Data channel payload (' +
                            data.body.length + ' bytes):' +
                            '</span>' +
                            ftpEscapeHtml(data.body);
                        body.classList.add('visible');
                    }
                }
                showClose();
            })
            .catch(function (err) {
                pre.textContent = 'ERROR: ' + err;
                showClose();
            });
    });
});
function ftpEscapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
function ftpUserPicked(sel) {
    var v = sel.value;
    if (v === 'custom') {
        document.getElementById('userField').value = '';
        document.getElementById('passField').value = '';
        return;
    }
    var i = parseInt(v, 10);
    if (typeof demoUsers !== 'undefined' && demoUsers[i]) {
        document.getElementById('userField').value =
            demoUsers[i].user;
        document.getElementById('passField').value =
            demoUsers[i].pass;
    }
}
/*
    Raw command-box submit. Posts the typed commands and
    renders the transcript inline below the form.
 */
var rawForm = document.getElementById('rawForm');
if (rawForm) {
    rawForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var slot = document.getElementById('rawResult');
        slot.innerHTML = '<pre class="transcript-static">' +
            '(sending...)</pre>';
        var fd = new FormData(rawForm);
        fetch('/raw', { method: 'POST', body: fd })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) {
                    slot.innerHTML =
                        '<pre class="transcript-static">' +
                        'ERROR: ' +
                        ftpEscapeHtml(data.error) +
                        '</pre>';
                    return;
                }
                slot.innerHTML =
                    '<pre class="transcript-static">' +
                    ftpEscapeHtml(data.transcript ||
                        '(empty)') + '</pre>';
            })
            .catch(function (err) {
                slot.innerHTML =
                    '<pre class="transcript-static">' +
                    'ERROR: ' + ftpEscapeHtml(String(err)) +
                    '</pre>';
            });
    });
}
JS;
}
/*
    --- Routes ---
 */
$site->get('/', function () use ($site, $cfg) {
    ftpRenderPage('scenarios', $cfg, function () use ($cfg) {
        ftpRenderScenarios($cfg);
    });
});
$site->get('/raw', function () use ($site, $cfg) {
    ftpRenderPage('raw', $cfg, function () use ($cfg) {
        ftpRenderRaw($cfg);
    });
});
$site->get('/browser', function () use ($site, $cfg) {
    ftpRenderPage('browser', $cfg,
        function () use ($cfg, $site) {
            ftpRenderBrowser($cfg, $_GET);
        });
});
/*
    Scenario runner. Given a scenario key, opens a control
    connection, logs in as the scenario's user, runs the
    scripted body, and returns the rendered transcript +
    optional payload as JSON.
 */
$site->post('/scenario', function () use ($site, $cfg) {
    $site->header("Content-Type: application/json");
    $key = isset($_POST['scenario']) ?
        $_POST['scenario'] : '';
    $list = ftpScenarioList();
    if (!isset($list[$key])) {
        echo json_encode(['error' =>
            'Unknown scenario: ' . $key]);
        return;
    }
    $info = $list[$key];
    $session = ftpSession($cfg['host'], $cfg['port'],
        $info['user'], $info['pass'], $info['run']);
    /* The body of the scenario may be the data-channel
       payload of the last transfer; surface it. The
       scenario callable optionally returns 'note'. */
    $note = null;
    /* No clean way to extract note from the callable's
       return value -- ftpSession() only forwards 'body'.
       Store note via a side channel: re-run the callable's
       last return value? Simpler: peek into the transcript
       for any "!" entry that signals an issue. */
    foreach ($session['transcript'] as $entry) {
        if ($entry['dir'] === '!' && $note === null) {
            $note = implode('; ', $entry['lines']);
        }
    }
    echo json_encode([
        'transcript' => ftpRenderTranscript(
            $session['transcript']),
        'body' => $session['body'],
        'note' => $note,
    ]);
});
/*
    Raw command box runner. Reads the credentials and the
    multi-line script from the form, sends them, returns
    the transcript as JSON.
 */
$site->post('/raw', function () use ($site, $cfg) {
    $site->header("Content-Type: application/json");
    $user = isset($_POST['user']) ?
        trim($_POST['user']) : '';
    $pass = isset($_POST['pass']) ? $_POST['pass'] : '';
    $script_text = isset($_POST['commands']) ?
        $_POST['commands'] : '';
    $commands = [];
    foreach (preg_split('/\r?\n/', $script_text) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $commands[] = $line;
    }
    /* Prepend USER/PASS so the script body assumes a
       logged-in session. */
    array_unshift($commands, "USER $user", "PASS $pass");
    $transcript = ftpScript($cfg['host'], $cfg['port'],
        $commands);
    echo json_encode([
        'transcript' => ftpRenderTranscript($transcript),
        'body' => '',
        'note' => null,
    ]);
});
/*
    File browser actions. Each posts to a dedicated route
    that runs one FTP command (or a small chain) against
    the running server, then redirects back to the browser
    at the cwd we started from.
 */
$site->post('/browser/download', function () use ($site,
    $cfg) {
    $who = isset($_POST['who']) ? (int) $_POST['who'] : 1;
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : '/';
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    if ($name === '') {
        $site->header("Location: /browser?who=$who&cwd=" .
            urlencode($cwd));
        return;
    }
    $path = $cwd === '/' ? '/' . $name :
        rtrim($cwd, '/') . '/' . $name;
    $session = ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($path) {
            ftpSendCmd($sock, 'TYPE I', $transcript);
            $r = ftpPasvTransfer($sock, "RETR $path",
                'download', $transcript);
            return ['body' => $r['body']];
        });
    /* Send the bytes as a download. */
    $site->header("Content-Type: application/octet-stream");
    $site->header("Content-Disposition: attachment; " .
        "filename=\"" . basename($name) . "\"");
    echo $session['body'];
});
$site->post('/browser/upload', function () use ($site,
    $cfg) {
    $who = isset($_POST['who']) ? (int) $_POST['who'] : 1;
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : '/';
    if (!isset($_FILES['file']) ||
        !is_uploaded_file($_FILES['file']['tmp_name'])) {
        $site->header("Location: /browser?who=$who&cwd=" .
            urlencode($cwd));
        return;
    }
    $name = basename($_FILES['file']['name']);
    $body = file_get_contents($_FILES['file']['tmp_name']);
    $path = $cwd === '/' ? '/' . $name :
        rtrim($cwd, '/') . '/' . $name;
    ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($path, $body) {
            ftpSendCmd($sock, 'TYPE I', $transcript);
            ftpPasvTransfer($sock, "STOR $path", 'upload',
                $transcript, $body);
            return null;
        });
    $site->header("Location: /browser?who=$who&cwd=" .
        urlencode($cwd));
});
$site->post('/browser/delete', function () use ($site,
    $cfg) {
    $who = isset($_POST['who']) ? (int) $_POST['who'] : 1;
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : '/';
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    $path = $cwd === '/' ? '/' . $name :
        rtrim($cwd, '/') . '/' . $name;
    ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($path) {
            /* DELE first (in case it is a file). If that
               fails with 550, try RMD (if it is a dir).
               This is what real clients do too. */
            $reply = ftpSendCmd($sock, "DELE $path",
                $transcript);
            $first = isset($reply[0]) ? $reply[0] : '';
            if (strpos($first, '550') === 0) {
                ftpSendCmd($sock, "RMD $path",
                    $transcript);
            }
            return null;
        });
    $site->header("Location: /browser?who=$who&cwd=" .
        urlencode($cwd));
});
$site->post('/browser/rename', function () use ($site,
    $cfg) {
    $who = isset($_POST['who']) ? (int) $_POST['who'] : 1;
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : '/';
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    $to = isset($_POST['to']) ? $_POST['to'] : '';
    if ($name === '' || $to === '') {
        $site->header("Location: /browser?who=$who&cwd=" .
            urlencode($cwd));
        return;
    }
    $from_path = $cwd === '/' ? '/' . $name :
        rtrim($cwd, '/') . '/' . $name;
    $to_path = $cwd === '/' ? '/' . $to :
        rtrim($cwd, '/') . '/' . $to;
    ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($from_path,
            $to_path) {
            ftpSendCmd($sock, "RNFR $from_path",
                $transcript);
            ftpSendCmd($sock, "RNTO $to_path", $transcript);
            return null;
        });
    $site->header("Location: /browser?who=$who&cwd=" .
        urlencode($cwd));
});
$site->post('/browser/mkdir', function () use ($site,
    $cfg) {
    $who = isset($_POST['who']) ? (int) $_POST['who'] : 1;
    if ($who < 0 || $who >= count($cfg['demo_users'])) {
        $who = 1;
    }
    $u = $cfg['demo_users'][$who];
    $cwd = isset($_POST['cwd']) ? $_POST['cwd'] : '/';
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    if ($name === '') {
        $site->header("Location: /browser?who=$who&cwd=" .
            urlencode($cwd));
        return;
    }
    $path = $cwd === '/' ? '/' . $name :
        rtrim($cwd, '/') . '/' . $name;
    ftpSession($cfg['host'], $cfg['port'],
        $u['user'], $u['pass'],
        function ($sock, &$transcript) use ($path) {
            ftpSendCmd($sock, "MKD $path", $transcript);
            return null;
        });
    $site->header("Location: /browser?who=$who&cwd=" .
        urlencode($cwd));
});
/*
    Reset endpoint: wipe everything under root/ and overlay
    a fresh copy of original-root/. Returns JSON with the
    file count and any errors. The reset bar's JS reloads
    the page with a status query-parameter so the result
    is visible without an additional state plumbing.
 */
$site->post('/reset', function () use ($site, $cfg) {
    $site->header("Content-Type: application/json");
    $live = $cfg['root_dir'];
    $original = $cfg['original_root_dir'];
    $errors = [];
    if (!is_dir($original)) {
        echo json_encode(['restored' => 0,
            'errors' => ["original-root/ not found"]]);
        return;
    }
    /*
        Two-phase clean. First, recursively delete every
        file and directory under root/ except root/ itself
        (we keep the top-level dir so the running FTP
        process's open file descriptors do not break).
     */
    if (is_dir($live)) {
        ftpRecursiveClean($live, $errors);
    } else {
        @mkdir($live, 0755, true);
    }
    /*
        Now mirror original-root/ over root/.
     */
    $count = 0;
    ftpRecursiveCopy($original, $live, $count, $errors);
    echo json_encode(['restored' => $count,
        'errors' => $errors]);
});
/*
    Recursively deletes all entries inside $dir, but leaves
    $dir itself in place. Records error strings in $errors.
 */
function ftpRecursiveClean($dir, &$errors)
{
    $entries = @scandir($dir);
    if ($entries === false) {
        $errors[] = "scandir failed: $dir";
        return;
    }
    foreach ($entries as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $name;
        if (is_dir($path) && !is_link($path)) {
            ftpRecursiveClean($path, $errors);
            if (!@rmdir($path)) {
                $errors[] = "rmdir failed: $path";
            }
        } else {
            if (!@unlink($path)) {
                $errors[] = "unlink failed: $path";
            }
        }
    }
}
/*
    Recursively copies all entries from $src into $dst
    (which must exist). Increments $count for each file
    copied and records error strings in $errors.
 */
function ftpRecursiveCopy($src, $dst, &$count, &$errors)
{
    $entries = @scandir($src);
    if ($entries === false) {
        $errors[] = "scandir failed: $src";
        return;
    }
    foreach ($entries as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        $sp = $src . DIRECTORY_SEPARATOR . $name;
        $dp = $dst . DIRECTORY_SEPARATOR . $name;
        if (is_dir($sp)) {
            if (!is_dir($dp) && !@mkdir($dp, 0755, true)) {
                $errors[] = "mkdir failed: $dp";
                continue;
            }
            ftpRecursiveCopy($sp, $dp, $count, $errors);
        } else if (is_file($sp)) {
            if (@copy($sp, $dp)) {
                $count++;
            } else {
                $errors[] = "copy failed: $sp -> $dp";
            }
        }
    }
}
$site->listen(8080);
