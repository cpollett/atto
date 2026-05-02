<?php
/**
 * AttoMail demo: companion WebSite that drives the mail
 * listeners on localhost:2525/1143/4465/9933 from a browser
 * UI on http://localhost:8080/. Each scenario opens a TCP
 * (or TLS) connection to the appropriate port, runs a short
 * scripted dialogue, and renders the transcript so you can
 * watch the protocol exchange line by line.
 *
 * The "Direct API" scenarios skip the wire protocol entirely
 * and call public methods on a freshly-constructed MailSite
 * instance pointing at the same on-disk store as the running
 * server. That is the integration point a webmail front-end
 * would use in practice; the wire-level scenarios show what a
 * Thunderbird/Apple Mail client sees.
 *
 * This file is spawned by index.php as a detached child; do
 * not run it directly unless you want to host the UI without
 * the mail server.
 */
require '../../src/WebSite.php';
require '../../src/MailSite.php';
use seekquarry\atto\WebSite;
use seekquarry\atto\MailSite;
use seekquarry\atto\FileAuthenticator;
use seekquarry\atto\FileMailStorage;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
/*
    Pass "." as base_path to opt out of WebSite's automatic
    base_path detection. The constructor normalizes "." to ""
    (empty string), which means "match request URIs as-is".
    Without this, atto's auto-detection sees the script's
    absolute path under SCRIPT_NAME and tries to strip that
    long prefix from every request URI, which would route
    all incoming requests to "/" regardless of path.
 */
$site = new WebSite(".");
/*
    Configuration shared with index.php. The UI scenarios all
    target these ports; if you change them in index.php, mirror
    the change here.
 */
$cfg = [
    'host' => '127.0.0.1',
    'smtp' => 2525,
    'imap' => 1143,
    'smtps' => 4465,
    'imaps' => 9933,
];
$users_file = __DIR__ . '/users.htpasswd';
$store_dir = __DIR__ . '/maildata';
/*
    Catalog of scenarios. Each entry has:
      id       - URL-safe slug used in the form POST
      group    - section heading in the rendered UI
      label    - button text
      desc     - one-line explanation
      kind     - 'wire' (SMTP/IMAP transcript) or 'api'
                 (direct method call on MailSite)
      run      - callable returning the transcript text
    Wire scenarios share runScript() for the connect+dialogue
    machinery; API scenarios touch the MailStorage directly.
 */
$scenarios = [];
/*
    Helper: open a TCP (or TLS) connection to $port, send each
    string in $script verbatim, and after each send drain
    whatever the server replies with within ~400ms. Returns the
    transcript with ">>> " prefixing lines we sent. Connection
    is closed on return. $tls_mode is one of 'none', 'implicit'
    (TLS on connect), or 'starttls' (caller arranges the
    upgrade by including the protocol-specific upgrade verb in
    its $script and calling enableTlsOnSocket() between turns
    -- handled by special markers __STARTTLS_SMTP__ and
    __STARTTLS_IMAP__ which trigger an in-script upgrade).
 */
function runScript($host, $port, $script, $tls_mode = 'none')
{
    $url = ($tls_mode === 'implicit') ?
        "tls://$host:$port" : "tcp://$host:$port";
    $opts = ['ssl' => [
        'allow_self_signed' => true,
        'verify_peer' => false,
        'verify_peer_name' => false,
    ]];
    $ctx = stream_context_create($opts);
    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client($url, $errno, $errstr, 5,
        STREAM_CLIENT_CONNECT, $ctx);
    if (!$sock) {
        return "ERROR: connect $url: $errstr (errno $errno)\n";
    }
    stream_set_blocking($sock, 0);
    $transcript = "";
    /*
        Drain whatever the server has already pushed into the
        socket. Returns once (a) the deadline elapses, (b) the
        server quiets down for $idle_us microseconds after
        having sent at least one byte, or (c) the socket reads
        empty/false. The $require_first_byte flag is for the
        post-connect initial drain: TLS handshakes can take a
        few tens of ms and the server may not have written the
        banner yet, so we keep waiting up to the deadline for
        the first byte before considering "no data" a clean
        empty response.
     */
    $drain = function ($timeout_s = 0.4, $idle_us = 50000,
        $require_first_byte = false)
        use ($sock, &$transcript) {
        $deadline = microtime(true) + $timeout_s;
        $buf = "";
        $got_any = false;
        while (microtime(true) < $deadline) {
            $r = [$sock]; $w = $e = null;
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                break;
            }
            $tv_us = (int) min(200000, $remaining * 1e6);
            $n = @stream_select($r, $w, $e, 0, $tv_us);
            if ($n > 0) {
                $chunk = @fread($sock, 8192);
                if ($chunk === false) {
                    break;
                }
                if ($chunk === "") {
                    /*
                        On a TLS stream, select() may report the
                        socket readable while the SSL layer has
                        not yet decoded a full record, so fread
                        returns "" without indicating EOF. Treat
                        empty as "try again" unless the stream
                        has actually hit EOF.
                     */
                    if (feof($sock)) {
                        break;
                    }
                    continue;
                }
                $buf .= $chunk;
                $got_any = true;
                /*
                    Once we have at least one byte, a short
                    quiet period means the server is done
                    sending its current burst.
                 */
                $r2 = [$sock]; $w2 = $e2 = null;
                if (@stream_select($r2, $w2, $e2, 0, $idle_us)
                    === 0) {
                    break;
                }
            } else if (!$require_first_byte || $got_any) {
                break;
            }
        }
        $transcript .= $buf;
    };
    /*
        Read the initial banner the server pushes on connect.
        Larger budget here since TLS handshakes on implicit-
        TLS sockets can delay the first banner byte by several
        tens of milliseconds.
     */
    $drain(1.5, 50000, true);
    foreach ($script as $line) {
        if ($line === '__STARTTLS_SMTP__' ||
            $line === '__STARTTLS_IMAP__') {
            /*
                In-script TLS upgrade: switch the socket to
                blocking mode for the handshake (PHP's
                stream_socket_enable_crypto is documented to
                require blocking) then back to non-blocking so
                the rest of the dialogue keeps the same I/O
                shape.
             */
            stream_set_blocking($sock, 1);
            $ok = @stream_socket_enable_crypto($sock, true,
                STREAM_CRYPTO_METHOD_TLS_CLIENT);
            stream_set_blocking($sock, 0);
            if ($ok !== true) {
                $transcript .= "<<< TLS handshake FAILED >>>\n";
                break;
            }
            $transcript .= "<<< TLS handshake OK >>>\n";
            continue;
        }
        $transcript .= ">>> " . $line;
        @fwrite($sock, $line);
        $drain(0.4, 50000, true);
    }
    @fclose($sock);
    return $transcript;
}
/*
    Build a freshly-constructed MailSite that shares the on-
    disk store and password file with the running server. We
    do NOT call ->listen() on it; we only use its public
    methods. Both processes touch the same files, so the view
    is consistent (file-locked UID counter handles concurrent
    appends should they happen).
 */
function shareMail($users_file, $store_dir)
{
    $m = new MailSite();
    $m->auth(new FileAuthenticator($users_file));
    $m->storage(new FileMailStorage($store_dir));
    $m->domains(['localhost', 'example.test']);
    return $m;
}
/* ---------- SMTP plaintext ---------- */
$scenarios['smtp_ehlo'] = [
    'group' => 'SMTP plaintext (port 2525)',
    'label' => 'EHLO + capabilities',
    'desc' => 'Connect, send EHLO, and quit. Shows ' .
        'STARTTLS/AUTH/SIZE advertisement.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "QUIT\r\n",
        ]);
    },
];
$scenarios['smtp_lenient'] = [
    'group' => 'SMTP plaintext (port 2525)',
    'label' => 'Lenient bareword MAIL FROM',
    'desc' => '"MAIL FROM: bob@client.com" without angle ' .
        'brackets is accepted as a tolerance.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM: bob@client.com\r\n",
            "RSET\r\n",
            "QUIT\r\n",
        ]);
    },
];
$scenarios['smtp_relay'] = [
    'group' => 'SMTP plaintext (port 2525)',
    'label' => 'Anti-relay (external + external + no auth)',
    'desc' => 'Try to relay an external sender to an external ' .
        'recipient without authentication.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM:<random@external.com>\r\n",
            "RCPT TO:<external@elsewhere.com>\r\n",
            "QUIT\r\n",
        ]);
    },
];
$scenarios['smtp_local'] = [
    'group' => 'SMTP plaintext (port 2525)',
    'label' => 'Anonymous delivery to alice@localhost',
    'desc' => 'External sender, local recipient, no auth ' .
        'required (this is INBOUND mail).',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM:<chris@example.com>\r\n",
            "RCPT TO:<alice@localhost>\r\n",
            "DATA\r\n",
            "Subject: webui-test " . date('H:i:s') . "\r\n" .
                "From: chris@example.com\r\n" .
                "To: alice@localhost\r\n\r\n" .
                "Sent from the webui scenario runner.\r\n.\r\n",
            "QUIT\r\n",
        ]);
    },
];
/* ---------- SMTP auth ---------- */
$scenarios['smtp_auth_plain'] = [
    'group' => 'SMTP authentication',
    'label' => 'AUTH PLAIN as alice, deliver to bob',
    'desc' => 'AUTH PLAIN with the precomputed blob ' .
        'AGFsaWNlAGh1bnRlcjI= (alice / hunter2).',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "AUTH PLAIN AGFsaWNlAGh1bnRlcjI=\r\n",
            "MAIL FROM:<alice@localhost>\r\n",
            "RCPT TO:<bob@localhost>\r\n",
            "DATA\r\n",
            "Subject: from alice via webui\r\n" .
                "From: alice@localhost\r\n" .
                "To: bob@localhost\r\n\r\n" .
                "Authenticated submission.\r\n.\r\n",
            "QUIT\r\n",
        ]);
    },
];
$scenarios['smtp_auth_login'] = [
    'group' => 'SMTP authentication',
    'label' => 'AUTH LOGIN as bob (continuation)',
    'desc' => 'AUTH LOGIN walks through the two 334 ' .
        'challenges. bob -> Ym9i, hunter2 -> aHVudGVyMg==.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "AUTH LOGIN\r\n",
            "Ym9i\r\n",
            "aHVudGVyMg==\r\n",
            "QUIT\r\n",
        ]);
    },
];
/* ---------- Hooks ---------- */
$scenarios['hook_block'] = [
    'group' => 'Hooks',
    'label' => 'onHeader: [BLOCK] Subject -> 550',
    'desc' => 'Subject starting with [BLOCK] is rejected by ' .
        'policy at the onHeader stage.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM:<x@y.com>\r\n",
            "RCPT TO:<alice@localhost>\r\n",
            "DATA\r\n",
            "Subject: [BLOCK] go away\r\n\r\nbody\r\n.\r\n",
            "QUIT\r\n",
        ]);
    },
];
$scenarios['hook_spam'] = [
    'group' => 'Hooks',
    'label' => 'onMessage: [SPAM] Subject -> Junk folder',
    'desc' => 'Subject starting with [SPAM] gets routed to ' .
        'alice/Junk. Junk count is shown after delivery.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $users_file, $store_dir) {
        $tx = runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM:<x@y.com>\r\n",
            "RCPT TO:<alice@localhost>\r\n",
            "DATA\r\n",
            "Subject: [SPAM] cheap pills\r\n\r\nbody\r\n.\r\n",
            "QUIT\r\n",
        ]);
        $m = shareMail($users_file, $store_dir);
        $tx .= "\n--- direct API after delivery ---\n";
        $tx .= "alice/Junk count: " .
            $m->messageCount('alice', 'Junk') . "\n";
        return $tx;
    },
];
$scenarios['hook_drop'] = [
    'group' => 'Hooks',
    'label' => 'onMessage: noreply@ From -> silent drop',
    'desc' => 'noreply@ sender is dropped silently. Server ' .
        'still says 250 (does not leak filter behavior).',
    'kind' => 'wire',
    'run' => function () use ($cfg, $users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $before = $m->messageCount('alice', 'INBOX');
        $tx = runScript($cfg['host'], $cfg['smtp'], [
            "EHLO test\r\n",
            "MAIL FROM:<noreply@bot.com>\r\n",
            "RCPT TO:<alice@localhost>\r\n",
            "DATA\r\n",
            "Subject: ping\r\nFrom: noreply@bot.com\r\n\r\n" .
                "body\r\n.\r\n",
            "QUIT\r\n",
        ]);
        $after = $m->messageCount('alice', 'INBOX');
        $tx .= "\n--- direct API ---\n";
        $tx .= "alice/INBOX count before: $before\n";
        $tx .= "alice/INBOX count after:  $after\n";
        $tx .= ($before === $after) ?
            "(unchanged: filter dropped the message)\n" :
            "(grew: drop did not work?)\n";
        return $tx;
    },
];
/* ---------- IMAP plaintext ---------- */
$scenarios['imap_caps'] = [
    'group' => 'IMAP plaintext (port 1143)',
    'label' => 'CAPABILITY + LOGOUT',
    'desc' => 'IMAP4rev1 IDLE STARTTLS plus AUTH= or ' .
        'LOGINDISABLED depending on TLS state and config.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "1 CAPABILITY\r\n",
            "2 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_starttls'] = [
    'group' => 'IMAP plaintext (port 1143)',
    'label' => 'STARTTLS upgrade + post-upgrade CAPABILITY',
    'desc' => 'Issue STARTTLS, do the TLS handshake on this ' .
        'side, then re-issue CAPABILITY in the secure tunnel.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "1 CAPABILITY\r\n",
            "2 STARTTLS\r\n",
            "__STARTTLS_IMAP__",
            "3 CAPABILITY\r\n",
            "4 LOGOUT\r\n",
        ]);
    },
];
/* ---------- Implicit TLS ---------- */
$scenarios['smtps_banner'] = [
    'group' => 'Implicit TLS',
    'label' => 'SMTPS banner + EHLO (port 4465)',
    'desc' => 'TLS-from-the-start; EHLO inside the tunnel ' .
        'should NOT advertise STARTTLS again.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['smtps'], [
            "EHLO test\r\n",
            "QUIT\r\n",
        ], 'implicit');
    },
];
$scenarios['imaps_caps'] = [
    'group' => 'Implicit TLS',
    'label' => 'IMAPS CAPABILITY (port 9933)',
    'desc' => 'TLS-from-the-start; capabilities should NOT ' .
        'list STARTTLS or LOGINDISABLED.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imaps'], [
            "1 CAPABILITY\r\n",
            "2 LOGOUT\r\n",
        ], 'implicit');
    },
];
/* ---------- Direct API ---------- */
$scenarios['api_folders'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'List alice\'s folders',
    'desc' => '$mail->listFolders("alice") -- the same call ' .
        'a webmail UI would make.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $folders = $m->listFolders('alice');
        if (empty($folders)) {
            return "(alice has no folders yet; deliver some " .
                "messages first)\n";
        }
        return implode("\n", $folders) . "\n";
    },
];
$scenarios['api_inbox'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'List alice/INBOX metadata',
    'desc' => '$mail->listMessages("alice", "INBOX") -- ' .
        'returns uid, size, flags, internal_date.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $msgs = $m->listMessages('alice', 'INBOX');
        if (empty($msgs)) {
            return "(no messages in alice/INBOX)\n";
        }
        $out = sprintf("%-5s %-7s %-25s %s\n",
            'UID', 'SIZE', 'INTERNAL_DATE', 'FLAGS');
        foreach ($msgs as $meta) {
            $out .= sprintf("%-5d %-7d %-25s %s\n",
                $meta['uid'], $meta['size'],
                gmdate('Y-m-d H:i:s', $meta['internal_date']),
                implode(' ', $meta['flags']) ?: '(none)');
        }
        return $out;
    },
];
$scenarios['api_show'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'Fetch latest alice/INBOX message',
    'desc' => '$mail->fetchMessage(...) -- raw RFC 5322 ' .
        'bytes including the trace header we stamped.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $msgs = $m->listMessages('alice', 'INBOX');
        if (empty($msgs)) {
            return "(no messages in alice/INBOX)\n";
        }
        $latest = end($msgs);
        $bytes = $m->fetchMessage('alice', 'INBOX',
            $latest['uid']);
        return $bytes !== false ? $bytes :
            "(fetch returned false)\n";
    },
];
$scenarios['api_junk_count'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'alice/Junk message count',
    'desc' => '$mail->messageCount("alice", "Junk").',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        return "alice/Junk: " .
            $m->messageCount('alice', 'Junk') . "\n";
    },
];
/* ---------- HTTP routes ---------- */
$site->post('/run', function () use ($site, $scenarios) {
    $id = $_POST['scenario'] ?? '';
    $site->header("Content-Type: application/json; charset=utf-8");
    if (!isset($scenarios[$id])) {
        echo json_encode([
            'error' => "unknown scenario: $id",
        ]);
        return;
    }
    $tx = call_user_func($scenarios[$id]['run']);
    echo json_encode([
        'transcript' => $tx,
        'label' => $scenarios[$id]['label'],
    ]);
});
$site->get('/', function () use ($scenarios) {
    /*
        Group scenarios by their 'group' field for rendering.
        Stable order: keys are inserted in scenario-list
        declaration order, so the first group seen leads.
     */
    $by_group = [];
    foreach ($scenarios as $id => $s) {
        $by_group[$s['group']][$id] = $s;
    }
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AttoMail Demo Harness</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    max-width: 920px; margin: 1.5em auto; padding: 0 1em;
    color: #222; }
h1 { margin-bottom: 0.1em; }
.meta { color: #666; font-size: 0.9em; margin-bottom: 1.5em; }
h2 { font-size: 1.05em; margin-top: 1.6em; padding-bottom: 0.2em;
    border-bottom: 1px solid #ddd; }
.scenario { margin: 0.6em 0; padding: 0.7em 0.9em;
    background: #f6f6f6; border-radius: 4px; }
.scenario .row { display: flex; align-items: center;
    justify-content: space-between; gap: 1em; }
.scenario button { font: inherit; padding: 0.35em 0.9em;
    background: #06c; color: white; border: 0; border-radius: 4px;
    cursor: pointer; flex-shrink: 0; }
.scenario button:disabled { background: #888; cursor: default; }
.scenario .label { font-weight: 600; }
.scenario .desc { color: #555; font-size: 0.92em;
    margin-top: 0.25em; }
.scenario .transcript { display: none; margin-top: 0.7em;
    background: #1e1e1e; color: #ddd; padding: 0.8em;
    border-radius: 4px; white-space: pre-wrap; font-size: 0.85em;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    max-height: 360px; overflow: auto; }
.scenario .transcript.visible { display: block; }
.note { color: #555; font-size: 0.88em; }
code { background: #eee; padding: 0.1em 0.3em; border-radius: 3px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<h1>AttoMail Demo Harness</h1>
<div class="meta">
Companion UI to <code>index.php</code>. Each scenario opens a
short connection to one of the listening ports (SMTP 2525,
IMAP 1143, SMTPS 4465, IMAPS 9933) and shows the protocol
transcript. The "Direct API" scenarios bypass the wire
protocol and call <code>MailSite</code> public methods on a
shared instance pointing at the same on-disk store.
</div>
<p class="note">Demo accounts: <code>alice</code> /
<code>bob</code>, password <code>hunter2</code>.</p>
<?php foreach ($by_group as $group => $items): ?>
<h2><?= htmlspecialchars($group) ?></h2>
<?php foreach ($items as $id => $s): ?>
<div class="scenario" data-id="<?= htmlspecialchars($id) ?>">
<div class="row">
<div>
<div class="label"><?= htmlspecialchars($s['label']) ?></div>
<div class="desc"><?= htmlspecialchars($s['desc']) ?></div>
</div>
<button type="button">Run</button>
</div>
<pre class="transcript"></pre>
</div>
<?php endforeach; endforeach; ?>
<script>
document.querySelectorAll('.scenario').forEach(function (el) {
    var btn = el.querySelector('button');
    var id = el.dataset.id;
    var pre = el.querySelector('.transcript');
    btn.addEventListener('click', function () {
        btn.disabled = true;
        btn.textContent = 'Running...';
        pre.classList.add('visible');
        pre.textContent = '(running...)';
        var body = new URLSearchParams();
        body.set('scenario', id);
        fetch('/run', {
            method: 'POST',
            headers: {
                'Content-Type':
                    'application/x-www-form-urlencoded'
            },
            body: body.toString()
        }).then(function (r) {
            return r.json();
        }).then(function (data) {
            if (data.error) {
                pre.textContent = 'ERROR: ' + data.error;
            } else {
                pre.textContent = data.transcript ||
                    '(empty transcript)';
            }
        }).catch(function (err) {
            pre.textContent = 'ERROR: ' + err;
        }).finally(function () {
            btn.disabled = false;
            btn.textContent = 'Run';
        });
    });
});
</script>
</body>
</html><?php
});
if ($site->isCli()) {
    $site->listen(8080);
} else {
    $site->process();
}
