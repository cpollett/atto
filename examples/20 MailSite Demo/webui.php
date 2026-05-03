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
/* ---------- IMAP authenticated (Phase 3) ---------- */
$scenarios['imap_login_list'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'LOGIN alice and LIST all folders',
    'desc' => 'LOGIN with quoted credentials, then LIST "" "*" ' .
        'to get the full folder tree.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN \"alice\" \"hunter2\"\r\n",
            "a2 LIST \"\" \"*\"\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_auth_plain'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'AUTHENTICATE PLAIN as alice',
    'desc' => 'Single-step base64 blob ' .
        'AGFsaWNlAGh1bnRlcjI= (alice / hunter2). Same blob ' .
        'used by SMTP AUTH PLAIN.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 AUTHENTICATE PLAIN\r\n",
            "AGFsaWNlAGh1bnRlcjI=\r\n",
            "a2 LIST \"\" \"*\"\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_auth_login'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'AUTHENTICATE LOGIN as bob (continuation)',
    'desc' => 'Two-step continuation; the server prompts ' .
        'with base64-encoded "Username:" and "Password:" ' .
        'between turns.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 AUTHENTICATE LOGIN\r\n",
            "Ym9i\r\n",
            "aHVudGVyMg==\r\n",
            "a2 LIST \"\" \"*\"\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_select'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'SELECT INBOX, EXAMINE Junk, CLOSE',
    'desc' => 'SELECT opens read-write; EXAMINE opens ' .
        'read-only. Both return EXISTS, RECENT, UIDVALIDITY, ' .
        'UIDNEXT, FLAGS, PERMANENTFLAGS.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 CLOSE\r\n",
            "a4 EXAMINE Junk\r\n",
            "a5 CLOSE\r\n",
            "a6 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_status'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'STATUS without selecting',
    'desc' => 'Probes message counts and UID metadata for a ' .
        'mailbox without making it the active one.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 STATUS INBOX (MESSAGES UIDNEXT " .
                "UIDVALIDITY UNSEEN RECENT)\r\n",
            "a3 STATUS Junk (MESSAGES UIDNEXT)\r\n",
            "a4 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_create_rename_delete'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'CREATE / RENAME / DELETE folder lifecycle',
    'desc' => 'Build a hierarchy under Archive/, rename a ' .
        'subfolder, then delete it. INBOX cannot be deleted.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 CREATE Archive\r\n",
            "a3 CREATE \"Archive/2025\"\r\n",
            "a4 LIST \"\" \"*\"\r\n",
            "a5 RENAME \"Archive/2025\" \"Archive/Old\"\r\n",
            "a6 LIST \"\" \"*\"\r\n",
            "a7 DELETE \"Archive/Old\"\r\n",
            "a8 DELETE Archive\r\n",
            "a9 DELETE INBOX\r\n",
            "a10 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_login_required'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'Pre-auth refusal: LIST without LOGIN',
    'desc' => 'Commands that require authentication get ' .
        '"NO Login required" before LOGIN runs.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LIST \"\" \"*\"\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_bad_password'] = [
    'group' => 'IMAP authenticated (port 1143)',
    'label' => 'Bad password rejection',
    'desc' => 'LOGIN with wrong password returns ' .
        '"NO [AUTHENTICATIONFAILED]" and the connection ' .
        'stays in INIT state.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice wrong-password\r\n",
            "a2 LIST \"\" \"*\"\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
/*
    Helper used by the message-ops scenarios below: deliver a
    couple of test messages to alice/INBOX via SMTP so each
    scenario starts with something to operate on. Idempotent;
    if the scenarios are re-run after a Reset, the deliveries
    re-populate INBOX.
 */
$prep_inbox = function () use ($cfg) {
    runScript($cfg['host'], $cfg['smtp'], [
        "EHLO test\r\n",
        "MAIL FROM:<x@y.com>\r\n",
        "RCPT TO:<alice@localhost>\r\n",
        "DATA\r\n",
        "Subject: hello\r\n" .
            "From: x@y.com\r\n" .
            "To: alice@localhost\r\n" .
            "Message-ID: <hello@y.com>\r\n" .
            "Date: Mon, 01 Jan 2026 12:00:00 +0000\r\n\r\n" .
            "First test message body.\r\n.\r\n",
        "QUIT\r\n",
    ]);
    runScript($cfg['host'], $cfg['smtp'], [
        "EHLO test\r\n",
        "MAIL FROM:<pizza@shop.com>\r\n",
        "RCPT TO:<alice@localhost>\r\n",
        "DATA\r\n",
        "Subject: hot pizza\r\n" .
            "From: pizza@shop.com\r\n" .
            "To: alice@localhost\r\n\r\n" .
            "yummy body content\r\n.\r\n",
        "QUIT\r\n",
    ]);
};
/* ---------- IMAP message operations (Phase 4) ---------- */
$scenarios['imap_fetch_basic'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'FETCH 1:* (FLAGS UID INTERNALDATE RFC822.SIZE)',
    'desc' => 'The standard message-list query a webmail UI ' .
        'issues right after SELECT. One untagged FETCH ' .
        'response per message.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 FETCH 1:* (FLAGS UID INTERNALDATE " .
                "RFC822.SIZE)\r\n",
            "a4 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_fetch_envelope'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'FETCH 1 (ENVELOPE)',
    'desc' => 'IMAP-parsed envelope: date, subject, from, ' .
        'sender, reply-to, to, cc, bcc, in-reply-to, ' .
        'message-id. Each address is a paren-list of ' .
        '(name source-route mailbox-local host).',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 FETCH 1 (ENVELOPE)\r\n",
            "a4 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_fetch_body'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'FETCH 1 BODY[HEADER.FIELDS (Subject From)]',
    'desc' => 'Selective header fetch. PEEK form would not ' .
        'set \\Seen; using non-PEEK BODY[HEADER.FIELDS] ' .
        'leaves \\Seen untouched per RFC 3501 since only ' .
        'BODY[] / BODY[TEXT] / BODY[<part>] without HEADER ' .
        'is considered "viewing" the body.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 FETCH 1 BODY.PEEK[HEADER.FIELDS " .
                "(Subject From Date)]\r\n",
            "a4 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_store_seen'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'STORE +FLAGS (\\Seen) and -FLAGS (\\Recent)',
    'desc' => 'Add or remove flags on a message set. .SILENT ' .
        'variant suppresses the per-message FETCH response.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 STORE 1 +FLAGS (\\Seen \\Flagged)\r\n",
            "a4 STORE 2 FLAGS.SILENT (\\Deleted)\r\n",
            "a5 FETCH 1:* (FLAGS)\r\n",
            "a6 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_uid_fetch'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'UID FETCH 1:* (FLAGS) -- UID auto-included',
    'desc' => 'UID-prefixed FETCH operates on UIDs rather ' .
        'than sequence numbers. Per RFC 3501 sec 6.4.8 the ' .
        'response MUST include a UID data item even when ' .
        'the client did not request one.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 UID FETCH 1:* (FLAGS)\r\n",
            "a4 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_copy'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'COPY 1:2 to a sibling folder',
    'desc' => 'COPY allocates fresh UIDs in the target ' .
        'because each message file gets a new UID from the ' .
        'per-user counter. Flags carry over.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 CREATE Saved\r\n",
            "a3 SELECT INBOX\r\n",
            "a4 COPY 1:2 Saved\r\n",
            "a5 EXAMINE Saved\r\n",
            "a6 FETCH 1:* (UID FLAGS)\r\n",
            "a7 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_move'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'MOVE 1 to Junk (UID preserved)',
    'desc' => 'MOVE (RFC 6851) relocates files in place, so ' .
        'UIDs are preserved across the move. The source ' .
        'mailbox sees an EXPUNGE response per moved msg.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 MOVE 1 Junk\r\n",
            "a4 EXAMINE Junk\r\n",
            "a5 FETCH 1:* (UID FLAGS)\r\n",
            "a6 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_expunge'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'STORE \\Deleted then EXPUNGE',
    'desc' => 'Mark a message \\Deleted, then EXPUNGE to ' .
        'permanently remove. The server emits one ' .
        '"* N EXPUNGE" per removed message in descending ' .
        'sequence order so client counts stay consistent.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 STORE 2 +FLAGS (\\Deleted)\r\n",
            "a4 EXPUNGE\r\n",
            "a5 FETCH 1:* (UID FLAGS)\r\n",
            "a6 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_search'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'SEARCH boolean queries',
    'desc' => 'A few common SEARCH forms: UNSEEN, FROM ' .
        'substring, SUBJECT substring, BODY substring, NOT, ' .
        'OR, and a sequence-set predicate.',
    'kind' => 'wire',
    'run' => function () use ($cfg, $prep_inbox) {
        $prep_inbox();
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 SEARCH ALL\r\n",
            "a4 SEARCH UNSEEN\r\n",
            "a5 SEARCH FROM \"pizza\"\r\n",
            "a6 SEARCH SUBJECT \"hello\"\r\n",
            "a7 SEARCH BODY \"yummy\"\r\n",
            "a8 SEARCH OR FLAGGED FROM \"pizza\"\r\n",
            "a9 SEARCH NOT SEEN\r\n",
            "a10 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_append'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'APPEND a literal-bodied message',
    'desc' => 'APPEND with a (\\Seen) flag list and a ' .
        'synchronizing literal {N} body. Server replies ' .
        '"+ Ready", consumes the byte-counted body across ' .
        'TCP fragments, and finishes with "OK [APPENDUID ' .
        'validity uid]".',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        $body = "Subject: from APPEND\r\n" .
            "From: x@y.com\r\n" .
            "To: alice@localhost\r\n\r\n" .
            "Body delivered via APPEND, not SMTP.\r\n";
        $size = strlen($body);
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 APPEND INBOX (\\Seen) {" . $size . "}\r\n",
            $body,
            "a3 SELECT INBOX\r\n",
            "a4 FETCH 1:* (UID FLAGS)\r\n",
            "a5 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_idle'] = [
    'group' => 'IMAP message ops (Phase 4)',
    'label' => 'IDLE / DONE round-trip',
    'desc' => 'Client says IDLE, server replies "+ idling" ' .
        'and parks. Client sends "DONE" on its own line to ' .
        'terminate. Server-side push of new-mail ' .
        'notifications during the idle window is not yet ' .
        'implemented; the round-trip is exercised here.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 SELECT INBOX\r\n",
            "a3 IDLE\r\n",
            "DONE\r\n",
            "a4 NOOP\r\n",
            "a5 LOGOUT\r\n",
        ]);
    },
];
/* ---------- IMAP capabilities + MIME (Phase 5) ---------- */
$scenarios['imap_special_use'] = [
    'group' => 'IMAP capabilities + MIME (Phase 5)',
    'label' => 'SPECIAL-USE attributes in LIST',
    'desc' => 'Folders named Drafts / Sent / Trash / Junk / ' .
        'Archive get RFC 6154 special-use attributes in LIST ' .
        'so clients can auto-discover the right destination ' .
        'for "Save Sent", "Save Draft", "Move to Trash", etc. ' .
        '\\HasChildren / \\HasNoChildren are RFC 3348 ' .
        'children flags clients use to render the tree.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 CREATE Drafts\r\n",
            "a3 CREATE Sent\r\n",
            "a4 CREATE Trash\r\n",
            "a5 CREATE Archive\r\n",
            "a6 CREATE \"Archive/2025\"\r\n",
            "a7 LIST \"\" \"*\"\r\n",
            "a8 LIST (SPECIAL-USE) \"\" \"*\"\r\n",
            "a9 LIST \"\" \"*\" RETURN (CHILDREN SPECIAL-USE)\r\n",
            "a10 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_namespace'] = [
    'group' => 'IMAP capabilities + MIME (Phase 5)',
    'label' => 'NAMESPACE response',
    'desc' => 'Tells the client about personal, other-users, ' .
        'and shared mailbox prefixes. We have a single ' .
        'personal namespace using "/" as the hierarchy ' .
        'delimiter, no shared or other-users namespaces.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 NAMESPACE\r\n",
            "a3 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_id'] = [
    'group' => 'IMAP capabilities + MIME (Phase 5)',
    'label' => 'ID exchange (RFC 2971)',
    'desc' => 'Client sends a paren-list of name/value ' .
        'identification strings; server replies with its own ' .
        'identification. Permitted in any state including ' .
        'before LOGIN.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 ID (\"name\" \"TestClient\" \"version\" \"1.0\")\r\n",
            "a2 LOGOUT\r\n",
        ]);
    },
];
$scenarios['imap_multipart'] = [
    'group' => 'IMAP capabilities + MIME (Phase 5)',
    'label' => 'Multipart MIME: BODYSTRUCTURE + BODY[1] / BODY[2]',
    'desc' => 'APPEND a multipart/alternative message ' .
        '(text/plain + text/html), then FETCH BODYSTRUCTURE ' .
        'to see the nested structure and BODY[1] / BODY[2] ' .
        'to fetch each part individually.',
    'kind' => 'wire',
    'run' => function () use ($cfg) {
        $body = "Subject: multipart demo\r\n" .
            "From: x@y.com\r\n" .
            "To: alice@localhost\r\n" .
            "MIME-Version: 1.0\r\n" .
            "Content-Type: multipart/alternative; " .
                "boundary=\"BOUNDARY42\"\r\n\r\n" .
            "--BOUNDARY42\r\n" .
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n" .
            "This is the plain text part.\r\n" .
            "--BOUNDARY42\r\n" .
            "Content-Type: text/html; charset=UTF-8\r\n" .
            "Content-Transfer-Encoding: quoted-printable" .
                "\r\n\r\n" .
            "<html><body><p>HTML version.</p></body>" .
                "</html>\r\n" .
            "--BOUNDARY42--\r\n";
        $size = strlen($body);
        return runScript($cfg['host'], $cfg['imap'], [
            "a1 LOGIN alice hunter2\r\n",
            "a2 APPEND INBOX {" . $size . "}\r\n",
            $body,
            "a3 SELECT INBOX\r\n",
            "a4 FETCH 1 (BODYSTRUCTURE)\r\n",
            "a5 FETCH 1 BODY.PEEK[1]\r\n",
            "a6 FETCH 1 BODY.PEEK[2]\r\n",
            "a7 FETCH 1 BODY.PEEK[1.MIME]\r\n",
            "a8 LOGOUT\r\n",
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
    'desc' => '$mail->fetchMessage("alice", "INBOX", $uid) ' .
        'returns raw RFC 5322 bytes, including the Received: ' .
        'trace header we stamped on inbound.',
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
$scenarios['api_create_folder'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'Create a folder via the direct API',
    'desc' => '$mail->createFolder("alice", "Notes") -- ' .
        'idempotent; calling on an existing folder is a ' .
        'successful no-op.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $m->createFolder('alice', 'Notes');
        $tx = "Folders after createFolder('Notes'):\n";
        foreach ($m->listFolders('alice') as $f) {
            $tx .= "  $f\n";
        }
        $tx .= "\nCalling createFolder('Notes') again is a " .
            "no-op:\n";
        $tx .= "  result = " .
            ($m->createFolder('alice', 'Notes') ?
                'true (idempotent)' : 'false') . "\n";
        return $tx;
    },
];
$scenarios['api_lifecycle'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'CREATE / RENAME / DELETE folder lifecycle',
    'desc' => 'Walks createFolder -> renameFolder -> ' .
        'deleteFolder, listing folders at each step. ' .
        'deleteFolder("alice", "INBOX") is refused.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $tx = "";
        $list = function ($label) use ($m, &$tx) {
            $tx .= "$label:\n";
            foreach ($m->listFolders('alice') as $f) {
                $tx .= "  $f\n";
            }
            $tx .= "\n";
        };
        $list("Folders at start");
        $tx .= '$mail->createFolder("alice", "Demo") => ' .
            ($m->createFolder('alice', 'Demo') ? 'true' :
                'false') . "\n";
        $tx .= '$mail->createFolder("alice", "Demo/2026") => ' .
            ($m->createFolder('alice', 'Demo/2026') ? 'true' :
                'false') . "\n";
        $list("After CREATE");
        $tx .= '$mail->renameFolder("alice", "Demo/2026",' .
            ' "Demo/Archived") => ' .
            ($m->renameFolder('alice', 'Demo/2026',
                'Demo/Archived') ? 'true' : 'false') . "\n";
        $list("After RENAME");
        $tx .= '$mail->deleteFolder("alice", "Demo/Archived")' .
            ' => ' .
            ($m->deleteFolder('alice', 'Demo/Archived') ?
                'true' : 'false') . "\n";
        $tx .= '$mail->deleteFolder("alice", "Demo") => ' .
            ($m->deleteFolder('alice', 'Demo') ? 'true' :
                'false') . "\n";
        $list("After DELETE");
        $tx .= '$mail->deleteFolder("alice", "INBOX") => ' .
            ($m->deleteFolder('alice', 'INBOX') ? 'true' :
                'false (refused; INBOX is reserved)') . "\n";
        return $tx;
    },
];
$scenarios['api_setflags'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'Set flags on the latest INBOX message',
    'desc' => '$mail->setFlags("alice", "INBOX", $uid, ' .
        '["\\Seen", "\\Flagged"]) replaces the flag set. ' .
        'Pass [] to clear all flags.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $msgs = $m->listMessages('alice', 'INBOX');
        if (empty($msgs)) {
            return "(no messages in alice/INBOX; deliver " .
                "one first via the SMTP scenarios)\n";
        }
        $latest = end($msgs);
        $uid = $latest['uid'];
        $tx = "Operating on alice/INBOX UID $uid\n";
        $tx .= "Flags before: " .
            (implode(' ', $latest['flags']) ?: '(none)') .
            "\n";
        $m->setFlags('alice', 'INBOX', $uid,
            ['\Seen', '\Flagged']);
        $after = $m->messageMeta('alice', 'INBOX', $uid);
        $tx .= "Flags after setFlags(\\Seen, \\Flagged): " .
            (implode(' ', $after['flags']) ?: '(none)') .
            "\n";
        return $tx;
    },
];
$scenarios['api_movemessage'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'Move a message between folders',
    'desc' => '$mail->moveMessage("alice", "INBOX", "Junk", ' .
        '$uid). UID is preserved across the move because ' .
        'UIDs are per-user, not per-folder (matches IMAP ' .
        'UIDPLUS semantics).',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $msgs = $m->listMessages('alice', 'INBOX');
        if (empty($msgs)) {
            return "(no messages in alice/INBOX; deliver " .
                "one first via the SMTP scenarios)\n";
        }
        $latest = end($msgs);
        $uid = $latest['uid'];
        $m->createFolder('alice', 'Junk');
        $tx = "INBOX before: " .
            $m->messageCount('alice', 'INBOX') .
            " message(s); Junk before: " .
            $m->messageCount('alice', 'Junk') .
            " message(s)\n";
        $tx .= '$mail->moveMessage("alice", "INBOX", ' .
            "\"Junk\", $uid) => " .
            ($m->moveMessage('alice', 'INBOX', 'Junk', $uid) ?
                'true' : 'false') . "\n";
        $tx .= "INBOX after:  " .
            $m->messageCount('alice', 'INBOX') .
            " message(s); Junk after:  " .
            $m->messageCount('alice', 'Junk') .
            " message(s)\n";
        $moved = $m->messageMeta('alice', 'Junk', $uid);
        if ($moved !== false) {
            $tx .= "Junk now contains UID $uid (preserved " .
                "across the move).\n";
        } else {
            $tx .= "(could not find UID $uid in Junk after " .
                "move)\n";
        }
        return $tx;
    },
];
$scenarios['api_uidnext'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'uidNext / uidValidity for INBOX',
    'desc' => '$mail->uidNext() and $mail->uidValidity() ' .
        'expose the same UIDNEXT and UIDVALIDITY a webmail ' .
        'cache uses for invalidation.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        return "uidNext('alice', 'INBOX')     = " .
            $m->uidNext('alice', 'INBOX') . "\n" .
            "uidValidity('alice', 'INBOX') = " .
            $m->uidValidity('alice', 'INBOX') . "\n";
    },
];
$scenarios['api_folder_exists'] = [
    'group' => 'Direct API (no wire protocol)',
    'label' => 'folderExists probe',
    'desc' => '$mail->folderExists() returns a boolean ' .
        'without scanning the full folder list.',
    'kind' => 'api',
    'run' => function () use ($users_file, $store_dir) {
        $m = shareMail($users_file, $store_dir);
        $tx = "folderExists('alice', 'INBOX')   = " .
            ($m->folderExists('alice', 'INBOX') ? 'true' :
                'false') . "\n";
        $tx .= "folderExists('alice', 'NoSuch')  = " .
            ($m->folderExists('alice', 'NoSuch') ? 'true' :
                'false') . "\n";
        $tx .= "folderExists('alice', 'Junk')    = " .
            ($m->folderExists('alice', 'Junk') ? 'true' :
                'false') . "\n";
        return $tx;
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
/*
    POST /reset wipes the on-disk message store so subsequent
    scenario runs start from a clean slate. Deletes everything
    under maildata/ but leaves users.htpasswd alone (that file
    is a static seed; removing it would lock alice/bob out
    until index.php restart re-seeded it). The recursive
    deletion uses RecursiveIteratorIterator with CHILD_FIRST
    so files are unlinked before the directories that contain
    them, the only walk order rmdir tolerates.
 */
$site->post('/reset', function () use ($site, $store_dir) {
    $site->header("Content-Type: application/json; charset=utf-8");
    if (!is_dir($store_dir)) {
        echo json_encode([
            'message' => 'maildata/ already absent; nothing ' .
                'to do.',
        ]);
        return;
    }
    $errors = [];
    $deleted_files = 0;
    $deleted_dirs = 0;
    try {
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($store_dir,
                \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $entry) {
            $path = $entry->getPathname();
            if ($entry->isDir()) {
                if (@rmdir($path)) {
                    $deleted_dirs++;
                } else {
                    $errors[] = "rmdir failed: $path";
                }
            } else {
                if (@unlink($path)) {
                    $deleted_files++;
                } else {
                    $errors[] = "unlink failed: $path";
                }
            }
        }
        /*
            The iterator does not visit the root itself; remove
            and recreate it so the next delivery has a fresh
            directory to populate.
         */
        @rmdir($store_dir);
        @mkdir($store_dir, 0700, true);
    } catch (\Throwable $e) {
        $errors[] = $e->getMessage();
    }
    echo json_encode([
        'message' => "Reset complete. Deleted $deleted_files " .
            "file(s) and $deleted_dirs director(ies).",
        'errors' => $errors,
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
    cursor: pointer; flex-shrink: 0; min-width: 4.5em;
    text-align: center; }
.scenario button:disabled { background: #888; cursor: default; }
.scenario button.close { background: #b33; }
.scenario button.close:hover { background: #c44; }
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
.reset-bar { display: flex; align-items: center; gap: 1em;
    margin: 1em 0 1.5em; padding: 0.7em 0.9em;
    background: #fff8e6; border: 1px solid #f0d890;
    border-radius: 4px; }
.reset-bar button { font: inherit; padding: 0.4em 1em;
    background: #d97706; color: white; border: 0;
    border-radius: 4px; cursor: pointer; flex-shrink: 0; }
.reset-bar button:hover { background: #b85f04; }
.reset-bar button:disabled { background: #888; cursor: default; }
.reset-bar .reset-status { color: #555; font-size: 0.9em; }
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
<div class="reset-bar">
<button type="button" id="reset-btn">Reset all stored mail</button>
<span class="reset-status" id="reset-status">
Wipes <code>maildata/</code> so every scenario starts fresh.
The committed <code>users.htpasswd</code> is left in place.
</span>
</div>
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
/*
    Each scenario button is a tri-state toggle:
        Run   -> click sends the request and renders the
                 transcript; the button switches to [X].
        [X]   -> click hides the transcript and reverts the
                 button to Run.
        busy  -> while the request is in flight the button
                 shows "Running..." and is disabled.
 */
document.querySelectorAll('.scenario').forEach(function (el) {
    var btn = el.querySelector('button');
    var id = el.dataset.id;
    var pre = el.querySelector('.transcript');
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
    btn.addEventListener('click', function () {
        if (btn.classList.contains('close')) {
            pre.classList.remove('visible');
            pre.textContent = '';
            showRun();
            return;
        }
        showBusy();
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
            showClose();
        }).catch(function (err) {
            pre.textContent = 'ERROR: ' + err;
            showClose();
        });
    });
});
/*
    Reset button: confirms before posting to /reset, then
    reports the deletion summary. Also closes any open
    scenario transcripts since their results may now be stale.
 */
(function () {
    var resetBtn = document.getElementById('reset-btn');
    var resetStatus = document.getElementById('reset-status');
    var defaultStatus = resetStatus.innerHTML;
    resetBtn.addEventListener('click', function () {
        if (!window.confirm(
            'Delete every stored message under maildata/?\n' +
            'This cannot be undone.')) {
            return;
        }
        resetBtn.disabled = true;
        resetBtn.textContent = 'Resetting...';
        resetStatus.textContent = '';
        fetch('/reset', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                resetStatus.textContent = data.message ||
                    '(reset returned no message)';
                if (data.errors && data.errors.length) {
                    resetStatus.textContent += ' Errors: ' +
                        data.errors.join('; ');
                }
                document.querySelectorAll('.scenario')
                    .forEach(function (el) {
                        var pre = el.querySelector('.transcript');
                        var btn = el.querySelector('button');
                        pre.classList.remove('visible');
                        pre.textContent = '';
                        btn.textContent = 'Run';
                        btn.classList.remove('close');
                        btn.disabled = false;
                    });
            })
            .catch(function (err) {
                resetStatus.textContent = 'ERROR: ' + err;
            })
            .finally(function () {
                resetBtn.disabled = false;
                resetBtn.textContent = 'Reset all stored mail';
                /*
                    Restore the original explanatory text after
                    a few seconds so the bar does not stay
                    cluttered with the last operation summary.
                 */
                setTimeout(function () {
                    resetStatus.innerHTML = defaultStatus;
                }, 6000);
            });
    });
})();
</script>
</body>
</html><?php
});
if ($site->isCli()) {
    $site->listen(8080);
} else {
    $site->process();
}
