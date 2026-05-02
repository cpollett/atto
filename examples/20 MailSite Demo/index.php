<?php
/**
 * AttoMail demo: a minimal mail server backed by a flat
 * password file and an on-disk message store. Demonstrates:
 *   - FileAuthenticator for password-file accounts
 *   - FileMailStorage for per-user folders on disk
 *   - Per-stage hooks: onConnect (IP allow-list), onMailFrom
 *     (sender policy), onHeader (subject filter), onMessage
 *     (folder routing)
 *   - STARTTLS for both SMTP and IMAP, plus implicit-TLS
 *     submission on SMTPS_PORT and IMAPS_PORT
 *   - Anti-relay enforcement (try sending to an external
 *     address without authenticating; you will get 550)
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * That single command boots the mail listeners and spawns a
 * companion WebSite on http://localhost:8080/ that exposes a
 * click-through harness for driving the mail server. Open the
 * browser to that URL after launching. Bind to 25/143/465/993
 * in production (you will need root or setcap on the php
 * binary).
 *
 *
 * --- TEST CREDENTIALS (preseeded into users.htpasswd) ---
 *
 * Two demo accounts, both with password 'hunter2'.
 *
 *   Username   Password
 *   --------   --------
 *   alice      hunter2
 *   bob        hunter2
 *
 *
 * --- AUTH STRINGS (for typing into telnet / openssl) ---
 *
 * AUTH PLAIN takes a single base64 blob of "\0username\0password":
 *
 *   AUTH PLAIN AGFsaWNlAGh1bnRlcjI=     (alice / hunter2)
 *   AUTH PLAIN AGJvYgBodW50ZXIy         (bob   / hunter2)
 *
 * AUTH LOGIN is a two-step continuation. After "AUTH LOGIN"
 * the server responds "334 VXNlcm5hbWU6" (base64 "Username:")
 * and then "334 UGFzc3dvcmQ6" (base64 "Password:"). Send the
 * usernames and password base64-encoded:
 *
 *   alice   -> YWxpY2U=
 *   bob     -> Ym9i
 *   hunter2 -> aHVudGVyMg==        (password for both)
 *
 *
 * --- SAMPLE SESSION ---
 *
 *   $ telnet localhost 2525
 *   220 localhost AttoMail ESMTP ready
 *   EHLO test
 *   250-localhost Hello
 *   250-STARTTLS
 *   250-AUTH PLAIN LOGIN
 *   250-SIZE 26214400
 *   250 HELP
 *   AUTH PLAIN AGFsaWNlAGh1bnRlcjI=
 *   235 2.7.0 Authentication succeeded
 *   MAIL FROM: alice@localhost
 *   250 2.1.0 Ok
 *   RCPT TO: bob@localhost
 *   250 2.1.5 Ok
 *   DATA
 *   354 End data with <CR><LF>.<CR><LF>
 *   Subject: hi bob
 *
 *   short body
 *   .
 *   250 2.0.0 Ok: message accepted
 *   QUIT
 *   221 Bye
 *
 * Bare-word MAIL FROM / RCPT TO (no angle brackets) is
 * accepted as a tolerance for clumsy hand-typing.
 */
require '../../src/MailSite.php';
use seekquarry\atto\MailSite;
use seekquarry\atto\FileAuthenticator;
use seekquarry\atto\FileMailStorage;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
/*
    Create a password file on first run if the committed
    users.htpasswd is missing. In a real deployment maintain
    this file with htpasswd -B users.htpasswd alice or write
    your own admin tool that calls password_hash().
 */
$users_file = __DIR__ . '/users.htpasswd';
if (!is_file($users_file)) {
    $hash = password_hash('hunter2', PASSWORD_BCRYPT);
    file_put_contents($users_file, "alice:$hash\nbob:$hash\n");
    chmod($users_file, 0600);
    echo "Created $users_file with demo accounts alice / bob, " .
        "password 'hunter2'\n";
}
/*
    On-disk mail store under maildata/. The directory is
    created lazily on first delivery. Per-user state lives
    under maildata/users/<username>/.
 */
$store_dir = __DIR__ . '/maildata';
if (!is_dir($store_dir)) {
    mkdir($store_dir, 0700, true);
}
$mail = new MailSite();
$mail->auth(new FileAuthenticator($users_file));
$mail->storage(new FileMailStorage($store_dir));
$mail->domains(['localhost', 'example.test']);
/*
    onConnect: an IP-based allow-list / deny-list lives here.
    Example below is permissive; uncomment the deny block to
    refuse a specific source.
 */
$mail->onConnect(function ($info, $ctx) {
    /*
    if ($info['remote_addr'] === '203.0.113.7') {
        return 'reject';
    }
    */
    return null;
});
/*
    onMailFrom: drop messages from obviously-bogus senders at
    the envelope step, before the client even ships DATA.
 */
$mail->onMailFrom(function ($info, $ctx) {
    $from = strtolower($info['from']);
    if (strpos($from, 'spammer@') === 0) {
        return 'reject';
    }
    return null;
});
/*
    onHeader: inspect parsed headers to apply policy that
    needs the message-as-written. Reject (hard 550) anything
    whose Subject begins with [BLOCK].
 */
$mail->onHeader(function ($info, $ctx) {
    foreach ($info['headers'] as $h) {
        if (strcasecmp($h[0], 'Subject') === 0 &&
            stripos($h[1], '[BLOCK]') === 0) {
            return 'reject';
        }
    }
    return null;
});
/*
    onMessage: final delivery decision. [SPAM]-tagged subjects
    go to Junk; messages from no-reply / mailer-daemon Froms
    are dropped silently.
 */
$mail->onMessage(function ($info, $ctx) {
    $bytes = $info['bytes'];
    if (preg_match(
        '/^From:\s*<?(?:no-?reply|mailer-daemon)@/im',
        $bytes)) {
        return false;
    }
    if (preg_match('/^Subject:\s*\[SPAM\]/im', $bytes)) {
        return ['folder' => 'Junk', 'flags' => ['\Recent']];
    }
    return true;
});
/*
    Spawn the companion WebSite (webui.php) as a detached
    child process. The pattern follows the cross-platform
    recipe used elsewhere in atto: "start /B" on Windows,
    "&"-detach on Unix, with pclose(popen(...)) so the parent
    does not wait. We capture the child PID on Unix so a
    register_shutdown_function can stop the webui when the
    mail server exits; on Windows the user closes the spawned
    cmd window or kills via Task Manager.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . "webui.php");
if (strstr(PHP_OS, "WIN")) {
    $job = "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows; close cmd window to stop)\n";
} else {
    /*
        { exec ... } & echo $! gives us the exact PID of the
        php interpreter running webui.php, not a transient
        subshell. Without this wrapper, $! would point at the
        subshell that wrapped the redirection and the kill
        below would silently miss the actual webui process.
     */
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
$mail->setTimer(60, function () {
    echo "[" . date('H:i:s') . "] heartbeat, mem=" .
        round(memory_get_usage() / 1024) . "KiB\n";
});
$mail->listen([
    'SMTP_PORT' => 2525,
    'IMAP_PORT' => 1143,
    'SMTPS_PORT' => 4465,
    'IMAPS_PORT' => 9933,
    'SERVER_NAME' => 'localhost',
    'ALLOW_PLAINTEXT_AUTH' => true,
    'SERVER_CONTEXT' => ['ssl' => [
        'allow_self_signed' => true,
        'local_cert' => __DIR__ . '/../../security/server.crt',
        'local_pk' => __DIR__ . '/../../security/server.key',
        'verify_peer' => false,
    ]],
]);
