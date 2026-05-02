<?php
/**
 * AttoMail demo: a minimal mail server backed by a flat
 * password file and an on-disk message store. Demonstrates:
 *   - FileAuthenticator for password-file accounts
 *   - FileMailStorage for per-user folders on disk
 *   - A simple Subject-line filter that diverts spam-like
 *     messages to a Junk folder
 *   - Anti-relay enforcement (try sending to an external
 *     address without authenticating; you will get 550)
 *
 * Run with low ports for development:
 *      php index.php
 * Bind to 25/143 in production (you will need root or
 * setcap cap_net_bind_service=+ep on the php binary).
 */
require '../../src/MailSite.php';

use seekquarry\atto\MailSite;
use seekquarry\atto\FileAuthenticator;
use seekquarry\atto\FileMailStorage;

if (!defined("seekquarry\\atto\\RUN")) {
    /*
        The ATTO convention: the framework only runs when its
        host script is launched directly, not when included
        from another script (e.g. a webmail front-end that
        wants to call the public API methods on MailSite
        without booting the listener).
     */
    define("seekquarry\\atto\\RUN", true);
}
/*
    Create a password file on first run with one demo account.
    In a real deployment you would maintain this file with
    htpasswd -B users.htpasswd alice or by writing your own
    admin tool that calls password_hash().
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
    Demo filter: route messages whose Subject starts with
    [SPAM] into the user's Junk folder, drop messages from
    obviously-bogus senders, and let everything else fall
    through to INBOX. The filter sees the full RFC 5322
    message, the envelope addresses, and the connection
    context (so it can also implement IP-based policy if
    desired).
 */
$mail->filter(function ($from, $to, $bytes, $ctx) {
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
$mail->setTimer(60, function () {
    echo "[" . date('H:i:s') . "] heartbeat, mem=" .
        round(memory_get_usage() / 1024) . "KiB\n";
});
$mail->listen([
    'SMTP_PORT' => 2525,
    'IMAP_PORT' => 1143,
    'SERVER_NAME' => 'localhost',
]);
