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
 * Run with low ports for development:
 *      php index.php
 * Bind to 25/143/465/993 in production (you will need root or
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
    onHeader: inspect parsed headers to apply policy that needs
    the message-as-written. Reject (hard 550) anything whose
    Subject begins with [BLOCK].
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
        'local_cert' => __DIR__ . '/cert.pem',
        'local_pk' => __DIR__ . '/key.pem',
        'verify_peer' => false,
    ]],
]);
