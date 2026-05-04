<?php
/**
 * AttoMail demo: a disposable-inbox mail service. Visitors
 * land on the webmail UI, are assigned a random throwaway
 * address (e.g. quiet-fox-9412@anon.test), and can receive
 * mail at that address until either they hit Burn or the
 * server restarts. There are no accounts, no passwords, and
 * nothing on disk: every mailbox lives in RAM and disappears
 * when this process exits. That ephemerality is the privacy
 * property -- not a limitation -- and it matches the public
 * disposable-mail services the design is modeled on
 * (Mailinator, 10MinuteMail, etc.).
 *
 * Demonstrates:
 *   - RamMailStorage: zero-disk storage backend, exercised
 *     end-to-end through the same SMTP and IMAP code paths
 *     as the on-disk file backend in example 20
 *   - AnonAuthenticator: shared-password authenticator used
 *     only on the IMAP loopback between the webmail UI
 *     process and the mail server process; the webmail UI
 *     is the sole real consumer of IMAP here
 *   - A custom domain (anon.test) so RCPT TO at any local-
 *     part allocates a mailbox lazily; no preregistration
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * Listens on the same SMTP and IMAP ports as example 20
 * (2525 / 1143) -- if you have example 20 running, kill it
 * first or these binds will fail. The companion webmail UI
 * is spawned automatically and lives at
 *
 *      http://localhost:8080/
 *
 * Open that URL in a browser; you will be assigned an
 * anonymous address on first visit and can immediately have
 * mail delivered to it. To send mail TO an anonymous user
 * from outside, point your client at localhost:2525 and use
 *
 *      MAIL FROM: anyone@example.com
 *      RCPT TO: <whatever-they-told-you>@anon.test
 *
 * No authentication required -- anon.test is configured as
 * a local domain so anti-relay accepts it.
 *
 *
 * --- TESTING DELIVERY FROM THE COMMAND LINE ---
 *
 * The webmail UI's landing page includes a one-line
 * "How do I send a test message" block with the visitor's
 * assigned address pre-filled. The block shows two
 * variants: a printf | nc one-liner for Unix-like shells
 * (macOS, Linux, BSD, WSL), and a PowerShell block for
 * native Windows. Both walk through the same SMTP wire
 * protocol; pick whichever your shell supports.
 *
 * If you would rather drive it interactively by hand on a
 * Unix shell:
 *
 *      $ telnet localhost 2525
 *      220 anon.test AttoMail ESMTP ready
 *      EHLO test
 *      250-anon.test Hello
 *      250 HELP
 *      MAIL FROM: friend@example.com
 *      250 2.1.0 Ok
 *      RCPT TO: <ADDRESS>@anon.test
 *      250 2.1.5 Ok
 *      DATA
 *      354 End data with <CR><LF>.<CR><LF>
 *      Subject: hi
 *
 *      body
 *      .
 *      250 2.0.0 Ok: message accepted
 *      QUIT
 *      221 Bye
 *
 * On Windows where telnet is not installed by default, an
 * interactive equivalent is:
 *
 *      PS> $c = New-Object Net.Sockets.TcpClient localhost,2525
 *      PS> $r = New-Object IO.StreamReader $c.GetStream()
 *      PS> $w = New-Object IO.StreamWriter $c.GetStream()
 *      PS> $w.NewLine = "`r`n"; $w.AutoFlush = $true
 *      PS> $r.ReadLine()       # banner
 *      PS> $w.WriteLine('EHLO test')
 *      PS> $r.ReadLine()       # 250-anon.test Hello
 *      PS> ...                 # continue with MAIL/RCPT/DATA
 *      PS> $c.Close()
 *
 * which behaves identically to telnet for line-oriented
 * protocols.
 *
 *
 * --- A REAL DEPLOYMENT WOULD ALSO ---
 *
 *   - Bind to port 25 (with root or a setcap'd php)
 *   - Set up MX records pointing at this host
 *   - Add rate limiting per source IP (an onConnect hook
 *     with a sliding window is the natural place)
 *   - Add spam filtering (an onMessage hook calling out to
 *     SpamAssassin or rspamd)
 *   - Run behind a reverse proxy that terminates TLS for
 *     the webmail UI
 *   - Allocate a real domain instead of anon.test
 *
 * The demo skips all of that to keep the example readable.
 * The same MailSite hooks shown in example 20 still work
 * here; nothing about RamMailStorage changes the policy
 * surface.
 */
require '../../src/MailSite.php';
use seekquarry\atto\MailSite;
use seekquarry\atto\AnonAuthenticator;
use seekquarry\atto\RamMailStorage;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
/*
    The shared password used between this process and the
    webmail UI process when the UI authenticates against
    IMAP loopback. The webmail UI reads this file on
    startup; if it does not exist on either side, both
    sides generate the same value from the same recipe and
    you would still match -- but writing it once at server
    start guarantees the UI always sees the same value
    even if a future change makes the recipe non-
    deterministic. The file is created with mode 0600 so
    only the running user can read it.
 */
$shared_pw_file = __DIR__ . DIRECTORY_SEPARATOR .
    'shared_password.txt';
if (!is_file($shared_pw_file)) {
    $pw = bin2hex(random_bytes(16));
    file_put_contents($shared_pw_file, $pw);
    /*
        chmod with mode 0600 is a no-op on Windows (which uses
        ACLs rather than POSIX bits); on Unix it makes the
        file readable only by the user that started the
        server. Either way we suppress errors so the demo
        does not abort on a filesystem that does not
        support chmod at all.
     */
    @chmod($shared_pw_file, 0600);
}
$shared_password = trim((string) file_get_contents($shared_pw_file));
/*
    Wipe the password file on clean exit. The file only
    needs to live long enough for webui.php to read it
    (which happens at webui startup); leaving it on disk
    after the server stops would let a later, unrelated
    process reuse a stale password by accident.
 */
register_shutdown_function(function () use ($shared_pw_file) {
    @unlink($shared_pw_file);
});
$mail = new MailSite();
$mail->auth(new AnonAuthenticator($shared_password));
$mail->storage(new RamMailStorage());
/*
    anon.test is the throwaway-mailbox domain; localhost is
    kept as a local domain so smoke-test sends from telnet
    to <user>@localhost still work. Anything else is
    rejected by anti-relay.
 */
$mail->domains(['anon.test', 'localhost']);
/*
    onMailFrom: drop obviously-bogus senders before DATA so
    we do not waste bandwidth on multi-megabyte spam. A real
    deployment would add SPF / DKIM / rate-limiting hooks
    here.
 */
$mail->onMailFrom(function ($info, $context) {
    $from = strtolower((string) $info['from']);
    if ($from === '' || strpos($from, '@') === false) {
        return 'reject';
    }
    return null;
});
/*
    Spawn the companion webmail UI. Same detached-child
    pattern as example 20; see that file for cross-platform
    notes. The webui is reached at http://localhost:8080/
    -- the conventional port for atto example webuis. If
    you have example 20 (or any other example webui)
    running on the same machine, kill it before starting
    this one.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . "webui.php");
if (strstr(PHP_OS, "WIN")) {
    /*
        Windows path: "start /B" detaches the child but does
        NOT surface its PID, so we cannot kill it from the
        parent on a graceful Ctrl+C. The user closes the cmd
        window or kills php.exe via Task Manager when done.
     */
    $job = "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows). Open " .
        "http://localhost:8080/\n";
    echo "  To stop, close this cmd window or end php.exe " .
        "in Task Manager.\n";
} else {
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
    'SERVER_NAME' => 'anon.test',
    'ALLOW_PLAINTEXT_AUTH' => true,
]);
