<?php
/**
 * AttoFTP demo: a click-through tour of the File Transfer
 * Protocol. Visitors land on a webui that exercises the
 * running FTP server in three modes:
 *
 *   1. Click-through scenarios -- pre-built sequences of
 *      FTP commands (anonymous browse, named-user upload,
 *      MLSD listings, REST resume, security-guard probes,
 *      etc.) that show the actual control-channel
 *      transcript of the conversation between client and
 *      server.
 *   2. Raw command box -- pick a username/password, type any
 *      sequence of FTP commands, see the wire transcript.
 *   3. File browser -- a server-side view of the current
 *      root with download/upload/rename/delete UI driven by
 *      real FTP commands against the running server.
 *
 * Demonstrates:
 *
 *   - FtpSite: control-connection state machine, command
 *     dispatcher, passive and active data-channel handling
 *   - FilesystemFtpStorage: a no-escape filesystem backend
 *     with realpath()-based path-traversal guard
 *   - CompositeAuthenticator: combines a static user list
 *     with anonymous access, the common shape for an FTP
 *     server that hosts a public /pub plus per-user folders
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * The demo binds:
 *
 *      TCP 12121   -- FTP control channel (and AUTH TLS for
 *                     explicit FTPS)
 *      TCP 19990   -- implicit-FTPS, served with the
 *                     self-signed cert from atto's security/
 *                     folder
 *
 * The high ports follow the same "decade-shifted" pattern
 * the AttoDNS demo uses (15353 / 18853): 12121 is mnemonic
 * for "FTP-on-21-but-prefixed-with-1", 19990 for "implicit-
 * FTPS-on-990-but-prefixed-with-1". A real deployment would
 * bind 21 (privileged) and 990 (privileged).
 *
 * Passive data transfers use a small port range (50000-50050
 * by default) which the launcher passes to the server. If
 * you put a firewall in front of this server, that range
 * needs to be open.
 *
 * The launcher binds on IPv4 by default (127.0.0.1). Use the
 * "Bind" dropdown in the demo's web UI to switch to IPv6
 * (::1) or to a dual-stack listener (::); the choice is
 * persisted in bind.txt and takes effect on the next
 * launch. Modern clients send EPSV / EPRT (RFC 2428) over
 * v6; classic PASV and PORT are IPv4-only and the server
 * refuses them with 522 on a v6 control channel.
 *
 * The companion web UI is spawned automatically and lives at
 *
 *      http://localhost:8080/
 *
 *
 * --- CONNECTING WITH FILEZILLA ---
 *
 * Open Filezilla, "File" -> "Site Manager" -> "New Site":
 *
 *   Protocol:   FTP
 *   Host:       127.0.0.1
 *   Port:       12121
 *   Encryption: Use plain FTP, or "Use explicit FTPS over
 *               FTP" to upgrade after connect (the demo
 *               serves the self-signed cert from atto's
 *               security/ folder; Filezilla will warn the
 *               first time and let you trust it)
 *   Logon Type: Anonymous (or "Normal" for alice/bob)
 *   Transfer Settings -> Passive (default)
 *
 * Connect, and you should land in /pub (anonymous) or
 * /users/<name> (named user). Upload/download/rename should
 * all work; anonymous is read-only.
 *
 *
 * --- TESTING FROM A SHELL (Unix) ---
 *
 * The Debian/Ubuntu "ftp" client (or "lftp"):
 *
 *      ftp -p 127.0.0.1 12121
 *      Name: anonymous
 *      Password: guest@example.com
 *      ftp> ls
 *      ftp> get hello.txt
 *      ftp> bye
 *
 * Or one-liner with lftp:
 *
 *      lftp -e 'cls -l /pub; bye' \
 *          ftp://anonymous:guest@127.0.0.1:12121
 *
 *
 * --- TESTING FROM A SHELL (Windows) ---
 *
 * Windows ships ftp.exe but it does NOT support a non-
 * standard port on the connect command line. Use the open
 * subcommand interactively:
 *
 *      C:\> ftp
 *      ftp> open 127.0.0.1 12121
 *      User: anonymous
 *      Password: guest@example.com
 *      ftp> dir
 *      ftp> get hello.txt
 *      ftp> bye
 *
 * Note that Windows ftp.exe defaults to ACTIVE mode and may
 * fail behind a NAT or with Windows Firewall. For a richer
 * client on Windows, install Filezilla or WinSCP.
 *
 *
 * --- A REAL DEPLOYMENT WOULD ALSO ---
 *
 *   - Bind to ports 21 and 990 (privileged, needs root or
 *     setcap cap_net_bind_service)
 *   - Replace the static user list with a real user store
 *     hooked through a closure-based authenticator
 *   - Put a TLS cert from a real CA in place so AUTH TLS
 *     hands clients a verifiable certificate
 *   - Front the public listener with a rate-limiter to
 *     dampen brute-force login attempts
 *   - Pin the passive port range and open it in the firewall
 *
 * The demo skips all of that to keep the example readable.
 */
require '../../src/FtpSite.php';
use seekquarry\atto\FtpSite;
use seekquarry\atto\AnonAuthenticator;
use seekquarry\atto\StaticUserAuthenticator;
use seekquarry\atto\CompositeAuthenticator;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$root = __DIR__ . DIRECTORY_SEPARATOR . 'root';
if (!is_dir($root)) {
    mkdir($root, 0755, true);
}
/*
    Two named users plus anonymous. Static-user passwords
    here are obviously demo-grade; a real deployment would
    plug a closure-based authenticator into a real user
    store. The CompositeAuthenticator tries the static list
    first and falls back to anonymous, so a USER named
    "alice" with the wrong password is rejected outright
    rather than silently downgrading to anonymous.
 */
$ftp = new FtpSite();
$ftp->auth(new CompositeAuthenticator([
    new StaticUserAuthenticator([
        'alice' => [
            'password' => 'hunter2',
            'login_folder' => '/users/alice',
        ],
        'bob' => [
            'password' => 'sekret',
            'login_folder' => '/users/bob',
        ],
    ]),
    new AnonAuthenticator('/pub'),
]))
    ->root($root)
    ->banner('AttoFTP demo ready (try anonymous, ' .
        'alice/hunter2, or bob/sekret).')
    ->serverName('atto-ftp-demo')
    ->passivePortRange(50000, 50050);
/*
    Bind family is selectable at runtime via the dropdown in
    the webui's reset bar. The selection is persisted in
    bind.txt and read here on every launch. Allowed values:
        "127.0.0.1" -- IPv4 loopback only (default; classic
                       PASV/PORT both work)
        "::1"       -- IPv6 loopback only (forces clients to
                       speak EPSV/EPRT; PASV/PORT are
                       refused with 522)
        "0.0.0.0"   -- IPv4 on all interfaces
        "::"        -- IPv6 on all interfaces; on most Linux
                       and BSD systems with IPV6_V6ONLY off
                       this also accepts IPv4 connections
                       through v4-mapped v6 addresses
    Anything else falls back to "127.0.0.1" so a corrupted
    bind.txt cannot ground the demo.
 */
$bind_file = __DIR__ . DIRECTORY_SEPARATOR . 'bind.txt';
$bind_value = is_file($bind_file) ?
    trim((string) file_get_contents($bind_file)) :
    '127.0.0.1';
if (!in_array($bind_value,
    ['127.0.0.1', '::1', '0.0.0.0', '::'], true)) {
    $bind_value = '127.0.0.1';
}
$config = [
    'BIND' => $bind_value,
    'FTP_PORT' => 12121,
    'FTPS_PORT' => 19990,
];
/*
    FTPS (RFC 4217 explicit + RFC 7151 implicit) uses the
    self-signed server cert that ships under atto's security/
    folder. The same pair powers examples 09 (HTTPS), 12
    (Virtual Hosting), 16 (Server Push), 17 (HTTP/3), so
    Filezilla treating it as trusted once is enough for the
    whole repo.
 */
$cert = __DIR__ . DIRECTORY_SEPARATOR . '..' .
    DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .
    'security' . DIRECTORY_SEPARATOR . 'server.crt';
$key = __DIR__ . DIRECTORY_SEPARATOR . '..' .
    DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .
    'security' . DIRECTORY_SEPARATOR . 'server.key';
if (is_file($cert) && is_file($key)) {
    $config['SERVER_CONTEXT'] = ['ssl' => [
        'local_cert' => $cert,
        'local_pk' => $key,
        'allow_self_signed' => true,
        'verify_peer' => false,
    ]];
}
/*
    Spawn the companion web UI. Same detached-child pattern
    as examples 22-24; on Unix we capture the child PID and
    kill it on shutdown via register_shutdown_function. On
    Windows "start /B" does not surface the PID, so the user
    closes the cmd window or kills php.exe via Task Manager
    after stopping the FTP server.

    We export ATTOFTP_SERVER_PID into the spawned webui's
    environment so the bind-switch endpoint in webui.php can
    signal index.php (us) to shut down. posix_getppid() does
    not work for that because the wrapper subshell detaches
    webui from index.php (its parent becomes init); the env
    var survives the detach.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR .
    "webui.php");
$self_pid = getmypid();
if (strstr(PHP_OS, "WIN")) {
    $job = "set ATTOFTP_SERVER_PID=$self_pid && " .
        "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows). Open " .
        "http://localhost:8080/\n";
    echo "  To stop, click 'Switch bind' in the UI, or " .
        "close this cmd window, or end php.exe in Task " .
        "Manager.\n";
} else {
    $job = "{ export ATTOFTP_SERVER_PID=$self_pid; " .
        "exec $php $webui ; } < /dev/null > /dev/null " .
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
$ftp->listen($config);
