<?php
/**
 * AttoSSH demo: a click-through tour of the Secure Shell
 * (RFC 4253 transport, RFC 4252 userauth, RFC 4254
 * connection layer) and the SFTP file-transfer protocol
 * (draft-ietf-secsh-filexfer-02). Visitors land on a
 * webui that exercises the running SSH server in three
 * modes:
 *
 *   1. Click-through scenarios -- pre-built SSH sessions
 *      (bare connect, password auth, Ed25519 publickey
 *      auth, exec command, interactive shell, sftp
 *      listing, sftp upload, wrong password, host-key
 *      pinning) that show the actual on-wire transcript
 *      between the demo's embedded SSH client and the
 *      running server.
 *   2. Raw command box -- pick a username/password (or an
 *      Ed25519 key from the bundled keys/ folder), type
 *      any "exec" command, see the output and the
 *      transcript.
 *   3. File browser -- a server-side view of the current
 *      root with download/upload/rename/delete UI driven
 *      by real SFTP commands against the running server.
 *
 * Demonstrates:
 *
 *   - SshSite: KEX with curve25519-sha256 (via ext-sodium),
 *     AES-128-CTR + HMAC-SHA-256 packet protection (via
 *     ext-openssl), Ed25519 host-key signing, both password
 *     and publickey userauth, the channel layer's flow-
 *     control windows, exec/shell/subsystem dispatch,
 *     and SFTP-3 file-transfer protocol on top.
 *   - StaticSshAuthenticator: in-memory password store.
 *   - AuthorizedKeysAuthenticator: per-user
 *     OpenSSH-format authorized_keys files, identical to
 *     what /etc/ssh/ uses on Unix.
 *   - CompositeSshAuthenticator: combines the two so
 *     either password or publickey login succeeds.
 *   - FilesystemFtpStorage: shared with examples 25
 *     (FTP) -- the same path-traversal-guarded backend
 *     serves both protocols from one tree.
 *
 *
 * --- HOW TO RUN ---
 *
 *      php index.php
 *
 * The demo binds:
 *
 *      TCP 12222   -- SSH control / SFTP subsystem
 *
 * The high port follows the same "decade-shifted" pattern
 * the other atto demos use (15353 for DNS, 12121 for FTP,
 * 13478 for STUN/TURN). 12222 is mnemonic for "SSH-on-22-
 * but-prefixed-with-12". A real deployment binds 22, which
 * is privileged.
 *
 * The launcher binds on IPv4 by default (127.0.0.1). Use
 * the "Bind" dropdown in the demo's web UI to switch to
 * IPv6 (::1) or to a dual-stack listener (::); the choice
 * is persisted in bind.txt and takes effect on the next
 * launch. The SSH transport is family-agnostic, so both
 * v4 and v6 exercise the same scenarios.
 *
 * The companion web UI is spawned automatically and lives
 * at
 *
 *      http://localhost:8080/
 *
 *
 * --- DEMO CREDENTIALS ---
 *
 * The static credential store is configured with three
 * users out of the box:
 *
 *      alice / hunter2          (login folder /users/alice)
 *      bob   / sekret           (login folder /users/bob)
 *      guest / guest            (login folder /, read-only)
 *
 * Plus an Ed25519 keypair pre-generated in keys/ that's
 * authorized for the user "alice":
 *
 *      keys/alice_demo_key      private key (PEM)
 *      keys/alice_demo_key.pub  public key (OpenSSH format)
 *
 * The authorized_keys file the server reads is
 *
 *      keys/alice.authorized_keys
 *
 * which contains the matching public-key line.
 *
 *
 * --- CONNECTING WITH OPENSSH ---
 *
 * From a terminal:
 *
 *      ssh -p 12222 alice@127.0.0.1
 *
 * with password "hunter2", or
 *
 *      ssh -p 12222 -i "keys/alice_demo_key" alice@127.0.0.1
 *
 * with the bundled pubkey. The first connection asks
 * about the host fingerprint; that is the demo's
 * Ed25519 host key, persisted in host_key on first
 * launch.
 *
 *
 * --- CONNECTING WITH SFTP / FILEZILLA ---
 *
 * sftp:
 *
 *      sftp -P 12222 alice@127.0.0.1
 *
 * Filezilla, "File" -> "Site Manager" -> "New Site":
 *
 *      Protocol:   SFTP - SSH File Transfer Protocol
 *      Host:       127.0.0.1
 *      Port:       12222
 *      Logon Type: Normal (or "Key file" with the
 *                  private key from keys/)
 *      User:       alice
 *      Password:   hunter2
 *
 * The server speaks SFTP version 3. Most modern clients
 * negotiate that version automatically.
 *
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 *
 * LICENSE:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license http://www.gnu.org/licenses/ GPL-3.0-or-later
 * @link http://www.seekquarry.com/
 * @copyright 2017-2026
 * @filesource
 */
require '../../src/SshSite.php';
require '../../src/FtpSite.php';
use seekquarry\atto\SshSite;
use seekquarry\atto\StaticSshAuthenticator;
use seekquarry\atto\AuthorizedKeysAuthenticator;
use seekquarry\atto\CompositeSshAuthenticator;
use seekquarry\atto\FilesystemFtpStorage;
if (!defined("seekquarry\\atto\\RUN")) {
    define("seekquarry\\atto\\RUN", true);
}
$here = __DIR__;
$root = $here . DIRECTORY_SEPARATOR . 'root';
$keys_dir = $here . DIRECTORY_SEPARATOR . 'keys';
$host_key = $here . DIRECTORY_SEPARATOR . 'host_key';
/*
    Keep the demo in self-repairing shape: if anyone
    deletes the demo root, recreate it from the bundled
    pristine copy in original-root/. ex23 uses the same
    pattern; we mirror it here so the file-browser tab's
    "reset" button has a reliable known-good state to
    snap back to.
 */
$pristine = $here . DIRECTORY_SEPARATOR . 'original-root';
if (is_dir($pristine) && !is_dir($root)) {
    @mkdir($root);
    foreach ((array) @scandir($pristine) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        @copyTree($pristine . DIRECTORY_SEPARATOR . $entry,
            $root . DIRECTORY_SEPARATOR . $entry);
    }
}
function copyTree($src, $dst)
{
    if (is_dir($src)) {
        @mkdir($dst);
        foreach (@scandir($src) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            copyTree($src . DIRECTORY_SEPARATOR . $entry,
                $dst . DIRECTORY_SEPARATOR . $entry);
        }
    } else {
        @copy($src, $dst);
    }
}
$users = [
    [
        'user' => 'alice',
        'password' => 'hunter2',
        'login_folder' => '/users/alice',
        'read_only' => false,
    ],
    [
        'user' => 'bob',
        'password' => 'sekret',
        'login_folder' => '/users/bob',
        'read_only' => false,
    ],
    [
        'user' => 'guest',
        'password' => 'guest',
        'login_folder' => '/',
        'read_only' => true,
    ],
];
/*
    StaticSshAuthenticator wants either [user => password]
    or [user => ['password', 'login_folder', 'read_only']].
    We use the rich form so each user gets their own home
    folder and the demo's read-only "guest" can be a real
    read-only user.
 */
$pw_info = [];
foreach ($users as $u) {
    $pw_info[$u['user']] = [
        'password' => $u['password'],
        'login_folder' => $u['login_folder'],
        'read_only' => $u['read_only'],
    ];
}
$pw_auth = new StaticSshAuthenticator($pw_info);
$pk_auth = new AuthorizedKeysAuthenticator([
    'alice' => [
        'authorized_keys' =>
            $keys_dir . DIRECTORY_SEPARATOR .
            'alice.authorized_keys',
        'login_folder' => '/users/alice',
        'read_only' => false,
    ],
]);
$ssh = new SshSite();
$ssh->auth(new CompositeSshAuthenticator([
        $pw_auth, $pk_auth]))
    ->storage(new FilesystemFtpStorage($root))
    ->hostKey($host_key)
    ->software('atto-ssh-demo_1.0')
    ->enableExec(true)
    ->enableShell(true)
    ->enableSftp(true);
$bind_file = $here . DIRECTORY_SEPARATOR . 'bind.txt';
$bind_value = is_file($bind_file) ?
    trim((string) file_get_contents($bind_file)) :
    '127.0.0.1';
if (!in_array($bind_value,
    ['127.0.0.1', '::1', '0.0.0.0', '::'], true)) {
    $bind_value = '127.0.0.1';
}
$config = [
    'BIND' => $bind_value,
    'SSH_PORT' => 12222,
];
/*
    Spawn the companion web UI. Same detached-child pattern
    as examples 22-27. ATTOSSH_SERVER_PID lets the bind-
    switch endpoint in webui.php signal index.php (us) to
    shut down.
 */
$php = escapeshellarg(PHP_BINARY);
$webui = escapeshellarg($here . DIRECTORY_SEPARATOR .
    'webui.php');
$self_pid = getmypid();
if (strstr(PHP_OS, "WIN")) {
    $job = "set ATTOSSH_SERVER_PID=$self_pid && " .
        "start /B $php $webui > NUL 2>&1";
    pclose(popen($job, "r"));
    echo "Spawned webui.php (Windows). Open " .
        "http://localhost:8080/\n";
    echo "  To stop, click 'Switch bind' in the UI, or " .
        "close this cmd window, or end php.exe in Task " .
        "Manager.\n";
} else {
    $job = "{ export ATTOSSH_SERVER_PID=$self_pid; " .
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
        register_shutdown_function(
            function () use ($webui_pid) {
                @posix_kill($webui_pid, 15);
            });
    } else {
        echo "Warning: failed to capture webui pid; " .
            "you may need to kill it manually.\n";
    }
}
$ssh->listen($config);
