Atto is a collection of single-file, low-dependency, pure-PHP servers and
routing engines. Each server is one file you drop into a project, configure
with a few chained setters, and start with a `listen()` call. No Composer
modules required. No build step.

What's in the box:

 * **WebSite** -- HTTP/1.1, HTTP/2, and HTTP/3 web server and router.
   Doubles as a micro-framework under Apache, nginx, or lighttpd, or runs
   standalone. All protocols are pure PHP implementations, the largest,
   HTTP/3 is in an optional side file as its performance mainly just matches
   HTTP/2 in our benchmarking. A sibling H3QuicheListener wraps
   libquiche through PHP-FFI for side-by-side comparison. In our testing,
   this is slower than the pure implementation because of the FFI overhead.

 * **GopherSite** -- a [gopher protocol](
   https://en.wikipedia.org/wiki/Gopher_%28protocol%29) server, shaped
   just like WebSite.

 * **MailSite** -- SMTP and IMAP in one process. STARTTLS, authenticated
   submission, mailbox storage, the lot.

 * **DnsSite** -- authoritative DNS server. Reads zone files, answers UDP
   and TCP queries, supports DoT (DNS over TLS).

 * **FtpSite** -- FTP server with explicit and implicit FTPS. Speaks the
   command set FileZilla and curl expect, including MLSD listings, passive
   and active data connections, and a path-traversal guard.

 * **SshSite** -- SSH-2 server (RFC 4250-4254) with the SFTP subsystem.
   Curve25519 KEX, Ed25519 host keys, AES-128-CTR + HMAC-SHA-256. Password
   and publickey auth (OpenSSH-format authorized_keys). All crypto comes
   from PHP's bundled ext-sodium / ext-openssl / ext-hash.

 * **TurnSite** -- STUN/TURN server (RFC 8489 / RFC 8656) for WebRTC and
   SIP relays. Long-term credentials, allocations, channels.

A few things every Atto server has in common: request-event-driven (one
PHP process, async I/O); the `$site->get('/', ...)` routing API carries
through where it makes sense; familiar superglobals like `$_GET`, `$_POST`,
`$_SESSION`, `$_FILES` are populated for the protocols where that idiom
fits. Sessions live in RAM, timers fire on a schedule, and file I/O goes
through caching `fileGetContents` / `filePutContents` helpers.

Hello, World
------------

```php
<?php
require 'atto_server_path/src/WebSite.php'; // adjust to your path

use seekquarry\atto\WebSite;

$site = new WebSite();

$site->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Hello World - Atto Server</title></head>
    <body>
    <h1>Hello World!</h1>
    <div>My first atto server route!</div>
    </body>
    </html>
    <?php
});

if ($site->isCli()) {
    /* From the command line: php index.php */
    $site->listen(8080);
} else {
    /* Behind Apache/nginx/lighttpd via .htaccess + this index.php */
    $site->process();
}
```

Run `php index.php`, point a browser at `http://localhost:8080/`, done.
The other servers follow the same shape: swap WebSite for FtpSite or
SshSite or whichever, configure with chained setters, call `listen()`.

Installation
------------

Atto runs on PHP 8+. HTTPS works on any PHP build with
ext-openssl; SshSite additionally needs ext-sodium.

Get the code:

```
git clone https://github.com/seekquarry/atto.git
```

Then drop one require line into your project:

```php
require 'atto_server_path/src/WebSite.php'; // or whichever Site class
use seekquarry\atto\WebSite;
```

Composer works too:

```
composer require seekquarry/atto
```

Then `require "vendor/autoload.php"` and the Atto Site classes autoload.

Examples
--------

The `examples/` folder has a numbered tour: 01-20 are WebSite features
(routing, forms, sessions, WebDAV, CalDAV, WebSockets, streaming,
HTTP/3, benchmarks), and 21 onward are full-protocol demos:

 * **21 GopherSite Demo** -- a working gopher hole.
 * **22 MailSite Demo** -- SMTP + IMAP, with `swaks` and `openssl s_client`
   smoke tests.
 * **23 Anonymous WebMail** -- a webmail front-end on top of MailSite.
 * **24 DNS Demo** -- click-through DNS scenarios, a query box, and a
   browser-style zone-file editor.
 * **25 FTP Demo** -- click-through FTP scenarios, a raw command box, and
   a live FTP-driven file browser.
 * **26 SSH Demo** -- click-through SSH/SFTP scenarios with on-wire
   transcripts, a raw exec command box, and a multi-user file browser.
 * **27 TURN Demo** -- click-through STUN/TURN scenarios with full STUN
   message decode and a raw STUN/TURN method explorer.

To run any example:

```
php index.php 20   # or 21, 22, 23, 24, 25, 26, ...
```

Each demo's `index.php` carries a header docblock describing its config,
demo credentials, and a "How to connect" pointer for real-world clients
(curl, FileZilla, ssh, swaks, etc.). Demos 22-25 also spawn a companion
web UI at `http://localhost:8080/` so you can poke at the server from
your browser without leaving PHP.

Going Further
-------------

The demo `webui.php` files are full worked examples of using an Atto Site
class as a library: client classes, transcripts, error handling, all in
one file. Copy a Site class into your own project, write your own routes,
and you're off.

Atto's whole pitch is *single-file, no friction*. Skim the source of any
Site class -- they're documented top to bottom -- and write the server
your project actually needs.
