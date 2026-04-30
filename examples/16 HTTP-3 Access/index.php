<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;
use seekquarry\atto\H3FFI;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
/*
    H3 Working diagnostic page.

    Run from this folder with:
        php index.php

    Then point a browser at:
        https://localhost:8443/

    The page reports whether HTTP/3 (cloudflare/quiche via PHP FFI) is
    available on this system. If everything is in place a green
    success page renders; otherwise the page shows step-by-step
    install instructions for the missing piece.

    The server always binds 8080 (plain HTTP/1.1) and 8443 (HTTPS,
    HTTP/1.1 + HTTP/2). The H3 listener is opt-in: if libquiche or
    PHP FFI is missing, the H3 listener is silently skipped and the
    diagnostic page reports what to install. If libquiche is found,
    H3 is also bound on 8443/UDP and the page shows the version.
 */
$test = new WebSite();
$cert = realpath(__DIR__ . "/../../security/server.crt");
$key  = realpath(__DIR__ . "/../../security/server.key");

$test->get('/', function () use ($test) {
    $checks = collectH3Diagnostics();
    $all_ok = true;
    foreach ($checks as $c) {
        if (!$c['ok']) { $all_ok = false; break; }
    }
    $test->header('Content-Type: text/html; charset=utf-8');
    renderDiagnosticPage($checks, $all_ok);
});

if ($test->isCli()) {
    $test->listen([
        8080,
        ['address' => 8443, 'context' => ['ssl' => [
            'local_cert' => $cert,
            'local_pk' => $key,
            'allow_self_signed' => true,
            'verify_peer' => false,
            'alpn_protocols' => 'h2,http/1.1',
        ]]],
        ['address' => 8443, 'protocol' => 'h3', 'context' => ['ssl' => [
            'local_cert' => $cert,
            'local_pk' => $key,
        ]]],
    ]);
} else {
    $test->process();
}

/**
 * Probes the runtime to see what's needed for HTTP/3 to work and
 * returns an ordered list of check rows. Each row has 'name'
 * (short label), 'ok' (bool), 'detail' (string). The page renders
 * them top-to-bottom; the first failing row is where the operator
 * should focus.
 */
function collectH3Diagnostics()
{
    $rows = [];

    /* 1. PHP version */
    $php_ok = version_compare(PHP_VERSION, '7.4.0', '>=');
    $rows[] = [
        'name' => 'PHP version',
        'ok' => $php_ok,
        'detail' => PHP_VERSION
            . ($php_ok ? ' (>= 7.4 required for FFI)'
                       : ' — need at least 7.4 for FFI support'),
    ];

    /* 2. FFI extension */
    $ffi_ok = extension_loaded('FFI');
    $rows[] = [
        'name' => 'PHP FFI extension',
        'ok' => $ffi_ok,
        'detail' => $ffi_ok ? 'loaded' :
            'not loaded — enable "ffi" in your php.ini '
            . '(extension=ffi) and ensure ffi.enable=true',
    ];
    if (!$ffi_ok) {
        return $rows;
    }

    /*
        FFI itself can be present but disabled outside of CLI by
        the ffi.enable setting. Atto runs the H3 listener from CLI
        so this is rarely an issue, but worth flagging clearly.
     */
    $ffi_enable = ini_get('ffi.enable');
    $cli_only_ok = $ffi_enable === 'true' || $ffi_enable === '1'
        || $ffi_enable === 'preload'
        || ($ffi_enable === 'preload' && PHP_SAPI === 'cli');
    if (PHP_SAPI === 'cli') {
        $cli_only_ok = true;
    }
    $rows[] = [
        'name' => 'ffi.enable',
        'ok' => $cli_only_ok,
        'detail' => 'ffi.enable = ' . var_export($ffi_enable, true)
            . ($cli_only_ok ? ' (OK in CLI)' : ' — set to true'),
    ];

    /* 3. libquiche discoverable */
    $quiche_avail = H3FFI::isAvailable();
    $rows[] = [
        'name' => 'libquiche library',
        'ok' => $quiche_avail,
        'detail' => $quiche_avail
            ? 'found and dlopens cleanly'
            : 'not found in any of the standard search paths',
    ];
    if (!$quiche_avail) {
        return $rows;
    }

    /* 4. quiche_version() real call */
    try {
        $ffi_obj = new H3FFI();
        $version = $ffi_obj->version();
        $version_ok = $version !== '' && $version !== 'unknown';
        $rows[] = [
            'name' => 'quiche_version()',
            'ok' => $version_ok,
            'detail' => $version_ok
                ? "$version (loaded from {$ffi_obj->library_path})"
                : 'returned empty string',
        ];
    } catch (\Throwable $e) {
        $rows[] = [
            'name' => 'quiche_version()',
            'ok' => false,
            'detail' => 'FFI call threw: ' . $e->getMessage(),
        ];
        return $rows;
    }

    /* 5. H3Listener class loaded (since listen() lazy-loads) */
    $h3_class_ok = class_exists('seekquarry\\atto\\H3Listener', false);
    $rows[] = [
        'name' => 'H3Listener class',
        'ok' => $h3_class_ok,
        'detail' => $h3_class_ok
            ? 'loaded into the running process'
            : 'src/H3Listener.php not loaded — check that listen() '
                . 'was called with a "protocol" => "h3" entry',
    ];

    /* 6. UDP socket bound on 8443 (probe via local connect) */
    $errno = 0; $errstr = '';
    $udp = @stream_socket_client('udp://127.0.0.1:8443', $errno,
        $errstr, 1, STREAM_CLIENT_CONNECT);
    $udp_ok = $udp !== false;
    if ($udp) { fclose($udp); }
    $rows[] = [
        'name' => 'UDP 8443 reachable',
        'ok' => $udp_ok,
        'detail' => $udp_ok
            ? 'a UDP packet to 127.0.0.1:8443 is accepted'
            : "stream_socket_client(udp) failed: $errstr",
    ];

    return $rows;
}

/**
 * Renders the diagnostic page. Two main bodies depending on
 * whether all checks passed: success body with "try it" hints,
 * or instructions body with platform-specific install steps.
 */
function renderDiagnosticPage($checks, $all_ok)
{
    $os = strtolower(PHP_OS);
    ?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Atto - HTTP/3 Diagnostic</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif;
    max-width: 760px; margin: 2em auto; padding: 0 1em;
    color: #1a1a1a; line-height: 1.5; }
h1 { margin-bottom: 0.2em; }
.subtitle { color: #666; margin-top: 0; }
.banner { padding: 1em 1.2em; border-radius: 6px;
    margin: 1.5em 0; }
.banner.ok { background: #e6f7e9; border: 1px solid #2c9e3a;
    color: #195e22; }
.banner.fail { background: #fdecea; border: 1px solid #c82333;
    color: #6b0e15; }
.banner h2 { margin: 0 0 0.3em 0; font-size: 1.1em; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
th, td { text-align: left; padding: 0.5em 0.7em;
    border-bottom: 1px solid #eee; vertical-align: top; }
th { background: #f6f6f6; }
.mark { font-size: 1.2em; width: 2.5em; text-align: center; }
.mark.ok { color: #2c9e3a; }
.mark.fail { color: #c82333; }
.detail { color: #555; font-family: ui-monospace, Menlo,
    Consolas, monospace; font-size: 0.9em; }
pre { background: #f6f6f6; padding: 0.8em 1em;
    border-radius: 4px; overflow-x: auto;
    font-size: 0.9em; }
code { background: #f6f6f6; padding: 0.1em 0.3em;
    border-radius: 3px; font-size: 0.92em; }
.install { background: #fff8e1; border: 1px solid #f0c040;
    padding: 1em 1.2em; border-radius: 6px;
    margin: 1.5em 0; }
.install h3 { margin-top: 0; }
.tab-row { display: flex; gap: 0.5em; margin-bottom: 0;
    flex-wrap: wrap; }
.tab-row a { padding: 0.5em 1em; background: #eee;
    border-radius: 4px 4px 0 0; text-decoration: none;
    color: #333; border: 1px solid #ddd; border-bottom: none; }
.tab-content { border: 1px solid #ddd; padding: 1em 1.2em;
    border-radius: 0 4px 4px 4px; }
</style>
</head>
<body>
<h1>HTTP/3 diagnostic</h1>
<p class="subtitle">atto example 16 - checks whether libquiche
    via PHP FFI is wired up so HTTP/3 can be served.</p>

<?php if ($all_ok) { ?>
<div class="banner ok">
<h2>All checks passed</h2>
<p>HTTP/3 is available. atto is binding port 8443 over UDP and
serving HTTP/3 alongside HTTP/1.1 and HTTP/2 on the same TCP
port.</p>
</div>
<?php } else { ?>
<div class="banner fail">
<h2>HTTP/3 not available yet</h2>
<p>One or more checks failed. The server is still serving
HTTP/1.1 (port 8080) and HTTP/1.1 + HTTP/2 over TLS (port 8443
TCP). To enable HTTP/3, fix the failing rows below in order;
they are listed top-down by dependency.</p>
</div>
<?php } ?>

<table>
<thead>
<tr><th>Check</th><th></th><th>Detail</th></tr>
</thead>
<tbody>
<?php foreach ($checks as $row) { ?>
<tr>
<td><?php echo htmlspecialchars($row['name']); ?></td>
<td class="mark <?php echo $row['ok'] ? 'ok' : 'fail'; ?>">
    <?php echo $row['ok'] ? '&#10003;' : '&#10007;'; ?>
</td>
<td class="detail"><?php
    echo htmlspecialchars($row['detail']);
?></td>
</tr>
<?php } ?>
</tbody>
</table>

<?php if ($all_ok) { ?>
<h3>Verify with curl</h3>
<p>Use a curl built with HTTP/3 support (curl 7.66+ with the
--http3 flag) to confirm a real HTTP/3 connection:</p>
<pre>curl -vk --http3 https://localhost:8443/</pre>
<p>If your curl was not built with HTTP/3, the request will
silently fall back to HTTP/2 over TCP. The server-side log will
show a UDP read in either case.</p>
<?php } else {
    renderInstallInstructions($os);
} ?>

</body>
</html>
<?php
}

/**
 * Renders the platform-specific install instructions block.
 * The user picks their platform in the tab row; all three are
 * always rendered so the page works without JS.
 */
function renderInstallInstructions($os_lower)
{
    $is_mac = strpos($os_lower, 'darwin') !== false;
    $is_linux = strpos($os_lower, 'linux') !== false;
    $is_win = strpos($os_lower, 'win') !== false;
    ?>
<div class="install">
<h3>How to install libquiche and enable PHP FFI</h3>

<p>Atto detects your OS as <code><?php
    echo htmlspecialchars(PHP_OS); ?></code>; the section
matching your platform is shown first.</p>

<?php if ($is_mac) { renderMacInstructions(); }
      else if ($is_linux) { renderLinuxInstructions(); }
      else if ($is_win) { renderWindowsInstructions(); }
      else { renderMacInstructions(); renderLinuxInstructions();
             renderWindowsInstructions(); } ?>

<h3>Enable PHP FFI</h3>
<p>FFI ships with PHP 7.4 and later but is often not enabled by
default. To turn it on:</p>
<ol>
<li>Find your <code>php.ini</code>:
<pre>php --ini</pre></li>
<li>Ensure these lines are uncommented (or add them):
<pre>extension=ffi
ffi.enable=true</pre>
For CLI-only use, <code>ffi.enable=preload</code> also works.
</li>
<li>Restart your atto process and reload this page.</li>
</ol>

<h3>Restart this example</h3>
<pre>php index.php</pre>
<p>then reload <a href="/">this page</a>.</p>
</div>
<?php
}

/**
 * Renders the macOS Homebrew install path.
 */
function renderMacInstructions()
{
    ?>
<h4>macOS (Homebrew)</h4>
<pre>brew install cloudflare-quiche</pre>
<p>This installs <code>libquiche.dylib</code> under
<code>/opt/homebrew/lib/</code> (Apple Silicon) or
<code>/usr/local/lib/</code> (Intel). Atto's library lookup
checks both.</p>
<?php
}

/**
 * Renders the Linux source-build install path. Distributions vary
 * widely so we point at the canonical cargo build rather than
 * recommending a specific distro package.
 */
function renderLinuxInstructions()
{
    ?>
<h4>Linux (build from source)</h4>
<p>Most distributions do not ship a libquiche package yet, so
build from source via cargo:</p>
<pre>sudo apt install -y rustc cargo cmake pkg-config libssl-dev
git clone --recursive https://github.com/cloudflare/quiche
cd quiche
cargo build --release --features ffi,pkg-config-meta
sudo cp target/release/libquiche.so /usr/local/lib/
sudo cp quiche/include/quiche.h /usr/local/include/
sudo ldconfig</pre>
<p>The build takes a few minutes (libquiche bundles BoringSSL).
Once <code>/usr/local/lib/libquiche.so</code> exists, atto's
library lookup finds it automatically.</p>
<?php
}

/**
 * Renders the Windows install path. There is no direct
 * Chocolatey package as of this writing, so the user goes via
 * Rust toolchain + cargo build.
 */
function renderWindowsInstructions()
{
    ?>
<h4>Windows (Rust toolchain)</h4>
<pre>choco install rust git cmake nasm pkgconfiglite
git clone --recursive https://github.com/cloudflare/quiche
cd quiche
cargo build --release --features ffi</pre>
<p>Copy <code>target\release\quiche.dll</code> next to your
<code>php.exe</code>, or somewhere on the system <code>PATH</code>.
</p>
<?php
}
