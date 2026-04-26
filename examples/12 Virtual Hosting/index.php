<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();
/*
    An Atto WebSite consisting of landing pages for three different hosts,
    served over HTTPS. A second listener bound to the cleartext port
    redirects every request to its TLS counterpart so visitors who type
    http:// in their browser are upgraded automatically. This shows two
    Atto features at once: virtual hosting (one Atto process serving
    different responses based on Host header) and multi-listener (one
    Atto process binding to two ports with different TLS settings).

    To run this example you may need administrator privileges to bind
    ports 80 and 443; on macOS and Linux you can use higher ports
    (8080 and 8443 are pre-set below) and skip the redirect listener
    if you do not need it.

    Use ifconfig or ipconfig to determine your LAN ip address and edit
    the third $host_list entry appropriately. In the real world you
    would use different hostnames you had paid for as $host_list keys.

    After commenting the exit() line above, you can run the example by
    typing:
       php index.php
    and pointing a browser to https://localhost:8443/ or
    https://127.0.0.1:8443/ or https://your_lan_ip_address:8443/. The
    cleartext listener on port 8080 will redirect any visitor to the
    TLS port. Note: because the cert is self-signed your browser will
    require you to accept it; on macOS Safari you can mark the cert as
    trusted in Keychain Access.
 */
$cleartext_port = 8080;
$tls_port = 8443;

$test->middleware(function () use ($test, $tls_port) {
    /*
        On the cleartext listener, rewrite REQUEST_URI to a sentinel
        path so the registered redirect route below handles every
        request uniformly. We capture the original URI in a custom
        $_SERVER key so the route handler can build the Location
        header. Atto sets $_SERVER['IS_SECURE'] for each incoming
        connection based on which listener accepted it.
     */
    if (empty($_SERVER['IS_SECURE'])) {
        $_SERVER['ORIGINAL_URI'] =
            $_SERVER['REQUEST_URI'] ?? '/';
        $_SERVER['REQUEST_URI'] = $test->base_path
            . '/__redirect_to_https';
        return;
    }
    $host_list = ["localhost" => "/host1", "127.0.0.1" => "/host2",
        "192.168.5.237" => "/host3"
        /* For testing change this last ip to one of your LAN
           addresses. Probably do not be running a VPN. */ ];
    $host_parts = explode(":", $_SERVER['HTTP_HOST']);
        // strip port number
    $host = (!isset($host_list[$host_parts[0]])) ? "/host1" :
        $host_list[$host_parts[0]];
    $uri = empty($_SERVER['REQUEST_URI']) ? "/" : $_SERVER['REQUEST_URI'];
    $active_uri = substr($uri, strlen($test->base_path) - 1);
    $_SERVER['REQUEST_URI'] = urldecode($test->base_path . $host
        . $active_uri);
});

$test->get('/__redirect_to_https', function () use ($test, $tls_port) {
    $host_parts = explode(":", $_SERVER['HTTP_HOST'] ?? "localhost");
    $host = $host_parts[0];
    $original = $_SERVER['ORIGINAL_URI'] ?? '/';
    $location = "https://" . $host . ":" . $tls_port . $original;
    $test->header("HTTP/1.1 301 Moved Permanently");
    $test->header("Location: " . $location);
    $test->header("Content-Type: text/html; charset=utf-8");
    echo "<html><body>Redirecting to <a href=\"" . $location . "\">"
        . htmlspecialchars($location) . "</a></body></html>";
});

$host1site = new WebSite();
$host1site->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host1 Site - Atto Server</title></head>
    <body>
    <h1>Host1 Site - Atto Server</h1>
    <div>Welcome to the host 1 site, served over HTTPS.</div>
    </body>
    </html>
    <?php
});
$test->subsite('/host1', $host1site);

$host2site = new WebSite();
$host2site->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host2 Site - Atto Server</title></head>
    <body>
    <h1>Host2 Site - Atto Server</h1>
    <div>Welcome to the host 2 site, served over HTTPS.</div>
    </body>
    </html>
    <?php
});
$test->subsite('/host2', $host2site);

$host3site = new WebSite();
$host3site->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host3 Site - Atto Server</title></head>
    <body>
    <h1>Host3 Site - Atto Server</h1>
    <div>Welcome to the host 3 site, served over HTTPS.</div>
    </body>
    </html>
    <?php
});
$test->subsite('/host3', $host3site);

if ($test->isCli()) {
    /*
        Two listeners: cleartext on $cleartext_port for the redirect,
        TLS on $tls_port for the actual content. Each listener can
        carry its own stream context. The TLS listener gets the
        self-signed cert from the security folder; the cleartext
        listener has no context so it serves plain HTTP.
     */
    $tls_context = ['ssl' => [
        'local_cert' => __DIR__ . "/../../security/server.crt",
        'local_pk' => __DIR__ . "/../../security/server.key",
        'allow_self_signed' => true,
        'verify_peer' => false,
        'alpn_protocols' => "h2,http/1.1"
    ]];
    $test->listen([
        $cleartext_port,
        ['address' => "tcp://0.0.0.0:" . $tls_port,
            'context' => $tls_context]
    ]);
} else {
    $test->process();
}
