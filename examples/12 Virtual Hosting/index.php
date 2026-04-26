<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();
/*
    An Atto WebSite consisting of landing pages for four different hosts,
    served over HTTPS. Two cleartext listeners (one IPv4, one IPv6) bound
    to the cleartext port redirect every request to the corresponding
    TLS listener. This shows three Atto features at once:

      * virtual hosting (one Atto process serving different responses
        based on the HTTP Host header)
      * multi-listener (one Atto process binding to multiple ports
        and stack families with different TLS settings)
      * IPv6 support (the [::1] loopback address routes to host4)

    To run this example you may need administrator privileges to bind
    ports 80 and 443; on macOS and Linux you can use higher ports
    (8080 and 8443 are pre-set below).

    Use ifconfig or ipconfig to determine your LAN ip address and edit
    the third $host_list entry appropriately. In the real world you
    would use different hostnames you had paid for as $host_list keys.

    For the IPv6 demo to work over HTTPS, the self-signed cert in the
    security folder must include ::1 as a subjectAltName. The bundled
    san.cnf has IP.1 = 127.0.0.1; add IP.2 = ::1 and regenerate with:
       openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key \
         -out server.crt -days 365 -config san.cnf
    Then re-trust the cert in your browser/OS keychain.

    After commenting the exit() line above, you can run the example by
    typing:
       php index.php
    and pointing a browser to:
       https://localhost:8443/         -> host1
       https://127.0.0.1:8443/         -> host2
       https://your_lan_ip:8443/       -> host3 (after editing host_list)
       https://[::1]:8443/             -> host4 (IPv6 loopback)
    The cleartext listeners on port 8080 will redirect any visitor to
    the corresponding TLS port.
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
        "192.168.5.237" => "/host3", "[::1]" => "/host4"
        /* For testing change the LAN ip to one of your LAN
           addresses. Probably do not be running a VPN. */ ];
    $http_host = $_SERVER['HTTP_HOST'] ?? "localhost";
    /*
        Extract the host part of the Host header, stripping the
        port. Browsers send IPv6 addresses bracketed, e.g.
        [::1]:8443, so we have to look for a closing bracket
        before falling back to the last colon for IPv4 / hostname.
     */
    if (substr($http_host, 0, 1) === "[") {
        $close = strpos($http_host, "]");
        $host_only = ($close !== false)
            ? substr($http_host, 0, $close + 1) : $http_host;
    } else {
        $colon = strpos($http_host, ":");
        $host_only = ($colon !== false)
            ? substr($http_host, 0, $colon) : $http_host;
    }
    $host = $host_list[$host_only] ?? "/host1";
    $uri = empty($_SERVER['REQUEST_URI']) ? "/" : $_SERVER['REQUEST_URI'];
    $active_uri = substr($uri, strlen($test->base_path) - 1);
    $_SERVER['REQUEST_URI'] = urldecode($test->base_path . $host
        . $active_uri);
});

$test->get('/__redirect_to_https', function () use ($test, $tls_port) {
    $http_host = $_SERVER['HTTP_HOST'] ?? "localhost";
    if (substr($http_host, 0, 1) === "[") {
        $close = strpos($http_host, "]");
        $host_only = ($close !== false)
            ? substr($http_host, 0, $close + 1) : $http_host;
    } else {
        $colon = strpos($http_host, ":");
        $host_only = ($colon !== false)
            ? substr($http_host, 0, $colon) : $http_host;
    }
    $original = $_SERVER['ORIGINAL_URI'] ?? '/';
    $location = "https://" . $host_only . ":" . $tls_port . $original;
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
    <div>Welcome to the host 1 site, served over HTTPS at
    <code>localhost</code>.</div>
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
    <div>Welcome to the host 2 site, served over HTTPS at
    <code>127.0.0.1</code>.</div>
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
    <div>Welcome to the host 3 site, served over HTTPS at the LAN
    address.</div>
    </body>
    </html>
    <?php
});
$test->subsite('/host3', $host3site);

$host4site = new WebSite();
$host4site->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host4 Site - Atto Server (IPv6)</title></head>
    <body>
    <h1>Host4 Site - Atto Server (IPv6)</h1>
    <div>Welcome to the host 4 site, served over HTTPS at the IPv6
    loopback <code>[::1]</code>.</div>
    </body>
    </html>
    <?php
});
$test->subsite('/host4', $host4site);

if ($test->isCli()) {
    /*
        Four listeners: cleartext IPv4 + IPv6 on $cleartext_port for
        the redirect, TLS IPv4 + IPv6 on $tls_port for the actual
        content. Each listener can carry its own stream context. Both
        TLS listeners share the same self-signed cert from the
        security folder; the cleartext listeners have no context so
        they serve plain HTTP.

        We bind explicit IPv4 and IPv6 sockets rather than relying on
        a single dual-stack bind because behavior varies by OS.
        Linux defaults dual-stack, BSDs (including macOS) default
        single-stack. Two explicit listeners is portable.
     */
    $tls_context = ['ssl' => [
        'local_cert' => __DIR__ . "/../../security/server.crt",
        'local_pk' => __DIR__ . "/../../security/server.key",
        'allow_self_signed' => true,
        'verify_peer' => false,
        'alpn_protocols' => "h2,http/1.1"
    ]];
    $test->listen([
        "tcp://0.0.0.0:" . $cleartext_port,
        "tcp://[::1]:" . $cleartext_port,
        ['address' => "tcp://0.0.0.0:" . $tls_port,
            'context' => $tls_context],
        ['address' => "tcp://[::1]:" . $tls_port,
            'context' => $tls_context]
    ]);
} else {
    $test->process();
}
