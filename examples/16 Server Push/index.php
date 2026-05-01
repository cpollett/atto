<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    HTTP/2 Server Push demo.

    When a client requests the root page, the server pushes the
    stylesheet and the script alongside the HTML response in the
    same TLS connection. The client receives all three resources
    in one round trip instead of having to parse the HTML, find
    the <link> and <script> tags, and request them as separate
    follow-up GETs.

    Push is requested via $site->push($url) inside a route. The
    URL must be same-origin (cross-origin pushes are silently
    dropped per RFC 7540 sec 8.2). The pushed resource is
    dispatched through the same route table the client would
    have hit if it had requested it directly, so adding push
    to an existing route only changes the wire format, not the
    server-side request handling.

    Push is no-op (returns false) under any of these conditions:
      - The connection is HTTP/1.1 or HTTP/3 (push is HTTP/2-
        specific). HTTP/3 has its own server-push mechanism
        but Atto does not currently implement it.
      - The client has set SETTINGS_ENABLE_PUSH=0 in its
        initial SETTINGS frame. Most modern browsers
        (Chrome 106+, Firefox 102+) disable push by default
        because real-world data showed it rarely improved
        page-load times and often made them worse. Push is
        most useful for first-party CDN scenarios over fast
        links where the server has stable knowledge of the
        client's cache state, or for HTTP/2-aware command-
        line tools like nghttp.
      - The route is not running inside an HTTP/2 streaming
        context, e.g., it was called from PHP-FPM rather than
        from atto's listen() event loop.

    Returns true when a PUSH_PROMISE plus the synthesized
    response have been queued for the client.

    To test:

      php index.php
      nghttp -nv https://localhost:8443/

    nghttp will print "recv PUSH_PROMISE" frames followed by
    the corresponding HEADERS/DATA on the promised stream ids
    (2, 4, ...). Try again with --no-push and PUSH_PROMISE will
    not appear.

    KEY API:

        $site->push($url)
            Same-origin URL of a resource the client will need
            to render the current response. Returns true if the
            push was queued, false if push is unavailable. Call
            from inside a route, before flushing or returning.

    DEPLOYMENT NOTE: Push only works in CLI mode (it depends on
    direct frame-level access to the H2 connection). When Atto
    runs behind a reverse proxy, the proxy must also speak H2
    end-to-end and forward PUSH_PROMISE frames to the client;
    nginx supports this with http2_push_preload directive but
    the support is in maintenance mode upstream. Cloudflare and
    other CDNs have generally removed push support entirely. For
    new code consider the simpler alternative of adding a
    Link: rel=preload header (see WebSite::preload) which works
    over HTTP/1.1, HTTP/2, and HTTP/3 alike.
 */
$test->get('/', function () use ($test) {
    /*
        Push the stylesheet and script before emitting the
        HTML so the client starts fetching them while it
        parses the body. Order matters: pushes that appear
        earlier in the route get into the client's cache
        sooner.
     */
    $test->push('/styles.css');
    $test->push('/app.js');
    $test->header('Content-Type: text/html; charset=utf-8');
    ?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Atto HTTP/2 Server Push Demo</title>
<link rel="stylesheet" href="/styles.css">
<script src="/app.js" defer></script>
</head>
<body>
<h1>Atto HTTP/2 Server Push Demo</h1>
<p>If you ran this with <code>nghttp -nv https://localhost:8443/</code>
   you should see <code>recv PUSH_PROMISE</code> frames in the
   trace before this HTML body arrives. The <code>styles.css</code>
   and <code>app.js</code> resources were pushed alongside this
   page in a single connection turn.</p>
<p>Push is HTTP/2-specific. If you load this page in a browser
   over HTTP/1.1 the resources will load as normal follow-up
   requests; the page works the same either way.</p>
<p id="status">Loading...</p>
</body>
</html>
    <?php
});

$test->get('/styles.css', function () use ($test) {
    $test->header('Content-Type: text/css');
    echo <<<CSS
body { font-family: system-ui, sans-serif; max-width: 40em;
    margin: 2em auto; padding: 0 1em; color: #222;
    background: #fafafa; }
h1 { color: #c33; border-bottom: 2px solid #c33;
    padding-bottom: .3em; }
code { background: #eee; padding: .1em .3em; border-radius: 3px;
    font-size: .9em; }
#status { font-style: italic; color: #690; }
CSS;
});

$test->get('/app.js', function () use ($test) {
    $test->header('Content-Type: application/javascript');
    echo <<<JS
document.addEventListener('DOMContentLoaded', function () {
    var status = document.getElementById('status');
    if (status) {
        status.textContent =
            'Pushed JS ran. Page used ' +
            performance.getEntriesByType('resource').length +
            ' resource(s).';
    }
});
JS;
});

/*
    Listen on TLS port 8443 only. HTTP/2 requires TLS in
    practice (browsers refuse h2c). The cert is the same
    self-signed dev cert used by the other examples; for
    production, use the make-local-ca.sh script in
    security/ to generate a CA-signed leaf cert browsers
    will trust.
 */
$cert = __DIR__ . "/../../security/server.crt";
$key  = __DIR__ . "/../../security/server.key";
$test->listen([
    ['address' => 8443, 'context' => ['ssl' => [
        'local_cert' => $cert,
        'local_pk' => $key,
        'allow_self_signed' => true,
        'verify_peer' => false,
        'alpn_protocols' => 'h2,http/1.1',
    ]]],
]);
