<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    A streaming-response demo for Atto. Shows three patterns:

    1. /         A landing page with two live demos: an SSE event
                 stream and a "send chunks as you compute them"
                 plain-text progress feed.

    2. /events   Server-Sent Events endpoint. Calls $site->flush()
                 between events so the browser's EventSource sees
                 each one as it arrives instead of waiting for the
                 route to return. Headers are emitted before the
                 first flush; subsequent flushes write further
                 chunks. After the route returns, Atto writes the
                 chunked terminator automatically.

    3. /progress Plain text/event-stream-style progress feed for
                 a simulated multi-step job. The route walks
                 through 5 "steps", flushes a status line after
                 each, and the browser appends them to the page
                 as they arrive. Demonstrates the same flush
                 mechanism without SSE framing.

    4. /export.csv  Streaming CSV download. Useful when the row
                    set is large (or expensive to compute) and
                    you want the browser to start receiving and
                    saving rows immediately rather than waiting
                    for the whole file to assemble in memory.

    After commenting the exit() line above, you can run this
    example by typing:
        php index.php
    and pointing a browser to http://localhost:8080/

    KEY API:
        $site->flush()
            Pushes any buffered output to the client right away.
            On first call: composes response headers (with
            Transfer-Encoding: chunked for HTTP/1.1, or a HEADERS
            frame without END_STREAM for HTTP/2) and writes them
            with the buffered output as the first chunk.
            On subsequent calls: writes only the new buffered
            output as another chunk.
            After the route returns, Atto sends the chunked
            terminator (or empty DATA frame with END_STREAM).

    IMPORTANT: Atto is single-threaded. While a streaming route
    is running, the event loop cannot serve other connections.
    So routes that flush should do bounded work per request and
    return promptly. For long-lived "push" channels prefer the
    SSE auto-reconnect pattern (the EventSource constructor
    reconnects automatically when the server closes), or use
    WebSockets (example 14) for true bidirectional streaming.

    DEPLOYMENT NOTE: streaming responses require Atto to run in
    CLI mode. They cannot work when this script is invoked by
    Apache or nginx-FPM, because those environments buffer the
    response. For production, run this script as a CLI daemon
    behind a reverse proxy. For nginx, disable proxy buffering
    on the streaming locations:

        location /events {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_cache off;
            proxy_read_timeout 3600s;
        }
 */
$test->get('/', function () use ($test) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Atto Streaming Demo</title>
        <style>
            body { font-family: sans-serif; max-width: 720px;
                margin: 2em auto; padding: 0 1em; }
            h2 { margin-top: 2em; }
            .panel { border: 1px solid #ccc; padding: 1em;
                background: #f8f8f8; margin: 0.5em 0;
                font-family: monospace; min-height: 6em;
                white-space: pre-wrap; }
            button { padding: 0.5em 1em; margin-right: 0.5em; }
            .meta { color: #666; font-size: 0.9em; }
            a { color: #06c; }
        </style>
    </head>
    <body>
        <h1>Atto Streaming Responses</h1>
        <p>Three demos of <code>$site-&gt;flush()</code>. Each
        pushes data to the browser incrementally rather than
        buffering the whole response.</p>

        <h2>1. Server-Sent Events (<code>/events</code>)</h2>
        <p class="meta">Uses the browser's
        <code>EventSource</code>. The server flushes one event,
        sleeps briefly, flushes the next.</p>
        <button id="sse_start">Start</button>
        <button id="sse_stop">Stop</button>
        <div id="sse_log" class="panel"></div>

        <h2>2. Live Progress Feed (<code>/progress</code>)</h2>
        <p class="meta">Plain text/plain response. Each line is
        a flushed chunk. Click and watch the lines appear over
        five seconds.</p>
        <button id="prog_start">Run job</button>
        <div id="prog_log" class="panel"></div>

        <h2>3. Streaming CSV Download
            (<a href="/export.csv">/export.csv</a>)</h2>
        <p class="meta">Click the link. The browser starts the
        download as soon as the first chunk arrives, even though
        the server is still generating rows. Useful for large or
        slow-to-compute exports.</p>

        <script>
            var sse_log = document.getElementById('sse_log');
            var prog_log = document.getElementById('prog_log');
            var es = null;

            function append(panel, text) {
                panel.textContent += text + "\n";
                panel.scrollTop = panel.scrollHeight;
            }

            document.getElementById('sse_start').onclick = function () {
                if (es) { es.close(); }
                sse_log.textContent = '';
                es = new EventSource('/events');
                append(sse_log, '[connecting]');
                es.onopen = function () {
                    append(sse_log, '[open]');
                };
                es.onmessage = function (event) {
                    append(sse_log, '< ' + event.data);
                };
                es.onerror = function () {
                    append(sse_log, '[closed; will retry]');
                };
            };
            document.getElementById('sse_stop').onclick = function () {
                if (es) { es.close(); es = null; }
                append(sse_log, '[stopped]');
            };

            document.getElementById('prog_start').onclick = function () {
                prog_log.textContent = '';
                fetch('/progress').then(function (response) {
                    var reader = response.body.getReader();
                    var decoder = new TextDecoder();
                    function pump() {
                        return reader.read().then(function (chunk) {
                            if (chunk.done) {
                                append(prog_log, '[done]');
                                return;
                            }
                            var text = decoder.decode(
                                chunk.value, {stream: true});
                            prog_log.textContent += text;
                            prog_log.scrollTop =
                                prog_log.scrollHeight;
                            return pump();
                        });
                    }
                    return pump();
                });
            };
        </script>
    </body>
    </html>
    <?php
});
$test->get('/events', function () use ($test) {
    /*
        Server-Sent Events. The browser's EventSource expects
        Content-Type: text/event-stream and one or more
        "data: <payload>\n\n" frames. We flush after each so the
        browser sees them as they arrive.

        We send a bounded number of events and return. The
        EventSource API auto-reconnects after the connection
        closes, so a long-lived "channel" is built from many
        short responses rather than one infinite one. This keeps
        the event loop free to serve other requests between
        bursts.
     */
    $test->header("Content-Type: text/event-stream");
    $test->header("Cache-Control: no-cache");
    $test->header("X-Accel-Buffering: no");
    for ($i = 1; $i <= 5; $i++) {
        echo "data: event {$i} at " . date('H:i:s') . "\n\n";
        $test->flush();
        usleep(400000);
    }
});
$test->get('/progress', function () use ($test) {
    /*
        Plain text/plain progress feed. Each step echos a
        status line and flushes; the browser reads incrementally
        via fetch() + ReadableStream.
     */
    $test->header("Content-Type: text/plain; charset=utf-8");
    $test->header("X-Accel-Buffering: no");
    $steps = ["Connecting to database",
              "Loading 12,000 records",
              "Computing aggregates",
              "Writing report",
              "Cleaning up"];
    foreach ($steps as $i => $label) {
        echo sprintf("[%d/%d] %s ...\n", $i + 1, count($steps),
            $label);
        $test->flush();
        usleep(700000);
        echo "       done.\n";
        $test->flush();
    }
    echo "All steps complete.\n";
});
$test->get('/export.csv', function () use ($test) {
    /*
        Streaming CSV. The browser starts saving the file as
        soon as the first chunk arrives instead of waiting for
        the whole body to assemble. Lets you export huge or
        slow-to-compute datasets without buffering them in PHP
        memory.
     */
    $test->header("Content-Type: text/csv; charset=utf-8");
    $test->header(
        "Content-Disposition: attachment; filename=\"export.csv\"");
    echo "id,name,value,timestamp\n";
    $test->flush();
    for ($i = 1; $i <= 200; $i++) {
        echo sprintf("%d,row_%d,%.4f,%s\n",
            $i, $i, mt_rand() / mt_getrandmax(),
            date('c'));
        if ($i % 25 === 0) {
            $test->flush();
            usleep(50000);
        }
    }
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
