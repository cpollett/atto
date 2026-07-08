<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    A simple Atto WebSocket example. Serves an HTML page at / with a
    JavaScript client that connects to a WebSocket endpoint at /echo
    and exchanges messages with the server. The server echoes each
    received message back in upper case so the round-trip is visible.

    After commenting the exit() line above, you can run this example
    by typing:
        php index.php
    and pointing a browser to http://localhost:8080/

    The page will open a WebSocket connection to ws://localhost:8080/echo
    and let you type messages that are echoed back.

    DEPLOYMENT NOTE: WebSockets require Atto to run in CLI mode (as a
    long-lived process). They cannot work when this script is invoked
    by Apache, nginx-FPM, or a CGI handler, because those environments
    do not expose the underlying TCP socket to PHP. For production,
    run this script as a CLI daemon on an internal port and configure
    nginx or Apache as a reverse proxy that forwards the WebSocket
    upgrade. Example nginx location block:

        location /echo {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "Upgrade";
            proxy_set_header Host $host;
            proxy_read_timeout 3600s;
        }
 */
$test->get('/', function () use ($test) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Atto WebSocket Demo</title>
        <style>
            body { font-family: sans-serif; max-width: 600px;
                margin: 2em auto; }
            #log { border: 1px solid #ccc; padding: 1em;
                height: 300px; overflow-y: auto; margin-bottom: 1em;
                font-family: monospace; background: #f8f8f8; }
            .sent { color: #06c; }
            .recv { color: #060; }
            .sys { color: #999; font-style: italic; }
            input[type=text] { width: 70%; padding: 0.5em; }
            button { padding: 0.5em 1em; }
        </style>
    </head>
    <body>
        <h1>Atto WebSocket Demo</h1>
        <p>Type a message and the server will echo it back upper-cased.</p>
        <div id="log"></div>
        <form id="form">
            <input type="text" id="msg" placeholder="Say something"
                autocomplete="off" autofocus>
            <button type="submit">Send</button>
        </form>
        <script>
            var log = document.getElementById('log');
            var form = document.getElementById('form');
            var input = document.getElementById('msg');
            function append(text, cls) {
                var div = document.createElement('div');
                div.className = cls;
                div.textContent = text;
                log.appendChild(div);
                log.scrollTop = log.scrollHeight;
            }
            var proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
            var ws = new WebSocket(proto + '//' + location.host + '/echo');
            ws.onopen = function () {
                append('[connected]', 'sys');
            };
            ws.onmessage = function (event) {
                append('< ' + event.data, 'recv');
            };
            ws.onclose = function () {
                append('[disconnected]', 'sys');
            };
            ws.onerror = function () {
                append('[error]', 'sys');
            };
            form.onsubmit = function (event) {
                event.preventDefault();
                var text = input.value;
                if (text === '') {
                    return;
                }
                ws.send(text);
                append('> ' + text, 'sent');
                input.value = '';
            };
        </script>
    </body>
    </html>
    <?php
});
$test->ws('/echo', function ($ws) {
    $ws->send("Welcome! Type a message and I will shout it back.");
    $ws->onMessage(function ($message, $ws) {
        $ws->send(strtoupper($message));
    });
    $ws->onClose(function ($ws) {
        echo "Client disconnected from /echo\n";
    });
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
