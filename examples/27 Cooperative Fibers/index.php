<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example
               under a web server */
}
$test = new WebSite();
/*
    Cooperative fibers: keeping a server responsive during slow work.

    Atto's WebSite (and MailSite, FtpSite, ...) run in one process with a
    single event loop. If one request does something slow -- reading a
    mailbox over IMAP, talking to a mail server, waiting on a child process
    -- a plain blocking read would freeze every other connection until it
    finished. This is the problem the cooperative work solved for Yioop when
    it served pages and webmail on top of WebSite and MailSite.

    The fix is to run the slow handler inside a fiber and, wherever it would
    block, call Fiber::suspend() to hand the loop back so it can serve
    everyone else, resuming once the thing it waited for is ready. Two
    pieces do this:

      * deferResponse($handler) runs $handler inside a fiber under the atto
        loop (and straight through, outside any fiber, under Apache where
        each request is its own process). Whatever the handler echoes
        becomes the response once it finishes.
      * a cooperative wait -- Fiber::suspend(['read' => $stream]) -- yields
        until $stream has data. This is exactly what Yioop's ImapClient and
        SmtpClient do around every mail-socket read.

    The /slow route below stands in for that slow work: it starts a child
    process that prints a line a second for a few seconds and reads the
    child's output cooperatively. While /slow waits between lines, the loop
    is free, so a request to /now is answered at once instead of being made
    to wait for /slow to finish. Open /slow in one browser tab and then hit
    /now in another to watch it stay instant.

    After commenting the exit() line above, you can run the example by
    typing:
       php index.php
    and pointing a browser at http://localhost:8080/ .
 */

/*
    Waits until $stream has data to read without freezing the whole server.
    Inside a fiber (running under the atto loop) it hands the loop back with
    Fiber::suspend(['read' => $stream]) so other connections are served
    until the stream is ready. Outside a fiber (under Apache, where the
    request is its own process and there is nobody else to serve) it simply
    blocks on a select. This guard -- suspend when in a fiber, block when
    not -- is the same one Yioop's mail clients use around every read.

    @param resource $stream the stream to wait on until it is readable
 */
$wait_readable = function ($stream) {
    if (\Fiber::getCurrent() === null) {
        $read = [$stream];
        $write = [];
        $except = [];
        stream_select($read, $write, $except, null);
        return;
    }
    \Fiber::suspend(['read' => $stream]);
};

/*
    The slow route. deferResponse runs this handler as a fiber. It launches
    a child that prints one line a second (standing in for any slow producer
    -- a mail server, a shell job, a remote fetch) and collects the child's
    output, waiting cooperatively between lines so the loop stays free.
 */
$test->get('/slow', function () use ($test, $wait_readable) {
    return $test->deferResponse(function () use ($test, $wait_readable) {
        $started = microtime(true);
        $descriptors = [1 => ['pipe', 'w']];
        $child = proc_open([PHP_BINARY, "-r",
            'for ($i = 1; $i <= 4; $i++) { echo "step $i\n"; sleep(1); }'],
            $descriptors, $pipes);
        stream_set_blocking($pipes[1], false);
        $lines = [];
        while (!feof($pipes[1])) {
            $wait_readable($pipes[1]);
            $chunk = fread($pipes[1], 8192);
            if ($chunk === false || $chunk === "") {
                continue;
            }
            foreach (explode("\n", trim($chunk)) as $line) {
                if ($line !== "") {
                    $lines[] = $line;
                }
            }
        }
        fclose($pipes[1]);
        proc_close($child);
        $elapsed = round(microtime(true) - $started, 1);
        $test->header("Content-Type: text/plain");
        echo "slow work finished in {$elapsed}s while the server stayed " .
            "responsive\n";
        echo implode("\n", $lines) . "\n";
    });
});

/*
    The fast route. Returns at once. Requested while /slow is mid-run, it
    still answers immediately, because /slow gave the loop back instead of
    freezing it.
 */
$test->get('/now', function () use ($test) {
    $test->header("Content-Type: text/plain");
    echo "now: " . date("H:i:s") . "\n";
});

$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Cooperative Fibers - Atto</title></head>
    <body>
    <h1>Cooperative Fibers - Atto</h1>
    <p>Atto runs everything in one event loop, so a slow request must not
    block the rest. A slow handler runs inside a fiber (via
    <code>deferResponse</code>) and, wherever it would wait, calls
    <code>Fiber::suspend(['read' =&gt; $stream])</code> to hand the loop
    back. This is the machinery that let Yioop serve pages while a webmail
    request waited on a slow IMAP server.</p>
    <p>To see it:</p>
    <ol>
    <li>Open <a href="/slow" target="_blank">/slow</a> in one tab. It reads
    a child process that prints a line a second for four seconds, waiting
    cooperatively between lines.</li>
    <li>While it runs, open <a href="/now" target="_blank">/now</a> in
    another tab (or reload it). It answers instantly every time, even
    though /slow is still working -- the fiber suspended instead of
    blocking the loop.</li>
    </ol>
    <p>Under Apache or another web server there is no atto loop and each
    request is its own process, so the same code runs straight through and
    the waits simply block -- which is correct, since there is nobody else
    in that process to serve.</p>
    </body>
    </html>
    <?php
});

/*
    Start the server: listen on 8080 from the command line, or handle the
    current request when running under another web server.
 */
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
