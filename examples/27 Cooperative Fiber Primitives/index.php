<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example
               under a web server */
}
/*
    Cooperative fiber primitives, shown as a live web page.

    Atto's servers are single-process reactors: one select loop drives
    every connection. A handler that blocks -- on a lock, a socket, a
    child process -- would freeze every other client. The fix used across
    WebSite, MailSite, and FtpSite is to run handlers inside a Fiber so a
    blocking step can suspend, let the loop serve everyone else, and be
    resumed once its resource is ready.

    This example is itself an Atto WebSite. Its landing page runs a small,
    self-contained cooperative loop that exercises the primitives those
    servers depend on, and renders a timestamped trace so you can watch
    tasks take turns in the browser instead of one blocking the rest:

        1. the cooperative loop     -- run tasks as fibers, park them when
           they suspend, resume them when ready
        2. plain yield              -- hand control back so others run
        3. readable / writable wait -- suspend until a socket is ready
        4. cooperative lock         -- yield while waiting for a flock
        5. worker offload           -- run a child process, suspend on its
                                       output, collect the result

    Each section starts as a one-line description and a trace. The
    description is a link: click it to reveal the exact code that produced
    the trace, read straight from this file so the page can never drift
    from what actually ran.

    After commenting the exit() line above, you can run the example by
    typing:
       php index.php
    and pointing a browser to http://localhost:8080/. Reload the page to
    run the trace again.

    Everything here is plain PHP -- Fiber, streams, flock, proc_open --
    with no outside dependencies, so it mirrors what the real servers do
    without pulling any of them in.
 */

/**
 * A miniature cooperative loop: the same shape the atto servers use,
 * reduced to the essentials. Tasks are added as fibers; run() starts
 * them, parks each one when it suspends, and resumes it once whatever it
 * named is ready. A task says what it is waiting for by returning a
 * ['stream' => ..., 'dir' => 'r' or 'w'] pair from its suspend, or null
 * to simply yield. The loop sleeps in stream_select on the named sockets,
 * so a parked task costs no CPU until its socket is ready. Each trace line
 * is collected rather than printed, so the landing page can show the run.
 */
class CooperativeLoop
{
    /** @var array task label => Fiber */
    protected $tasks = [];
    /** @var array task label => wait descriptor, or null for a plain yield */
    protected $waits = [];
    /** @var float wall-clock start time, used for the trace timestamps */
    protected $started;
    /** @var array collected trace lines for the current section */
    protected $lines = [];

    /**
     * Records the loop's start time so trace() can report each line's
     * offset from when the loop began.
     */
    public function __construct()
    {
        $this->started = microtime(true);
    }

    /**
     * Clears the collected trace and restarts the clock. Each demo calls
     * this first so its section reads from zero milliseconds.
     *
     * @return void
     */
    public function reset()
    {
        $this->lines = [];
        $this->started = microtime(true);
    }

    /**
     * Records one trace line: milliseconds since the section started, the
     * task label, and a message. Reading the timestamps down the block
     * shows how the tasks interleave.
     *
     * @param string $label which task is speaking
     * @param string $message what it is doing
     * @return void
     */
    public function trace($label, $message)
    {
        $elapsed = (microtime(true) - $this->started) * 1000;
        $this->lines[] = sprintf("[%7.1f ms] %-11s %s", $elapsed,
            $label, $message);
    }

    /**
     * Returns the trace collected so far as one block of text and clears
     * it, ready for the next section.
     *
     * @return string the collected trace lines joined by newlines
     */
    public function takeLines()
    {
        $text = implode("\n", $this->lines);
        $this->lines = [];
        return $text;
    }

    /**
     * Registers a task to run in the loop. The body runs inside a fiber,
     * so it may call the wait helpers below to suspend cooperatively.
     *
     * @param string $label name shown in the trace
     * @param callable $body the task's work
     * @return void
     */
    public function addTask($label, callable $body)
    {
        $this->tasks[$label] = new \Fiber($body);
    }

    /**
     * Runs until every task has finished. Each pass sleeps in
     * stream_select until a waited-on socket is ready (or returns at once
     * when some task only yielded), then resumes every parked task. A
     * resumed task rechecks its own readiness and either proceeds or
     * parks again -- exactly what the real servers do.
     *
     * @return void
     */
    public function run()
    {
        foreach ($this->tasks as $label => $fiber) {
            $this->waits[$label] = $fiber->start();
            $this->dropIfDone($label, $fiber);
        }
        while (!empty($this->tasks)) {
            $reads = [];
            $writes = [];
            $yielded = false;
            foreach ($this->waits as $wait) {
                if (is_array($wait) && isset($wait['stream'])) {
                    if ($wait['dir'] === 'w') {
                        $writes[] = $wait['stream'];
                    } else {
                        $reads[] = $wait['stream'];
                    }
                } else {
                    $yielded = true;
                }
            }
            if (!empty($reads) || !empty($writes)) {
                $ready_reads = empty($reads) ? null : $reads;
                $ready_writes = empty($writes) ? null : $writes;
                $excepts = null;
                @stream_select($ready_reads, $ready_writes, $excepts,
                    $yielded ? 0 : 1);
            } else if (!$yielded) {
                usleep(2000);
            }
            foreach ($this->tasks as $label => $fiber) {
                if ($fiber->isSuspended()) {
                    $this->waits[$label] = $fiber->resume();
                }
                $this->dropIfDone($label, $fiber);
            }
        }
    }

    /**
     * Forgets a task once its fiber has run to completion.
     *
     * @param string $label task label
     * @param \Fiber $fiber the task's fiber
     * @return void
     */
    protected function dropIfDone($label, $fiber)
    {
        if ($fiber->isTerminated()) {
            unset($this->tasks[$label], $this->waits[$label]);
        }
    }

    /**
     * Hands control back to the loop for one pass, then continues. Use
     * this to break a long stretch of work into cooperative steps, the
     * way a CPU-heavy handler does.
     *
     * @return void
     */
    public function yieldOnce()
    {
        \Fiber::suspend(null);
    }

    /**
     * Suspends until the given socket has data to read, then returns.
     * Parking here costs no CPU: the loop sleeps in stream_select on the
     * socket until it is ready.
     *
     * @param resource $stream socket to wait on
     * @return void
     */
    public function waitReadable($stream)
    {
        while (true) {
            $reads = [$stream];
            $writes = null;
            $excepts = null;
            if (@stream_select($reads, $writes, $excepts, 0) > 0) {
                return;
            }
            \Fiber::suspend(['stream' => $stream, 'dir' => 'r']);
        }
    }

    /**
     * Suspends until the given socket can accept more data, then
     * returns. This is the write-side twin of waitReadable, used when a
     * send buffer fills up because the far end is reading slowly.
     *
     * @param resource $stream socket to wait on
     * @return void
     */
    public function waitWritable($stream)
    {
        while (true) {
            $reads = null;
            $writes = [$stream];
            $excepts = null;
            if (@stream_select($reads, $writes, $excepts, 0) > 0) {
                return;
            }
            \Fiber::suspend(['stream' => $stream, 'dir' => 'w']);
        }
    }

    /**
     * Takes an exclusive lock on an open file, yielding while another
     * holder has it rather than blocking the whole loop. Returns true
     * once the lock is held, or false on a real lock error as opposed to
     * mere contention. This mirrors the daemon's cooperative store locks.
     *
     * @param resource $handle open file handle to lock
     * @return bool true when the lock is held, false on a real error
     */
    public function coopLock($handle)
    {
        while (true) {
            $would_block = false;
            if (@flock($handle, LOCK_EX | LOCK_NB, $would_block)) {
                return true;
            }
            if (!$would_block) {
                return false;
            }
            \Fiber::suspend(null);
        }
    }

    /**
     * Runs a command in a child process and returns its output without
     * blocking the loop while the child works. The child's standard
     * output is read non-blocking, suspending on it until bytes arrive,
     * so other tasks keep running meanwhile. This is the shape the web
     * server uses to offload a one-shot job such as an outgoing mail
     * send.
     *
     * @param string $command the child command line to run
     * @param string $input bytes to send the child on its standard input
     * @return string|false the child's output, or false if it would not
     *      start
     */
    public function offload($command, $input)
    {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $pipes = [];
        $process = @proc_open($command, $descriptors, $pipes);
        if (!is_resource($process)) {
            return false;
        }
        fwrite($pipes[0], $input);
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        $output = '';
        while (!feof($pipes[1])) {
            $this->waitReadable($pipes[1]);
            $chunk = fread($pipes[1], 8192);
            if ($chunk === false) {
                break;
            }
            $output .= $chunk;
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        return $output;
    }
}

/**
 * Returns the source text of a top-level function, read straight from
 * this file, so the page can show the exact code a demo ran next to the
 * trace it produced. Reflection points at the line of the function
 * keyword, so the docblock above it is left out.
 *
 * @param string $function_name name of the function to read
 * @return string the function's source lines
 */
function functionSource($function_name)
{
    $reflection = new \ReflectionFunction($function_name);
    $source = file($reflection->getFileName());
    $start = $reflection->getStartLine() - 1;
    $length = $reflection->getEndLine() - $start;
    return rtrim(implode('', array_slice($source, $start, $length)));
}

/**
 * Returns the source text of a class, read straight from this file, so
 * the page can reveal the cooperative loop itself on request.
 *
 * @param string $class_name name of the class to read
 * @return string the class's source lines
 */
function classSource($class_name)
{
    $reflection = new \ReflectionClass($class_name);
    $source = file($reflection->getFileName());
    $start = $reflection->getStartLine() - 1;
    $length = $reflection->getEndLine() - $start;
    return rtrim(implode('', array_slice($source, $start, $length)));
}

/**
 * Renders one demonstration as an HTML block. The note is a link: a
 * click toggles a panel holding the exact code the demo ran, so the page
 * stays short until the reader asks to see how a result was made. Below
 * the note sit that hidden code panel, the timestamped trace the code
 * produced, and an optional summary line.
 *
 * @param string $code_id unique id tying the note's toggle to its panel
 * @param string $title short name of the primitive being shown
 * @param string $note a sentence on what to watch for; also the toggle
 * @param string $code the exact source the demo ran
 * @param string $trace the timestamped trace the code produced
 * @param string $summary optional closing remark below the trace
 * @return string the section's HTML
 */
function section($code_id, $title, $note, $code, $trace, $summary = '')
{
    $html = '<section class="demo">';
    $html .= '<h2>' . htmlspecialchars($title) . '</h2>';
    $html .= '<p class="note"><a class="toggle" href="#" onclick="' .
        'return toggleCode(\'' . $code_id . '\')">' .
        htmlspecialchars($note) . '</a></p>';
    $html .= '<pre class="code" id="' . $code_id . '">' .
        htmlspecialchars($code) . '</pre>';
    $html .= '<pre class="trace">' . htmlspecialchars($trace) . '</pre>';
    if ($summary !== '') {
        $html .= '<p class="summary">' . htmlspecialchars($summary) .
            '</p>';
    }
    $html .= '</section>';
    return $html;
}

/**
 * Plain yield: two compute tasks that hand control back after each step.
 * The trace shows their steps interleaving rather than one finishing
 * before the other starts.
 *
 * @param CooperativeLoop $loop the shared loop
 * @return array the trace and an empty summary
 */
function demoPlainYield($loop)
{
    $loop->reset();
    foreach (['compute-a', 'compute-b'] as $name) {
        $loop->addTask($name, function () use ($loop, $name) {
            for ($i = 1; $i <= 3; $i++) {
                $loop->trace($name, "step $i");
                $loop->yieldOnce();
            }
            $loop->trace($name, "done");
        });
    }
    $loop->run();
    return ['trace' => $loop->takeLines(), 'summary' => ''];
}

/**
 * Readable / writable wait: a producer pushes a payload through a socket
 * whose consumer reads slowly. When the send buffer fills the producer
 * parks on writable; when it has caught up the consumer parks on
 * readable. A compute task runs alongside to show neither park stalls
 * the loop.
 *
 * @param CooperativeLoop $loop the shared loop
 * @return array the trace and an empty summary
 */
function demoSocketWait($loop)
{
    $loop->reset();
    $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    stream_set_blocking($pair[0], false);
    stream_set_blocking($pair[1], false);
    $total = 1024 * 1024;
    $loop->addTask('producer', function () use ($loop, $pair, $total) {
        $payload = str_repeat('x', $total);
        $sent = 0;
        $noted = false;
        while ($sent < $total) {
            $count = @fwrite($pair[0], substr($payload, $sent, 65536));
            if ($count === false) {
                break;
            }
            if ($count === 0) {
                if (!$noted) {
                    $loop->trace('producer',
                        'send buffer full -- parking on writable');
                    $noted = true;
                }
                $loop->waitWritable($pair[0]);
                continue;
            }
            $sent += $count;
        }
        fclose($pair[0]);
        $loop->trace('producer', "sent " . round($sent / 1024) . " KB");
    });
    $loop->addTask('consumer', function () use ($loop, $pair, $total) {
        $got = 0;
        $mark = $total / 4;
        while ($got < $total) {
            $loop->waitReadable($pair[1]);
            $chunk = fread($pair[1], 65536);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $got += strlen($chunk);
            if ($got >= $mark) {
                $loop->trace('consumer',
                    "drained " . round($got / 1024) . " KB");
                $mark += $total / 4;
            }
            $loop->yieldOnce();
        }
        fclose($pair[1]);
    });
    $loop->addTask('compute', function () use ($loop) {
        for ($i = 1; $i <= 5; $i++) {
            $loop->trace('compute', "working ($i)");
            $loop->yieldOnce();
        }
    });
    $loop->run();
    return ['trace' => $loop->takeLines(), 'summary' => ''];
}

/**
 * Cooperative lock: two tasks want the same exclusive file lock. The
 * holder keeps it across a few steps while the waiter yields and retries
 * instead of blocking, so a compute task keeps running until the lock is
 * free.
 *
 * @param CooperativeLoop $loop the shared loop
 * @return array the trace and an empty summary
 */
function demoCooperativeLock($loop)
{
    $loop->reset();
    $path = tempnam(sys_get_temp_dir(), 'attocoop');
    $loop->addTask('holder', function () use ($loop, $path) {
        $handle = fopen($path, 'c');
        $loop->coopLock($handle);
        $loop->trace('holder', 'acquired the lock');
        for ($i = 1; $i <= 3; $i++) {
            $loop->trace('holder', "holding ($i)");
            $loop->yieldOnce();
        }
        flock($handle, LOCK_UN);
        fclose($handle);
        $loop->trace('holder', 'released the lock');
    });
    $loop->addTask('waiter', function () use ($loop, $path) {
        $handle = fopen($path, 'c');
        $loop->trace('waiter', 'want the lock -- waiting cooperatively');
        $loop->coopLock($handle);
        $loop->trace('waiter', 'acquired the lock after the holder');
        flock($handle, LOCK_UN);
        fclose($handle);
    });
    $loop->addTask('compute', function () use ($loop) {
        for ($i = 1; $i <= 4; $i++) {
            $loop->trace('compute', "working ($i)");
            $loop->yieldOnce();
        }
    });
    $loop->run();
    @unlink($path);
    return ['trace' => $loop->takeLines(), 'summary' => ''];
}

/**
 * Worker offload: two slow jobs run in child processes at the same time.
 * Because the loop suspends on each child's output instead of waiting,
 * the two overlap, so the total is about one job's time rather than two.
 *
 * @param CooperativeLoop $loop the shared loop
 * @return array the trace and a summary noting the overlap
 */
function demoWorkerOffload($loop)
{
    $loop->reset();
    $job = 'usleep(400000); $sum = 0; ' .
        'for ($i = 1; $i <= 1000; $i++) { $sum += $i; } echo $sum;';
    $command = escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($job);
    $began = microtime(true);
    foreach (['job-1', 'job-2'] as $name) {
        $loop->addTask($name, function () use ($loop, $name, $command) {
            $loop->trace($name, 'started a worker process');
            $result = $loop->offload($command, '');
            $loop->trace($name, "worker returned $result");
        });
    }
    $loop->run();
    $spent = round((microtime(true) - $began) * 1000);
    $summary = "Both jobs (400 ms each) finished in {$spent} ms; run " .
        "one after another they would take about 800 ms.";
    return ['trace' => $loop->takeLines(), 'summary' => $summary];
}

$test = new WebSite();

$test->get('/', function () {
    $loop = new CooperativeLoop();
    $demos = [
        ['plain-yield', 'Plain yield',
            'Two compute tasks give control back after every step, so ' .
            'the loop runs them turn by turn rather than one to ' .
            'completion first.',
            'demoPlainYield'],
        ['socket-wait', 'Readable / writable wait',
            'A producer and a slow consumer share a socket. Each parks ' .
            'when the socket is not ready -- the producer when the ' .
            'buffer is full, the consumer when it is empty -- while a ' .
            'compute task keeps running, proving neither park stalls ' .
            'the loop.',
            'demoSocketWait'],
        ['coop-lock', 'Cooperative lock',
            'Two tasks want the same exclusive file lock. The holder ' .
            'keeps it across a few steps; the waiter yields and retries ' .
            'instead of blocking, so the compute task keeps running ' .
            'until the lock is free.',
            'demoCooperativeLock'],
        ['worker-offload', 'Worker offload',
            'Two slow jobs run in child processes at once. The loop ' .
            'suspends on each child\'s output instead of waiting, so ' .
            'the two run side by side rather than one after the other.',
            'demoWorkerOffload'],
    ];
    $body = '';
    foreach ($demos as $demo) {
        list($code_id, $title, $note, $function_name) = $demo;
        $result = $function_name($loop);
        $body .= section($code_id, $title, $note,
            functionSource($function_name), $result['trace'],
            $result['summary']);
    }
    $loop_source = classSource('CooperativeLoop');
    ?>
    <!DOCTYPE html>
    <html>
    <head>
    <title>Cooperative Fiber Primitives - Atto Server</title>
    <style>
    body {
        font-family: system-ui, sans-serif;
        max-width: 62em;
        margin: 2em auto;
        padding: 0 1em;
        color: #222;
        line-height: 1.5;
    }
    h1 { margin-bottom: 0.2em; }
    .lead { color: #555; margin-top: 0; }
    .demo {
        border: 1px solid #ddd;
        border-radius: 6px;
        margin: 1.4em 0;
        padding: 0 1.2em 1em;
    }
    .demo h2 { margin-bottom: 0.2em; }
    .note { color: #333; margin-top: 0.3em; }
    .toggle {
        color: #0366d6;
        text-decoration: none;
        cursor: pointer;
        border-bottom: 1px dotted #0366d6;
    }
    .toggle:hover { background: #eef4ff; }
    .toggle::before { content: "\25B8\00a0\00a0"; }
    .code {
        display: none;
        background: #f6f8fa;
        color: #24292e;
        border: 1px solid #e1e4e8;
        padding: 1em;
        border-radius: 4px;
        overflow-x: auto;
        font-size: 0.82em;
        line-height: 1.45;
    }
    .trace {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 1em;
        border-radius: 4px;
        overflow-x: auto;
        font-size: 0.85em;
        line-height: 1.4;
    }
    .summary { font-weight: bold; }
    footer { color: #555; margin: 2em 0; }
    </style>
    </head>
    <body>
    <h1>Cooperative Fiber Primitives</h1>
    <p class="lead">
    Atto's servers are single-process reactors: one loop drives every
    connection, and a handler runs inside a Fiber so a blocking step can
    suspend and let the loop serve everyone else. The blocks below run a
    small cooperative loop that exercises the same primitives. Each
    description is a link -- click it to see the exact code that produced
    the trace beneath it. You can also
    <a class="toggle" href="#" onclick="return toggleCode('loop-source')">
    show the cooperative loop itself</a>.
    </p>
    <pre class="code" id="loop-source"><?=
        htmlspecialchars($loop_source) ?></pre>
    <?= $body ?>
    <footer>
    The loop served every task without blocking on any one of them -- the
    same way atto's servers stay responsive. Reload to run the trace
    again.
    </footer>
    <script>
    function toggleCode(id) {
        var element = document.getElementById(id);
        if (element.style.display === 'block') {
            element.style.display = 'none';
        } else {
            element.style.display = 'block';
        }
        return false;
    }
    </script>
    </body>
    </html>
    <?php
});

if ($test->isCli()) {
    /*
       This line is used if the app is run from the command line with a
       line like:
       php index.php
       It causes the server to run on port 8080.
     */
    $test->listen(8080);
} else {
    /* This line is for when the site is run under a web server like
       Apache, nginx, lighttpd, etc. This folder contains a .htaccess to
       redirect traffic through this index.php file, so redirects need to
       be on to use this example under a different web server.
     */
    $test->process();
}
