<?php
/**
 * seekquarry\atto\Website --
 * a small web server and web routing engine
 *
 * Copyright (C) 2018-2026  Chris Pollett chris@pollett.org
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018-2026
 * @filesource
 */

 namespace seekquarry\atto;

/**
 * A single file, low dependency, pure PHP web server and web routing engine
 * class.
 *
 * This software can be used to route requests, and hence, serve as a micro
 * framework for use under a traditional web server such as Apache, nginx,
 * or lighttpd. It can also be used to serve web apps as a stand alone
 * web server for apps created using its routing facility. As a standalone
 * web server, it is web request event-driven, supporting asynchronous I/O
 * for web traffic. It also supports timers for background events. Unlike
 * similar PHP software, as a Web Server it instantiates traditional
 * PHP superglobals like $_GET, $_POST, $_REQUEST, $_COOKIE, $_SESSION,
 * $_FILES, etc and endeavors to make it easy to code apps in a rapid PHP
 * style.
 *
 * @author Chris Pollett
 */

use Exception;

class WebSite
{
    /**
     * Bytes the file write journal may reach before a write starts it
     * again empty. A process that finds the journal shorter than where it
     * last read drops its whole file cache, which is always safe.
     */
    const FILE_JOURNAL_MAX_BYTES = 1000000;
    /**
     * PAYLOAD_TOO_LARGE is the response code sent for a request whose
     * length passes MAX_REQUEST_LEN, so a client such as git can say the
     * request was too large rather than malformed. For example, a 24 MB
     * push to a server whose MAX_REQUEST_LEN is 10 MB is answered 413.
     */
    const PAYLOAD_TOO_LARGE = 413;
    /**
     * Seconds a worker process has to start and connect back.
     */
    const WORKER_START_SECONDS = 30;
    /**
     * Seconds the front waits for a connection on the worker link to show
     * the hash that proves it is the worker it started, before closing it.
     */
    const WORKER_PROOF_SECONDS = 0.5;
    /**
     * WORKER_ACCEPT_WAIT is how long, in seconds, startWorkers waits each
     * time it looks for the first workers to connect back, the same as the
     * front once waited between looks while a worker started.
     */
    const WORKER_ACCEPT_WAIT = 0.05;
    /**
     * Seconds before a worker that failed to start is started again, so a
     * worker that cannot start does not cost every request a new process.
     */
    const WORKER_RETRY_SECONDS = 30;
    /**
     * Most connections refused on the worker link noted in the worker log
     * in one minute; beyond it they are counted and the count is noted.
     */
    const WORKER_REFUSALS_NOTED_PER_MINUTE = 5;
    /**
     * Most bytes read from a worker's link in one go.
     */
    const WORKER_READ_BYTES = 1048576;
    /*
        Field component name constants used in input or output stream array
     */
    /**
     * What is added to a file's path to key its gzip compressed contents
     * in the RAM file cache, beside the plain contents under the path
     * itself. A path cannot end this way, so the two never collide.
     */
    const COMPRESSED_CACHE_SUFFIX = "#gzip";
    const CONNECTION = 0;
    const DATA = 1;
    /**
     * Seconds a stopping server keeps serving the connections it still
     * has before it closes them and stops. A client that keeps its
     * connection open, as a crawler does, would otherwise hold the
     * server up for as long as it liked, and a restart waiting behind the
     * loop would never run.
     */
    const STOP_DRAIN_LIMIT = 10;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
    /**
     * Subkey for the per-socket head pointer into
     * $out_streams[self::DATA][$key]. The drain loop in
     * processResponseStreams advances this offset rather
     * than mutating the DATA buffer with a substr-shift,
     * which avoids an O(n^2) cost when fwrite() returns
     * partial-write counts repeatedly across a single
     * large response (e.g. a 1 MiB body that drains in
     * 64 KiB-or-smaller kernel sendbuf bites). Compaction
     * of the consumed prefix happens in-place once the
     * offset crosses OUT_DATA_COMPACT_THRESHOLD so memory
     * usage on long-lived connections stays bounded.
     */
    const DATA_OFFSET = 4;
    /**
     * Subkey for a file standing in for the rest of
     * $out_streams[self::DATA][$key]. A reply that is a file on disk --
     * a pack built for a git pull, an attachment -- is drained from the
     * file a piece at a time rather than read into a string, so a reply
     * far larger than the server's memory can be sent while the loop
     * keeps serving everything else. Holds ["path" => where the file is,
     * "handle" => the open file, "left" => bytes still to send].
     */
    const DATA_FILE = 5;
    /**
     * Threshold for compacting the consumed prefix of
     * $out_streams[self::DATA][$key] when DATA_OFFSET
     * grows past this many bytes (and at least half the
     * buffer is consumed prefix). 64 KiB is large enough
     * that compactions are rare on bursty traffic and
     * small enough that idle memory does not bloat per
     * connection.
     */
    const OUT_DATA_COMPACT_THRESHOLD = 65536;
    /**
     * How many bytes of a file-backed reply are read into the send buffer
     * at a time. Small enough that a reply of any size costs little
     * memory, large enough that a big file is not read a sliver at a
     * time.
     */
    const OUT_FILE_STEP = 262144;
    /**
     * How long a timer's callback may run, in seconds, before the loop
     * writes a line saying which callback held it and for how long. A
     * request that arrives while a callback runs waits the whole of it,
     * so a callback past this is what a slow reply that did no work
     * itself was waiting on.
     */
    const SLOW_TIMER = 0.1;
    /**
     * Milliseconds in a second, for printing a callback's running time.
     */
    const MILLISECONDS_PER_SECOND = 1000;
    /**
     * How many bytes long an IPv4 address is. Used to tell an IPv4
     * address from an IPv6 one, which is sixteen bytes long.
     */
    const IPV4_ADDRESS_BYTES = 4;
    /**
     * How many leading bytes of an IPv4 address say which block of IP
     * addresses it belongs to. Three of its four, the smallest block an
     * internet provider hands out as a unit.
     */
    const IPV4_BLOCK_BYTES = 3;
    /**
     * How many leading bytes of an IPv6 address say which block of IP
     * addresses it belongs to. Eight of its sixteen, the smallest block
     * an internet provider hands out as a unit.
     */
    const IPV6_BLOCK_BYTES = 8;
    /**
     * Largest number of bytes moved between a socket and memory in a
     * single read or write pass, 128 kibibytes, when the server is not
     * told otherwise. Capping each pass keeps one very large response
     * from being copied whole and running the process out of memory.
     */
    const MAX_IO_LEN_DEFAULT = 128 * 1024;
    /**
     * Number of random bytes in a session id. The id is stored and
     * compared as hex, so it is twice this many characters long.
     */
    const SESSION_ID_BYTE_LEN = 32;
    /**
     * Length of a session id once written as hex, used to check that a
     * cookie-supplied id has the right shape before it is trusted.
     */
    const SESSION_ID_HEX_LEN = 64;
    /**
     * How many sessions are kept in memory at once when the server is
     * not told otherwise. The oldest are dropped past this point so a
     * flood of new visitors cannot grow memory without bound.
     */
    const MAX_SESSIONS_DEFAULT = 10000;
    /**
     * How many kept sessions are measured when working out about how much
     * memory the sessions hold between them. Enough for a fair average,
     * few enough that the reckoning stays cheap on a busy server.
     * @var int
     */
    const SESSION_SAMPLE_COUNT = 20;
    /**
     * How long in seconds a session may sit untouched before the
     * periodic sweep drops it from memory, used when the server config
     * does not set SESSION_IDLE_TIMEOUT. Stops one-shot visitors and
     * bots, who make a single cookieless request and never return to
     * reuse their cookie, from piling up server-side sessions for the
     * whole life of the always-on server.
     */
    const SESSION_IDLE_TIMEOUT_DEFAULT = 3600;
    /**
     * How many seconds to leave between idle-session sweeps. The sweep
     * walks every live session, so it runs on this cadence rather than
     * on every event-loop pass to keep its cost away.
     */
    const SESSION_REAP_INTERVAL = 60;
    /**
     * How many seconds to leave between walks of the session folder for
     * session files no kept session owns. The first walk is made when the
     * server starts, so files left by an earlier run go then.
     */
    const SESSION_FILE_SWEEP_INTERVAL = 3600;
    /**
     * What every session file's name starts with; the session id follows.
     */
    const SESSION_FILE_PREFIX = "atto_session_";
    /**
     * How old in seconds a session file no kept session owns must be
     * before the walk of the session folder deletes it. Other servers may
     * keep their session files in the same folder; a session of theirs
     * left unchanged this long would have been dropped by their own idle
     * sweep, unless they were set to keep sessions longer than this.
     */
    const SESSION_FILE_ORPHAN_AGE = 86400;
    /**
     * Most names of the session folder one event-loop pass looks at. The
     * walk of the folder is spread over many passes, so a folder holding a
     * great many files never keeps the server from taking connections.
     */
    const SESSION_FILE_SWEEP_BATCH = 500;
    /**
     * Most seconds one event-loop pass spends walking the session folder,
     * whichever of this and SESSION_FILE_SWEEP_BATCH is reached first.
     */
    const SESSION_FILE_SWEEP_STEP_TIME = 0.01;
    /**
     * Most microseconds the event loop sleeps between steps of a walk of
     * the session folder, so the walk goes on while no one connects.
     */
    const SESSION_FILE_SWEEP_PAUSE = 50000;
    /**
     * Number of times openListener retries a failed bind before
     * giving up. A restart spawns the replacement process while the
     * exiting one may still hold the privileged port for a short
     * teardown window, so the first bind can fail transiently; the
     * retries let the replacement wait that window out rather than
     * coming up with a dead listener.
     */
    const BIND_ATTEMPTS = 40;
    /**
     * Milliseconds the bind retry waits between attempts. Total
     * worst-case wait is BIND_ATTEMPTS times this value.
     */
    const BIND_RETRY_WAIT = 250;
    /*
      Length in characters of the longest HTTP method atto routes. The
      CalDAV verb MKCALENDAR, which makes a calendar collection, is the
      longest at ten. The request reader peeks at this many bytes plus one
      to read the method name off the front of a request line.
     */
    const LEN_LONGEST_HTTP_METHOD = 10;
    /*
        Length in bytes of an HTTP/2 frame header (RFC 7540 sec 4.1):
        3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream id
     */
    const H2_FRAME_HEADER_LEN = 9;
    /*
        The 24-byte connection preface an HTTP/2 client must send
        as the first data on an H2 connection (RFC 7540 sec 3.5)
     */
    const H2_CLIENT_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    /*
        Maximum permitted size of an inbound HTTP/2 frame payload
        in bytes. Per RFC 7540 sec 6.5.2 the SETTINGS_MAX_FRAME_SIZE
        default is 16384 (the value also advertised when the server
        sends an empty SETTINGS). Frames larger than this are
        rejected with FRAME_SIZE_ERROR and the connection is
        torn down before the oversized payload is allocated, so
        a malicious client cannot trigger memory exhaustion by
        announcing huge frames.
     */
    const H2_MAX_FRAME_SIZE = 16384;
    /**
     * Initial HTTP/2 flow-control window in bytes for a connection
     * and for each new stream, per RFC 7540 sec 6.9.2, before any
     * SETTINGS_INITIAL_WINDOW_SIZE or WINDOW_UPDATE adjustments
     * from the peer.
     */
    const H2_DEFAULT_WINDOW = 65535;
    /**
     * How much upload data, in bytes, the server lets a client send
     * on one stream before it has to pause for the server to confirm
     * it has read the data. The HTTP/2 default is only about 64KB,
     * which forces a client uploading a large file to send a small
     * burst, wait for the server to acknowledge, then send another,
     * over and over. On any connection with real round-trip delay
     * that pause-and-wait pattern makes uploads slow. Advertising a
     * larger window (1MB) lets the client keep the upload pipe full,
     * which speeds up large file posts. It stays well under
     * MAX_REQUEST_LEN, which is the real cap on how big a body the
     * server will accept.
     */
    const H2_ADVERTISED_WINDOW = 1048576;
    /**
     * Most bytes of one stream's pending response body queued per
     * pump call, in bytes. Responses bigger than this go out in
     * slices interleaved with other streams' frames as the
     * connection's outbound buffer drains, so one large response
     * (a video range, say) does not delay every other response
     * multiplexed on the same connection (a page of thumbnails)
     * by its full length.
     */
    const H2_PUMP_SLICE = 262144;
    /**
     * RFC 7540 sec 7 PROTOCOL_ERROR code, sent in GOAWAY frames
     * when tearing a connection down over a malformed frame.
     */
    const H2_ERROR_PROTOCOL = 0x1;
    /**
     * RFC 7540 sec 6.5.2 SETTINGS_INITIAL_WINDOW_SIZE identifier:
     * the per-stream flow-control window the peer's SETTINGS
     * frame advertises.
     */
    const H2_SETTING_INITIAL_WINDOW = 0x04;
    /**
     * Maximum bytes read from an HTTP/2 connection in one readable
     * event before parsing buffered frames. Bounds the work done
     * per event; remaining bytes are read on the next event.
     */
    const H2_READ_CHUNK_SIZE = 65536;
    /**
     * How many seconds a whole-frame control write waits for the
     * socket to take more bytes after a partial write, before the
     * connection is given up as past saving. Control frames are a
     * few tens of bytes, so a peer that cannot take them inside
     * this wait is gone or wedged.
     */
    const CONTROL_FRAME_WRITE_WAIT = 5;
    /**
     * Most HTTP/2 streams the server keeps open at once on one
     * connection. A request that would open a stream past this is
     * refused with RST_STREAM rather than served, so a client that
     * sends requests faster than it reads the replies cannot make
     * the server hold an unbounded amount of request and response
     * state for that one connection. This is also the value the
     * server advertises in its SETTINGS, so a well-behaved client
     * never reaches it; the limit is enforced for clients that
     * ignore the advertisement.
     */
    const H2_MAX_CONCURRENT_STREAMS = 100;
    /**
     * Most unsent response bytes plus unread request-body bytes, in
     * bytes, the server will hold for one HTTP/2 connection before
     * it refuses to open further streams on that connection until
     * the backlog drains. The per-stream limit alone is not enough,
     * because a single stream can carry a sizeable body, so a client
     * could stay under the stream count yet still tie up far too much
     * memory; this caps the total a single slow-reading client can
     * hold. 64 megabytes leaves room for a normal page's worth of
     * concurrent responses and one large upload while staying far
     * below the level that exhausted the process in production.
     */
    const H2_MAX_CONN_BUFFER = 67108864;
    /**
     * RFC 7540 sec 7 REFUSED_STREAM error code. Sent in an
     * RST_STREAM frame when the server declines to open a stream
     * because the connection is at its concurrent-stream or
     * buffered-byte limit. It tells the client the request was not
     * acted on and may be retried once the connection frees up.
     */
    const H2_ERROR_REFUSED_STREAM = 0x7;
    /*
        Magic GUID concatenated with the client-supplied
        Sec-WebSocket-Key during the WebSocket handshake to compute
        the Sec-WebSocket-Accept response header (RFC 6455 sec 4.2.2)
     */
    const WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    /*
        WebSocket frame opcodes (RFC 6455 sec 5.2). Continuation is
        used for fragmented messages; text and binary are application
        data; close, ping, pong are control frames.
     */
    const WS_OPCODE_CONTINUATION = 0x0;
    const WS_OPCODE_TEXT = 0x1;
    const WS_OPCODE_BINARY = 0x2;
    const WS_OPCODE_CLOSE = 0x8;
    const WS_OPCODE_PING = 0x9;
    const WS_OPCODE_PONG = 0xA;
    /*
        Maximum permitted size of a single inbound WebSocket message
        in bytes. Messages exceeding this cause the connection to be
        closed with status 1009 (message too big).
     */
    const WS_MAX_MESSAGE_SIZE = 1048576;
    /**
     * Maximum bytes read from a WebSocket connection in one
     * readable event before parsing buffered frames. Bounds the
     * work done per event so one busy connection cannot monopolize
     * the loop; remaining bytes are read on the next event.
     */
    const WS_READ_CHUNK_SIZE = 65536;
    /**
     * Keys of stream that won't disappear (for example the server socket)
     * @var array
     */
    public $immortal_stream_keys = [];
    /**
     * Check if the current run of the website is after a restart
     * @var boolean
     */
    public $restart;
    /**
     * $listen_address holds the address this server was told to listen
     * on, kept so that whatever starts a replacement server can be told
     * the same address. A server told to listen on several addresses at
     * once keeps the word "multi" here instead.
     * @var string
     */
    public $listen_address = "";
    /**
     * Used to signal stopping the website
     * @var boolean
     */
    public $stop;
    /**
     * $stop_started holds the time the loop first saw the stop signal, so
     * it can give the connections still open STOP_DRAIN_LIMIT seconds and
     * then close them; zero while the server is not stopping.
     * @var float
     */
    public $stop_started = 0;
    /**
     * $stop_drain_limit is how many seconds a stopping server keeps serving
     * the connections it still has, STOP_DRAIN_LIMIT unless whoever asked
     * for the stop wants it shorter, as a restart that has to be over in a
     * few seconds does.
     * @var float
     */
    public $stop_drain_limit = self::STOP_DRAIN_LIMIT;
    /**
     * Most microseconds the event loop of a stopping server sleeps between
     * passes, so it sees at once that its connections have closed or that
     * its time to drain them is up, rather than at its next timer.
     */
    const STOP_PASS_PAUSE = 100000;
    /**
     * A WebSite instance-wide associative array that can be used by routes to
     * store things like bad ips without having deprecation notices for
     * defining fields not in class on the fly. See example 13.
     * This could be a source of memory leaks so use with caution
     * @var array
     */
    public $storage = [];
    /**
     * Default values to write into $_SERVER before processing a connection
     * request (in CLI mode)
     * @var array
     */
    public $default_server_globals;
    /**
     * Associative array http_method => array of how to handle paths for
     *  that method
     * @var array
     */
    protected $routes = ["CONNECT" => [], "COPY" => [], "DELETE" => [],
        "ERROR" => [], "GET" => [], "HEAD" => [], "LOCK" => [],
        "MKCALENDAR" => [], "MKCOL" => [], "MOVE" => [], "OPTIONS" => [],
        "POST" => [], "PROPFIND" => [], "PROPPATCH" => [], "PUT" => [],
        "REPORT" => [], "TRACE" => [], "UNLOCK" => [], "WS" => []];
    /**
     * Default values used to set up session variables
     * @var array
     */
    protected $session_configs = [ 'cookie_lifetime' => '0',
        'cookie_path' => '/', 'cookie_domain' => '', 'cookie_secure' => '',
        'cookie_httponly' => true, 'cookie_samesite' => 'Lax',
        'name' => 'PHPSESSID', 'save_path' => ''];
    /**
     * Array of all connection streams for which we are receiving data from
     * client together with associated stream info
     * @var array
     */
    protected $in_streams = [];
    /**
     * Whether a failure while a request is handled is let out rather
     * than caught. Caught, it is written down and only that one
     * connection is let go, so the server carries on for everyone
     * else; let out, it ends the server, which is what someone
     * tracking such a failure down wants. The site sets this from its
     * own settings; the server itself reads no settings.
     * @var bool
     */
    public $no_wrap_requests = false;
    /**
     * Array of all connection streams for which we are writing data to a
     * client together with associated stream info
     * @var array
     */
    protected $out_streams = [];
    /**
     * A short description of the request currently being handled, set
     * just before each request runs. If the process dies of a memory
     * fatal mid-request, the shutdown handler reads this to name the
     * request that was in flight, which the after-the-request memory log
     * cannot do because it never gets to run. Empty when no request is
     * being handled.
     * @var string
     */
    protected $in_flight_request = "";
    /**
     * How many requests this server has handled since it started. The
     * memory line reports it so a reader can tell memory that climbs
     * with work done from memory that climbs with time.
     * @var int
     */
    protected $requests_served = 0;
    /**
     * The time, in seconds since the epoch, the last memory line was
     * written. Zero before the first one, which starts the clock rather
     * than writing a line.
     * @var int
     */
    protected $memory_line_written_at = 0;
    /**
     * How many requests had been served when the last memory line was
     * written, so the next line can say how many came between them.
     * @var int
     */
    protected $memory_line_requests = 0;
    /**
     * The memory in bytes the server held when the last memory line was
     * written, so the next line can say how much it grew.
     * @var int
     */
    protected $memory_line_used = 0;
    /**
     * A block of memory claimed up front and freed at the very start of
     * the memory-fatal handler, so that after the allocator has refused
     * the request that pushed it over the limit there is still room to
     * build and write the log line naming that request. Without it the
     * handler could itself fail to allocate and the fatal would leave no
     * diagnostic.
     * @var string
     */
    protected $oom_log_reserve = "";
    /**
     * Live Connection objects, keyed by (int)$resource. Created in
     * processServerRequest after a successful accept and torn down
     * by shutdownHttpStream. Per-connection protocol state (HPACK
     * encoder/decoder, H2 stream registry, etc.) hangs off the
     * Connection's protocolState property; existing in_streams /
     * out_streams arrays still hold the I/O buffers and request
     * context. Migrating state from those arrays into Connection
     * is gradual: new code that needs typed access should fetch
     * the Connection via $this->connection($key) and read its
     * protocolState; old call sites that index in_streams
     * directly continue to work unchanged.
     * @var array<int,Connection>
     */
    protected $connections = [];
    /**
     * Middle ware callbacks to run when processing a request
     * @var array
     */
    protected $middle_wares = [];
    /**
     * Callbacks run after a response is finalized, each given the
     * response's status code and body size in bytes. Used to record an
     * access line that includes how a request turned out, not just that
     * it arrived.
     * @var array
     */
    protected $response_loggers = [];
    /**
     * Whether the response currently being built has already had its
     * access line recorded by the streaming path. A streamed body does not
     * pass through getResponseData's size accounting, so the streaming
     * entry point logs it directly; this flag stops getResponseData from
     * then logging the same response a second time with a zero length.
     * @var bool
     */
    protected $streaming_response_logged = false;
    /**
     * Filename of currently requested script
     * @var array
     */
    protected $request_script;
    /**
     * Used to store session data in ram for all currently active sessions
     * @var array
     */
    protected $sessions = [];
    /**
     * Least-recently-used ordering of sessions, used to pick which one
     * to drop when memory is tight. It is a min-heap of [use-count, id]
     * pairs, smallest use-count first, so the least recently used
     * session is found in logarithmic time rather than by scanning a
     * list. A session reused after it was last recorded leaves an
     * out-of-date pair behind; that pair is recognized and skipped when
     * it surfaces during eviction (its recorded use-count no longer
     * matches the session's current one), so no scan-and-remove is
     * needed.
     * @var \SplMinHeap
     */
    protected $session_lru;
    /**
     * Ever-increasing counter stamped on a session each time it is
     * used, so the least-recently-used ordering has something to sort
     * by. The newest use always has the largest number.
     * @var int
     */
    protected $session_sequence = 0;
    /**
     * A well-formed session id a visitor's cookie offered that was not
     * found in memory. It is recorded without any database work so a
     * higher layer can decide whether it maps to a signed-in user and,
     * if so, restore that session. Empty when the current request had
     * no such id.
     * @var string
     */
    protected $rehydrate_candidate = "";
    /**
     * Timer function callbacks that have been declared
     * @var array
     */
    protected $timers = [];
    /**
     * How many timers setTimer has made, so each is given an id of its own
     * that it keeps for as long as it repeats.
     * @var int
     */
    protected $timers_made = 0;
    /**
     * Priority queue of which timers are about to go off
     * @var \SplMinHeap
     */
    protected $timer_alarms;
    /**
     * Wall-clock time in whole seconds when the last memory-usage
     * sample was written to the error log, or zero before the first
     * one. Used to keep samples spaced out by the configured period.
     * @var int
     */
    protected $last_memory_sample_time = 0;
    /**
     * Wall-clock time, in seconds with a fraction, of the last memory
     * sample, from which sampleMemoryUsage measures how much processor
     * time the server used since then. Zero before the first sample.
     * @var float
     */
    protected $last_cpu_sample_wall = 0.0;
    /**
     * Processor seconds, user and system together, this process had used
     * at the last memory sample. sampleMemoryUsage subtracts it from the
     * current total to get the time used over the sample period.
     * @var float
     */
    protected $last_cpu_sample_seconds = 0.0;
    /**
     * How many seconds to leave between memory-usage samples, set from
     * the server config when the server starts, with zero meaning the
     * sampling is off. See sampleMemoryUsage.
     * @var int
     */
    protected $memory_sample_period = 0;
    /**
     * Path of the file write journal that several server processes share,
     * or "" when this server runs alone. filePutContents appends the path
     * of each file it writes, and syncFileJournal reads what other
     * processes appended, so no process serves a cached copy another has
     * replaced. Set from FILE_JOURNAL when the server starts.
     * @var string
     */
    protected $file_journal = "";
    /**
     * How many bytes of the file write journal this process has read.
     * @var int
     */
    protected $file_journal_offset = 0;
    /**
     * Worker processes that run requests for this front process, when the
     * WORKERS start option asks for more than one process. Each entry has
     * the worker's proc_open handle, its loopback link, how many requests
     * it is running and the bytes read from it not yet parsed. Empty when
     * the server runs as one process, which is the default.
     * @var array
     */
    protected $workers = [];
    /**
     * How many workers WORKERS asked for, so one that stops is replaced.
     * @var int
     */
    protected $worker_count = 0;
    /**
     * By worker number, the time before which a worker that failed to
     * start is not started again.
     * @var array
     */
    protected $worker_retry_after = [];
    /**
     * $worker_starts holds, by worker number, each worker started and not
     * yet connected back: its process, if this process started it with
     * proc_open, the hash it must show to prove it is that worker, and the
     * time past which the front stops waiting for it. finishWorkerStarts
     * takes a worker from here into $workers once it has connected, so
     * the front serves requests while a worker starts.
     * @var array
     */
    protected $worker_starts = [];
    /**
     * $worker_pending_links holds the connections taken on the worker link
     * that have not yet shown a hash: for each, the connection, what it has
     * sent so far and when it was taken.
     * @var array
     */
    protected $worker_pending_links = [];
    /**
     * The minute, refusals noted in it, and refusals counted but not noted,
     * for connections refused on the worker link.
     * @var array
     */
    protected $worker_refusals = ["minute" => 0, "noted" => 0,
        "unnoted" => 0];
    /**
     * The command line that starts a worker: the PHP binary, the script
     * that builds this site, and whatever tells that script to call
     * serveAsWorker rather than listen. Set from WORKER_COMMAND.
     * @var array
     */
    protected $worker_command = [];
    /**
     * $worker_start, where the site gives one with the WORKER_START start
     * option, is the function that starts a worker in place of running
     * $worker_command here. The site can then start workers the way it
     * starts its other programs, which need not keep this process's
     * listening sockets open in the worker. It is called with the
     * worker's settings already in the environment, and the worker
     * reports its process id over its link once it has proved itself.
     * @var callable|null
     */
    protected $worker_start = null;
    /**
     * $worker_reserved, from the WORKER_RESERVED start option, is a
     * function the front calls on each request it relays. When it returns
     * true and there are two or more workers, the request goes to the last
     * worker, which no other request uses, so that kind of request never
     * waits behind the rest. An application can keep its own most urgent
     * requests there.
     * @var callable|null
     */
    protected $worker_reserved = null;
    /**
     * $worker_stop, from the WORKER_STOP start option, is a function the
     * front calls with a worker's process id and true to ask the worker to
     * stop, or false to end it at once. An application can pass one that
     * works on Linux, macOS and Windows. Without it, a worker started with
     * proc_open
     * is ended through its process handle, and any other through
     * posix_kill where PHP has it.
     * @var callable|null
     */
    protected $worker_stop = null;
    /**
     * $front_work holds, since the last [website-front] line, how many
     * requests of each kind the front handled and the processor time it
     * spent on them: "relayed" for requests sent to a worker, counting
     * only the front's own part, "kept" for requests the front ran itself
     * while it has workers, and "served" when it has none. For kept and
     * served requests it also counts each path, cut at its query, so the
     * line can name the ones that cost the front most.
     * "closed_before_first_byte" counts connections to a TLS port whose
     * peer closed before sending anything.
     * @var array
     */
    protected $front_work = [];
    /**
     * $front_work_since is the front's whole processor time, in seconds,
     * when the last [website-front] line was written, so the next line
     * can say how much went to work outside any one request: accepting
     * connections, TLS, reading and writing sockets, and the loop itself.
     * @var float
     */
    protected $front_work_since;
    /**
     * $relayed_by_connection maps a connection key to the ids of the
     * requests from that connection now at a worker, each to its worker
     * number. When the connection closes, relayToWorker's work is wasted,
     * so cancelRelayedRequests tells the worker to drop them.
     * @var array
     */
    protected $relayed_by_connection = [];
    /**
     * $cancelled_requests holds the ids of relayed requests whose
     * connection closed before their reply came, so the request's fiber
     * ends without writing anything.
     * @var array
     */
    protected $cancelled_requests = [];
    /**
     * File a worker's standard output and errors go to, from WORKER_LOG.
     * @var string
     */
    protected $worker_log = "";
    /**
     * Loopback listener workers connect back to at start.
     * @var resource|null
     */
    protected $worker_listener = null;
    /**
     * Replies read from workers and not yet taken by the request waiting
     * for them, keyed by request id.
     * @var array
     */
    protected $worker_replies = [];
    /**
     * $worker_started holds, keyed by request id with the value true, the
     * requests a worker has said it took up and whose relay has not yet
     * finished. It outlasts the worker, so a request whose worker was
     * ended while it ran is answered with a 502 rather than run a second
     * time on another worker.
     * @var array
     */
    protected $worker_started = [];
    /**
     * Id given to the last request sent to a worker.
     * @var int
     */
    protected $worker_request_id = 0;
    /**
     * Says, for the request about to run, whether it must run in this
     * process rather than a worker, from the FRONT_ONLY start option. A
     * site gives it for requests whose reply is streamed, such as a video
     * sent in ranges, since a stream is sent from here as it is made; a
     * worker would have to finish it first. Null when none is given.
     * @var callable|null
     */
    protected $front_only = null;
    /**
     * Path saveSessionsForRestart last wrote sessions to during the
     * current request, so a worker can tell the front process, which
     * holds every session, to write them all there instead.
     * @var string
     */
    protected $saved_sessions_path = "";
    /**
     * $worker_reply_file is the file a worker's route handed over with
     * deferBodyFromFile as its reply's body, which serveAsWorker sends to
     * the front by name; "" while a worker runs a request that handed over
     * no file, and null outside a worker
     * @var string|null
     */
    protected $worker_reply_file = null;
    /**
     * $worker_remove_file says whether the front deletes
     * $worker_reply_file once it has sent it
     * @var bool
     */
    protected $worker_remove_file = false;
    /**
     * $worker_link is a worker's connection to its front process, kept by
     * serveAsWorker so that deferBodyFromFile can name a growing file to
     * the front while the route is still writing it; null outside a worker
     * @var resource|null
     */
    protected $worker_link = null;
    /**
     * $worker_running_id is the id the front gave the request a worker is
     * running, which a message about that request carries; 0 outside a
     * worker
     * @var int
     */
    protected $worker_running_id = 0;
    /**
     * $worker_grown_file is the growing file a worker's route named to the
     * front during the request being run, or "" when it named none. The
     * request's last reply names it again, so a front whose client went
     * away before the file was sent can delete it.
     * @var string
     */
    protected $worker_grown_file = "";
    /**
     * $worker_growing holds, by request id, the message a worker sends
     * when its route starts a reply whose body is a file it is still
     * writing. readWorkerReplies stores the message here, and the fiber
     * relaying that request takes it and starts sending the file.
     * @var array
     */
    protected $worker_growing = [];
    /**
     * $parked_files holds, by connection key, the socket of each HTTP/1.1
     * connection whose reply is a growing file that has no unsent bytes
     * yet. Such a connection is taken out of the write set, so the loop
     * sleeps instead of going round with nothing to write;
     * refillStreamingGenerators puts it back once the file has grown or
     * its writer has finished.
     * @var array
     */
    protected $parked_files = [];
    /**
     * Unix time in seconds of the last idle-session sweep, used to keep
     * the sweep to the SESSION_REAP_INTERVAL cadence. See
     * reapIdleSessions.
     * @var int
     */
    protected $last_session_reap_time = 0;
    /**
     * Unix time in seconds of the last walk of the session folder, used to
     * keep the walk to the SESSION_FILE_SWEEP_INTERVAL cadence. See
     * sweepSessionFiles.
     * @var int
     */
    protected $last_session_file_sweep_time = 0;
    /**
     * Directory handle of the session folder while a walk of it is under
     * way, null between walks. See sweepSessionFiles.
     * @var resource|null
     */
    protected $session_file_sweep_handle = null;
    /**
     * What the walk of the session folder under way has done so far: the
     * names it has looked at (LOOKED), the files it has deleted (DELETED)
     * and the time it began (BEGAN), for the log line written when it
     * ends. See sweepSessionFiles.
     * @var array
     */
    protected $session_file_sweep_counts = [];
    /**
     * Cookie name value of the currently active request's session
     * @var string
     */
    protected $current_session = "";
    /**
     * Cookie options last used to emit the session cookie, kept so the
     * session cookie can be re-issued under a new name without signing
     * the current user out.
     * @var array
     */
    protected $session_cookie_options = [];
    /**
     * List of HTTP methods for which routes have been declared
     * @var array
     */
    protected $http_methods;
    /**
     * Holds the header portion so far of the HTTP response
     * @var string
     */
    public $header_data = "";
    /**
     * Whether the current response already has declared a Content-Type.
     * If not, WebSite will default to adding a text/html header
     * @var bool
     */
    protected $content_type;
    /**
     * Streaming state: when a route calls $site->flush() its
     * buffered output (and headers, on first flush) are written
     * to the socket immediately rather than buffered until route
     * return. Subsequent flushes write further chunks. The
     * normal end-of-route response composition is bypassed in
     * stream mode and a terminating chunk / END_STREAM frame is
     * emitted instead.
     * @var bool
     */
    protected $is_streaming = false;
    /**
     * Generator a route registers via stream() to produce an H2
     * response body lazily, one yielded chunk at a time, instead of
     * echoing the whole body. Picked up by dispatchH2Request, which
     * parks it and resumes it from the event loop as the peer takes
     * data. Null outside a streaming route.
     * @var \Generator|null
     */
    protected $streaming_producer = null;
    /**
     * Drives long pieces of work (a big mailbox read, a mail-server
     * round trip) a slice at a time so they do not freeze the
     * single-process server, handing control back to this loop between
     * slices. Created lazily the first time a route defers work via
     * deferTask(); null, and entirely skipped, when no long work is in
     * flight.
     * @var \seekquarry\atto\CooperativeScheduler|null
     */
    public $cooperative_scheduler = null;
    /**
     * Holds the in-flight request's cooperative task between the moment a
     * route calls deferResponse() and the moment getResponseData() notices
     * it and tells the protocol layer to send nothing now. Null except
     * during that brief hand-off. The task itself (its captured
     * environment, accumulated body, and how to send it) lives on the
     * object stored here.
     * @var object|null
     */
    protected $deferred_request = null;
    /**
     * Counts, for each connection, the deferred requests on it whose work
     * has not finished. Such a connection carries no traffic while the
     * work runs, since nothing has been made to send yet, and the sweep
     * for idle connections must not close it then: a git clone of a large
     * repository is silent for as long as its pack takes to build.
     * @var array
     */
    protected $deferred_running = [];
    /**
     * The deferred task whose fiber is running right now, or null between
     * fibers. deferBodyFromFile hands a route's file to this task. It is a
     * field of its own, apart from $deferred_request, because that field
     * is also how getResponseData tells that a route has just deferred:
     * an internal request made inside a running fiber, such as a search
     * asking its own machine for results, must not read as deferred.
     * @var object|null
     */
    protected $running_task = null;
    /**
     * Set by the HTTP/3 listener for the duration of one request to the
     * details its deferred response would need to be sent later (the
     * listener, the QUIC connection, and the stream id). Null at all other
     * times. HTTP/3 keeps this on its own field rather than in
     * streaming_context so it cannot disturb the HTTP/1.1 and HTTP/2
     * flush()/stream() path, which reads streaming_context.
     * @var array|null
     */
    protected $deferrable_h3 = null;
    /**
     * Returned by getResponseData() in place of a response when the route
     * deferred itself with deferResponse(): a marker, not real bytes, that
     * tells the H1/H2/H3 send paths to send nothing now because the real
     * response will be produced and sent later when the task's fiber
     * finishes. The NUL bytes make it impossible to collide with a genuine
     * response body.
     */
    const RESPONSE_DEFERRED = "\x00__atto_response_deferred__\x00";
    /**
     * WORKER_REQUEST_SECONDS is the most time, in seconds, a worker may
     * spend on one request that is not a POST. The front measures it by
     * the clock from the worker's word that it took the request up, so
     * time queued or spent starting the worker is not counted, and a request
     * that waits on a lock or on another server counts as much as one
     * that computes. Past it, the front ends the worker and answers the
     * request with a 502, and starts a new worker on the next request. A
     * worker also gives each such request this many seconds of processor
     * time. A POST, which may carry an upload, has no limit; a streamed
     * reply never reaches a worker.
     */
    const WORKER_REQUEST_SECONDS = 5;
    /**
     * WORKER_WRITE_SIZE is the most bytes, past the start of a request,
     * that writeToWorkers copies for one write to a worker's link.
     */
    const WORKER_WRITE_SIZE = 1048576;
    /**
     * WORKER_SILENT_SECONDS is how long, in seconds, a worker with requests
     * queued to it may send the front nothing at all before
     * endOverdueWorkers ends it. A worker sends a word as it takes up each
     * request and a reply when it finishes, so one silent this long is
     * stuck, wherever it is stuck, and every request queued to it would
     * otherwise wait for good. A POST it has taken up is not counted, since
     * an upload may run long.
     */
    const WORKER_SILENT_SECONDS = 30;
    /**
     * WORKER_STOP_SECONDS is how long, in seconds, endOverdueWorkers gives a
     * worker it has asked to stop before it kills the worker outright.
     */
    const WORKER_STOP_SECONDS = 2;
    /**
     * WORKER_TRACE_STEPS is how many calls, innermost first, a worker
     * names in its log line when it is asked to stop.
     */
    const WORKER_TRACE_STEPS = 12;
    /**
     * How long, in microseconds, the event loop will sleep at most while
     * a cooperative task is in flight. The loop wakes at least this often
     * to give a fiber waiting on a slow socket a chance to make progress,
     * without spinning the CPU at a zero-length sleep. Five milliseconds
     * is short next to network round-trip times, so it adds no meaningful
     * latency while a mail server is being waited on.
     */
    const COOPERATIVE_POLL = 5000;
    /**
     * Number of microseconds in a second. Used to compare a wanted
     * stream_select wake-up, which this loop tracks as whole seconds plus
     * microseconds, against the cooperative poll interval. atto is a
     * self-contained server and reads no application settings, so
     * this conversion factor is kept here rather than pulled from Config.
     */
    const MICROSECONDS_PER_SECOND = 1000000;
    /**
     * Number of bytes in one megabyte, used to show memory figures in
     * megabytes in the memory-usage samples. This is the binary
     * megabyte (1024 times 1024) so the figures line up with the way
     * PHP itself reports its memory limit. As with the conversion
     * factor above, atto is self-contained and keeps this here rather
     * than reading an application constant.
     */
    const BYTES_PER_MEGABYTE = 1048576;
    /**
     * Size in bytes above which a single response body is written to the
     * error log when the server config does not set LARGE_RESPONSE_LOG_LEN.
     * A response is held whole in memory before it drains to the socket,
     * so an unusually large one is the likeliest thing to push the
     * always-on server over its memory limit; the default catches those
     * while staying well above any ordinary page.
     */
    const LARGE_RESPONSE_LOG_LEN_DEFAULT = 50 * self::BYTES_PER_MEGABYTE;
    /**
     * How much the memory claimed from the system has to grow across a
     * single request before that request is named in the error log, when
     * the server config does not set REQUEST_MEMORY_GROWTH_LOG_LEN. PHP
     * hands memory back to the system rarely, so this figure only moves
     * when a request asks for more than every request before it did, and
     * a server that has been up a while writes nothing. PHP claims memory
     * two megabytes at a time, and a request that claims one such block
     * and frees it is every request; four megabytes is the smallest step
     * that says a request used more than the ones before it.
     */
    const REQUEST_MEMORY_GROWTH_LOG_LEN_DEFAULT =
        4 * self::BYTES_PER_MEGABYTE;
    /**
     * Seconds left between two lines saying how much memory the server
     * holds and how many requests it has served since the last such
     * line. Five minutes is often enough to watch a climb over an
     * afternoon without filling the log.
     */
    const SECONDS_BETWEEN_MEMORY_LINES = 300;
    /**
     * Bytes of memory held in reserve and released at the start of the
     * memory-fatal handler, so the handler still has room to name the
     * request that was in flight when the limit was hit. One megabyte is
     * plenty to build and write a short log line and small next to any
     * limit the always-on server runs under.
     */
    const OOM_LOG_RESERVE_LEN = self::BYTES_PER_MEGABYTE;
    /**
     * Connection resource for the in-flight request, set by
     * processRequestStreams (H1) or dispatchH2Request (H2)
     * before calling the route. Used by flush() to write
     * directly to the socket. Null outside a request.
     * @var resource|null
     */
    protected $streaming_socket = null;
    /**
     * Per-request streaming context. For H1 contains
     * ['protocol' => 'h1']; for H2 contains
     * ['protocol' => 'h2', 'stream_id' => int,
     *  'hpack_encode' => HPack].
     * @var array
     */
    protected $streaming_context = [];
    /**
     * Whether a write on the current streaming response failed
     * (client gone or stalled past the connection timeout). Once
     * set, further flushes are no-ops returning false so the
     * route can stop producing output; reset by endStreaming.
     * @var bool
     */
    protected $streaming_failed = false;
    /**
     * Whether the most recent readable-socket pass actually pulled new
     * bytes off the wire. The event loop only refreshes a connection's
     * activity time when it did, so a socket that select keeps reporting
     * readable while delivering nothing (a stalled or faulting peer) ages
     * out on the idle timeout instead of being kept alive forever. Reset
     * to true before each connection is handled and only the H1 read path
     * lowers it, so other protocols keep their existing behavior.
     * @var bool
     */
    protected $read_made_progress = true;
    /**
     * Used to cache in RAM files which have been read or written by the
     * fileGetContents or filePutContents
     * @var array
     */
    protected $file_cache = ['MARKED' => [], 'UNMARKED' => [], 'PATH' => [],
        'HASH' => []];
    /**
     * Whether this object is being run from the command line with a listen()
     * call or if it is being run under a web server and so only used for
     * routing
     * @var bool
     */
    protected $is_cli;
    /**
     * Host names this server should answer to, lower-cased. When this
     * list is non-empty, each request's $_SERVER['SERVER_NAME'] is set
     * to the served domain the visitor's Host header named (when it is
     * one of these) or to the first name here otherwise. Empty means
     * the per-request naming is off and the bound name is kept.
     * @var array
     */
    protected $served_domains = [];
    /**
     * Active Listener instances, indexed by (int)$server resource
     * so processRequestStreams can match an incoming readable
     * stream key to the listener that owns it. Each Listener
     * carries its server resource, bind address, TLS flag, and
     * per-listener server globals (SERVER_NAME, SERVER_PORT).
     * @var array<int,Listener>
     */
    protected $listeners = [];
    /**
     * Lazily-constructed ConnectionAcceptor that owns the
     * accept-and-protocol-detect step. Created on first use by
     * getConnectionAcceptor and reused for every accepted
     * connection thereafter.
     * @var ConnectionAcceptor|null
     */
    protected $connection_acceptor = null;
    /**
     * Transport instances keyed by protocol string ('h1', 'h2',
     * 'ws'; 'h3' once QUIC support lands). Each Transport owns
     * the readable-event handling for connections of that
     * protocol; processRequestStreams looks up the Transport via
     * the Connection's $protocol field and calls onReadable. New
     * protocols slot in by adding an entry here. Initialized on
     * first run of the event loop.
     * @var array<string,Transport>
     */
    public $transports = [];
    /**
     * UDP port on which an H3 listener was opened, or 0 if no
     * H3 listener was bound. When non-zero, getResponseData
     * automatically prepends an Alt-Svc header to H1/H2
     * responses so browsers learn that this origin also speaks
     * HTTP/3 and can race a QUIC connection on the next request.
     * @var int
     */
    protected $h3_advertise_port = 0;
    /**
     * List of acceptable Origin header values for WebSocket
     * upgrade requests, or empty array to accept any origin.
     * @var array
     */
    protected $ws_allowed_origins = [];
    /**
     * Seconds between server-initiated PINGs to each established
     * WebSocket connection. Zero disables the keepalive timer.
     * @var int
     */
    protected $ws_keepalive_interval = 30;
    /**
     * Seconds without a PONG response after which a WebSocket
     * connection is considered dead and closed.
     * @var int
     */
    protected $ws_keepalive_timeout = 60;
    /**
     * Whether the keepalive timer has been registered with the
     * timer heap. Set on first WebSocket upgrade.
     * @var bool
     */
    protected $ws_keepalive_registered = false;
    /**
     * Sets the base path used for determining request routes. Sets
     * precision for timed events and sets up timer heap and other
     * field variables
     *
     * @param string $base_path used to determine portion of path to
     *      ignore when checking if a route matches against the
     *      current request. If left blank, a base path will be
     *      computed using the $_SERVER script name variable.
     */
    public function __construct(public $base_path = "")
    {
        /* Every setting starts out here, not just the two the constructor
           used to name: a read of one before listen begins would otherwise
           find nothing there. */
        $this->default_server_globals = self::defaultServerGlobals();
        $this->http_methods = array_keys($this->routes);
        if (empty($this->base_path)) {
            /* A command-line run, such as a unit test, may have no
               SCRIPT_NAME; the base path is then the site's root. */
            $pathinfo = pathinfo($_SERVER['SCRIPT_NAME'] ?? "");
            $this->base_path = $pathinfo["dirname"] ?? "";
        }
        if ($this->base_path == ".") {
            $this->base_path = "";
        }
        $this->is_cli = (php_sapi_name() == 'cli');
        $this->stop = false;
        $this->restart = false;
        ini_set('precision', 16);
        $this->timer_alarms = new \SplMinHeap();
        $this->session_lru = new \SplMinHeap();
        $this->oom_log_reserve = str_repeat(" ",
            self::OOM_LOG_RESERVE_LEN);
        register_shutdown_function([$this, "logMemoryFatal"]);
    }
    /**
     * Names, in the error log, the request that was being handled when the
     * process died of a memory-limit fatal. The ordinary per-request memory
     * log runs after a request returns, so a request that never returns
     * because it exhausted memory leaves no line of its own; this fills that
     * gap. It first frees the reserve so there is room to work, then checks
     * whether the process is ending on an out-of-memory fatal and, if so,
     * writes the in-flight request together with the peak memory reached.
     * It does nothing for an ordinary shutdown or any other kind of fatal.
     */
    public function logMemoryFatal()
    {
        $this->oom_log_reserve = "";
        $error = error_get_last();
        if ($error === null || ($error["type"] ?? 0) !== E_ERROR) {
            return;
        }
        if (stripos($error["message"] ?? "", "allowed memory size") ===
            false) {
            return;
        }
        $peak = round(memory_get_peak_usage(true) /
            self::BYTES_PER_MEGABYTE, 1);
        /* What was really in use at the moment the limit was reached.
           Close to the peak means the memory was being held; well under
           it means the server was carrying many requests at once, each
           of which would have let go. */
        $held = round(memory_get_usage(false) /
            self::BYTES_PER_MEGABYTE, 1);
        $connections = count($this->connections);
        $sessions = count($this->sessions);
        $request = $this->in_flight_request !== "" ?
            $this->in_flight_request : "(none in flight)";
        error_log("[website-memory-fatal] peak={$peak}MB " .
            "held={$held}MB connections={$connections} " .
            "sessions={$sessions} " .
            "request={$request} detail=" . ($error["message"] ?? ""));
    }
    /**
     * Decides whether enough time has gone by to write another
     * memory-usage sample, based on the sample period the server was
     * started with (in seconds, with zero meaning off). When it says
     * yes it also records the current time as the last sample time.
     * Kept apart from the logging itself so the timing rule can be
     * checked on its own.
     *
     * @param int $now current wall-clock time in whole seconds
     * @return bool true when a sample should be written now
     */
    protected function memorySampleDue($now)
    {
        if ($this->memory_sample_period <= 0) {
            return false;
        }
        if ($now - $this->last_memory_sample_time <
            $this->memory_sample_period) {
            return false;
        }
        $this->last_memory_sample_time = $now;
        return true;
    }
    /**
     * Writes one line to the error log every so often describing how
     * much memory the running server is using and how many connections
     * and related items it is holding. This is a switchable aid for
     * tracking down slow memory growth in the always-on server: turned
     * on, the log shows whether memory climbs while the connection and
     * stream counts stay flat, which would point at something held
     * across requests rather than a connection that is never released.
     * It does nothing unless the server was started with a positive
     * WEBSITE_MEMORY_SAMPLE_PERIOD in its config; the loop calls this
     * on every pass and the timing check keeps the cost away.
     */
    protected function sampleMemoryUsage()
    {
        if (!$this->memorySampleDue(time())) {
            return;
        }
        $used = round(memory_get_usage(true) /
            self::BYTES_PER_MEGABYTE, 1);
        /* What PHP has claimed from the system only ever climbs, so it
           cannot tell a leak from a busy moment. What is really in use
           falls back as soon as a request lets its memory go, so the two
           read together say which is happening: both climbing means
           something is being kept, while a climbing claim over a steady
           real figure means many requests at once, each letting go. */
        $held = round(memory_get_usage(false) /
            self::BYTES_PER_MEGABYTE, 1);
        $peak = round(memory_get_peak_usage(true) /
            self::BYTES_PER_MEGABYTE, 1);
        $peak_held = round(memory_get_peak_usage(false) /
            self::BYTES_PER_MEGABYTE, 1);
        $connections = count($this->connections);
        $reading = count($this->in_streams[self::CONNECTION] ?? []);
        $writing = count($this->out_streams[self::CONNECTION] ?? []);
        $sessions = count($this->sessions);
        $timers = count($this->timers);
        $buffered = round($this->bufferedBytes() /
            self::BYTES_PER_MEGABYTE, 1);
        $session_megabytes = round($this->sessionBytes() /
            self::BYTES_PER_MEGABYTE, 1);
        $cpu = $this->cpuPercentSinceLastSample();
        error_log("[website-memory] used={$used}MB held={$held}MB " .
            "cpu={$cpu}% " .
            "peak={$peak}MB peak_held={$peak_held}MB " .
            "connections={$connections} reading={$reading} " .
            "writing={$writing} sessions={$sessions} " .
            "session_data={$session_megabytes}MB " .
            "buffered={$buffered}MB timers={$timers}");
        $front_line = "";
        foreach (["relayed", "kept", "served"] as $kind) {
            $count = $this->front_work[$kind]["count"] ?? 0;
            $cpu = $this->front_work[$kind]["cpu"] ?? 0;
            $front_line .= " $kind=$count cpu=" . round($cpu, 3) . "s" .
                " each=" . ($count > 0 ? round(1000 * $cpu / $count, 2) : 0) .
                "ms";
        }
        $usage = getrusage();
        $total = $usage["ru_utime.tv_sec"] + $usage["ru_stime.tv_sec"] +
            ($usage["ru_utime.tv_usec"] + $usage["ru_stime.tv_usec"]) /
            self::MICROSECONDS_PER_SECOND;
        if (isset($this->front_work_since)) {
            $requests_cpu = ($this->front_work["relayed"]["cpu"] ?? 0) +
                ($this->front_work["kept"]["cpu"] ?? 0) +
                ($this->front_work["served"]["cpu"] ?? 0);
            $front_line .= " outside_requests=" . round($total -
                $this->front_work_since - $requests_cpu, 3) . "s";
        }
        $this->front_work_since = $total;
        $front_line .= " closed_before_first_byte=" .
            ($this->front_work["closed_before_first_byte"] ?? 0);
        $paths = $this->front_work["paths"] ?? [];
        arsort($paths);
        foreach (array_slice($paths, 0, 3, true) as $path => $cpu) {
            $front_line .= " $path:" . round($cpu, 3) . "s";
        }
        error_log("[website-front]" . $front_line);
        $this->front_work = [];
        foreach ($this->workers as $i => $worker) {
            $waiting = $worker["waiting"] ?? [];
            $running = reset($waiting);
            if ($running !== false) {
                error_log("[website-worker] worker " . ($i + 1) .
                    " running " . $running[0] . " for " .
                    (time() - $running[1]) . " s, with " .
                    (count($waiting) - 1) . " more waiting");
            }
        }
    }
    /**
     * cpuPercentSinceLastSample says how busy this server process was since
     * the last memory sample, as its processor time, user and system
     * together, over the wall time between the two samples. 100 means one
     * core fully used; a single server process cannot go above that, so a
     * reading near it says the server itself is what everything else is
     * waiting on. sampleMemoryUsage calls it for each line it writes. It
     * uses getrusage, which PHP provides on Linux, macOS and Windows.
     *
     * @return string the percentage to one decimal place, or "-" for the
     *      first sample, which has nothing to compare against
     */
    protected function cpuPercentSinceLastSample()
    {
        $usage = getrusage();
        $cpu_seconds = ($usage["ru_utime.tv_sec"] ?? 0) +
            ($usage["ru_utime.tv_usec"] ?? 0) / 1000000 +
            ($usage["ru_stime.tv_sec"] ?? 0) +
            ($usage["ru_stime.tv_usec"] ?? 0) / 1000000;
        $wall = microtime(true);
        $percent = "-";
        if ($this->last_cpu_sample_wall > 0 &&
            $wall > $this->last_cpu_sample_wall) {
            $percent = sprintf("%.1f", 100 * ($cpu_seconds -
                $this->last_cpu_sample_seconds) /
                ($wall - $this->last_cpu_sample_wall));
        }
        $this->last_cpu_sample_wall = $wall;
        $this->last_cpu_sample_seconds = $cpu_seconds;
        return $percent;
    }
    /**
     * Bytes currently held in the read and write buffers of every open
     * connection. Reported alongside total memory so a server sitting near
     * its limit shows whether what it is holding is traffic in flight.
     *
     * @return int bytes buffered across all connections
     */
    protected function bufferedBytes()
    {
        $total = 0;
        foreach (($this->in_streams[self::DATA] ?? []) as $data) {
            $total += strlen($data);
        }
        foreach (($this->out_streams[self::DATA] ?? []) as $data) {
            $total += strlen($data);
        }
        return $total;
    }
    /**
     * About how many bytes the kept sessions hold between them. A handful
     * are measured and the result scaled to the number kept, rather than
     * measuring every one, so reporting this costs the same whether ten
     * sessions are held or ten thousand.
     *
     * @return int estimated bytes held by all kept sessions
     */
    protected function sessionBytes()
    {
        $kept = count($this->sessions);
        if ($kept == 0) {
            return 0;
        }
        $sampled = 0;
        $sampled_size = 0;
        foreach ($this->sessions as $session) {
            $sampled_size += strlen(serialize($session));
            $sampled++;
            if ($sampled >= self::SESSION_SAMPLE_COUNT) {
                break;
            }
        }
        return (int)round(($sampled_size / $sampled) * $kept);
    }
    /**
     * Returns whether enough time has passed since the last idle-session
     * sweep to run another one, recording the new sweep time when it has.
     * Keeps the sweep on the SESSION_REAP_INTERVAL cadence instead of
     * running it on every event-loop pass.
     *
     * @param int $now current Unix time in seconds
     * @return bool true if a sweep is due now
     */
    protected function sessionReapDue($now)
    {
        if ($now - $this->last_session_reap_time <
            self::SESSION_REAP_INTERVAL) {
            return false;
        }
        $this->last_session_reap_time = $now;
        return true;
    }
    /**
     * Drops sessions that have sat untouched longer than the configured
     * idle timeout. Without this, a one-shot visitor or bot that makes a
     * single cookieless request and never comes back would keep its
     * server-side session in memory for the whole life of the always-on
     * server, so the session count, and the memory those sessions hold,
     * would only ever grow. The session being served right now was just
     * stamped with the current time, so it is never near the cutoff and
     * cannot be signed out by a sweep. An idle timeout of zero or less
     * turns the sweep off. A dropped session's file is deleted with it;
     * before, only the session was forgotten and its file stayed in the
     * session folder for good.
     *
     * The sweep then holds the sessions to MAX_SESSIONS, dropping those
     * used longest ago. sessionStart does this too, but when requests run
     * in worker processes a worker holds only the few sessions its request
     * names, so it is never over the cap; this process holds them all, so
     * the cap is kept here. Sessions are ordered by the time they were
     * last used, since each worker counts uses on its own. The
     * least-recently-used heap that backs sessionStart's cap tolerates
     * these removals: its now-stale entries are skipped during cap
     * eviction and cleared when that heap is rebuilt. A sweep that drops
     * any session writes a line to the log saying how many it dropped and
     * how many it kept.
     */
    protected function reapIdleSessions()
    {
        $now = time();
        if (!$this->sessionReapDue($now)) {
            return;
        }
        $idle_timeout =
            $this->default_server_globals['SESSION_IDLE_TIMEOUT']
            ?? self::SESSION_IDLE_TIMEOUT_DEFAULT;
        $idle_dropped = 0;
        if ($idle_timeout > 0) {
            $cutoff = $now - $idle_timeout;
            foreach ($this->sessions as $reap_id => $session) {
                $session_time = $session['TIME'] ?? $now;
                if ($session_time < $cutoff) {
                    $this->forgetSession($reap_id);
                    $idle_dropped++;
                }
            }
        }
        $max_sessions = $this->default_server_globals['MAX_SESSIONS'] ??
            self::MAX_SESSIONS_DEFAULT;
        $excess = count($this->sessions) - $max_sessions;
        if ($excess > 0) {
            $last_used = array_map(fn($session) => $session['TIME'] ?? $now,
                $this->sessions);
            asort($last_used);
            foreach (array_slice(array_keys($last_used), 0, $excess) as
                $drop_id) {
                $this->forgetSession($drop_id);
            }
        }
        if ($idle_dropped > 0 || $excess > 0) {
            error_log("[website-session-sweep] dropped $idle_dropped " .
                "idle sessions and " . max(0, $excess) . " over the cap " .
                "of $max_sessions with their files; " .
                count($this->sessions) . " sessions kept");
        }
    }
    /**
     * sweepSessionFiles keeps the session folder from filling up with files
     * that belong to no session: those no kept session owns, unchanged for
     * SESSION_FILE_ORPHAN_AGE seconds, are deleted. Such files are left
     * when the server stops without saving its sessions, such as when it
     * is killed or crashes, and were left by versions whose idle sweep did
     * not delete files, so a long-running site can hold a great many of
     * them. A walk
     * of the folder begins when the server starts and then every
     * SESSION_FILE_SWEEP_INTERVAL seconds. The event loop calls this on
     * every pass, and each call looks at no more than
     * SESSION_FILE_SWEEP_BATCH names and spends no more than
     * SESSION_FILE_SWEEP_STEP_TIME seconds before handing back, keeping its
     * place in the folder for the next pass. A walk done in one go held
     * the event loop for as long as the folder took to read, and in that
     * time the server took no connections. The folder is read one name at
     * a time, so a folder holding a great many files costs no more memory
     * than one holding a few.
     *
     * @param int $now current Unix time in seconds
     * @return bool whether a walk of the folder is still under way
     */
    protected function sweepSessionFiles($now)
    {
        $folder = (string)($this->default_server_globals['SESSION_DIR'] ??
            "");
        if ($this->session_file_sweep_handle === null) {
            if ($now - $this->last_session_file_sweep_time <
                self::SESSION_FILE_SWEEP_INTERVAL) {
                return false;
            }
            $this->last_session_file_sweep_time = $now;
            $handle = ($folder === "") ? false : @opendir($folder);
            if ($handle === false) {
                error_log("[website-session-sweep] could not open the " .
                    "session folder $folder to look for old session files");
                return false;
            }
            $this->session_file_sweep_handle = $handle;
            $this->session_file_sweep_counts = ['LOOKED' => 0,
                'DELETED' => 0, 'BEGAN' => microtime(true)];
            error_log("[website-session-sweep] looking in $folder for " .
                "session files no session owns, unchanged for " .
                self::SESSION_FILE_ORPHAN_AGE . " seconds, a few hundred " .
                "names per pass of the event loop");
        }
        $prefix = self::SESSION_FILE_PREFIX;
        $cutoff = $now - self::SESSION_FILE_ORPHAN_AGE;
        $began = microtime(true);
        for ($looked = 0; $looked < self::SESSION_FILE_SWEEP_BATCH;
            $looked++) {
            $name = readdir($this->session_file_sweep_handle);
            if ($name === false) {
                closedir($this->session_file_sweep_handle);
                $this->session_file_sweep_handle = null;
                $counts = $this->session_file_sweep_counts;
                error_log("[website-session-sweep] done in $folder: " .
                    "looked at {$counts['LOOKED']} names, deleted " .
                    "{$counts['DELETED']} old session files, in " .
                    round(microtime(true) - $counts['BEGAN'], 1) .
                    " seconds");
                return false;
            }
            $this->session_file_sweep_counts['LOOKED']++;
            if (str_starts_with($name, $prefix) &&
                !isset($this->sessions[substr($name, strlen($prefix))])) {
                $path = $folder . "/" . $name;
                $modified = @filemtime($path);
                if ($modified !== false && $modified < $cutoff &&
                    @unlink($path)) {
                    $this->session_file_sweep_counts['DELETED']++;
                }
            }
            if (microtime(true) - $began >
                self::SESSION_FILE_SWEEP_STEP_TIME) {
                break;
            }
        }
        return true;
    }
    /**
     * Writes one line to the error log when a single response body is
     * larger than the configured threshold. The whole body is held in
     * memory before it drains to the socket, so an unexpectedly large
     * one is the thing most likely to push the always-on server past its
     * memory limit; recording its size, status, and request makes the
     * offending request identifiable instead of guessed at. The check is
     * one length comparison on every response and logs nothing in the
     * normal case; a threshold of zero or less turns it off.
     *
     * @param int $body_size size in bytes of the response body
     */
    protected function logLargeResponse($body_size)
    {
        $threshold =
            $this->default_server_globals['LARGE_RESPONSE_LOG_LEN']
            ?? self::LARGE_RESPONSE_LOG_LEN_DEFAULT;
        if ($threshold <= 0 || $body_size < $threshold) {
            return;
        }
        $status = "200";
        if (preg_match('/^HTTP\/\S+\s+(\d+)/', $this->header_data,
            $matches)) {
            $status = $matches[1];
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? "?";
        $uri = $_SERVER['REQUEST_URI'] ?? "?";
        $remote = $_SERVER['REMOTE_ADDR'] ?? "?";
        $megabytes = round($body_size / self::BYTES_PER_MEGABYTE, 1);
        error_log("[website-large-response] {$megabytes}MB " .
            "status={$status} {$method} {$remote} {$uri}");
    }
    /**
     * logMemoryPerRequest writes a line every few minutes saying how
     * much memory the server holds and how many requests it has served
     * since the last such line. The request loop calls it after each
     * request.
     *
     * A figure that climbs on its own does not say whether the climbing
     * comes from work done or from time passing. Reporting the growth
     * against the requests served between two lines tells those apart:
     * a steady number of bytes per request says something is held
     * between requests, while a falling one says the memory is claimed
     * once and reused.
     */
    protected function logMemoryPerRequest()
    {
        $now = time();
        $served = $this->requests_served - $this->memory_line_requests;
        if ($this->memory_line_written_at == 0 ||
            $now - $this->memory_line_written_at <
            self::SECONDS_BETWEEN_MEMORY_LINES) {
            if ($this->memory_line_written_at == 0) {
                $this->memory_line_written_at = $now;
                $this->memory_line_requests = $this->requests_served;
                $this->memory_line_used = memory_get_usage(true);
            }
            return;
        }
        $used = memory_get_usage(true);
        $grew = $used - $this->memory_line_used;
        $each = ($served > 0) ? (int)round($grew / $served) : 0;
        $used_megabytes = round($used / self::BYTES_PER_MEGABYTE, 1);
        $grew_megabytes = round($grew / self::BYTES_PER_MEGABYTE, 1);
        $peak_megabytes = round(memory_get_peak_usage(true) /
            self::BYTES_PER_MEGABYTE, 1);
        error_log("[website-memory-per-request] " .
            "now={$used_megabytes}MB peak={$peak_megabytes}MB " .
            "grew={$grew_megabytes}MB over {$served} requests, " .
            "{$each}B each, total_served={$this->requests_served}");
        $this->memory_line_written_at = $now;
        $this->memory_line_requests = $this->requests_served;
        $this->memory_line_used = $used;
    }
    /**
     * Records when a single request makes the server claim more memory
     * from the system than it ever had, naming the request that did it.
     * The periodic memory sample says the server is holding a lot but
     * not what asked for it: PHP hands memory back to the system rarely,
     * so a figure that only climbs says nothing about which request did
     * the climbing, and by the time anyone reads the sample that request
     * is long finished. Checking the figure either side of a request
     * turns that into a line naming the request the moment it happens.
     * It is two subtractions per request and writes nothing once the
     * server has settled, since by then requests are being served out of
     * memory already claimed; a threshold of zero or less turns it off.
     *
     * @param int $before_used memory in bytes claimed from the system
     *      before the request was handled
     * @param int $before_peak the most memory in bytes ever claimed from
     *      the system, read before the request was handled
     */
    protected function logRequestMemoryGrowth($before_used, $before_peak)
    {
        $threshold =
            $this->default_server_globals['REQUEST_MEMORY_GROWTH_LOG_LEN']
            ?? self::REQUEST_MEMORY_GROWTH_LOG_LEN_DEFAULT;
        if ($threshold <= 0) {
            return;
        }
        $used_growth = memory_get_usage(true) - $before_used;
        $peak_growth = memory_get_peak_usage(true) - $before_peak;
        if ($peak_growth < $threshold) {
            return;
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? "?";
        $uri = $_SERVER['REQUEST_URI'] ?? "?";
        $remote = $_SERVER['REMOTE_ADDR'] ?? "?";
        $used_megabytes = round($used_growth /
            self::BYTES_PER_MEGABYTE, 1);
        $peak_megabytes = round($peak_growth /
            self::BYTES_PER_MEGABYTE, 1);
        $now_used = round(memory_get_usage(true) /
            self::BYTES_PER_MEGABYTE, 1);
        /* What the request is still holding now that it is answered. A
           request that let everything go reads near nothing here however
           much it claimed, so a run of lines with a figure that keeps
           climbing names the requests that keep something. */
        $now_held = round(memory_get_usage(false) /
            self::BYTES_PER_MEGABYTE, 1);
        error_log("[website-request-memory] grew={$used_megabytes}MB " .
            "peak_grew={$peak_megabytes}MB now={$now_used}MB " .
            "held={$now_held}MB " .
            "{$method} {$remote} {$uri}");
    }
    /**
     * Records, once, when a single connection's outbound buffer first grows
     * past the large-response threshold. Each response body is already
     * checked on its own, but under HTTP/2 many stream responses are
     * appended into one per-connection buffer, so a connection whose client
     * drains slowly can pile up hundreds of megabytes that no single
     * response would reveal. Logging the moment the buffer crosses the
     * threshold, together with the chunk just added and the request, points
     * at the connection responsible instead of leaving it to guesswork. It
     * logs at most once per crossing and nothing in the normal case; a
     * threshold of zero or less turns it off.
     *
     * @param int $chunk_size size in bytes of the chunk just appended
     * @param int $buffer_size size in bytes of the whole outbound buffer
     *      after appending the chunk
     */
    protected function logOutboundBuffer($chunk_size, $buffer_size)
    {
        $threshold =
            $this->default_server_globals['LARGE_RESPONSE_LOG_LEN']
            ?? self::LARGE_RESPONSE_LOG_LEN_DEFAULT;
        if ($threshold <= 0 || $buffer_size < $threshold ||
            $buffer_size - $chunk_size >= $threshold) {
            return;
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? "?";
        $uri = $_SERVER['REQUEST_URI'] ?? "?";
        $remote = $_SERVER['REMOTE_ADDR'] ?? "?";
        $buffer_megabytes =
            round($buffer_size / self::BYTES_PER_MEGABYTE, 1);
        error_log("[website-outbound-buffer] {$buffer_megabytes}MB " .
            "chunk={$chunk_size}B {$method} {$remote} {$uri}");
    }
    /**
     * Returns whether this class is being used from the command-line or in a
     * web server/cgi setting
     *
     * @return boolean whether the class is being run from the command line
     */
    public function isCli()
    {
        return $this->is_cli;
    }
    /**
     * __call traps unknown method calls. If the method name is a
     * lowercase HTTP verb and the args are [route, callback], the
     * route is registered.
     *
     * @param string $method HTTP verb to register the route under
     * @param array $route_callback [pattern, callable]. Pattern
     *      uses * as wildcard and {var_name} to capture a path
     *      segment into $_GET[var_name] / $_REQUEST[var_name].
     *      Examples: '/foo' matches /foo; '/foo*goo' matches
     *      /foogoo, /foodgoo, /footsygoo; '/thread/{thread_num}'
     *      matches /thread/5 and sets $_GET['thread_num'] = 5.
     */
    public function __call($method, $route_callback)
    {
        $num_args = count($route_callback);
        $route_name = strtoupper($method);
        if ($num_args < 1 || $num_args > 2 ||
            !in_array($route_name, $this->http_methods) ||
            $method != strtolower($method)) {
            throw new \Error("Call to undefined method \"$method.\"");
        } else if ($num_args == 1) {
            array_unshift($route_callback, $route_name);
        }
        list($route, $callback) = $route_callback;
        $this->addRoute($route_name, $route, $callback);
    }
    /**
     * Used to add all the routes and callbacks of a WebSite object to the
     * current WebSite object under paths matching $route.
     *
     * @param string $route request pattern to match
     * @param WebSite $subsite WebSite object to add sub routes from
     */
    public function subsite($route, WebSite $subsite)
    {
        foreach ($this->http_methods as $method) {
            foreach ($subsite->routes[$method] as $sub_route => $callback) {
                $this->routes[$method][$route . $sub_route] = $callback;
            }
        }
    }
    /**
     * Generic function for associating a function $callback to be called
     * when a web request using $method method and with a uri matching
     * $route occurs.
     *
     * @param string $method the name of a web request method for example, "GET"
     * @param string $route request pattern to match
     * @param callable $callback function to be called if the incoming request
     *      matches with $method and $route
     */
    public function addRoute($method, $route, callable $callback)
    {
        if (!isset($this->routes[$method])) {
            throw new \Error("Unknown Router Method");
        } else if (!is_callable($callback)) {
            throw new \Error("Callback not callable");
        }
        if (!isset($this->routes[$method])) {
            $this->routes[$method] = [];
        }
        $this->routes[$method][$route] = $callback;
    }
    /**
     * Registers a WebSocket route. When a client sends a WebSocket
     * upgrade request whose URI matches $route, the handshake is
     * completed automatically and $callback is invoked once with a
     * WebSocket object. The callback typically registers handlers
     * via $ws->onMessage() and $ws->onClose() and may send an
     * initial greeting frame via $ws->send(). Subsequent inbound
     * frames are read from the event loop and dispatched to the
     * registered handlers without re-invoking $callback.
     *
     * @param string $route URI pattern matching the WebSocket path,
     *      using the same {var_name} and * syntax as get/post routes
     * @param callable $callback function called once on successful
     *      upgrade with a single WebSocket argument
     */
    public function ws($route, callable $callback)
    {
        $this->addRoute("WS", $route, $callback);
    }
    /**
     * Restricts which Origin header values are accepted for
     * WebSocket upgrade requests. Default: accept all origins
     * (fine for dev / services that expose themselves to any web
     * page). For production behind a known origin, pass exact
     * origin strings (scheme + host + optional port, no trailing
     * slash):
     *   $site->setAllowedOrigins(['https://example.com',
     *       'https://www.example.com']);
     *
     * Requests with an Origin not in the list get 403 during the
     * handshake. Requests with no Origin header (curl, native
     * apps, test scripts) are always allowed — the protection
     * target is the browser same-origin model.
     *
     * @param array $origins acceptable origin strings, or empty
     *      to allow all
     */
    public function setAllowedOrigins(array $origins)
    {
        $this->ws_allowed_origins = $origins;
    }
    /**
     * Configures the keepalive timer for established WebSocket
     * connections. Every $interval seconds the server sends a
     * PING to each open WebSocket. If a PONG is not received
     * within $timeout seconds of the last PING, the connection
     * is presumed dead and closed. Pass interval = 0 to disable
     * keepalive entirely (the default is 30 seconds with a 60
     * second timeout, which is appropriate for most NAT and
     * load balancer idle-connection timers).
     *
     * @param int $interval seconds between server PINGs, or 0
     *      to disable
     * @param int $timeout seconds without PONG after which a
     *      connection is closed as dead
     */
    public function setWebSocketKeepalive($interval, $timeout = 60)
    {
        $this->ws_keepalive_interval = $interval;
        $this->ws_keepalive_timeout = $timeout;
    }

    /**
     * Adds a middle ware callback that should be called before any processing
     * on the request is done.
     *
     * @param callable $callback function to be called before processing of
     *      request
     */
    public function middleware(callable $callback)
    {
        $this->middle_wares[] = $callback;
    }
    /**
     * Adds a callback to run after a response has been finalized. Each
     * such callback is passed the response status code and the response
     * body size in bytes, so a caller can log how a request actually
     * turned out (its status and how large a reply it produced) rather
     * than only that the request arrived.
     *
     * @param callable $callback function called with (int status code,
     *      int body size in bytes) once a response is ready to send
     */
    public function logResponses(callable $callback)
    {
        $this->response_loggers[] = $callback;
    }
    /**
     * Reads the numeric HTTP status code from the response status line
     * built so far. Falls back to 200 when no status line has been set,
     * which matches the default the server fills in for a route that
     * only emitted a body.
     *
     * @return int the response status code
     */
    public function responseStatusCode()
    {
        if (preg_match('/^HTTP\/\S+\s+(\d+)/', $this->header_data,
            $matches)) {
            return (int)$matches[1];
        }
        if (preg_match('/^HTTP\/\S+\s+(\d+)/',
            $this->statusLineForHeaders(), $matches)) {
            return (int)$matches[1];
        }
        return 200;
    }
    /**
     * Cause all the current HTTP request to be processed according to the
     * middleware callbacks and routes currently set on this WebSite object.
     */
    public function process()
    {
        $before_used = memory_get_usage(true);
        $before_peak = memory_get_peak_usage(true);
        $method = $_SERVER['REQUEST_METHOD'] ?? "?";
        $remote = $_SERVER['REMOTE_ADDR'] ?? "?";
        $uri = $_SERVER['REQUEST_URI'] ?? "?";
        $this->in_flight_request = "{$method} {$remote} {$uri}";
        $this->processRequest();
        $this->in_flight_request = "";
        $this->logRequestMemoryGrowth($before_used, $before_peak);
        $this->requests_served++;
        $this->logMemoryPerRequest();
    }
    /**
     * Cause all the current HTTP request to be processed according to the
     * middleware callbacks and routes currently set on this WebSite object.
     * Kept apart from process() so that the memory a request costs can be
     * read either side of it without every way out of here having to
     * remember to do the reading.
     */
    protected function processRequest()
    {
        if (empty($_SERVER['REQUEST_URI'])) {
            $_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'];
        }
        foreach ($this->middle_wares as $middleware) {
            /* A callback that has answered the request itself gives back
               false, and nothing further is done with the request. That
               is how a callback can refuse a request outright, having
               written its own status and body, rather than having its
               reply followed by whatever a route would have sent. */
            if ($middleware() === false) {
                return;
            }
        }
        /*
            WebSocket upgrades cannot be handled in SAPI mode
            (PHP-FPM, mod_php, CGI) because those environments do
            not expose the underlying TCP socket to the script.
            If the request is a WebSocket upgrade, emit a 501 with
            an explanatory message so the developer knows to run
            the server in CLI mode (or behind a reverse proxy that
            forwards to a CLI Atto server).
         */
        if (!empty($_SERVER['HTTP_UPGRADE'])
            && strtolower($_SERVER['HTTP_UPGRADE']) === 'websocket') {
            $this->header("HTTP/1.1 501 Not Implemented");
            $this->header("Content-Type: text/plain");
            echo "WebSocket upgrades require running this script "
                . "from the command line. The PHP "
                . "SAPI used by Apache, nginx-FPM, and CGI does not "
                . "expose the underlying TCP socket and so cannot "
                . "handle WebSocket frames. A typical deployment "
                . "runs the CLI server on an internal port behind "
                . "a reverse proxy.\n";
            return;
        }
        // Handle Upgrade Header
        if (($_SERVER['HTTP_UPGRADE'] ?? '') === 'HTTP/2') {
            $this->header_data = "UPGRADE";
            // $this->handleUpgradeToHttp2();
            return;
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? "ERROR";
        /*
            Compute the request path, separating it from
            the query string. The chop must happen on the
            still-encoded REQUEST_URI: a query string
            containing percent-encoded chars (most commonly
            "%2F" for slashes inside a value) shrinks under
            urldecode(), so doing the chop on the decoded
            string against the still-encoded QUERY_STRING
            length undercounts and silently truncates the
            path. Find the literal "?" delimiter on the
            raw URI, then urldecode only the path portion.
         */
        $raw_uri = $_SERVER['REQUEST_URI'];
        $query_start = strpos($raw_uri, '?');
        $raw_path = ($query_start === false) ? $raw_uri :
            substr($raw_uri, 0, $query_start);
        $decoded_path = urldecode($raw_path);
        $this->request_script = rtrim(substr($decoded_path,
            strlen($this->base_path)), "?");
        if ($this->request_script == "") {
            $this->request_script = "/";
        }
        if (empty($this->routes[$method])) {
            $method = "ERROR";
            $route = "/404";
        }
        $route = $this->request_script;
        $handled = $this->trigger($method, $route);
        if (!$handled) {
            $handled =  false;
            if ($method != 'ERROR') {
                $route = "/404";
                $handled = $this->trigger('ERROR', $route);
            }
            if (!$handled) {
                $this->defaultErrorHandler($route);
            }
        }
    }
    /**
     * Calls any callbacks associated with a given $method and $route provided
     * that recursion in method route call is not detected.
     *
     * @param string $method the name of a web request method for example, "GET"
     * @param string $route  request pattern to match
     * @return bool whether the $route was handled by any callback
     */
    public function trigger($method, $route)
    {
        if (empty($_SERVER['RECURSION'])) {
            $_SERVER['RECURSION'] = [];
        }
        if (empty($this->routes[$method])) {
            return false;
        }
        if (in_array($method . " " . $route, $_SERVER['RECURSION']) ) {
            echo "<br>\nError: Recursion detected for $method $route.\n";
            return true;
        }
        $method_routes = $this->routes[$method];
        $handled = false;
        foreach ($method_routes as $check_route => $callback) {
            if (($add_vars = $this->checkMatch($route, $check_route)) !==
                false) {
                $_GET = array_merge($_GET, $add_vars);
                $_REQUEST = array_merge($_REQUEST, $add_vars);
                $_SERVER['RECURSION'][] = $method . " ". $check_route;
                $handled = true;
                if ($callback()) {
                    return true;
                }
            }
        }
        return $handled;
    }
    /**
     * Adds an HTTP header to the response. If $header begins with
     * "HTTP/" it's treated as the status line and replaces any
     * existing one. In non-CLI mode defers to PHP's header().
     *
     * Headers with CR/LF are rejected (CRLF injection / HTTP
     * response splitting). PHP's built-in header() has had this
     * defense since 5.1.2; Atto matches it for CLI mode where
     * header_data goes directly to the wire. Rejected headers
     * trigger an E_USER_WARNING and return false.
     *
     * @param string $header HTTP header or status line
     * @return bool true if accepted, false if CRLF-rejected
     */
    public function header($header)
    {
        if (strpbrk($header, "\r\n") !== false) {
            trigger_error("Header contains CR or LF and was rejected"
                . " to prevent response splitting", E_USER_WARNING);
            return false;
        }
        if ($this->isCli()) {
            if (strtolower(substr($header, 0, 5)) == 'http/') {
                if (strtolower(substr($this->header_data, 0, 5)) == 'http/') {
                    $header_parts = explode("\x0D\x0A", $this->header_data, 2);
                    $this->header_data = $header . "\x0D\x0A" .
                        ($header_parts[1] ?? "");
                } else {
                    $this->header_data = $header . "\x0D\x0A" .
                        $this->header_data;
                }
            } else {
                if (strtolower(substr($header, 0, 12)) == "content-type") {
                    $this->content_type = true;
                }
                $this->header_data .= $header . "\x0D\x0A";
            }
        } else {
            header($header);
        }
        return true;
    }
    /**
     * Registers a generator that produces the response body lazily,
     * one yielded string chunk at a time, for the in-flight request.
     * Run from the command line the body is then produced and sent
     * incrementally: HTTP/2 and HTTP/3 pace it by the peer's
     * flow-control window and HTTP/1 writes it as chunked-transfer
     * blocks, so an arbitrarily large response (a full video range,
     * say) never has to be held in memory at once and, on the
     * multiplexed protocols, other streams on the connection keep
     * being served. A route calls this and returns immediately; it
     * must not also echo a body. Headers set before the call (status,
     * content-type, content-length, content-range) are sent as the
     * response HEADERS. Under a SAPI, and for a request whose protocol
     * was never recorded, there is no incremental path, so the
     * generator is drained into the normal buffered response instead,
     * which still produces the correct body.
     *
     * @param callable|\Generator $producer a generator, or a
     *      callable returning one, that yields body chunks
     * @return bool true (the request is considered handled)
     */
    public function stream($producer)
    {
        $generator = is_callable($producer) ? $producer() : $producer;
        if (!($generator instanceof \Generator)) {
            return true;
        }
        $this->logStreamingResponse();
        $protocol = $this->streaming_context['protocol'] ?? null;
        if ($this->isCli() && ($protocol === 'h2' || $protocol === 'h3')) {
            $this->streaming_producer = $generator;
        } else if ($this->isCli() && $protocol === 'h1') {
            /* H1 streams incrementally: echo each chunk and flush it
               as a chunked-transfer block, stopping if the peer goes
               away (a seek aborting the request), the same contract
               as a route that echoes and calls flush() itself. Where
               this runs inside a fiber, the loop is handed back after
               every chunk. Without that, reading a whole large file
               here held the one process for as long as the download
               took, and every other request waited: a hundred megabyte
               video stalled the site for the half minute it took to
               go out. */
            foreach ($generator as $chunk) {
                if ($chunk !== null && $chunk !== "") {
                    echo $chunk;
                }
                if (!$this->flush() && $this->streamingFailed()) {
                    break;
                }
                if (\Fiber::getCurrent() !== null) {
                    \Fiber::suspend();
                }
            }
        } else {
            /* Nothing to pace against here: the SAPI hands the body to
               the web server rather than to a socket this code owns, and
               a CLI request whose protocol was never recorded has no
               stream to write chunks to. Produce the body now so the
               result is still correct, just not memory-bounded. */
            foreach ($generator as $chunk) {
                if ($chunk !== null && $chunk !== "") {
                    echo $chunk;
                }
            }
        }
        return true;
    }
    /**
     * Records the access line for a response whose body is streamed rather
     * than buffered. A streamed body (a video range, a large download)
     * never passes through getResponseData's size accounting, so without
     * this such a reply would be missing from the access log or recorded
     * with a zero length. The status and length are read from the headers
     * the route has already set before it began streaming. The response is
     * marked as logged so getResponseData does not record it a second time.
     */
    protected function logStreamingResponse()
    {
        if ($this->streaming_response_logged) {
            return;
        }
        $this->streaming_response_logged = true;
        $length = 0;
        if (preg_match('/^Content-Length:\s*(\d+)/im', $this->header_data,
            $matches)) {
            $length = (int)$matches[1];
        }
        $status = $this->responseStatusCode();
        foreach ($this->response_loggers as $response_logger) {
            $response_logger($status, $length);
        }
    }
    /**
     * Records which HTTP protocol the request being served right now is
     * running over, so $site->stream() can tell how to deliver a streamed
     * body: parked and advanced by the loop, or produced whole. The
     * HTTP/3 listener sets this to 'h3' before it runs a route and back to
     * '' afterwards (the HTTP/1.1 and HTTP/2 paths set the equivalent
     * inline). Passing '' clears it.
     *
     * @param string $protocol the protocol tag, e.g. 'h3', or '' to clear
     * @return void
     */
    public function setStreamingProtocol($protocol)
    {
        $this->streaming_context = ($protocol === '') ? [] :
            ['protocol' => $protocol];
    }
    /**
     * Tells which HTTP protocol version the request being served right
     * now arrived over, as a short tag: 'h1' for HTTP/1.1, 'h2' for
     * HTTP/2, or 'h3' for HTTP/3. The access log uses this so each line
     * shows how the client connected. It reads the per-request
     * SERVER_PROTOCOL the dispatcher stamps for the request being
     * served, which is the reliable value even for a buffered reply;
     * anything other than the HTTP/2 and HTTP/3 markers is reported as
     * 'h1'.
     *
     * @return string the protocol tag 'h1', 'h2', or 'h3'
     */
    public function requestProtocol()
    {
        $server_protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
        if ($server_protocol === 'HTTP/2.0') {
            return 'h2';
        }
        if ($server_protocol === 'HTTP/3') {
            return 'h3';
        }
        return 'h1';
    }
    /**
     * Takes the streaming producer a route parked by calling
     * $site->stream(), clearing it so the next request starts fresh.
     * Returns null when the route did not stream. The HTTP/3 listener uses
     * this after running a route to decide whether to stream the response
     * incrementally or send it whole.
     *
     * @return \Generator|null the parked producer, or null if none
     */
    public function takeStreamingProducer()
    {
        $producer = $this->streaming_producer;
        $this->streaming_producer = null;
        return $producer;
    }
    /**
     * Hands a long piece of work to the event loop to run a little at a
     * time instead of all at once. The work is given as a callable; under
     * the atto loop it is run inside a fiber, so wherever it would wait it
     * can call Fiber::suspend() to let the loop serve every other
     * connection and be resumed later, and when it finishes the optional
     * completion callback runs with its result (or with the exception it
     * threw). This is how one slow operation in this single-process server
     * stops freezing all the others. The scheduler is built on first use,
     * so a server that never defers work carries none of its cost. Under
     * another web server such as Apache, where there is no atto loop and
     * each request is its own process, the work is simply run straight
     * through here, outside any fiber, so its waits just block.
     *
     * @param callable $task the work to run; under the atto loop it runs
     *      inside a fiber and may call Fiber::suspend() at its wait points
     * @param callable|null $on_complete called once the task ends, as
     *      $on_complete($result, $error); see CooperativeScheduler::add
     * @return bool true, so a route may `return $site->deferTask(...)`
     *      and count the request as handled
     */
    public function deferTask(callable $task, $on_complete = null)
    {
        if (!$this->isCli()) {
            /* Under another web server (Apache and the like) there is no
               atto event loop and each request is its own process, so the
               work blocks nobody else. Run it straight through, NOT inside
               a fiber: with no fiber active a cooperative wait deep in the
               work sees Fiber::getCurrent() come back null and falls back
               to a plain blocking wait, which is exactly right here. */
            $result = null;
            $error = null;
            try {
                $result = $task();
            } catch (\Throwable $throwable) {
                $error = $throwable;
            }
            if (is_callable($on_complete)) {
                $on_complete($result, $error);
            }
            return true;
        }
        if ($this->cooperative_scheduler === null) {
            $this->cooperative_scheduler = new CooperativeScheduler();
        }
        $this->cooperative_scheduler->add(new \Fiber($task), $on_complete);
        return true;
    }
    /**
     * Streams the buffered output to the client immediately
     * instead of buffering until the route returns. Use to push
     * Server-Sent Events, deliver large dynamic responses
     * incrementally, or send headers + initial bytes before
     * computing the rest.
     *
     * Behavior:
     *   First call: composes headers (using $this->header_data
     *     plus Transfer-Encoding: chunked for H1, or a HEADERS
     *     frame without END_STREAM for H2) and writes them with
     *     the buffered output as the first chunk.
     *   Subsequent calls: write only the new buffered output as
     *     a chunk.
     *   Route return: getResponseData detects stream mode and
     *     emits a terminating chunk / END_STREAM frame.
     *
     * Streaming routes block the event loop while running, so
     * avoid sleep() between flushes; instead structure routes
     * to do bounded work per request and let the client
     * reconnect (the EventSource auto-reconnect pattern).
     *
     * @return bool true if a flush happened, false if not in
     *      a request context where streaming is supported
     */
    public function flush()
    {
        if (!$this->isCli()
                || $this->streaming_socket === null
                || empty($this->streaming_context)) {
            return false;
        }
        $protocol = $this->streaming_context['protocol'] ?? null;
        if ($protocol !== 'h1') {
            /* only H1 chunked streaming is supported: sending H2
               DATA frames ahead of the peer's flow-control window
               makes clients reset the stream once their window
               (10 MiB for curl) is exceeded, and honoring the
               window would require processing WINDOW_UPDATE
               frames mid-dispatch. H2 and H3 responses buffer and
               go out whole through the normal response path, so
               the output buffer must be left untouched here. */
            return false;
        }
        $chunk = ob_get_clean();
        ob_start();
        if ($this->streaming_failed) {
            /* the client is gone or stalled out; discard the
               buffered output and tell the route so it can stop */
            return false;
        }
        if (!$this->is_streaming) {
            $this->is_streaming = true;
            $this->writeStreamingHead_H1($chunk);
            return !$this->streaming_failed;
        }
        if ($chunk === '' || $chunk === false) {
            return true;
        }
        $this->writeStreamingChunk_H1($chunk);
        return !$this->streaming_failed;
    }
    /**
     * Tells whether a write on the current streaming response has
     * failed (client disconnected or stalled past the connection
     * timeout). A route streaming through flush() can use this to
     * distinguish a dead client (stop producing output) from
     * streaming being unavailable (buffer output as usual).
     *
     * @return bool whether the current streaming response failed
     */
    public function streamingFailed()
    {
        return $this->streaming_failed;
    }
    /**
     * writeFrameWhole writes the bytes of one protocol control frame to
     * a connection completely, looping on the partial writes a
     * non-blocking socket gives, and waiting briefly on the socket
     * becoming writable between attempts. The framing of a connection
     * is a byte stream: a control frame written short leaves the next
     * frame starting mid-frame, after which the peer reads garbage or
     * waits on a frame that never completes. A window-credit frame cut
     * short this way left a browser waiting for credit it never got
     * while the server waited for data the browser was never going to
     * send, and the two sat silent. Callers pass the serialized frame;
     * where the write cannot complete the connection is past saving and
     * false says so, letting the caller tear it down.
     *
     * @param resource $connection the socket the frame goes to
     * @param string $bytes the whole serialized frame
     * @return bool whether every byte was written
     */
    protected function writeFrameWhole($connection, $bytes)
    {
        $total = strlen($bytes);
        $written = 0;
        $stalls = 0;
        while ($written < $total) {
            $sent = @fwrite($connection, ($written == 0) ? $bytes :
                substr($bytes, $written));
            if ($sent === false || feof($connection)) {
                return false;
            }
            $written += $sent;
            if ($written >= $total) {
                break;
            }
            if ($sent == 0) {
                $stalls++;
                if ($stalls > 1) {
                    return false;
                }
                $read_streams = [];
                $write_streams = [$connection];
                $except_streams = [];
                set_error_handler(null);
                $ready = stream_select($read_streams, $write_streams,
                    $except_streams,
                    self::CONTROL_FRAME_WRITE_WAIT);
                restore_error_handler();
                if (empty($ready)) {
                    return false;
                }
            } else {
                $stalls = 0;
            }
        }
        return true;
    }
    /**
     * Writes $data completely to the streaming socket, looping on
     * the partial writes a non-blocking socket gives when the
     * kernel send buffer is full. Between attempts it waits for
     * the socket to become writable for up to the connection
     * timeout. On a write error, a stalled-out wait, or no
     * progress after a writable wait (a half-closed peer), it
     * marks the streaming response failed and gives up; the
     * remaining transfer is abandoned rather than silently
     * dropping bytes mid-frame, which corrupts the chunked or
     * DATA framing.
     *
     * @param string $data bytes to write in full
     * @return bool whether all bytes were written
     */
    protected function writeAll($data)
    {
        if ($this->streaming_failed) {
            return false;
        }
        $socket = $this->streaming_socket;
        $total = strlen($data);
        $written = 0;
        $zero_writes = 0;
        $stall_limit =
            $this->default_server_globals['CONNECTION_TIMEOUT'];
        while ($written < $total) {
            $num_written = @fwrite($socket, ($written == 0) ? $data :
                substr($data, $written));
            if ($num_written === false || feof($socket)) {
                $this->streaming_failed = true;
                return false;
            }
            $written += $num_written;
            if ($written >= $total) {
                break;
            }
            if ($num_written == 0) {
                $zero_writes++;
                if ($zero_writes > 1) {
                    /* writable per select below yet nothing
                       accepted twice running: peer is gone */
                    $this->streaming_failed = true;
                    return false;
                }
                $read_streams = [];
                $write_streams = [$socket];
                $except_streams = [];
                set_error_handler(null);
                $ready = stream_select($read_streams,
                    $write_streams, $except_streams, $stall_limit);
                restore_error_handler();
                if (empty($ready)) {
                    $this->streaming_failed = true;
                    return false;
                }
            } else {
                $zero_writes = 0;
            }
        }
        return true;
    }
    /**
     * Composes and writes the H1 response head plus first chunk
     * for a streaming response. Forces Transfer-Encoding: chunked
     * (no Content-Length, since the total length is unknown
     * during streaming). Called from flush() on the first call.
     *
     * @param string $chunk first chunk of body to send with the
     *      response head; may be the empty string if the route
     *      flushed only headers so far
     */
    protected function writeStreamingHead_H1($chunk)
    {
        if (!str_starts_with($this->header_data, "HTTP/")) {
            $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                " 200 OK\x0D\x0A" . $this->header_data;
        }
        if (!$this->content_type) {
            $this->header_data .= "Content-Type: text/html\x0D\x0A";
        }
        /* A streamed body has unknown length, so it is sent chunked;
           strip any Content-Length the route set or the response
           would carry both Content-Length and Transfer-Encoding. */
        $this->header_data = preg_replace(
            '/^Content-Length:[^\r\n]*\r\n/im', '',
            $this->header_data);
        $this->header_data .= "Transfer-Encoding: chunked\x0D\x0A";
        $head = $this->header_data . "\x0D\x0A";
        $this->writeAll($head);
        if ($chunk !== '' && $chunk !== false) {
            $this->writeStreamingChunk_H1($chunk);
        }
    }
    /**
     * Writes a single H1 chunked-transfer chunk. RFC 7230 sec 4.1
     * format: <hex-length>\r\n<data>\r\n.
     *
     * @param string $chunk body bytes for this chunk
     */
    protected function writeStreamingChunk_H1($chunk)
    {
        $this->writeAll(
            dechex(strlen($chunk)) . "\x0D\x0A" . $chunk . "\x0D\x0A");
    }
    /**
     * Closes a streaming response by sending the terminating
     * frame (zero-length chunk for H1, empty DATA with END_STREAM
     * for H2) and clearing streaming state. Called from
     * getResponseData after the route returns when
     * $is_streaming is true.
     */
    protected function endStreaming()
    {
        $protocol = $this->streaming_context['protocol'] ?? null;
        if (!$this->streaming_failed && $protocol === 'h1') {
            $this->writeAll("0\x0D\x0A\x0D\x0A");
        }
        $this->is_streaming = false;
        $this->streaming_failed = false;
        $this->streaming_socket = null;
        $this->streaming_context = [];
    }
    /**
     * Emits a Link: rel=preload response header telling browsers to
     * begin fetching the given resource in parallel with parsing of
     * the current response. Works on HTTP/1.1, HTTP/2, and HTTP/3
     * since it is a standard HTTP response header.
     *
     * For HTTP/2 the preloaded resource requests multiplex over the
     * existing connection. For fonts, crossorigin="anonymous" is
     * typically required or the browser will fetch the font twice.
     *
     * @param string $url URL or path of the resource to preload
     * @param string $as resource type hint: image, style, script,
     *      font, video, audio, document, fetch
     * @param string $crossorigin optional CORS mode: anonymous or
     *      use-credentials; required for font preloads
     */
    public function preload($url, $as, $crossorigin = "")
    {
        $link = "<" . $url . ">; rel=preload; as=" . $as;
        if ($crossorigin !== "") {
            $link .= "; crossorigin=" . $crossorigin;
        }
        $this->header("Link: " . $link);
    }
    /**
     * Initiates an HTTP/2 server-pushed response for the given
     * resource URL. The server announces a new stream to the
     * client via PUSH_PROMISE on the original request stream,
     * dispatches the resource through the same route table the
     * client would have hit, and writes the synthesized response
     * (HEADERS plus DATA frames with END_STREAM) on the new
     * stream. From the client's perspective the resource shows
     * up in cache without a roundtrip; for stylesheets, scripts,
     * and fonts this can shave one full RTT off page load.
     *
     * No-op if not running under HTTP/2, if streaming context is
     * not active (call this from inside a route, before the route
     * returns), or if the client has set SETTINGS_ENABLE_PUSH=0
     * (RFC 7540 sec 6.5.2; some clients disable push). Limited
     * to GET requests; POST/PUT/DELETE pushes have no defined
     * caching semantics.
     *
     * Returns true if a push was queued, false otherwise. Returns
     * false silently for non-HTTP/2 paths so callers can drop a
     * push() in any route without protocol-checking; HTTP/1.1 and
     * HTTP/3 clients fall back to normal in-page resource loads.
     *
     * @param string $url path or absolute URL of the resource to
     *      push (e.g. /styles.css). Same-origin only; cross-
     *      origin URLs are silently dropped per sec 8.2.
     * @return bool true if a PUSH_PROMISE plus response was
     *      queued for the client, false if push was unavailable
     */
    public function push($url)
    {
        if (empty($this->streaming_context)
            || ($this->streaming_context['protocol'] ?? null)
                !== 'h2') {
            return false;
        }
        $key = $this->streaming_context['key'] ?? null;
        $orig_stream_id =
            $this->streaming_context['stream_id'] ?? 0;
        $hpack_encode =
            $this->streaming_context['hpack_encode'] ?? null;
        $socket = $this->streaming_socket;
        if ($key === null || $orig_stream_id === 0
            || $hpack_encode === null || $socket === null) {
            return false;
        }
        $conn = $this->connection($key);
        if ($conn === null) {
            return false;
        }
        $state = &$conn->protocol_state;
        if (empty($state['enable_push'])) {
            return false;
        }
        /*
            Parse the URL into a same-origin path. Reject schemes
            and hosts that don't match the request: cross-origin
            push is a security boundary (a hostile route handler
            should not be able to seed the client's cache for
            another domain) and is forbidden by RFC 7540 sec 8.2.
         */
        $parts = parse_url($url);
        if ($parts === false) {
            return false;
        }
        if (!empty($parts['host'])
            && isset($_SERVER['HTTP_HOST'])
            && strcasecmp($parts['host'],
                $_SERVER['HTTP_HOST']) !== 0) {
            return false;
        }
        $path = $parts['path'] ?? '/';
        if ($path === '' || $path[0] !== '/') {
            return false;
        }
        $query = $parts['query'] ?? '';
        $request_uri = $path;
        if ($query !== '') {
            $request_uri .= '?' . $query;
        }
        /*
            Allocate the next server-initiated stream id (sec
            5.1.1: even-numbered, server picks). Bump by 2 so
            consecutive pushes don't collide.
         */
        $promised_id = $state['next_push_stream_id'];
        $state['next_push_stream_id'] += 2;
        /*
            Build the PUSH_PROMISE pseudo-request headers. RFC
            7540 sec 8.2.1: a PUSH_PROMISE carries a complete
            request header set as if the client had asked for
            this URL: :method, :scheme, :authority, :path are
            mandatory. Authority and scheme inherit from the
            current request so cross-origin sneaking is impossible
            (parse_url above already rejected explicit cross-
            origin URLs but the fallback default seals the
            same-origin invariant).
         */
        $scheme = !empty($_SERVER['HTTPS']) ? 'https' : 'http';
        $authority = $_SERVER['HTTP_HOST']
            ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $promise_headers = [
            [':method', 'GET'],
            [':scheme', $scheme],
            [':authority', $authority],
            [':path', $request_uri],
        ];
        $promise_block = $hpack_encode->encode($promise_headers,
            4096);
        if (strlen($promise_block) + 4 > self::H2_MAX_FRAME_SIZE) {
            /*
                The PUSH_PROMISE payload (4-byte promised stream
                id plus header block fragment) must fit in one
                frame; sending CONTINUATION for promises is
                possible but unimplemented here. Drop overlong
                pushes silently rather than splitting incorrectly.
             */
            return false;
        }
        $promise_frame = new PushPromiseFrame($orig_stream_id,
            $promised_id, $promise_block);
        $promise_frame->flags->add('END_HEADERS');
        $out = $promise_frame->serialize();
        /*
            Recursively dispatch the synthesized GET. Save and
            restore every superglobal and route-state field that
            setGlobals/getResponseData touch so the original
            request's state is unaffected on return. streaming_
            socket and streaming_context are temporarily cleared
            so the pushed route can't $site->flush() onto the
            wrong stream; any flush() inside the pushed route
            simply returns false.
         */
        $saved = [
            'SERVER' => $_SERVER,
            'GET' => $_GET,
            'POST' => $_POST,
            'REQUEST' => $_REQUEST,
            'COOKIE' => $_COOKIE,
            'SESSION' => $_SESSION,
            'FILES' => $_FILES,
            'header_data' => $this->header_data,
            'content_type' => $this->content_type,
            'current_session' => $this->current_session,
            'streaming_socket' => $this->streaming_socket,
            'streaming_context' => $this->streaming_context,
            'is_streaming' => $this->is_streaming,
            'streaming_failed' => $this->streaming_failed,
            'request_script' => $this->request_script,
        ];
        $context = [
            'REQUEST_METHOD' => 'GET',
            'SERVER_PROTOCOL' => 'HTTP/2.0',
            'REQUEST_URI' => $request_uri,
            'PHP_SELF' => $path,
            'QUERY_STRING' => $query,
            'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'HTTP_HOST' => $authority,
            'CONTENT' => '',
        ];
        $this->streaming_socket = null;
        $this->streaming_context = [];
        $this->is_streaming = false;
        $this->streaming_failed = false;
        $this->setGlobals($context, $conn);
        $body = $this->getResponseData(false);
        $pushed_header_data = $this->header_data;
        $_SERVER = $saved['SERVER'];
        $_GET = $saved['GET'];
        $_POST = $saved['POST'];
        $_REQUEST = $saved['REQUEST'];
        $_COOKIE = $saved['COOKIE'];
        $_SESSION = $saved['SESSION'];
        $_FILES = $saved['FILES'];
        $this->header_data = $saved['header_data'];
        $this->content_type = $saved['content_type'];
        $this->current_session = $saved['current_session'];
        $this->streaming_socket = $saved['streaming_socket'];
        $this->streaming_context = $saved['streaming_context'];
        $this->is_streaming = $saved['is_streaming'];
        $this->streaming_failed = $saved['streaming_failed'];
        $this->request_script = $saved['request_script'];
        /*
            Compose response HEADERS for the promised stream
            from the pushed dispatch's header_data. Mirror the
            forbidden-headers and content-type defaults from
            dispatchH2Request so the wire format matches what a
            normal H2 response would look like.
         */
        $status = "200";
        if (preg_match("/HTTP\/[\d.]+ (\d+)/",
                $pushed_header_data, $matches)) {
            $status = $matches[1];
        }
        $resp_headers_data = [[':status', $status]];
        $forbidden = ['connection', 'keep-alive',
            'proxy-connection', 'transfer-encoding', 'upgrade'];
        $has_content_type = false;
        $has_content_length = false;
        $header_lines = explode("\r\n", $pushed_header_data);
        if (!empty($header_lines[0])
            && str_starts_with($header_lines[0], 'HTTP/')) {
            array_shift($header_lines);
        }
        foreach ($header_lines as $line) {
            $colon = strpos($line, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = trim(substr($line, $colon + 1));
            if ($name === '' || $name[0] === ':'
                || in_array($name, $forbidden)) {
                continue;
            }
            if ($name === 'content-type') {
                $has_content_type = true;
            }
            if ($name === 'content-length') {
                $has_content_length = true;
            }
            $resp_headers_data[] = [$name, $value];
        }
        if (!$has_content_type) {
            $resp_headers_data[] =
                ['content-type', 'text/html; charset=utf-8'];
        }
        if (!$has_content_length) {
            $resp_headers_data[] =
                ['content-length', (string) strlen($body)];
        }
        $resp_headers = new HeaderFrame($promised_id,
            $resp_headers_data);
        $resp_headers->flags->add('END_HEADERS');
        $out .= $resp_headers->serialize($hpack_encode);
        /*
            Queue the PUSH_PROMISE and HEADERS frames on the same
            out_streams entry as the parent response so wire order
            matches HPACK encoding order (the dynamic table is
            stateful; reordered frames give the client's decoder
            wrong header values), then hand the pushed body to the
            outbound flow-control engine on the promised stream.
         */
        $this->queueResponseData($key, $socket, $out);
        $this->sendH2Body($key, $socket, $conn, $promised_id,
            $body);
        return true;
    }
    /**
     * Sends an HTTP cookie. In non-CLI mode defers to PHP's
     * setcookie(). Returned cookies show up in $_COOKIE.
     *
     * @param string $name cookie name
     * @param string $value cookie value
     * @param int $expire Unix expiry timestamp
     * @param string $path request path scope
     * @param string $domain request domain scope
     * @param string $secure HTTPS-only cookie if true
     * @param bool $httponly hide from client-side JavaScript
     * @param string $samesite cross-site sending policy for the cookie,
     *      "Lax", "Strict", or "None"; left off when empty
     */
    public function setCookie($name, $value = "", $expire = 0,
        $path = "", $domain = "", $secure = false, $httponly = false,
        $samesite = "")
    {
        if ($this->isCli()) {
            if ($secure && empty($_SERVER['HTTPS'])) {
                return;
            }
            $out_cookie = "Set-Cookie: $name=$value";
            if ($expire != 0) {
                set_error_handler(null);
                $out_cookie .= "; Expires=" . @gmdate("D, d M Y H:i:s",
                    $expire) . " GMT";
                restore_error_handler();
            }
            if ($path != "") {
                $out_cookie .= "; Path=$path";
            }
            if ($domain != "") {
                $out_cookie .= "; Domain=$domain";
            }
            if ($secure) {
                $out_cookie .= "; Secure";
            }
            if ($httponly) {
                $out_cookie .= "; HttpOnly";
            }
            if ($samesite != "") {
                $out_cookie .= "; SameSite=$samesite";
            }
            $this->header($out_cookie);
        } else {
            setcookie($name, $value, ['expires' => $expire,
                'path' => $path, 'domain' => $domain, 'secure' => $secure,
                'httponly' => $httponly, 'samesite' => $samesite]);
        }
    }
    /**
     * Re-issues the session cookie under a new name carrying the current
     * session id, so changing the configured session name does not sign
     * the current user out. The session store keys on the id rather than
     * the cookie name, so the same id under the new name continues the
     * session. The cookie under the old name is expired.
     *
     * @param string $old_name session cookie name in use for this request
     * @param string $new_name session cookie name to switch to
     */
    public function renameSessionCookie($old_name, $new_name)
    {
        if ($new_name === "" || $old_name === $new_name ||
            empty($_COOKIE[$old_name])) {
            return;
        }
        $session_id = $_COOKIE[$old_name];
        if ($this->isCli()) {
            $options = $this->session_cookie_options;
            $this->setCookie($new_name, $session_id,
                $options['expires'] ?? 0, $options['cookie_path'] ?? "",
                $options['cookie_domain'] ?? "",
                !empty($options['cookie_secure']),
                !empty($options['cookie_httponly']),
                $options['cookie_samesite'] ?? "");
            $this->setCookie($old_name, "", time() - 3600,
                $options['cookie_path'] ?? "");
        } else {
            $params = session_get_cookie_params();
            setcookie($new_name, $session_id, ['expires' => 0,
                'path' => $params['path'], 'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite']]);
            setcookie($old_name, "", ['expires' => time() - 3600,
                'path' => $params['path']]);
        }
        $_COOKIE[$new_name] = $session_id;
        unset($_COOKIE[$old_name]);
        if ($this->current_session === $old_name) {
            $this->current_session = $new_name;
        }
    }
    /**
     * Starts a web session by sending a cookie with a unique ID.
     * When the client returns the cookie, session data is looked
     * up. CLI mode stores session data in RAM; under another web
     * server, defaults to session_start().
     *
     * A session id is 32 random bytes written as hex, which is hard
     * to guess. An id offered by a cookie is trusted only when it has
     * that exact shape and already names a session held in memory;
     * otherwise a fresh id is made. This stops someone from planting a
     * known id and riding another person's signed-in session.
     *
     * Only so many sessions are kept in memory at once (MAX_SESSIONS,
     * default 10000). When there are more, the least recently used are
     * dropped first, so a flood of new visitors cannot grow memory
     * without bound. The session being served right now is never
     * dropped, so a busy moment cannot sign out the active person.
     *
     * @param array $options session cookie fields: 'name',
     *      'cookie_path', 'cookie_lifetime' (seconds from now),
     *      'cookie_domain', 'cookie_secure', 'cookie_httponly'
     */
    public function sessionStart($options = [])
    {
        if ($this->isCli()) {
            foreach ($this->session_configs as $key => $value) {
                if (empty($options[$key])) {
                    $options[$key] = $value;
                }
            }
            $cookie_name = $options['name'];
            $cookie_value = $_COOKIE[$cookie_name] ?? "";
            $time = time();
            $lifetime = intval($options['cookie_lifetime']);
            $expires = ($lifetime > 0) ? $time + $lifetime : 0;
            /*
                Only honor the cookie-supplied session id if it
                matches our id format and the session already exists
                server-side. Anything else falls through to fresh
                session id generation. This prevents session fixation
                where an attacker plants a known id and tries to ride
                the victim's authenticated session. A well-formed id we
                did not have is remembered (without any lookup here) so
                a higher layer can decide whether it maps to a signed-in
                user and should be restored.
             */
            $session_id = "";
            $this->rehydrate_candidate = "";
            if ($cookie_value !== ""
                && preg_match('/^[a-f0-9]{' . self::SESSION_ID_HEX_LEN .
                '}$/', $cookie_value)) {
                if (!empty($this->sessions[$cookie_value])) {
                    $session_id = $cookie_value;
                    $_SESSION = $this->sessionData($session_id);
                } else {
                    $this->rehydrate_candidate = $cookie_value;
                }
            }
            if ($session_id === "") {
                $session_id = bin2hex(
                    random_bytes(self::SESSION_ID_BYTE_LEN));
                $this->sessions[$session_id] = [];
                $_SESSION = [];
            }
            $this->sessions[$session_id]['TIME'] = $time;
            if ($this->session_lru === null) {
                $this->session_lru = new \SplMinHeap();
            }
            /* Stamp this session as most recently used and record that
               in the heap. An earlier pair for the same session stays
               in the heap but is now out of date; it is skipped when it
               surfaces during eviction below. */
            $this->session_sequence++;
            $this->sessions[$session_id]['SEQ'] = $this->session_sequence;
            $this->session_lru->insert(
                [$this->session_sequence, $session_id]);
            /* A session used more than once leaves earlier heap entries
               behind. They clear during eviction, but steady reuse
               while under the cap never triggers eviction, so the
               leftovers would pile up. When they have grown well past
               the number of live sessions, rebuild the heap from the
               live sessions to clear them. */
            if ($this->session_lru->count() >
                2 * count($this->sessions) + self::MAX_SESSIONS_DEFAULT) {
                $rebuilt = new \SplMinHeap();
                foreach ($this->sessions as $live_id => $live_session) {
                    $rebuilt->insert([$live_session['SEQ'], $live_id]);
                }
                $this->session_lru = $rebuilt;
            }
            $max_sessions = $this->default_server_globals[
                'MAX_SESSIONS'] ?? self::MAX_SESSIONS_DEFAULT;
            /* Drop the least recently used sessions while over the cap.
               The heap gives the smallest use-count first. A pair whose
               recorded use-count no longer matches the session (it was
               used again since) is stale and discarded. The session
               being served right now is never dropped, so a busy moment
               cannot sign out the active person. */
            while (count($this->sessions) > $max_sessions &&
                !$this->session_lru->isEmpty()) {
                list($pair_sequence, $drop_id) = $this->session_lru->top();
                if (!isset($this->sessions[$drop_id]) ||
                    $this->sessions[$drop_id]['SEQ'] != $pair_sequence) {
                    $this->session_lru->extract();
                    continue;
                }
                if ($drop_id == $session_id) {
                    break;
                }
                $this->session_lru->extract();
                $this->forgetSession($drop_id);
            }
            $this->setCookie($cookie_name, $session_id, $expires,
                $options['cookie_path'], $options['cookie_domain'],
                $options['cookie_secure'], $options['cookie_httponly'],
                $options['cookie_samesite'] ?? "");
            $_COOKIE[$cookie_name] = $session_id;
            $this->current_session = $cookie_name;
            $this->session_cookie_options = $options;
            $this->session_cookie_options['expires'] = $expires;
        } else {
            if (empty($options['cookie_lifetime']) ||
            $options['cookie_lifetime'] >= 0) {
                session_start($options);
            } else if (!empty($_COOKIE)) {
                setcookie($options['name'], "", time() - 3600,
                    $options['cookie_path'] ?? "/");
            }
        }
    }
    /**
     * Writes the current in-memory sessions and the counter used to
     * order them to a file, so a server that is about to restart can
     * hand them to its replacement and keep people signed in across the
     * restart. Shared by the admin Restart Server path and a
     * command-line restart.
     *
     * @param string $session_path file to write the saved sessions to
     */
    public function saveSessionsForRestart($session_path)
    {
        if (empty($session_path)) {
            return;
        }
        $this->saved_sessions_path = $session_path;
        $session_info = [];
        $session_info['SESSIONS'] = $this->sessions;
        $session_info['SESSION_SEQUENCE'] = $this->session_sequence;
        file_put_contents($session_path, serialize($session_info));
    }
    /**
     * Returns a well-formed session id the current request's cookie
     * offered that was not in memory, or an empty string if there was
     * none. A higher layer uses this to decide whether the id belongs
     * to a signed-in user whose session should be restored.
     *
     * @return string the candidate session id, or "" if none
     */
    public function rehydrateCandidate()
    {
        return $this->rehydrate_candidate;
    }
    /**
     * Where a session's contents are kept. Each session is a file of its
     * own rather than a value held in memory, so the server holds only as
     * much of them as the request it is serving needs.
     *
     * @param string $session_id the session to name a file for
     * @return string absolute path of that session's file
     */
    protected function sessionFilePath($session_id)
    {
        return $this->default_server_globals['SESSION_DIR'] . "/" .
            self::SESSION_FILE_PREFIX . $session_id;
    }
    /**
     * Reads a session's contents back from its file. A session the server
     * knows of but whose file is gone, or whose file no longer reads as a
     * session, comes back empty rather than as an error, which is what a
     * visitor whose session was swept would see anyway.
     *
     * @param string $session_id the session to read
     * @return array the session contents, empty when there are none
     */
    public function sessionData($session_id)
    {
        $path = $this->sessionFilePath($session_id);
        if (!file_exists($path)) {
            return [];
        }
        $written = $this->fileGetContents($path);
        if ($written === false || $written === "") {
            return [];
        }
        $data = @unserialize($written);
        return is_array($data) ? $data : [];
    }
    /**
     * Writes a session's contents to its file, refusing one that has grown
     * past what the server will accept as a request body. A session that
     * large is a defect rather than a person's work, and holding it would
     * cost the memory that limit exists to bound.
     *
     * The write itself goes through filePutContents, which leaves the file
     * alone when its contents already match, so a request that reads a
     * session without changing it costs nothing on disk.
     *
     * @param string $session_id the session to write
     * @param array $session_data the contents to write
     * @return bool whether the contents were written
     */
    protected function writeSessionData($session_id, $session_data)
    {
        $written = serialize($session_data);
        if (strlen($written) >
            $this->default_server_globals['MAX_REQUEST_LEN']) {
            return false;
        }
        $this->filePutContents($this->sessionFilePath($session_id),
            $written);
        return true;
    }
    /**
     * Drops a session, both what the server remembers of it and the file
     * its contents were kept in, so a session evicted for being least
     * recently used leaves nothing behind on disk.
     *
     * @param string $session_id the session to drop
     */
    protected function forgetSession($session_id)
    {
        $path = $this->sessionFilePath($session_id);
        if (file_exists($path)) {
            @unlink($path);
        }
        unset($this->sessions[$session_id]);
    }
    /**
     * Restores a session under a session id the current request already
     * carries, putting back the given data and switching the request to
     * use that id. Used to sign a person back in from a saved session
     * after the in-memory one was dropped or the server restarted,
     * keeping their existing cookie so nothing changes on their side.
     *
     * @param string $session_id the id to restore the session under
     * @param array $session_data the session contents to put back
     */
    public function adoptSession($session_id, $session_data)
    {
        $this->sessions[$session_id] = ['TIME' => time()];
        $this->writeSessionData($session_id, $session_data);
        $this->session_sequence++;
        $this->sessions[$session_id]['SEQ'] = $this->session_sequence;
        if ($this->session_lru === null) {
            $this->session_lru = new \SplMinHeap();
        }
        $this->session_lru->insert(
            [$this->session_sequence, $session_id]);
        $_SESSION = $session_data;
        $_COOKIE[$this->current_session] = $session_id;
    }
    /**
     * Reads the contents of a file, from the server's RAM cache when the
     * file is there. In CLI mode, it checks if the file exists in its
     * Marker Algorithm based RAM cache (Fiat et al 1991). If so, it
     * directly returns it. Otherwise, it reads it in using blocking I/O
     * file_get_contents() and caches it before returning its string
     * contents. Note this function assumes that only the web server is
     * performing I/O with this file. filemtime() can be used to see if a
     * file on disk has been changed and then you can use $force_read =
     * true below to force re-reading the file into the cache. When
     * $read_compress is true the gzip compressed contents are what is
     * cached and returned, under a cache entry of their own beside the
     * plain one, so a text file a client will accept compressed is
     * compressed once and then served from the cache until it is
     * evicted like any other entry.
     *
     * @param string $filename name of file to get contents of
     * @param bool $force_read whether to force the file to be read from
     *      persistent storage rather than the cache
     * @param bool $read_compress whether to return, and cache, the gzip
     *      compressed contents rather than the contents as they are
     * @return string contents of the file given by $filename, gzip
     *      compressed if asked
     */
    public function fileGetContents($filename, $force_read = false,
        $read_compress = false)
    {
        if ($this->isCli()) {
            $this->syncFileJournal();
            if (!empty($this->file_cache['PATH'][$filename])) {
                /*
                    We are caching realpath which already has its own cache.
                    realpath's cache though is based on time, ours is based on
                    the marking algorithm.
                 */
                $path = $this->file_cache['PATH'][$filename];
            } else {
                $path = realpath($filename);
                $this->file_cache['PATH'][$filename] = $path;
            }
            $cache_key = ($read_compress) ?
                $path . self::COMPRESSED_CACHE_SUFFIX : $path;
            if (isset($this->file_cache['MARKED'][$cache_key])) {
                if ($force_read) {
                    $this->file_cache['MARKED'][$cache_key] =
                        $this->readFileContents($path, $read_compress);
                }
                return $this->file_cache['MARKED'][$cache_key];
            } else if (isset($this->file_cache['UNMARKED'][$cache_key])) {
                if ($force_read) {
                    $this->file_cache['MARKED'][$cache_key] =
                        $this->readFileContents($path, $read_compress);
                } else {
                    $this->file_cache['MARKED'][$cache_key] =
                        $this->file_cache['UNMARKED'][$cache_key];
                }
                unset($this->file_cache['UNMARKED'][$cache_key]);
                return $this->file_cache['MARKED'][$cache_key];
            }
            $data = $this->readFileContents($path, $read_compress);
            $this->file_cache['HASH'][$cache_key] = md5($data);
            if (strlen($data) < $this->default_server_globals[
                'MAX_CACHE_FILESIZE']) {
                if (count($this->file_cache['MARKED']) +
                    ($num_unmarked = count($this->file_cache['UNMARKED'])) >=
                    $this->default_server_globals['MAX_CACHE_FILES'] &&
                    $num_unmarked > 0) {
                    $eject = random_int(0, $num_unmarked - 1);
                    $unmarked_paths = array_keys($this->file_cache['UNMARKED']);
                    unset(
                        $this->file_cache['UNMARKED'][$unmarked_paths[$eject]]);
                }
                $this->file_cache['MARKED'][$cache_key] = $data;
                if (count($this->file_cache['MARKED']) >=
                    $this->default_server_globals['MAX_CACHE_FILES']) {
                    foreach ($this->file_cache['PATH'] as $name => $path) {
                        if (empty($this->file_cache['MARKED'][$path]) &&
                            empty($this->file_cache['MARKED'][$path .
                            self::COMPRESSED_CACHE_SUFFIX])) {
                            unset($this->file_cache['PATH'][$name]);
                        }
                    }
                    foreach ($this->file_cache['MARKED'] as $path => $data) {
                        $this->file_cache['UNMARKED'][$path] = $data;
                        unset($this->file_cache['MARKED'][$path]);
                    }
                    /* The hashes of files no longer cached go too. Every
                       file read or written leaves a hash, so without this
                       they would pile up, one for each session file ever
                       made. A file whose hash is gone is just written
                       again the next time, even if unchanged. */
                    $this->file_cache['HASH'] = array_intersect_key(
                        $this->file_cache['HASH'] ?? [],
                        $this->file_cache['UNMARKED']);
                }
            }
            return $data;
        }
        return $this->readFileContents($filename, $read_compress);
    }
    /**
     * Reads a file from disk, gzip compressing what it read when asked.
     * fileGetContents calls this wherever it reads a file rather than its
     * cache, so the compressed and plain forms come from one place.
     *
     * @param string $path the file to read
     * @param bool $compress whether to gzip compress the contents
     * @return string the contents, compressed if asked
     */
    protected function readFileContents($path, $compress)
    {
        $data = file_get_contents($path);
        return ($compress && $data !== false) ? gzencode($data) : $data;
    }
    /**
     * Writes $data to the persistent file with name $filename. Saves a copy
     * in the RAM cache if there is a copy already there, and drops any gzip
     * compressed copy of the file, which fileGetContents makes again from
     * the new contents when it is next asked for.
     *
     * @param string $filename name of file to write to persistent storages
     * @param string $data string of data to store in file
     * @return int number of bytes written
     */
    public function filePutContents($filename, $data)
    {
        $this->syncFileJournal();
        $data_length = strlen($data);
        $fits_in_cache =
            $data_length <
            $this->default_server_globals['MAX_CACHE_FILESIZE'];
        if ($fits_in_cache) {
            if (isset($this->file_cache['PATH'][$filename])) {
                /*
                    we are caching realpath which already has its own cache
                    realpath's cache is based on time, ours is based on
                    the marking algorithm.
                 */
                $path = $this->file_cache['PATH'][$filename];
            } else {
                $path = realpath($filename);
                $this->file_cache['PATH'][$filename] = $path;
            }
        }
        if ($this->isCli()) {
            /* A compressed copy was made from the old contents, so it is
               dropped and made again from the new ones on the next read. */
            if (!empty($this->file_cache['PATH'][$filename])) {
                $gzip_key = $this->file_cache['PATH'][$filename] .
                    self::COMPRESSED_CACHE_SUFFIX;
                unset($this->file_cache['MARKED'][$gzip_key],
                    $this->file_cache['UNMARKED'][$gzip_key]);
            }
            if ($fits_in_cache)  {
                if (isset($this->file_cache['MARKED'][$path])) {
                    $this->file_cache['MARKED'][$path] = $data;
                } else if (isset($this->file_cache['UNMARKED'][$path])) {
                    $this->file_cache['UNMARKED'][$path] = $data;
                }
            } else if (!empty($this->file_cache['PATH'][$filename])) {
                $path = $this->file_cache['PATH'][$filename];
                unset($this->file_cache['MARKED'][$path],
                    $this->file_cache['UNMARKED'][$path],
                    $this->file_cache['PATH'][$filename]);
            }
        }
        /* A file whose contents already match what is about to be written
           is left alone. The hash of what was last read or written from
           each path is remembered, so a page saved unchanged, or a session
           whose values did not move, costs no disk write at all. */
        $hash_path = $this->file_cache['PATH'][$filename] ?? $filename;
        $hash = md5($data);
        if (isset($this->file_cache['HASH'][$hash_path]) &&
            $this->file_cache['HASH'][$hash_path] === $hash &&
            file_exists($filename)) {
            return $data_length;
        }
        $written_length = file_put_contents($filename, $data);
        $this->file_cache['HASH'][$hash_path] = $hash;
        @chmod($filename, 0777);
        if ($this->file_journal !== "") {
            clearstatcache(true, $this->file_journal);
            if (@filesize($this->file_journal) > self::FILE_JOURNAL_MAX_BYTES) {
                file_put_contents($this->file_journal, "", LOCK_EX);
            }
            file_put_contents($this->file_journal,
                (realpath($filename) ?: $filename) . "\n",
                FILE_APPEND | LOCK_EX);
        }
        return $written_length;
    }
    /**
     * startWorkers starts the worker processes that run requests for this
     * front process, and waits for each to connect back. A worker is the
     * same site script started with WORKER_COMMAND; it builds the same
     * routes and calls serveAsWorker, which reads requests from its link
     * instead of listening on a port. The workers are started with
     * proc_open and talk over loopback sockets, which PHP provides alike on
     * Linux, macOS and Windows, with no fork. listen calls it once the
     * ports are bound and the server has become its run-as user, so the
     * workers run as that user.
     *
     * @param int $count how many worker processes to start
     */
    protected function startWorkers($count)
    {
        $this->worker_count = $count;
        $this->worker_listener = stream_socket_server("tcp://127.0.0.1:0",
            $errno, $errstr);
        if ($this->worker_listener === false) {
            error_log("Workers not started: $errstr");
            $this->worker_listener = null;
            return;
        }
        for ($i = 0; $i < $count; $i++) {
            $this->startWorker($i);
        }
        /* Nothing is served yet, so the first workers are waited for, all
           at once rather than one after another. */
        while (!empty($this->worker_starts)) {
            $this->finishWorkerStarts(self::WORKER_ACCEPT_WAIT);
        }
    }
    /**
     * startWorker starts worker number $i and records it in $worker_starts
     * without waiting for it to connect back; finishWorkerStarts takes it
     * into $workers once it has. startWorkers calls it for each worker, and
     * leastBusyWorker calls it again for a worker that has stopped.
     *
     * @param int $i number of the worker to start
     * @return bool whether the worker's process could be started
     */
    protected function startWorker($i)
    {
        $port = parse_url("tcp://" .
            stream_socket_get_name($this->worker_listener, false),
            PHP_URL_PORT);
        $log = ($this->worker_log === "") ?
            ((PHP_OS_FAMILY === "Windows") ? "NUL" : "/dev/null") :
            $this->worker_log;
        $environment = getenv();
        $environment['ATTO_WORKER_LINK'] = $port;
        /* The link is a loopback port any local program could connect to,
           so the worker proves it was started here: it and this process
           share a secret no other program sees, and each side shows the
           other a hash of it before any request crosses the link. */
        $secret = bin2hex(random_bytes(32));
        $environment['ATTO_WORKER_SECRET'] = $secret;
        $environment['ATTO_WORKER_JOURNAL'] = $this->file_journal;
        $process = null;
        if ($this->worker_start !== null) {
            $settings = ["ATTO_WORKER_LINK", "ATTO_WORKER_SECRET",
                "ATTO_WORKER_JOURNAL"];
            foreach ($settings as $setting) {
                putenv("$setting=" . $environment[$setting]);
            }
            ($this->worker_start)();
            foreach ($settings as $setting) {
                putenv($setting);
            }
        } else {
            $process = proc_open($this->worker_command, [0 => ["file",
                (PHP_OS_FAMILY === "Windows") ? "NUL" : "/dev/null", "r"],
                1 => ["file", $log, "a"], 2 => ["file", $log, "a"]],
                $pipes, null, $environment);
        }
        /* The front does not wait here for the worker to connect, which
           took the whole front, every request it served, for as long as
           a worker took to start. finishWorkerStarts takes the worker in
           once it has connected and shown its hash. */
        unset($this->workers[$i]);
        $this->worker_starts[$i] = ["process" => $process,
            "secret" => $secret, "proof" => hash("sha256", "worker $secret"),
            "give_up" => time() + self::WORKER_START_SECONDS];
        if ($process === false) {
            $this->finishWorkerStarts();
            return false;
        }
        return true;
    }
    /**
     * finishWorkerStarts takes in the workers in $worker_starts that have
     * connected back, without waiting unless asked to. Every connection on
     * the worker link is held apart until it shows a hash; one that shows
     * the hash of a worker being started becomes that worker's link, and
     * one that shows a wrong hash, or none in WORKER_PROOF_SECONDS, is
     * closed and noted. A worker whose process exits before connecting, or
     * that has not connected within WORKER_START_SECONDS, is noted and
     * tried again after WORKER_RETRY_SECONDS. The event loop calls it on
     * each pass while a worker is starting, and startWorkers calls it with
     * a wait until the first workers are in.
     *
     * @param float $wait seconds to wait for a connection, 0 for none
     */
    protected function finishWorkerStarts($wait = 0)
    {
        if ($this->worker_listener === null) {
            return;
        }
        $accepted = @stream_socket_accept($this->worker_listener, $wait);
        while ($accepted !== false) {
            stream_set_blocking($accepted, false);
            $this->worker_pending_links[] = ["link" => $accepted,
                "said" => "", "since" => microtime(true)];
            $accepted = @stream_socket_accept($this->worker_listener, 0);
        }
        foreach ($this->worker_pending_links as $k => $connection) {
            $read = fread($connection["link"],
                64 - strlen($connection["said"]));
            $said = $connection["said"] . (($read === false) ? "" : $read);
            $started = null;
            foreach ($this->worker_starts as $i => $start) {
                if (strlen($said) == 64 && hash_equals($start["proof"],
                    $said)) {
                    $started = $i;
                }
            }
            if ($started !== null) {
                unset($this->worker_pending_links[$k]);
                $this->takeInWorker($started, $connection["link"]);
                continue;
            }
            if (strlen($said) == 64 || feof($connection["link"]) ||
                microtime(true) - $connection["since"] >
                self::WORKER_PROOF_SECONDS) {
                $this->refuseWorkerLink($connection["link"]);
                unset($this->worker_pending_links[$k]);
                continue;
            }
            $this->worker_pending_links[$k]["said"] = $said;
        }
        if ($this->worker_refusals["unnoted"] > 0) {
            $this->noteWorker(-1, "link refused " .
                $this->worker_refusals["unnoted"] . " more connections " .
                "that did not prove they were workers; they were not noted " .
                "one by one");
            $this->worker_refusals["unnoted"] = 0;
        }
        foreach ($this->worker_starts as $i => $start) {
            $process = $start["process"];
            $status = is_resource($process) ? proc_get_status($process) :
                ["running" => true];
            if ($process !== false && $status['running'] &&
                time() < $start["give_up"]) {
                continue;
            }
            $this->noteWorker($i, (($process === false) ?
                "could not be started" : (!$status['running'] ?
                "exited before connecting, with code " . $status['exitcode'] :
                "did not connect within " . self::WORKER_START_SECONDS .
                " seconds")) . "; it is tried again after " .
                self::WORKER_RETRY_SECONDS . " seconds");
            if (is_resource($process)) {
                /* Ended and waited for, so no finished process is left
                   behind for each failed start. */
                proc_terminate($process);
                proc_close($process);
            }
            unset($this->worker_starts[$i]);
            $this->worker_retry_after[$i] = time() +
                self::WORKER_RETRY_SECONDS;
        }
    }
    /**
     * takeInWorker makes $link, a connection that showed the hash of
     * worker $i, that worker's link: it shows the worker the front's own
     * hash, reads the worker's process id, notes the start, and records the
     * worker in $workers, ready for requests. finishWorkerStarts calls it.
     *
     * @param int $i number of the worker that connected
     * @param resource $link the worker's connection
     */
    protected function takeInWorker($i, $link)
    {
        $start = $this->worker_starts[$i];
        unset($this->worker_starts[$i]);
        stream_set_blocking($link, true);
        fwrite($link, hash("sha256", "front " . $start["secret"]));
        $worker_id = unpack("N", (string)fread($link, 4) . "\0\0\0\0")[1];
        $this->noteWorker($i, "started as process " . $worker_id);
        stream_set_blocking($link, false);
        $this->workers[$i] = ["process" => $start["process"],
            "link" => $link, "id" => $worker_id, "busy" => 0, "parts" => [],
            "have" => 0, "heard" => time()];
    }
    /**
     * relayToWorker hands the current request to the least busy worker and
     * lets this process serve others until the reply comes. It runs as a
     * deferred response: the waiting happens in a fiber, and the reply is
     * sent by the same code that sends any deferred reply, including one
     * whose body is a file read out a piece at a time. The worker is sent
     * the request's globals and the records of any sessions its cookies
     * name; back come the headers, the body or the file holding it, and
     * the session records the request made or changed, which are put back
     * into $sessions. getResponseData calls it in place of process.
     */
    protected function relayToWorker()
    {
        $session_records = [];
        foreach ($_COOKIE as $cookie_value) {
            if (is_string($cookie_value) &&
                isset($this->sessions[$cookie_value])) {
                $session_records[$cookie_value] =
                    $this->sessions[$cookie_value];
            }
        }
        $environment = $this->captureRequestEnvironment();
        unset($environment["STREAMING_SOCKET"],
            $environment["STREAMING_CONTEXT"]);
        $this->worker_request_id++;
        $request = ["ID" => $this->worker_request_id,
            "ENVIRONMENT" => $environment, "FILES" => $_FILES,
            "SESSIONS" => $session_records, "BASE_PATH" => $this->base_path,
            "SERVER_GLOBALS" => $this->default_server_globals];
        $this->deferResponse(function () use ($request) {
            /* A request still waiting its turn when its worker is ended
               was never run, so it is handed to another worker rather
               than answered with a 502. Each worker number is tried
               once, so a worker that keeps stopping cannot hold the
               request for good. */
            $tries_left = max(1, $this->worker_count);
            $growing_file = false;
            $reserved = $this->worker_reserved !== null &&
                ($this->worker_reserved)();
            do {
                $started = false;
                $this->waitForFreeWorker($reserved);
                $worker = $this->leastBusyWorker($reserved);
                if ($worker === null) {
                    $this->header(($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1') .
                        " 503 Service Unavailable");
                    echo "No worker process is running.";
                    return;
                }
                if (empty($this->workers[$worker]["waiting"])) {
                    $this->workers[$worker]["heard"] = time();
                }
                $this->workers[$worker]["busy"]++;
                /* Kept with the request, so the access line written when its
                   reply is sent can say which worker ran it. */
                $_SERVER['ATTO_WORKER'] = $worker;
                $message = serialize($request);
                $this->workers[$worker]["queued"][] =
                    pack("N", strlen($message)) . $message;
                $this->writeToWorkers();
                $id = $request["ID"];
                $this->workers[$worker]["waiting"][$id] =
                    [$_SERVER['REQUEST_URI'] ?? "", time(),
                    $_SERVER['REQUEST_METHOD'] ?? "GET", false];
                $connection_key = $this->deferredSendContext()['key'] ?? null;
                if ($connection_key !== null) {
                    $this->relayed_by_connection[$connection_key][$id] =
                        $worker;
                }
                /* A worker that stops is replaced under the same number,
                   so the request waits on this worker's link, not on the
                   number: a request queued to the stopped worker would
                   otherwise wait on its replacement, which never got it. */
                $link = $this->workers[$worker]["link"];
                $same_worker = fn() =>
                    ($this->workers[$worker]["link"] ?? null) === $link;
                while (!isset($this->worker_replies[$id]) &&
                    !isset($this->cancelled_requests[$id]) &&
                    $same_worker()) {
                    $this->readWorkerReplies($worker);
                    $started = $started ||
                        isset($this->worker_started[$id]);
                    if (isset($this->worker_growing[$id])) {
                        $growing_file = $this->startGrowingWorkerFile($id);
                    }
                    if (!isset($this->worker_replies[$id]) &&
                        \Fiber::getCurrent() !== null) {
                        \Fiber::suspend(["read" =>
                            $this->workers[$worker]["link"] ?? null,
                            "until" => fn() => isset($this->worker_replies[$id])
                            || isset($this->worker_growing[$id])
                            || isset($this->cancelled_requests[$id])
                            || !$same_worker()]);
                    }
                }
                /* The worker's word that it took the request up may come
                   after the fiber last looked, as when the worker is ended
                   while it runs the request. */
                $started = $started || isset($this->worker_started[$id]);
                unset($this->worker_started[$id]);
                if ($same_worker()) {
                    $this->workers[$worker]["busy"]--;
                    unset($this->workers[$worker]["waiting"][$id]);
                }
                if ($connection_key !== null) {
                    unset($this->relayed_by_connection[$connection_key][$id]);
                    if (empty($this->relayed_by_connection[$connection_key])) {
                        unset($this->relayed_by_connection[$connection_key]);
                    }
                }
                if (isset($this->cancelled_requests[$id])) {
                    unset($this->cancelled_requests[$id],
                        $this->worker_replies[$id],
                        $this->worker_growing[$id]);
                    return;
                }
                $reply = $this->worker_replies[$id] ?? null;
                unset($this->worker_replies[$id]);
                $tries_left--;
            } while ($reply === null && !$started && $tries_left > 0);
            if ($reply === null && $growing_file) {
                /* The headers and part of the file have gone out, so the
                   reply simply ends, short, where the worker stopped. */
                return;
            }
            if ($reply === null) {
                $this->header(($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1') .
                    " 502 Bad Gateway");
                echo "The worker process running this request stopped.";
                return;
            }
            foreach ($request["SESSIONS"] as $session_id => $record) {
                if (!isset($reply["SESSIONS"][$session_id])) {
                    unset($this->sessions[$session_id]);
                }
            }
            foreach ($reply["SESSIONS"] as $session_id => $record) {
                $this->sessions[$session_id] = $record;
            }
            $this->header_data = $reply["HEADER"];
            $this->content_type = $reply["CONTENT_TYPE"];
            $this->current_session = $reply["CURRENT_SESSION"];
            $_SESSION = $reply["SESSION"];
            if ($reply["STOP"]) {
                /* The worker's route asked for a stop or restart. The
                   front holds every session, so it saves them itself,
                   where the route saved the worker's few; and it stops
                   only once this reply has been sent, so the page that
                   polls for the restart reaches the browser. */
                if ($reply["SESSION_PATH"] !== "") {
                    $this->saveSessionsForRestart($reply["SESSION_PATH"]);
                }
                $this->running_task->stop_after = $reply["RESTART"];
            }
            if ($growing_file) {
                return;
            }
            /* A growing file this front could not start early is sent
               whole now that the worker has finished it. */
            $reply_file = ($reply["FILE"] ?? "") !== "" ? $reply["FILE"] :
                ($reply["GROWN_FILE"] ?? "");
            if ($reply_file !== "" && $this->deferBodyFromFile($reply_file,
                !empty($reply["REMOVE_FILE"]))) {
                return;
            }
            echo $reply["BODY"];
        });
    }
    /**
     * startGrowingWorkerFile starts sending a file a worker is still
     * writing, once the worker has named it. relayToWorker calls it from
     * the fiber relaying the request, with the message readWorkerReplies
     * kept in $worker_growing. The message carries the headers the route
     * had set, which go out first, and then the file is sent as it grows
     * until the worker's last reply for the request ends the fiber.
     *
     * @param int $id the id the front gave the relayed request
     * @return bool whether the file is being sent; false when the
     *      request's protocol cannot send a body of unknown length, in
     *      which case the file is sent whole after the worker finishes
     */
    protected function startGrowingWorkerFile($id)
    {
        $growing_message = $this->worker_growing[$id];
        unset($this->worker_growing[$id]);
        $this->header_data = $growing_message["HEADER"];
        $this->content_type = $growing_message["CONTENT_TYPE"];
        $this->current_session = $growing_message["CURRENT_SESSION"];
        $_SESSION = $growing_message["SESSION"];
        return $this->deferBodyFromFile($growing_message["FILE"],
            !empty($growing_message["REMOVE_FILE"]), true);
    }
    /**
     * loadSavedSessions takes back the sessions saveSessionsForRestart
     * wrote before a restart, so a signed-in user's cookie still names a
     * session the new server knows. Without them the first request after
     * the restart, such as the restart page's status poll, is given a new
     * session and the user is signed out. listen calls it with the
     * SESSION_INFO it is handed. Only well-formed session ids are taken;
     * other keys, such as TERMINAL, are not sessions.
     *
     * @param array $session_info what saveSessionsForRestart wrote, with
     *      the sessions under SESSIONS
     */
    public function loadSavedSessions($session_info)
    {
        foreach ($session_info['SESSIONS'] ?? [] as $session_id => $record) {
            if (!is_array($record) || !preg_match('/^[a-f0-9]{' .
                self::SESSION_ID_HEX_LEN . '}$/', (string)$session_id)) {
                continue;
            }
            $sequence = (int)($record['SEQ'] ?? 0);
            $this->sessions[$session_id] = $record;
            $this->session_sequence = max($this->session_sequence,
                $sequence);
            $this->session_lru ??= new \SplMinHeap();
            $this->session_lru->insert([$sequence, $session_id]);
        }
    }
    /**
     * refuseWorkerLink closes a connection to the worker link that did not
     * show the hash of the secret a worker is started with, as a program
     * other than the worker would not, and notes it in the worker log with
     * where it came from. Only WORKER_REFUSALS_NOTED_PER_MINUTE are noted
     * in a minute, so a flood of them cannot fill the log; the rest are
     * counted, and the count is noted with the next note. startWorker
     * calls it.
     *
     * @param resource $link the connection to refuse
     */
    protected function refuseWorkerLink($link)
    {
        $from = (string)stream_socket_get_name($link, true);
        fclose($link);
        $minute = intdiv(time(), 60);
        if ($this->worker_refusals["minute"] != $minute) {
            $this->worker_refusals["minute"] = $minute;
            $this->worker_refusals["noted"] = 0;
        }
        if ($this->worker_refusals["noted"] >=
            self::WORKER_REFUSALS_NOTED_PER_MINUTE) {
            $this->worker_refusals["unnoted"]++;
            return;
        }
        $this->worker_refusals["noted"]++;
        $unnoted = $this->worker_refusals["unnoted"];
        $this->worker_refusals["unnoted"] = 0;
        $this->noteWorker(-1, "link refused a connection from $from that " .
            "did not prove it was a worker started here" . (($unnoted > 0) ?
            "; $unnoted more were refused but not noted" : ""));
    }
    /**
     * noteWorker writes one line about a worker's life, starting, failing
     * to start or stopping, to the WORKER_LOG file its output also goes
     * to, or to the error log when there is none. startWorker and
     * readWorkerReplies call it, so a server whose workers never appear
     * says why.
     *
     * @param int $i number of the worker, counted from zero; -1 for a note
     *      about the worker link rather than one worker
     * @param string $what what happened to it
     */
    protected function noteWorker($i, $what)
    {
        $line = date("r") . " worker" . (($i >= 0) ? " " . ($i + 1) : "") .
            " " . $what;
        if ($this->worker_log === "" ||
            @file_put_contents($this->worker_log, "$line\n", FILE_APPEND) ===
            false) {
            error_log($line);
        }
    }
    /**
     * noteFrontWork adds one request of kind $kind to $front_work, with
     * the processor time the front used since $usage, a getrusage
     * reading taken when the front began on it. For a relayed request the
     * time covers handing it to a worker, not the worker's time or the
     * writing of its reply later. The request handler calls it after each
     * request, and sampleMemoryUsage writes and clears the totals.
     *
     * @param string $kind "relayed", "kept" or "served"
     * @param array $usage getrusage() taken before the request
     */
    protected function noteFrontWork($kind, $usage)
    {
        $now = getrusage();
        $used = ($now["ru_utime.tv_sec"] - $usage["ru_utime.tv_sec"]) +
            ($now["ru_stime.tv_sec"] - $usage["ru_stime.tv_sec"]) +
            (($now["ru_utime.tv_usec"] - $usage["ru_utime.tv_usec"]) +
            ($now["ru_stime.tv_usec"] - $usage["ru_stime.tv_usec"])) /
            self::MICROSECONDS_PER_SECOND;
        $this->front_work[$kind]["count"] =
            ($this->front_work[$kind]["count"] ?? 0) + 1;
        $this->front_work[$kind]["cpu"] =
            ($this->front_work[$kind]["cpu"] ?? 0) + $used;
        if ($kind != "relayed") {
            $path = strtok($_SERVER['REQUEST_URI'] ?? "", "?");
            $this->front_work["paths"][$path] =
                ($this->front_work["paths"][$path] ?? 0) + $used;
        }
    }
    /**
     * cancelRelayedRequests tells the workers to drop every request from
     * the connection $key that is still at a worker, since the connection
     * has closed and no reply can reach it. Each such request's fiber is
     * ended through $cancelled_requests, and its worker is sent a CANCEL
     * frame, which the worker applies when it reaches that request, so
     * work for a client that has gone is not done. shutdownHttpStream
     * calls it.
     *
     * @param int $key the connection's key
     */
    protected function cancelRelayedRequests($key)
    {
        foreach ($this->relayed_by_connection[$key] ?? [] as $id => $worker) {
            $this->cancelled_requests[$id] = true;
            if (!isset($this->workers[$worker])) {
                continue;
            }
            $waiting = $this->workers[$worker]["waiting"] ?? [];
            if (array_key_first($waiting) !== $id) {
                /* A request the worker has not reached yet costs it
                   nothing to drop; one it is already running finishes. */
                unset($this->workers[$worker]["waiting"][$id]);
                $this->workers[$worker]["busy"]--;
            }
            $message = serialize(["CANCEL" => $id]);
            $this->workers[$worker]["queued"][] =
                pack("N", strlen($message)) . $message;
        }
        unset($this->relayed_by_connection[$key]);
    }
    /**
     * writeToWorkers writes each worker's queued requests to the worker's
     * link, as much as the link takes without waiting. A request is queued
     * to a worker when the front has received it from a browser and chosen
     * that worker, and it leaves the queue once its last byte is written.
     * relayToWorker queues a request and calls writeToWorkers, and the main
     * loop calls it on every pass to write the rest. With each queue goes a
     * count of how much of its first request has been written, so a large
     * request is never copied whole to drop the part already written; at
     * most WORKER_WRITE_SIZE bytes are copied for one write. Requests reach
     * a worker whole and in order this way, and a worker that is busy and
     * not reading, with a large upload queued for it, never holds the front
     * up.
     */
    protected function writeToWorkers()
    {
        foreach ($this->workers as $i => $worker) {
            while (!empty($this->workers[$i]["queued"])) {
                $offset = $this->workers[$i]["queued_written"] ?? 0;
                $next_request = $this->workers[$i]["queued"][0];
                $written = @fwrite($worker["link"], $offset == 0 ?
                    $next_request : substr($next_request, $offset,
                    self::WORKER_WRITE_SIZE));
                if (empty($written)) {
                    break;
                }
                $offset += $written;
                if ($offset < strlen($next_request)) {
                    $this->workers[$i]["queued_written"] = $offset;
                    break;
                }
                array_shift($this->workers[$i]["queued"]);
                $this->workers[$i]["queued_written"] = 0;
            }
        }
    }
    /**
     * endOverdueWorkers ends any worker whose current request, other than
     * a POST, has run for more than WORKER_REQUEST_SECONDS by the clock, and
     * any worker with requests queued to it that has sent the front nothing
     * for WORKER_SILENT_SECONDS. The worker's link then closes,
     * readWorkerReplies notes it stopped with the request it was on, and
     * every request waiting on it gets a 502. The main loop calls it on
     * each pass. A worker started through WORKER_START is ended by its
     * process id, which needs posix_kill; one started with proc_open is
     * ended through its process handle.
     */
    protected function endOverdueWorkers()
    {
        $now = time();
        foreach ($this->workers as $i => $worker) {
            $waiting = $worker["waiting"] ?? [];
            $running = reset($waiting);
            if ($running === false) {
                continue;
            }
            if (!empty($worker["ended"])) {
                /* A worker asked to stop that has not stopped within
                   WORKER_STOP_SECONDS is killed outright. */
                if ($now - $worker["ended"] > 2 * self::WORKER_STOP_SECONDS) {
                    /* Killed and still not gone: its link is held open by
                       a process it started, which inherited it. The front
                       stops waiting on it. */
                    $this->dropWorker($i, "dropped, its link still open");
                    continue;
                }
                if ($now - $worker["ended"] > self::WORKER_STOP_SECONDS &&
                    !empty($worker["id"])) {
                    if ($this->worker_stop !== null) {
                        ($this->worker_stop)($worker["id"], false);
                    } else if (function_exists("posix_kill")) {
                        posix_kill($worker["id"], 9);
                    }
                }
                continue;
            }
            $overdue = $running[2] !== "POST" && !empty($running[3]) &&
                $now - $running[1] > self::WORKER_REQUEST_SECONDS;
            $silent = !($running[2] === "POST" && !empty($running[3])) &&
                $now - ($worker["heard"] ?? $now) > self::WORKER_SILENT_SECONDS;
            if (!$overdue && !$silent) {
                continue;
            }
            if (is_resource($worker["process"])) {
                proc_terminate($worker["process"], 9);
            } else if ($this->worker_stop !== null && !empty($worker["id"])) {
                /* Asked to stop first, so the worker can log where it was
                   before it exits. */
                ($this->worker_stop)($worker["id"], true);
            } else if (function_exists("posix_kill") &&
                !empty($worker["id"])) {
                posix_kill($worker["id"], 15);
            } else {
                continue;
            }
            $this->workers[$i]["ended"] = $now;
            $this->noteWorker($i, "ended after " . ($now - $running[1]) .
                " s on " . $running[0]);
        }
    }
    /**
     * leastBusyWorker picks the worker running the fewest requests, first
     * starting a new worker in place of any that has stopped. A worker
     * still starting is not chosen. relayToWorker and waitForFreeWorker
     * call it for each request.
     *
     * @param bool $reserved whether the request is one the reserved worker
     *      is kept for, in which case only that worker is chosen when one
     *      is kept
     * @return int|null number of the chosen worker, or null if none runs
     */
    protected function leastBusyWorker($reserved = false)
    {
        /* A worker whose link closed was dropped when its end was read;
           every number up to the count asked for that has no worker gets
           a new one here. */
        for ($i = 0; $i < $this->worker_count; $i++) {
            if (!isset($this->workers[$i]) &&
                !isset($this->worker_starts[$i]) &&
                time() >= ($this->worker_retry_after[$i] ?? 0)) {
                $this->startWorker($i);
            }
        }
        if (!empty($this->worker_starts)) {
            $this->finishWorkerStarts();
        }
        $last = $this->worker_count - 1;
        if ($this->worker_reserved !== null && $this->worker_count > 1) {
            if ($reserved) {
                return isset($this->workers[$last]) ? $last : null;
            }
        }
        $chosen = null;
        foreach ($this->workers as $i => $worker) {
            /* A worker asked to stop runs nothing more. */
            if (!empty($worker["ended"])) {
                continue;
            }
            if ($this->worker_reserved !== null && $this->worker_count > 1 &&
                $i == $last) {
                continue;
            }
            if ($chosen === null ||
                $worker["busy"] < $this->workers[$chosen]["busy"]) {
                $chosen = $i;
            }
        }
        /* The reserved worker also takes other requests while it has
           nothing to do and every other worker is busy, so it is never
           idle while requests queue; a reserved request then waits behind
           at most the one request it is running. */
        if ($this->worker_reserved !== null && $this->worker_count > 1 &&
            isset($this->workers[$last]) && $this->workers[$last]["busy"] == 0
            && empty($this->workers[$last]["ended"])
            && ($chosen === null || $this->workers[$chosen]["busy"] > 0)) {
            $chosen = $last;
        }
        return $chosen;
    }
    /**
     * waitForFreeWorker holds the current request in this process, rather
     * than queue it to a worker, while every worker it may go to is
     * running a request. A worker runs one request at a time, so a
     * request queued to a worker running a slow search waits for the whole
     * search, though another worker may be free in a moment; a slow
     * search then held up every page queued behind it. A request also
     * waits while the only workers are still starting. The wait ends when
     * a worker the request may go to has nothing to run, or after
     * WORKER_SILENT_SECONDS, when the request is queued to the least busy
     * worker as before. relayToWorker calls it before choosing a worker.
     *
     * @param bool $reserved whether the request is one the reserved worker
     *      is kept for, as leastBusyWorker takes it
     */
    protected function waitForFreeWorker($reserved)
    {
        if (\Fiber::getCurrent() === null) {
            return;
        }
        $give_up = time() + self::WORKER_SILENT_SECONDS;
        /* With no worker to choose, the request also waits while one is
           starting, or while one asked to stop has not yet gone, after
           which a new one is started in its place, rather than be
           answered that none is running. */
        $must_wait = fn($worker) => ($worker === null) ?
            (!empty($this->worker_starts) || !empty(array_filter(
            array_column($this->workers, "ended")))) :
            $this->workers[$worker]["busy"] > 0;
        $chosen = $this->leastBusyWorker($reserved);
        while ($must_wait($chosen) && time() < $give_up) {
            /* Waiting on the chosen worker's link wakes the event loop
               when that worker answers; a reply from any other worker
               wakes it too, through the request waiting on that one. A
               worker starting wakes it through the worker link. */
            \Fiber::suspend(["read" => ($chosen === null) ?
                $this->worker_listener : $this->workers[$chosen]["link"],
                "until" => fn() => time() >= $give_up ||
                    !$must_wait($this->leastBusyWorker($reserved))]);
            $chosen = $this->leastBusyWorker($reserved);
        }
    }
    /**
     * dropWorker forgets worker $i: it notes $how in the worker log with
     * the request the worker was on and how many more were queued to it,
     * closes the front's end of its link, and removes it, so every request
     * waiting on it gets a 502 and the next request starts a new worker.
     * readWorkerReplies calls it when a worker's link closes, and
     * endOverdueWorkers when a killed worker's link stays open.
     *
     * @param int $i number of the worker to drop
     * @param string $how what happened to the worker, for the log
     */
    protected function dropWorker($i, $how)
    {
        $waiting = $this->workers[$i]["waiting"] ?? [];
        $running = reset($waiting);
        $this->noteWorker($i, $how . (($running === false) ? "" :
            " while running " . $running[0] . " for " .
            (time() - $running[1]) . " s, with " . (count($waiting) - 1) .
            " more waiting"));
        if (is_resource($this->workers[$i]["process"])) {
            proc_close($this->workers[$i]["process"]);
        }
        if (is_resource($this->workers[$i]["link"])) {
            fclose($this->workers[$i]["link"]);
        }
        unset($this->workers[$i]);
    }
    /**
     * readWorkerReplies reads what worker $i has sent and files each whole
     * reply under its request id in $worker_replies. A closed link removes
     * the worker, so a request waiting on it is answered with an error.
     * relayToWorker calls it while it waits.
     *
     * @param int $i number of the worker to read from
     */
    protected function readWorkerReplies($i)
    {
        $link = $this->workers[$i]["link"];
        $read = fread($link, self::WORKER_READ_BYTES);
        if (($read === false || $read === "") && feof($link)) {
            $this->dropWorker($i, "stopped");
            return;
        }
        if ($read !== false && $read !== "") {
            $this->workers[$i]["heard"] = time();
        }
        /* What the worker sends is kept as a list of the pieces read, and
           joined only once a whole reply has come, so a reply of many
           megabytes is not copied again on every read. */
        $worker = &$this->workers[$i];
        if ($read !== false && $read !== "") {
            $worker["parts"][] = $read;
            $worker["have"] += strlen($read);
        }
        while (true) {
            if (!isset($worker["need"])) {
                if ($worker["have"] < 4) {
                    break;
                }
                if (strlen($worker["parts"][0]) < 4) {
                    $worker["parts"] = [implode("", $worker["parts"])];
                }
                $worker["need"] = 4 + unpack("N", $worker["parts"][0])[1];
            }
            if ($worker["have"] < $worker["need"]) {
                break;
            }
            $buffer = implode("", $worker["parts"]);
            $reply = unserialize(substr($buffer, 4, $worker["need"] - 4));
            $rest = substr($buffer, $worker["need"]);
            $worker["parts"] = ($rest === "") ? [] : [$rest];
            $worker["have"] = strlen($rest);
            unset($worker["need"], $buffer, $rest);
            if (is_array($reply) && isset($reply["STARTED"])) {
                /* The worker has taken this request up, so its time on
                   it counts from now, not from when it was queued or from
                   when the worker was starting up. */
                if (isset($this->workers[$i]["waiting"][$reply["STARTED"]])) {
                    $this->workers[$i]["waiting"][$reply["STARTED"]][1] =
                        time();
                    $this->workers[$i]["waiting"][$reply["STARTED"]][3] =
                        true;
                    $this->worker_started[$reply["STARTED"]] = true;
                }
                continue;
            }
            if (is_array($reply) && isset($reply["GROWING"])) {
                /* The request's route has started a file it is still
                   writing. The fiber relaying the request sends it; a
                   request whose connection has gone has no such fiber,
                   and its last reply deletes the file below. */
                if (!isset($this->cancelled_requests[$reply["GROWING"]])) {
                    $this->worker_growing[$reply["GROWING"]] = $reply;
                }
                continue;
            }
            if (is_array($reply) &&
                isset($this->cancelled_requests[$reply["ID"] ?? null])) {
                /* The connection went while the worker ran this request,
                   so no fiber waits for the reply. */
                unset($this->cancelled_requests[$reply["ID"]],
                    $this->workers[$i]["waiting"][$reply["ID"]],
                    $this->worker_started[$reply["ID"]]);
                $this->workers[$i]["busy"]--;
                if (($reply["GROWN_FILE"] ?? "") !== "" &&
                    !empty($reply["REMOVE_FILE"])) {
                    @unlink($reply["GROWN_FILE"]);
                }
                continue;
            }
            if (is_array($reply) && isset($reply["ID"])) {
                $this->worker_replies[$reply["ID"]] = $reply;
            }
        }
        unset($worker);
    }
    /**
     * serveAsWorker makes this process a worker for a front process: it
     * connects to the link ATTO_WORKER_LINK names and runs each request
     * sent there through the same routes and code as a normal request,
     * then sends back the headers, the body, the file holding a streamed
     * body, and the session records. A route that names a file it is still
     * writing has the file's name sent at once, through deferBodyFromFile,
     * and the last reply then says the file is done. It returns when the
     * link closes,
     * which is when the front process stops. A site script calls it
     * instead of listen when started as a worker.
     */
    public function serveAsWorker()
    {
        if (function_exists("pcntl_signal")) {
            /* When the front asks this worker to stop, it logs the code it
               was in, so a request that ran too long names its slow step. */
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, function () {
                $steps = [];
                foreach (array_slice(debug_backtrace(), 1,
                    self::WORKER_TRACE_STEPS) as $step) {
                    $steps[] = basename($step["file"] ?? "?") . ":" .
                        ($step["line"] ?? "?") . " " .
                        ($step["function"] ?? "");
                }
                error_log("[website-worker] asked to stop while running " .
                    ($_SERVER['REQUEST_URI'] ?? "") . " at " .
                    implode(" < ", $steps));
                exit();
            });
        }
        $link = @stream_socket_client("tcp://127.0.0.1:" .
            getenv("ATTO_WORKER_LINK"), $errno, $errstr,
            self::WORKER_START_SECONDS);
        if ($link === false) {
            return;
        }
        /* Each side shows the other a hash of the secret the front
           started this worker with; a program that is not the front
           cannot answer, and nothing is read from it. */
        $secret = (string)getenv("ATTO_WORKER_SECRET");
        fwrite($link, hash("sha256", "worker $secret"));
        /* The front may never answer: a front that stopped while this
           worker started leaves its listening socket open in this worker,
           which inherited it, so the connection is made but never taken.
           Waiting for good would keep this worker, and every worker whose
           link it also inherited, running after the front is gone. */
        stream_set_timeout($link, self::WORKER_START_SECONDS);
        $answer = "";
        while (strlen($answer) < 64) {
            $read = fread($link, 64 - strlen($answer));
            if ($read === false || ($read === "" && (feof($link) ||
                stream_get_meta_data($link)["timed_out"]))) {
                return;
            }
            $answer .= $read;
        }
        stream_set_timeout($link, (int)ini_get("default_socket_timeout"));
        if ($secret === "" ||
            !hash_equals(hash("sha256", "front $secret"), $answer)) {
            return;
        }
        $this->file_journal = (string)getenv("ATTO_WORKER_JOURNAL");
        fwrite($link, pack("N", getmypid()));
        $this->worker_link = $link;
        $queued = [];
        $cancelled = [];
        while (true) {
            /* Every frame already on the link is read before the next
               request is taken up, so a CANCEL the front sent for a
               request still in the queue is seen before that request
               runs. */
            do {
                $header = $this->readWorkerBytes($link, 4, $queued === []);
                if ($header === null) {
                    return;
                }
                if ($header === "") {
                    break;
                }
                $message = $this->readWorkerBytes($link,
                    unpack("N", $header)[1]);
                $frame = ($message === null) ? null : unserialize($message);
                if (!is_array($frame)) {
                    return;
                }
                if (isset($frame["CANCEL"])) {
                    $cancelled[$frame["CANCEL"]] = true;
                } else {
                    $queued[] = $frame;
                }
            } while (true);
            $request = array_shift($queued);
            if (isset($cancelled[$request["ID"]])) {
                unset($cancelled[$request["ID"]]);
                continue;
            }
            /* The base path comes from how the front process was started,
               which a worker started by another path would work out
               differently, and it decides which route a path matches. */
            $this->base_path = $request["BASE_PATH"];
            /* A request the route makes to this site itself is built
               from these settings. A worker never runs listen, so it takes
               the front's; without them such a request lacked SCRIPT_NAME,
               and an application routing on it showed its error page. */
            $this->default_server_globals = $request["SERVER_GLOBALS"];
            $this->sessions = $request["SESSIONS"];
            $this->applyRequestEnvironment($request["ENVIRONMENT"] + [
                "STREAMING_SOCKET" => null, "STREAMING_CONTEXT" => [],
                "IS_STREAMING" => false, "STREAMING_FAILED" => false]);
            $_FILES = $request["FILES"];
            $this->stop = false;
            $this->restart = "";
            $this->saved_sessions_path = "";
            set_time_limit((($_SERVER['REQUEST_METHOD'] ?? "GET") === "POST")
                ? 0 : self::WORKER_REQUEST_SECONDS);
            /* The front times WORKER_REQUEST_SECONDS from the word sent
               next, not from the request's arrival, which is earlier when
               the request waited for a free worker. A route that keeps
               within that limit times itself from here. */
            $_SERVER['WORKER_STARTED_FLOAT'] = microtime(true);
            $started = serialize(["STARTED" => $request["ID"]]);
            fwrite($link, pack("N", strlen($started)) . $started);
            $this->worker_reply_file = "";
            $this->worker_remove_file = false;
            $this->worker_running_id = $request["ID"];
            $this->worker_grown_file = "";
            $body = $this->getResponseData(false);
            set_time_limit(0);
            $reply = serialize(["ID" => $request["ID"],
                "HEADER" => (string)$this->header_data,
                "CONTENT_TYPE" => $this->content_type,
                "CURRENT_SESSION" => (string)$this->current_session,
                "SESSION" => $_SESSION, "SESSIONS" => $this->sessions,
                "BODY" => (string)$body, "STOP" => (bool)$this->stop,
                "RESTART" => $this->restart,
                "SESSION_PATH" => $this->saved_sessions_path,
                "FILE" => $this->worker_reply_file,
                "GROWN_FILE" => $this->worker_grown_file,
                "REMOVE_FILE" => $this->worker_remove_file]);
            $this->worker_reply_file = null;
            fwrite($link, pack("N", strlen($reply)) . $reply);
        }
    }
    /**
     * readWorkerBytes reads exactly $length bytes from a worker's link
     * for serveAsWorker. With $wait it waits as needed; without it, when
     * no byte is there to read it returns "" at once, so the worker can
     * see whether another frame has arrived before it takes up a request.
     *
     * @param resource $link the worker's link to the front process
     * @param int $length how many bytes to read
     * @param bool $wait whether to wait for bytes that are not there yet
     * @return string|null the bytes, "" if none were waiting and $wait is
     *      false, or null if the link closed first
     */
    protected function readWorkerBytes($link, $length, $wait = true)
    {
        $bytes = "";
        if (!$wait) {
            $reads = [$link];
            $writes = null;
            $excepts = null;
            if (stream_select($reads, $writes, $excepts, 0) < 1) {
                return "";
            }
        }
        while (strlen($bytes) < $length) {
            $read = fread($link, $length - strlen($bytes));
            if ($read === false || ($read === "" && feof($link))) {
                return null;
            }
            $bytes .= $read;
        }
        return $bytes;
    }
    /**
     * syncFileJournal drops from this process's file cache every file
     * another server process has written since this one last looked, so
     * a cached copy is never served after the file on disk changed. It
     * reads the new lines of the file write journal, each the path of one
     * written file, and forgets that path's cached contents, compressed
     * copy and hash; the hash matters too, since filePutContents skips a
     * write whose data matches the hash. A journal shorter than the part
     * already read was started again empty, so everything is dropped.
     * fileGetContents and filePutContents call it before using the cache.
     * It does nothing when the server runs alone. Appending with LOCK_EX
     * and reading under a shared lock work the same on Linux, macOS and
     * Windows.
     */
    protected function syncFileJournal()
    {
        if ($this->file_journal === "") {
            return;
        }
        clearstatcache(true, $this->file_journal);
        $size = @filesize($this->file_journal);
        if ($size === false || $size == $this->file_journal_offset) {
            return;
        }
        if ($size < $this->file_journal_offset) {
            $this->clearFileCache();
            $this->file_journal_offset = $size;
            return;
        }
        $journal = @fopen($this->file_journal, "rb");
        if ($journal === false) {
            return;
        }
        flock($journal, LOCK_SH);
        fseek($journal, $this->file_journal_offset);
        $added = stream_get_contents($journal);
        flock($journal, LOCK_UN);
        fclose($journal);
        $last_newline = strrpos($added, "\n");
        if ($last_newline === false) {
            return;
        }
        $this->file_journal_offset += $last_newline + 1;
        foreach (explode("\n", substr($added, 0, $last_newline)) as $path) {
            $compressed = $path . self::COMPRESSED_CACHE_SUFFIX;
            unset($this->file_cache['MARKED'][$path],
                $this->file_cache['UNMARKED'][$path],
                $this->file_cache['MARKED'][$compressed],
                $this->file_cache['UNMARKED'][$compressed],
                $this->file_cache['HASH'][$path]);
        }
    }
    /**
     * Deletes the files stored in the RAM FileCache
     */
    public function clearFileCache()
    {
        $this->file_cache = ['MARKED' => [], 'UNMARKED' => [],
            'PATH' => [], 'HASH' => []];
    }
    /**
     * Used to move a file that was uploaded from a form on the client to the
     * desired location on the server. In non-CLI mode this calls PHP's built-in
     * move_uploaded_file() function
     *
     * @param string $filename tmp_name in $_FILES of the uploaded file
     * @param string $destination where on server the file should be moved to
     * @return bool true on a successful save, false when no matching
     *      tmp_name was found in $_FILES; in non-CLI mode the
     *      return value of move_uploaded_file is propagated
     */
    public function moveUploadedFile($filename, $destination)
    {
        if ($this->isCli()) {
            foreach ($_FILES as $key => $file_array) {
                if ($filename == $file_array['tmp_name']) {
                    $this->filePutContents($destination, $file_array['data']);
                    return true;
                }
            }
            return false;
        }
        return move_uploaded_file($filename, $destination);
    }
    /**
     * Returns the mime type of the provided file name if it can be
     * determined from the file's name. The type is read from the name's
     * extension rather than the file's bytes, so it costs no file read.
     *
     * @param string $file_name name of file, including path, to figure out
     *      the mime type for
     * @return string mime type or unknown if can't be determined
     */
    public static function mimeType($file_name)
    {
        $mime_type = "unknown";
        $last_chars = "-1";
        /* The type is read from the file's name, not from its bytes. Reading
           the bytes (with finfo) opens and reads each file, which listing a
           folder of a thousand or more resources did once per entry and so
           took long enough to time the page out; the name is enough for the
           types these callers compare against. */
        $last_chars = strtolower(substr($file_name,
            strrpos($file_name, ".")));
        $mime_types = [
            ".aac" => "audio/aac",
            ".aif" => "audio/aiff",
            ".aiff" => "audio/aiff",
            ".aifc" => "audio/aiff",
            ".avi" => "video/x-msvideo",
            ".avif" => "image/avif",
            ".bmp" => "image/bmp",
            ".bz" => "application/bzip",
            ".ico" => "image/x-icon",
            ".css" => "text/css",
            ".csv" => "text/csv",
            ".diff" => "text/plain",
            ".epub" => "application/epub+zip",
            ".gif" => "image/gif",
            ".gz" => "application/gzip",
            ".html" => 'text/html',
            ".jpeg" => "image/jpeg",
            ".jpg" => "image/jpeg",
            ".js" => "text/javascript",
            ".oga" => "audio/ogg",
            ".ogg" => "audio/ogg",
            ".opus" => "audio/opus",
            ".patch" => "text/plain",
            ".mov" => "video/quicktime",
            ".mp3" => "audio/mpeg",
            ".mp4" => "video/mp4",
            ".m4a" => "audio/mp4",
            ".m4v" => "video/mp4",
            ".pdf" => "application/pdf",
            ".png" => "image/png",
            ".svg" => "image/svg+xml",
            ".tex" => "text/plain",
            ".txt" => "text/plain",
            ".wav" => "audio/vnd.wave",
            ".tif" => "image/tiff",
            ".tiff" => "image/tiff",
            ".webm" => "video/webm",
            ".webp" => "image/webp",
            ".zip" => "application/zip",
            ".Z" => "application/x-compress",
        ];
        if (isset($mime_types[$last_chars])) {
            $mime_type = $mime_types[$last_chars];
        }
        $mime_type = str_replace('application/ogg', 'video/ogg', $mime_type);
        return $mime_type;
    }
    /**
     * Sets up a repeating or one-time timer that calls $callback every or after
     * $time seconds
     *
     * @param float $time time in seconds (fractional seconds okay) after which
     *      $callback should be called. Or interval between calls if this is
     *      a repeating timer.
     * @param callable $callback a function to be called after now + $time
     * @param bool $repeating whether $callback should be called every $time
     *      seconds or just once.
     * @return string an id for the timer that can be used to turn
     *      it off (@see clearTimer())
     */
    public function setTimer($time, callable $callback, $repeating = true)
    {
        if (!$this->isCli()) {
            throw new \Exception("Atto WebSite Timers require CLI execution");
        }
        $next_time = microtime(true) + $time;
        /*
            Each timer has an id of its own, kept for as long as it
            repeats, so timers due at the same moment each run, and
            clearTimer stops a repeating timer by the id setTimer gave.
         */
        $this->timers_made++;
        $key = "timer" . $this->timers_made;
        $this->timers[$key] = [$repeating, $time, $callback];
        $this->timer_alarms->insert([$next_time, $key]);
        return $key;
    }
    /**
     * Deletes a timer from the list of active timers. The fact
     * that the timer is removed from the timers map but not from
     * the timer_alarms heap is intentional. processTimers checks
     * the timers map before invoking each callback, so a removed
     * timer is silently skipped when its alarm fires; explicitly
     * scrubbing the heap would be O(n) per cancellation.
     * (@see setTimer)
     *
     * @param string $timer_id the id of the timer to remove,
     *      as returned by setTimer
     */
    public function clearTimer($timer_id)
    {
        unset($this->timers[$timer_id]);
    }
    /**
     * Returns the array of bound Listener objects so app code can
     * introspect listener state (e.g. example 17's H3 stats route
     * iterates the connection map on the H3 listener). Useful for
     * diagnostic and admin endpoints; production apps generally
     * do not need to touch this. The returned array is the live
     * internal storage — callers should not mutate it.
     *
     * @return array<int,Listener> bound listeners
     */
    public function listeners()
    {
        return $this->listeners;
    }
    /**
     * Refreshes the certificate served by every secure listener by
     * re-setting the certificate and key options on each listener's
     * stream context. The accepted-socket TLS handshake reads the
     * listening socket's context at handshake time, so new
     * connections pick up the certificate currently on disk while
     * connections already established finish on the one they began
     * with. This lets a renewed certificate take effect without
     * rebinding the privileged ports or restarting the server, so
     * an external renewer (the AcmeRenew media job runs in the
     * MediaUpdater process, not this one) need only write the new
     * files. H3 listeners manage their own TLS and are left for a
     * restart to pick up.
     *
     * @param string $cert_file path to the certificate to serve
     *      (PEM, full chain)
     * @param string $key_file path to the private key (PEM) paired
     *      with $cert_file
     * @return int the number of secure listeners refreshed
     */
    public function reloadSecureCertificate($cert_file, $key_file)
    {
        $refreshed = 0;
        foreach ($this->listeners as $listener) {
            if (!($listener instanceof Listener) ||
                empty($listener->is_secure)) {
                continue;
            }
            $server = $listener->resource();
            if (!is_resource($server)) {
                continue;
            }
            stream_context_set_option($server, "ssl", "local_cert",
                $cert_file);
            stream_context_set_option($server, "ssl", "local_pk",
                $key_file);
            $refreshed++;
        }
        return $refreshed;
    }
    /**
     * The settings a server runs with before any configuration is read.
     * These live here alone: the constructor starts a server with them, so
     * anything reading one before listen begins finds a value rather than
     * nothing, listen starts from them, and a caller making a context to
     * hand in can ask for one instead of repeating its value.
     *
     * @return array the default server globals
     */
    public static function defaultServerGlobals()
    {
        $path = $_SERVER['PATH'] ?? $_SERVER['Path'] ?? ".";
        return ["CONNECTION_TIMEOUT" => 20,
            "CUSTOM_ERROR_HANDLER" => null,
            "DOCUMENT_ROOT" => getcwd(),
            "GATEWAY_INTERFACE" => "CGI/1.1",  "MAX_CACHE_FILESIZE" => 2000000,
            "MAX_CACHE_FILES" => 250,  "MAX_IO_LEN" => self::MAX_IO_LEN_DEFAULT,
            "MAX_REQUEST_LEN" => 10000000, "MAX_SESSIONS" => 10000,
            "SESSION_IDLE_TIMEOUT" => self::SESSION_IDLE_TIMEOUT_DEFAULT,
            "LARGE_RESPONSE_LOG_LEN" =>
                self::LARGE_RESPONSE_LOG_LEN_DEFAULT,
            "REQUEST_MEMORY_GROWTH_LOG_LEN" =>
                self::REQUEST_MEMORY_GROWTH_LOG_LEN_DEFAULT,
            "MAX_INPUT_VARS" => 1000,
            "SESSION_DIR" => sys_get_temp_dir(),
            "PATH" => $path,  "PHP_PATH" => "",
            "SERVER_ADMIN" => "you@example.com", "SERVER_NAME" => "localhost",
            "SERVER_SIGNATURE" => "",
            "USER" => $_SERVER['USER'] ?? "",
            "SERVER_SOFTWARE" => "ATTO WEBSITE SERVER",
        ];
    }
    /**
     * Starts an Atto Web Server listening on one or more addresses,
     * then runs the event loop. Streams are non-blocking and traffic
     * detection uses stream_select (portable Unix select wrapper).
     *
     * $address takes three forms:
     *  1. int 0..65535: bind to that port on 0.0.0.0 (or "localhost"
     *     on Windows to avoid the firewall prompt).
     *  2. string "tcp://0.0.0.0:8080" or "tcp://[::1]:8080" (IPv6
     *     must use bracket form per RFC 3986).
     *  3. array of listener specs for multi-port operation. Each
     *     entry is either a plain address (int/string, using the
     *     shared config) or an assoc array with 'address' (required)
     *     and 'context' (optional per-listener stream context, e.g.
     *     ssl options that override the shared context). This is
     *     how to bind both 80 and 443 from one Atto process.
     *
     * @param mixed $address int port, string address, or array of
     *      listener specs (see above)
     * @param mixed $config_array_or_ini_filename associative array
     *      of configuration parameters, or the path to an .ini
     *      file. Mainly sets fields that show up in the $_SERVER
     *      superglobal (see $default_server_globals below).
     *      SERVER_CONTEXT may be set to a stream-context array to
     *      configure SSL and other stream options.
     */
    public function listen($address, $config_array_or_ini_filename = false)
    {
        $default_server_globals = self::defaultServerGlobals();
        $original_address = is_array($address) ? "multi" : $address;
        $this->listen_address = $original_address;
        $shared_context = [];
        $shared_globals = [];
        if (is_array($config_array_or_ini_filename)) {
            if (!empty($config_array_or_ini_filename['SERVER_CONTEXT'])) {
                $shared_context =
                    $config_array_or_ini_filename['SERVER_CONTEXT'];
                unset($config_array_or_ini_filename['SERVER_CONTEXT']);
            }
            $shared_globals = $config_array_or_ini_filename;
        } else if (is_string($config_array_or_ini_filename) &&
            file_exists($config_array_or_ini_filename)) {
            $ini_data = parse_ini_file($config_array_or_ini_filename);
            if (!empty($ini_data['SERVER_CONTEXT'])) {
                $shared_context = $ini_data['SERVER_CONTEXT'];
                unset($ini_data['SERVER_CONTEXT']);
            }
            $shared_globals = $ini_data;
        }
        /* The host names this server should answer to. setGlobals
           uses them to set $_SERVER['SERVER_NAME'] per request to the
           served domain a visitor actually used, so links built during
           the request (the account-activation mail among them) point
           back at that domain rather than the one name the server
           bound to. The list may arrive as a top-level config entry or
           inside SERVER_CONTEXT, as a list or a comma- or
           space-separated string. It is taken out of the globals so it
           does not leak into $_SERVER as a stray CGI variable. */
        $served_source = $shared_globals['SECURE_DOMAINS'] ??
            ($shared_context['SECURE_DOMAINS'] ?? []);
        unset($shared_globals['SECURE_DOMAINS'],
            $shared_context['SECURE_DOMAINS']);
        $this->served_domains = $this->normalizeServedDomains(
            $served_source);
        /* How many seconds to leave between memory-usage samples may
           arrive as a top-level config value or inside SERVER_CONTEXT;
           zero or absent leaves the sampling off. It is taken out of
           the globals so it does not leak into $_SERVER as a stray CGI
           variable. */
        $this->file_journal = (string)($shared_globals['FILE_JOURNAL'] ??
            ($shared_context['FILE_JOURNAL'] ?? ""));
        unset($shared_globals['FILE_JOURNAL'],
            $shared_context['FILE_JOURNAL']);
        $this->loadSavedSessions($shared_globals['SESSION_INFO'] ?? []);
        unset($shared_globals['SESSION_INFO']);
        $worker_count = (int)($shared_globals['WORKERS'] ?? 0);
        $this->worker_command = (array)($shared_globals['WORKER_COMMAND'] ??
            []);
        $this->worker_start = $shared_globals['WORKER_START'] ?? null;
        $this->worker_reserved = $shared_globals['WORKER_RESERVED'] ?? null;
        $this->worker_stop = $shared_globals['WORKER_STOP'] ?? null;
        $this->worker_log = (string)($shared_globals['WORKER_LOG'] ?? "");
        $this->front_only = $shared_globals['FRONT_ONLY'] ?? null;
        unset($shared_globals['WORKERS'], $shared_globals['WORKER_COMMAND'],
            $shared_globals['WORKER_START'],
            $shared_globals['WORKER_RESERVED'],
            $shared_globals['WORKER_STOP'],
            $shared_globals['WORKER_LOG'], $shared_globals['FRONT_ONLY']);
        $this->memory_sample_period = (int)($shared_globals[
            'WEBSITE_MEMORY_SAMPLE_PERIOD'] ??
            ($shared_context['WEBSITE_MEMORY_SAMPLE_PERIOD'] ?? 0));
        unset($shared_globals['WEBSITE_MEMORY_SAMPLE_PERIOD'],
            $shared_context['WEBSITE_MEMORY_SAMPLE_PERIOD']);
        foreach ($default_server_globals as $server_global =>
            $server_value) {
            if (!empty($shared_context[$server_global])) {
                $shared_globals[$server_global] =
                    $shared_context[$server_global];
                unset($shared_context[$server_global]);
            }
        }
        $listener_specs = is_array($address) ? $address : [$address];
        $opened = [];
        foreach ($listener_specs as $spec) {
            if (is_array($spec)) {
                $spec_address = $spec['address'] ?? null;
                $spec_context = $spec['context'] ?? [];
                $spec_protocol = $spec['protocol'] ?? null;
            } else {
                $spec_address = $spec;
                $spec_context = [];
                $spec_protocol = null;
            }
            if ($spec_address === null) {
                echo "Listener spec missing address; skipping\n";
                continue;
            }
            $merged_context = array_replace_recursive($shared_context,
                $spec_context);
            if ($spec_protocol === 'h3'
                || $spec_protocol === 'h3-quiche') {
                /*
                    H3 listener. Two implementations are
                    available: 'h3' loads the pure-PHP
                    H3Listener, 'h3-quiche' loads the
                    libquiche-FFI H3QuicheListener. The two
                    listeners coexist -- both define
                    tryOpen() / accept() / nextTimeoutMillis()
                    / tickAllConnections() so the event loop
                    drives them interchangeably below via
                    duck-typing on those method names.

                    Either implementation may be unavailable:
                    'h3-quiche' needs FFI + libquiche, 'h3'
                    only needs ext-openssl + ext-sodium and
                    optionally ext-gmp for RSA certs. Both
                    fall through quietly when the optional
                    pieces are missing.
                 */
                $is_quiche = ($spec_protocol === 'h3-quiche');
                $cls = $is_quiche
                    ? '\seekquarry\atto\H3QuicheListener'
                    : '\seekquarry\atto\H3Listener';
                $file = $is_quiche
                    ? 'H3QuicheListener.php'
                    : 'H3Listener.php';
                if (!class_exists($cls, false)) {
                    $h3_path = __DIR__ . '/' . $file;
                    if (is_file($h3_path)) {
                        require_once $h3_path;
                    }
                }
                if (!class_exists($cls, false)) {
                    echo "$spec_protocol listener requested "
                        . "for $spec_address but src/$file "
                        . "is missing; skipping\n";
                    continue;
                }
                $parsed = $this->parseListenAddress(
                    $spec_address);
                $h3_globals = [
                    'SERVER_NAME' => $parsed['host'],
                    'SERVER_PORT' => $parsed['port'],
                ];
                $h3 = $cls::tryOpen($parsed['bind_address'],
                    $merged_context, $h3_globals);
                if ($h3 !== null) {
                    $h3->site = $this;
                    $opened[] = $h3;
                    if ($this->h3_advertise_port === 0) {
                        $this->h3_advertise_port =
                            (int) $parsed['port'];
                    }
                }
                continue;
            }
            $listener = $this->openListener($spec_address,
                $merged_context);
            if (empty($listener->server)) {
                /* the bind ultimately failed even after retries;
                   refuse to start rather than run with a listener
                   that accepts no connections, which would look
                   alive but serve nothing */
                echo "Could not bind $spec_address; server " .
                    "stopping\n";
                foreach ($opened as $already) {
                    if (!empty($already->server)) {
                        $already->close();
                    }
                }
                exit();
            }
            $opened[] = $listener;
        }
        if (empty($opened)) {
            echo "No listeners opened, server stopping\n";
            exit();
        }
        $primary = $opened[0];
        $primary_globals = $primary->globals;
        $this->default_server_globals = array_merge($_SERVER,
            $default_server_globals, $shared_globals, $primary_globals);
        $as_user = "";
        if (function_exists("posix_getuid") &&
            function_exists("posix_getpwuid") &&
            function_exists("posix_getpwnam") &&
            !empty($this->default_server_globals['USER'])) {
            $uid = posix_getuid();
            $active_user_info = posix_getpwuid($uid);
            if ($active_user_info['name'] !=
                $this->default_server_globals['USER']) {
                $user_info =
                    posix_getpwnam($this->default_server_globals['USER']);
                if (!empty($user_info['uid'])) {
                    posix_setuid($user_info['uid']);
                    $uid = posix_getuid();
                    if ($uid == $user_info['uid']) {
                        $as_user = " running as user " .
                            $this->default_server_globals['USER'];
                    }
                }
            }
        }
        if ($worker_count > 0 && (!empty($this->worker_command) ||
            $this->worker_start !== null)) {
            /* Workers start after the server has become its run-as
               user, so they run as that user too. They inherit the
               listening sockets, but each exits when its link to this
               process closes, so none outlives the server holding a
               port. */
            $this->startWorkers($worker_count);
        }
        $this->in_streams = [self::CONNECTION => [], self::DATA => [""]];
        $this->out_streams = [self::CONNECTION => [], self::DATA => [],
            self::DATA_OFFSET => []];
        /*
            Wire up the per-protocol Transports. Each Transport
            owns the readable-event handling for its protocol;
            processRequestStreams routes via Connection->protocol.
            Order doesn't matter — keys are looked up directly.
            A future H3Transport entry would slot in here.
         */
        $this->transports = [
            'h1' => new H1Transport($this),
            'h2' => new H2Transport($this),
            'ws' => new WsTransport($this),
            'handshake' => new HandshakeTransport($this),
        ];
        if (class_exists('\seekquarry\atto\H3Transport', false)) {
            $this->transports['h3'] = new H3Transport($this);
        }
        if (class_exists(
                '\seekquarry\atto\H3QuicheTransport',
                false)) {
            $this->transports['h3-quiche'] =
                new H3QuicheTransport($this);
        }
        foreach ($opened as $entry) {
            $server = $entry->server;
            if ($server === null) {
                continue;
            }
            $key = (int) $server;
            $this->listeners[$key] = $entry;
            $this->immortal_stream_keys[] = $key;
            $this->in_streams[self::CONNECTION][$key] = $server;
            echo "SERVER listening at " . $entry->address
                . ($entry->is_secure ? " (secure)" : "") . $as_user
                . "\n";
        }
        $excepts = null;
        $num_selected = 1;
        while (!$this->stop || $num_selected > 0) {
            $this->sampleMemoryUsage();
            $this->endOverdueWorkers();
            $this->writeToWorkers();
            $this->reapIdleSessions();
            $this->sweepSessionFiles(time());
            if ($this->stop) {
                if ($this->stop_started == 0) {
                    $this->stop_started = microtime(true);
                }
                $in_streams_with_data = $this->in_streams[self::CONNECTION];
                foreach ($this->listeners as $key => $entry) {
                    unset($in_streams_with_data[$key]);
                }
                if (count($in_streams_with_data) == 0) {
                    break;
                }
                if (microtime(true) - $this->stop_started >
                    $this->stop_drain_limit) {
                    foreach ($in_streams_with_data as $key => $stream) {
                        $this->shutdownHttpStream($key);
                    }
                    break;
                }
            } else {
                $in_streams_with_data = $this->in_streams[self::CONNECTION];
            }
            $out_streams_with_data = $this->out_streams[self::CONNECTION];
            if ($this->timer_alarms->isEmpty()) {
                $timeout = null;
                $micro_timeout = 0;
            } else {
                $next_alarm = $this->timer_alarms->top();
                $pre_timeout = max(0, $next_alarm[0] - microtime(true));
                $timeout = floor($pre_timeout);
                $micro_timeout = intval(($pre_timeout - $timeout)
                    * self::MICROSECONDS_PER_SECOND);
            }
            /*
                Bound the wait by the soonest pending TLS-handshake
                deadline so a peer that opens a connection and
                stalls is reaped on time even when no other socket
                has activity to wake the loop (otherwise select
                with a null timeout would block until unrelated
                traffic arrived).
             */
            $handshake_deadline = $this->nextHandshakeDeadline();
            if ($handshake_deadline !== null) {
                $until = max(0, $handshake_deadline - microtime(true));
                if ($timeout === null ||
                    $until < $timeout +
                        $micro_timeout / self::MICROSECONDS_PER_SECOND) {
                    $timeout = (int) floor($until);
                    $micro_timeout =
                        (int) (($until - floor($until)) *
                            self::MICROSECONDS_PER_SECOND);
                }
            }
            /*
                Clamp the stream_select wake-up by the next
                quiche-internal timer across every H3 listener
                so timer-driven retransmits, idle timeouts, and
                stale-handshake reaps fire at the right moment
                instead of waiting for the next inbound packet.
                Without this clamp, a connection sitting on a
                PTO with no incoming traffic would never get its
                quiche_conn_on_timeout call and the retransmit
                would never go out. The minimum is taken across
                listeners; if any listener wants a sooner wake,
                its value wins. The clamp is a no-op on servers
                without an H3 listener.
             */
            $h3_soonest = null;
            foreach ($this->listeners as $listener_entry) {
                /*
                    Duck-type any UDP-driven listener that
                    exposes nextTimeoutMillis(). Both
                    H3Listener (pure-PHP) and H3QuicheListener
                    (FFI) define the method.
                 */
                if (method_exists($listener_entry,
                        'nextTimeoutMillis')) {
                    $candidate = $listener_entry->nextTimeoutMillis();
                    if ($candidate !== null
                        && ($h3_soonest === null
                            || $candidate < $h3_soonest)) {
                        $h3_soonest = $candidate;
                    }
                }
            }
            if ($h3_soonest !== null) {
                $h3_wait = $h3_soonest / 1000.0;
                if ($timeout === null
                    || $h3_wait < $timeout +
                        $micro_timeout / self::MICROSECONDS_PER_SECOND) {
                    $timeout = (int) floor($h3_wait);
                    $micro_timeout = (int) (($h3_wait - $timeout)
                        * self::MICROSECONDS_PER_SECOND);
                }
            }
            /* A deferred task is ready to run on the next pass, so do
               not let stream_select sleep: wake right away, advance the
               task one slice, then re-check the sockets. The clamp is a
               no-op whenever no long work is in flight. */
            /* A cooperative task is in flight. If one wants to run again
               right away (a CPU- or disk-bound job that just gave the loop
               a brief turn), wake immediately so it is not slowed by the
               poll interval. If every task is only waiting on a socket,
               sleep at most one poll interval so a slow mail socket keeps
               getting chances without the CPU spinning. Either way take
               the smaller of that and whatever the rest of the loop wanted.
             */
            if ($this->cooperative_scheduler !== null &&
                    !$this->cooperative_scheduler->isEmpty()) {
                if ($this->cooperative_scheduler->hasImmediateWork()) {
                    $timeout = 0;
                    $micro_timeout = 0;
                } else {
                    $poll = self::COOPERATIVE_POLL;
                    $wanted = ($timeout === null) ? $poll + 1 :
                        $timeout * self::MICROSECONDS_PER_SECOND +
                        $micro_timeout;
                    if ($wanted > $poll) {
                        $timeout = 0;
                        $micro_timeout = $poll;
                    }
                }
            }
            /* While a walk of the session folder is under way, sleep at
               most SESSION_FILE_SWEEP_PAUSE between its steps, so a quiet
               server still gets through a folder of a great many files
               in reasonable time. While stopping, sleep at most
               STOP_PASS_PAUSE, so the stop is over as soon as its
               connections are, or as soon as its time to drain them is
               up. */
            $most_pause = null;
            if ($this->session_file_sweep_handle !== null) {
                $most_pause = self::SESSION_FILE_SWEEP_PAUSE;
            }
            if ($this->stop) {
                $most_pause = self::STOP_PASS_PAUSE;
            }
            if ($most_pause !== null) {
                $wanted = ($timeout === null) ? $most_pause + 1 :
                    $timeout * self::MICROSECONDS_PER_SECOND +
                    $micro_timeout;
                if ($wanted > $most_pause) {
                    $timeout = 0;
                    $micro_timeout = $most_pause;
                }
            }
            /* A worker's reply wakes the loop like any readable stream,
               so the request waiting for it resumes at once rather than
               at the next timer or client event. */
            foreach ($this->workers as $i => $worker) {
                $in_streams_with_data["worker $i"] = $worker["link"];
            }
            /* While a worker starts, its connecting back, and its showing
               its hash, wake the loop too. */
            if (!empty($this->worker_starts)) {
                $in_streams_with_data["starting workers"] =
                    $this->worker_listener;
                foreach ($this->worker_pending_links as $k => $connection) {
                    $in_streams_with_data["starting link $k"] =
                        $connection["link"];
                }
            }
            $num_selected = stream_select($in_streams_with_data,
                $out_streams_with_data, $excepts, $timeout, $micro_timeout);
            foreach (array_keys($in_streams_with_data) as $key) {
                if (is_string($key) && str_starts_with($key, "starting ")) {
                    unset($in_streams_with_data[$key]);
                } else if (is_string($key) &&
                    str_starts_with($key, "worker ")) {
                    unset($in_streams_with_data[$key]);
                    $i = (int)substr($key, strlen("worker "));
                    if (isset($this->workers[$i])) {
                        $this->readWorkerReplies($i);
                    }
                }
            }
            if (!empty($this->worker_starts)) {
                $this->finishWorkerStarts();
            }
            $this->processTimers();
            /*
                Drive H3 listener internal timers regardless of
                whether the listener showed up in the readable
                set. stream_select wakes us either because a
                packet arrived (in which case accept will tick
                via its own call) or because the H3 timeout we
                clamped above expired (in which case nothing
                else would tick). Calling tickAllConnections
                here covers both cases; the duplicated call from
                accept is cheap because tickAllConnections
                internally gates quiche_conn_on_timeout on the
                timeout_as_millis check.
             */
            foreach ($this->listeners as $listener_entry) {
                if (method_exists($listener_entry,
                        'tickAllConnections')) {
                    $listener_entry->tickAllConnections();
                }
            }
            if ($num_selected > 0) {
                $this->processRequestStreams(null,
                    $in_streams_with_data);
                /*
                    Drain the connections that have unsent response
                    bytes right now, not the writable set captured
                    before this tick read inbound frames. Reading a
                    frame can re-arm a connection that had nothing to
                    send a moment ago: a flow-control WINDOW_UPDATE or
                    a raised SETTINGS_INITIAL_WINDOW_SIZE re-pumps a
                    stream that was parked with its send window at
                    zero (its connection was dropped from the writable
                    set when it last drained), queueing the rest of a
                    large response. The pre-read snapshot does not
                    list that connection, so draining it would wait
                    for the next select; if the peer stops reading in
                    between, the tail never goes out and the transfer
                    ends partial. out_streams holds only connections
                    with bytes still to send, and a socket that is not
                    yet writable just takes no bytes this pass and is
                    retried, so draining the live set here is safe.
                 */
                $this->processResponseStreams(
                    $this->out_streams[self::CONNECTION]);
            }
            $this->refillStreamingGenerators();
            if ($this->cooperative_scheduler !== null) {
                $this->cooperative_scheduler->step();
            }
            $this->cullDeadStreams();
        }
        /* A worker still starting has no link yet to see this process
           end by, so it is ended here. */
        foreach ($this->worker_starts as $start) {
            if (is_resource($start["process"])) {
                proc_terminate($start["process"], 9);
            }
        }
        if ($this->restart && !empty($_SERVER['SCRIPT_NAME'])) {
            $session_path = substr($this->restart, strlen('restart') + 1);
            $php_path = $this->default_server_globals["PHP_PATH"] ?? "";
            $binary = empty($_ENV['HHVM']) ? "php" : "hhvm";
            /* prepend the configured interpreter directory only when
               one was supplied; with none, the bare name resolves
               through PATH. Building "$php_path/php" unconditionally
               would yield "/php" when no directory is set, which is
               not a real path and leaves the restart with nothing to
               exec. */
            $php = ($php_path === "") ? $binary :
                $php_path . "/" . $binary;
            /* a launcher can name the address the re-spawned
               process should be started with (for instance a marker
               that selects a multi-port bind), supplied as a server
               global so this server need not know
               what the marker means; fall back to the address this
               process was launched with otherwise */
            $restart_arg = $this->default_server_globals[
                "RESTART_ADDRESS"] ?? (is_array($original_address)
                ? "multi" : $original_address);
            /*
                Escape every command-line argument so a route handler
                that passes attacker-influenced strings into
                webExit("restart ...") cannot smuggle shell
                metacharacters. SCRIPT_NAME and PHP_PATH should be
                trusted in normal usage but get escaped too as
                defense in depth.
             */
            $script = escapeshellcmd($php) . " "
                . escapeshellarg($_SERVER['SCRIPT_NAME']) . " "
                . escapeshellarg((string) $restart_arg)
                . " 2 " . escapeshellarg((string) $session_path);
            if (strstr(PHP_OS, "WIN")) {
                $script = str_replace("/", "\\", $script);
            }
            foreach ($this->in_streams[self::CONNECTION] as $key => $stream) {
                if (!empty($stream)) {
                    @stream_socket_shutdown($stream, STREAM_SHUT_RDWR);
                }
            }
            foreach ($this->listeners as $entry) {
                $entry->close();
            }
            $job = strstr(PHP_OS, "WIN") ? "start $script "
                : "$script < /dev/null > /dev/null &";
            pclose(popen($job, "r"));
        }
    }
    /**
     * restartAddress gives the address a replacement for this server
     * should be started on. Where whatever launched this server named
     * an address for a restart, that is the one, since a launcher may
     * bind several ports from one word it alone understands; otherwise
     * it is the address this server was told to listen on. A caller
     * that starts a replacement reads this rather than working the
     * address out again.
     *
     * @return string the address a replacement server is started with
     */
    public function restartAddress()
    {
        $named = $this->default_server_globals["RESTART_ADDRESS"] ?? "";
        return ($named === "") ? $this->listen_address : $named;
    }
    /**
     * Opens a single server listener at $address with the given
     * stream context options. Returns an associative array with
     * the bound stream resource, the canonical address string,
     * the is_secure flag, and the per-listener server globals
     * (SERVER_NAME and SERVER_PORT). Used by listen() to set up
     * each listener spec.
     *
     * @param mixed $address int port, string "tcp://host:port",
     *      or string "tcp://[ipv6]:port"
     * @param array $context stream context options for this
     *      listener (typically ssl settings); a default backlog
     *      is added if not specified
     * @return array entry suitable for adding to $this->listeners
     */
    protected function openListener($address, $context)
    {
        $parsed = $this->parseListenAddress($address);
        $bind_address = $parsed['bind_address'];
        $is_secure = !empty($context['ssl']);
        if (empty($context['ssl']) && !empty($_SERVER['HTTPS'])
            && empty($this->listeners)) {
            /*
                Legacy fallback: when invoked with HTTPS=1 in the
                environment but no explicit ssl context, fall back
                to the working directory's server.crt/server.key.
                Only applies to the first listener for backward
                compatibility with the old single-listen behavior.
             */
            $is_secure = true;
            $context['ssl'] = [
                "local_cert" => "server.crt",
                "local_pk" => "server.key",
                "verify_peer" => false,
                "verify_peer_name" => false,
                "allow_self_signed" => true,
                "alpn_protocols" => "h2,http/1.1"
            ];
        }
        $context["socket"]["backlog"] = empty($context["socket"]["backlog"])
            ? 200 : $context["socket"]["backlog"];
        $server_context = stream_context_create($context);
        $server = false;
        $errstr = "";
        for ($attempt = 0; $attempt < self::BIND_ATTEMPTS;
            $attempt++) {
            $server = stream_socket_server($bind_address, $errno,
                $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
                $server_context);
            if ($server) {
                break;
            }
            /* the exiting process may still hold the port for a
               short teardown window after a restart; wait and try
               again before giving up so the replacement does not
               come up deaf */
            usleep(self::BIND_RETRY_WAIT * 1000);
        }
        if (!$server) {
            echo "Failed to bind address $bind_address: $errstr\n";
            return new Listener(null, $bind_address, $is_secure, []);
        }
        stream_set_blocking($server, false);
        return new Listener($server, $bind_address, $is_secure, [
            'SERVER_NAME' => $parsed['host'],
            'SERVER_PORT' => $parsed['port'],
        ]);
    }
    /**
     * Parses a listen address into its bind string, host and port
     * components. Accepts plain integers (interpreted as IPv4
     * ports), tcp://host:port URLs for IPv4 or hostnames, and
     * tcp://[ipv6]:port URLs for IPv6 addresses per RFC 3986.
     *
     * @param mixed $address int port, string address, or
     *      tcp://... URL
     * @return array associative array with keys 'bind_address'
     *      (suitable for stream_socket_server), 'host', and
     *      'port'
     */
    protected function parseListenAddress($address)
    {
        if (is_int($address) || (is_string($address)
            && ctype_digit($address))) {
            $port = (int) $address;
            $localhost = strstr(PHP_OS, "WIN") ? "localhost" : "0.0.0.0";
            return ['bind_address' => "tcp://$localhost:$port",
                'host' => $localhost, 'port' => (string) $port];
        }
        $stripped = $address;
        if (str_contains($stripped, "://")) {
            $stripped = substr($stripped,
                strpos($stripped, "://") + 3);
        }
        if (str_starts_with($stripped, "[")) {
            /*
                Bracketed IPv6 form: [::1]:8080. The bracketed host
                part is everything up to the closing bracket; the
                port is whatever follows the colon after the
                bracket.
             */
            $close = strpos($stripped, "]");
            if ($close === false) {
                return ['bind_address' => $address,
                    'host' => $stripped, 'port' => ""];
            }
            $host = substr($stripped, 1, $close - 1);
            $rest = substr($stripped, $close + 1);
            $port = ($rest !== "" && $rest[0] === ":")
                ? substr($rest, 1) : "";
            return ['bind_address' => $address,
                'host' => $host, 'port' => $port];
        }
        $colon = strrpos($stripped, ":");
        if ($colon === false) {
            return ['bind_address' => $address,
                'host' => $stripped, 'port' => ""];
        }
        return ['bind_address' => $address,
            'host' => substr($stripped, 0, $colon),
            'port' => substr($stripped, $colon + 1)];
    }
    /**
     * Takes a snapshot of everything about the request being handled
     * right now that lives in shared or global spots, so it can be put
     * back later.
     *
     * This single-process server keeps the current request's details in
     * the PHP superglobals ($_SERVER, $_GET and the rest) and in a few
     * fields on this object. That is fine when one request is handled
     * start to finish before the next begins. It stops being fine when a
     * request is set aside part-way through -- a cooperative task that
     * gives up the loop while it waits, or an in-process call to another
     * local page -- and another request is served in the gap: that other
     * request overwrites those shared spots. The set-aside request needs
     * its own copy of them to restore before it carries on. This captures
     * exactly the set of values the in-process loopback below already
     * saves and restores around a nested request.
     *
     * @return array the saved request environment, to be handed back
     *      later to applyRequestEnvironment()
     */
    public function captureRequestEnvironment()
    {
        return [
            "SERVER" => $_SERVER,
            "GET" => $_GET,
            "POST" => $_POST,
            "REQUEST" => $_REQUEST,
            "COOKIE" => $_COOKIE,
            "SESSION" => $_SESSION,
            "HEADER" => empty($this->header_data) ? "" :
                $this->header_data,
            "CONTENT_TYPE" => empty($this->content_type) ? false :
                $this->content_type,
            "CURRENT_SESSION" => empty($this->current_session) ? "" :
                $this->current_session,
            "STREAMING_SOCKET" => $this->streaming_socket,
            "STREAMING_CONTEXT" => $this->streaming_context,
            "IS_STREAMING" => $this->is_streaming,
            "STREAMING_FAILED" => $this->streaming_failed,
        ];
    }
    /**
     * Puts back a request environment saved earlier by
     * captureRequestEnvironment(), so a request that was set aside
     * part-way through sees exactly the superglobals and per-request
     * fields it had before another request was served in between.
     *
     * @param array $environment a snapshot from
     *      captureRequestEnvironment()
     * @return void
     */
    public function applyRequestEnvironment($environment)
    {
        $_SERVER = $environment["SERVER"];
        $_GET = $environment["GET"];
        $_POST = $environment["POST"];
        $_REQUEST = $environment["REQUEST"];
        $_COOKIE = $environment["COOKIE"];
        $_SESSION = $environment["SESSION"];
        $this->header_data = $environment["HEADER"];
        $this->content_type = $environment["CONTENT_TYPE"];
        $this->current_session = $environment["CURRENT_SESSION"];
        if (array_key_exists("STREAMING_CONTEXT", $environment)) {
            $this->streaming_socket = $environment["STREAMING_SOCKET"];
            $this->streaming_context = $environment["STREAMING_CONTEXT"];
            $this->is_streaming = $environment["IS_STREAMING"];
            $this->streaming_failed = $environment["STREAMING_FAILED"];
        }
    }
    /**
     * Handles a local HTTP request from inside a running WebSite
     * route back to itself. The single-threaded event loop makes
     * a real curl/socket loopback deadlock; this short-circuits
     * by invoking the route handler in-process. A route that fetches
     * pages of its own site should detect "local" URLs and call this
     * instead of curl.
     *
     * @param string $url local page url requested
     * @param bool $include_headers include HTTP response headers
     *      in the returned string
     * @param array $post_data POST variables for the simulated
     *      request, or null for GET
     * @return string the route's response, as if it had come
     *      back over the wire
     */
    public function processInternalRequest($url,
        $include_headers = false, $post_data = null)
    {
        static $request_context = [];
        if (count($request_context) > 5) {
            return "INTERNAL REQUEST FAILED DUE TO RECURSION";
        }
        $url_parts = parse_url($url ?? "");
        $uri = '';
        if (!empty($url_parts['path'])) {
            $uri .= $url_parts['path'];
        }
        $context = [];
        $context['QUERY_STRING'] = "";
        $context['REMOTE_ADDR'] = "0.0.0.0";
        if (!empty($url_parts['query'])) {
            $uri .= '?' . $url_parts['query'];
            $context['QUERY_STRING'] = $url_parts['query'];
        }
        if (!empty($url_parts['fragment'])) {
            $uri .= '#' . $url_parts['fragment'];
        }
        $context['REQUEST_METHOD'] = ($post_data) ? 'POST' : 'GET';
        $context['SERVER_PROTOCOL'] = 'HTTP/1.1';
        $context['REQUEST_URI'] = $uri;
        $context['PHP_SELF'] = $uri;
        if (!empty($_SERVER['HTTP_COOKIE'])) {
            $context['HTTP_COOKIE'] = $_SERVER['HTTP_COOKIE'];
        }
        /*
            Carry the scheme and authority of the in-flight request
            into the synthetic one. Without an HTTPS flag the secure
            server's http->https guard in configureRewrites treats an
            internal request as plain HTTP and answers it with a 301
            to https://<host>/ instead of running it, so the machine
            self-calls (statuses/update/log) never execute. Copying
            the host and port as well keeps any absolute URL the
            internal request builds pointed at the real authority
            rather than the 0.0.0.0 bind address.
         */
        foreach (['HTTPS', 'HTTP_HOST', 'SERVER_NAME', 'SERVER_PORT']
            as $inherited) {
            if (!empty($_SERVER[$inherited])) {
                $context[$inherited] = $_SERVER[$inherited];
            }
        }
        $context['SCRIPT_FILENAME'] =
            $this->default_server_globals['DOCUMENT_ROOT'] .
            $context['PHP_SELF'];
        $context['CONTENT'] = (empty($post_data)) ? "" : $post_data;
        $request_context[] = ["SERVER" => $_SERVER, "GET" => $_GET,
            "POST" => $_POST, "REQUEST" => $_REQUEST, "COOKIE" => $_COOKIE,
            "SESSION" => $_SESSION,
            "HEADER" => empty($this->header_data) ? "" : $this->header_data,
            "CONTENT_TYPE" => empty($this->content_type) ? false :
                $this->content_type,
            "CURRENT_SESSION" => empty($this->current_session) ? "" :
                $this->current_session];
        $this->setGlobals($context);
        $out_data = $this->getResponseData($include_headers);
        $saved = array_pop($request_context);
        $_SERVER = $saved["SERVER"];
        $_GET = $saved["GET"];
        $_POST = $saved["POST"];
        $_REQUEST = $saved["REQUEST"];
        $_COOKIE = $saved["COOKIE"];
        $_SESSION = $saved["SESSION"];
        $this->header_data = $saved["HEADER"];
        $this->content_type = $saved["CONTENT_TYPE"];
        $this->current_session = $saved["CURRENT_SESSION"];
        return $out_data;
    }
    /**
     * Says that a deferred reply's body is the given file rather than
     * whatever the handler prints. The file is drained to the client a
     * piece at a time, so a reply far larger than the server's memory can
     * be sent without being held. A handler that has built a file -- the
     * pack a git pull asks for, say -- names it here instead of printing
     * it, which would gather the whole reply in memory.
     *
     * A handler may also name a file it has only begun to write, with
     * $growing. The headers then go out at once, without a length, and the
     * file is sent as it grows: in chunks under HTTP/1.1 and in DATA
     * frames under HTTP/2 and HTTP/3. The reply ends when the handler
     * returns. A git
     * clone of a long history starts arriving this way while its pack is
     * still being made, rather than after the whole pack is built.
     *
     * @param string $path the file holding the body
     * @param bool $remove_after whether to delete the file once it has all
     *      gone out, for a file made only to be sent
     * @param bool $growing whether the handler is still writing the file
     *      and goes on writing it after this call
     * @return bool whether the file was taken; false when this request is
     *      not deferred, in which case the caller sends the file itself,
     *      and false for a growing file on HTTP/1.0, which has no way to
     *      send a body of unknown length and keep the connection
     */
    public function deferBodyFromFile($path, $remove_after = false,
        $growing = false)
    {
        $task = $this->running_task ?? $this->deferred_request;
        if ($growing && !in_array($_SERVER['SERVER_PROTOCOL'] ?? "",
            ["HTTP/1.1", "HTTP/2.0", "HTTP/3"])) {
            return false;
        }
        if ($growing && $task === null && $this->worker_link !== null) {
            /* The front starts sending the file as soon as it hears its
               name, while this worker goes on writing it; the request's
               last reply, sent when the route returns, says the file is
               finished. */
            $growing_reply = serialize(["GROWING" => $this->worker_running_id,
                "HEADER" => (string)$this->header_data,
                "CONTENT_TYPE" => $this->content_type,
                "CURRENT_SESSION" => (string)$this->current_session,
                "SESSION" => $_SESSION ?? [], "FILE" => $path,
                "REMOVE_FILE" => $remove_after]);
            fwrite($this->worker_link, pack("N", strlen($growing_reply)) .
                $growing_reply);
            $this->worker_grown_file = $path;
            $this->worker_remove_file = $remove_after;
            return true;
        }
        if ($growing && $task !== null) {
            $task->file = $path;
            $task->remove_file = $remove_after;
            $task->growing = true;
            $task->growing_done = false;
            $this->completeDeferredFile($task);
            return true;
        }
        if ($task === null && $this->worker_reply_file !== null) {
            /* A worker hands the file's name back to the front, which
               sends the file from disk. Sent as the reply's body it
               would be held whole by both processes, and a large git
               pack ran the front out of memory. */
            $this->worker_reply_file = $path;
            $this->worker_remove_file = $remove_after;
            return true;
        }
        if ($task === null) {
            /* This request is not being run as a deferred task -- under
               another web server, or where no send context was made -- so
               there is nothing to hand the file to and the caller has to
               send it itself. */
            return false;
        }
        $task->file = $path;
        $task->remove_file = $remove_after;
        return true;
    }
    /**
     * Lets a route finish later instead of right now, so a slow request
     * stops freezing every other connection.
     *
     * The route hands over a function that does its real work (the slow
     * part and the page it prints). Under the atto event loop that
     * function is run inside a fiber a little at a time: each time it
     * reaches a point where it would wait -- talking to a mail server,
     * say -- it can call Fiber::suspend() to give the loop back so other
     * connections are served, and is picked up again on a later pass. The
     * request's own superglobals and output are swapped in around each
     * resume so it always runs in its own context, and the finished page
     * is sent only once the function returns. If the function throws or
     * runs over its time budget, that one request gets a 500 and the rest
     * of the site is unaffected. Under another web server (Apache and the
     * like), or on a protocol whose deferred send is not wired yet, the
     * function is simply run straight through here instead.
     *
     * @param callable $handler does the request's real work and prints
     *      its response; may call Fiber::suspend() at its wait points
     * @param float|null $budget largest total running time this request may
     *      use, in seconds; the scheduler's own limit when not given
     * @return bool true, so a route may `return $site->deferResponse(...)`
     *      and count the request as handled
     */
    public function deferResponse(callable $handler, $budget = null)
    {
        $send = $this->deferredSendContext();
        if (!$this->isCli() || $send === null) {
            $handler();
            return true;
        }
        $task = new \stdClass();
        $task->body = "";
        $task->file = "";
        $task->remove_file = false;
        $task->environment = $this->captureRequestEnvironment();
        $task->send = $send;
        $task->saved = null;
        $task->outer_task = null;
        $task->producer = null;
        $task->outer_producer = null;
        $on_enter = function () use ($task) {
            $task->saved = $this->captureRequestEnvironment();
            $this->applyRequestEnvironment($task->environment);
            $task->outer_task = $this->running_task;
            $this->running_task = $task;
            $task->outer_producer = $this->streaming_producer;
            $this->streaming_producer = null;
            ob_start();
        };
        /* A body the handler gave to stream() belongs to this request, so
           it is kept with the task rather than left on the server, where
           the next ordinary HTTP/2 or HTTP/3 request would send it under
           its own headers. */
        $on_leave = function () use ($task) {
            $task->body .= ob_get_clean();
            if ($this->streaming_producer !== null) {
                $task->producer = $this->streaming_producer;
            }
            $this->streaming_producer = $task->outer_producer;
            $task->environment = $this->captureRequestEnvironment();
            $this->applyRequestEnvironment($task->saved);
            $this->running_task = $task->outer_task;
        };
        /* An HTTP/3 reply is sent over the QUIC listener rather than a
           connection of its own, so it has no connection key to keep. */
        $key = $send['key'] ?? null;
        if ($key !== null) {
            $this->deferred_running[$key] =
                ($this->deferred_running[$key] ?? 0) + 1;
        }
        $on_complete = function ($result, $error) use ($task, $key) {
            if ($key !== null && --$this->deferred_running[$key] <= 0) {
                unset($this->deferred_running[$key]);
            }
            $this->completeDeferredResponse($task, $error);
            if (isset($task->stop_after)) {
                /* A relayed request asked for a stop or restart, which
                   waits until its reply has been queued for sending. */
                $this->stop = true;
                $this->restart = $task->stop_after;
            }
        };
        $guarded = function () use ($handler) {
            try {
                $handler();
            } catch (WebException $web_exception) {
                /* A handler that calls webExit() -- a redirect, or any
                   normal early exit -- throws WebException under the atto
                   loop. The synchronous path treats that as a clean
                   finish: whatever was written before the exit is the
                   response. The deferred path must do the same rather
                   than let it surface as a 500, and give the restart and
                   stop control messages the same handling the
                   synchronous path gives them. */
                $message = $web_exception->getMessage();
                $command = substr($message, 0, strlen('restart'));
                if (in_array($command, ["restart", "stop"])) {
                    if ($command == 'restart') {
                        $session_path = substr($message,
                            strlen('restart') + 1);
                        $this->saveSessionsForRestart($session_path);
                        $this->restart = $message;
                    }
                    $this->stop = true;
                }
            }
        };
        if ($this->cooperative_scheduler === null) {
            $this->cooperative_scheduler = new CooperativeScheduler();
        }
        $this->cooperative_scheduler->add(new \Fiber($guarded),
            $on_complete, $on_enter, $on_leave, $budget);
        $this->deferred_request = $task;
        return true;
    }
    /**
     * Works out how a deferred response will eventually be sent, from the
     * connection details the protocol layer left in place for the current
     * request. Returns null when there is nothing to defer onto -- the
     * route was reached some other way, or over a protocol whose deferred
     * send is not wired yet (HTTP/3 today) -- in which case deferResponse
     * just runs the work straight through.
     *
     * @return array|null the bits needed later to send the response on
     *      this request's connection, or null if it cannot be deferred
     */
    protected function deferredSendContext()
    {
        $protocol = $this->streaming_context['protocol'] ?? '';
        if ($protocol === 'h1') {
            return ['protocol' => 'h1',
                'socket' => $this->streaming_socket,
                'key' => (int) $this->streaming_socket];
        }
        if ($protocol === 'h2') {
            return ['protocol' => 'h2',
                'connection' => $this->streaming_socket,
                'key' => $this->streaming_context['key'],
                'stream_id' => $this->streaming_context['stream_id'],
                'hpack_encode' =>
                    $this->streaming_context['hpack_encode']];
        }
        if ($this->deferrable_h3 !== null) {
            return ['protocol' => 'h3',
                'listener' => $this->deferrable_h3['listener'],
                'connection' => $this->deferrable_h3['connection'],
                'stream_id' => $this->deferrable_h3['stream_id']];
        }
        return null;
    }
    /**
     * The small HTML page sent with a 408 when a request ran past the time
     * a request is allowed. It is plain and self-contained, holding no
     * site content, since the timeout means the real page could not be
     * finished; a person seeing it is told the request took too long and
     * to try again.
     *
     * @return string a complete HTML document for the timeout response
     */
    protected function requestTimeoutPage()
    {
        return "<!DOCTYPE html>\n<html><head>" .
            "<meta charset=\"utf-8\">" .
            "<title>408 Request Timeout</title></head><body>" .
            "<h1>Request Timeout</h1>" .
            "<p>This request took too long to finish and was stopped. " .
            "Please try again.</p></body></html>\n";
    }
    /**
     * Sends a deferred reply whose body is a file. The headers go out
     * first, then the file is drained to the client a piece at a time by
     * the same loop that drains any other reply, so nothing larger than
     * one piece is ever held. HTTP/1.1 drains it through sendRestFromFile;
     * HTTP/2 and HTTP/3 draw on a generator that reads the file, through
     * emitDeferredH2 and the HTTP/3 transport's emitDeferredPieces.
     *
     * @param object $task the deferred request, carrying where to send and
     *      which file holds the body
     * @return void
     */
    protected function completeDeferredFile($task)
    {
        $key = $task->send['key'] ?? null;
        $growing = !empty($task->growing);
        $size = $growing ? null : filesize($task->file);
        /* The headers the handler set are left as they are: overwriting
           them threw away the kind of reply it said this was, which for a
           git service is what tells the client it is talking to git at
           all. */
        if ($task->send['protocol'] === 'h1') {
            $head = $this->finalizeDeferredResponse("", true, $size,
                $growing);
            $this->emitDeferredH1($task->send, $head);
            $this->sendRestFromFile($key, $task->file,
                !empty($task->remove_file), $growing ? $task : null);
            return;
        }
        $is_h3 = ($task->send['protocol'] === 'h3');
        if ($is_h3) {
            /* HTTP/3 reads the status line from the header buffer, which
               this adds where the handler set none. */
            $this->finalizeDeferredResponse("", false);
        }
        $reading = fopen($task->file, "rb");
        if ($reading === false) {
            if ($is_h3) {
                $task->send['listener']->emitDeferredResponse(
                    $task->send['connection'], $task->send['stream_id'], "");
            } else {
                $this->emitDeferredH2($task->send, "");
            }
            return;
        }
        $file = $task->file;
        $remove = !empty($task->remove_file);
        $pieces = (function () use ($reading, $file, $remove, $task,
            $growing) {
            try {
                while (true) {
                    $piece = fread($reading, self::OUT_FILE_STEP);
                    if ($piece !== false && $piece !== "") {
                        yield $piece;
                        continue;
                    }
                    /* A file still being written has no more bytes yet;
                       false tells the loop to come back on a later pass
                       rather than end the stream. */
                    if (!$growing || !empty($task->growing_done)) {
                        break;
                    }
                    yield false;
                }
            } finally {
                fclose($reading);
                $task->file_released = true;
                /* the file is let go once sent, as the HTTP/1.1 path does
                   in sendRestFromFile */
                if ($remove) {
                    @unlink($file);
                }
            }
        })();
        if ($is_h3) {
            $task->send['listener']->emitDeferredPieces(
                $task->send['connection'], $task->send['stream_id'],
                $pieces, $size);
            return;
        }
        $this->emitDeferredH2($task->send, "", $pieces, $size);
    }
    /**
     * finishGrowingFile marks a growing file's writer as finished, once
     * the deferred task that started sending the file has ended:
     * the route itself, or the fiber relaying it to a worker, which ends
     * on the worker's last reply. completeDeferredResponse calls it in
     * place of sending a reply, since the headers and most of the file
     * have gone already. The parked HTTP/1.1 connection or HTTP/2 stream
     * is then given its last bytes and its end on this pass, rather than
     * waiting for other traffic to wake the loop. A task that failed
     * after the headers went cannot be given an error page, so the
     * failure is logged and the reply ends where the file ends.
     *
     * @param object $task the deferred request that named the growing
     *      file
     * @param \Throwable|null $error why the task failed, or null if it
     *      finished cleanly
     * @return void
     */
    protected function finishGrowingFile($task, $error)
    {
        $task->growing_done = true;
        clearstatcache(true, $task->file);
        $size = is_file($task->file) ? filesize($task->file) : 0;
        /* A client that left before the file was sent had the file let
           go while it was still open for writing, which Windows does not
           allow to be deleted, so it is deleted now that it is closed. */
        $key = $task->send['key'] ?? null;
        $released = !empty($task->file_released) ||
            ($task->send['protocol'] === 'h1' &&
            ($this->out_streams[self::DATA_FILE][$key]["path"] ?? "") !==
            $task->file);
        if ($released && !empty($task->remove_file) &&
            is_file($task->file)) {
            @unlink($task->file);
        }
        if ($error !== null) {
            error_log("Deferred request failed after its reply began: " .
                ($_SERVER['REQUEST_METHOD'] ?? "") . " " .
                ($_SERVER['REQUEST_URI'] ?? "") . ": " .
                $error->getMessage());
        }
        foreach ($this->response_loggers as $response_logger) {
            $response_logger($this->responseStatusCode(), $size);
        }
        $this->refillStreamingGenerators();
        if ($task->send['protocol'] === 'h3') {
            $task->send['listener']->advanceH3StreamingGenerator(
                $task->send['connection'], $task->send['stream_id']);
        }
    }
    /**
     * Sends a deferred request's response once its fiber has finished,
     * over the same connection the request arrived on. On success the
     * accumulated page is finished off (status line, content type, length)
     * and handed to the right protocol's send path; on failure the one
     * request gets a plain 500 and nothing else is disturbed.
     *
     * @param object $task the finished deferred request, carrying its
     *      saved environment, accumulated body, and send details
     * @param \Throwable|null $error the reason it failed, or null if it
     *      finished cleanly
     * @return void
     */
    protected function completeDeferredResponse($task, $error)
    {
        $this->applyRequestEnvironment($task->environment);
        if (!empty($task->growing)) {
            $this->finishGrowingFile($task, $error);
            return;
        }
        if ($error !== null) {
            if ($error instanceof TaskBudgetExceededException) {
                /* The request ran longer than a request is allowed to,
                   rather than failing outright, so it is answered as a
                   request timeout with a short page a person can read,
                   not a bare server error. */
                error_log("Deferred request timed out: " .
                    ($_SERVER['REQUEST_METHOD'] ?? "") . " " .
                    ($_SERVER['REQUEST_URI'] ?? "") . ": " .
                    $error->getMessage());
                $body = $this->requestTimeoutPage();
                $this->header_data =
                    ($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1') .
                    " 408 Request Timeout\x0D\x0A";
                $this->content_type = "text/html";
            } else {
                /* Where the failure happened is what a person needs
                   to act on it; the message alone leaves them reading
                   the whole site for a call that takes a word and was
                   given a list. The first few steps of the way in are
                   logged with it, since the failing line is often
                   reached from somewhere unexpected. */
                $way_in = [];
                foreach (array_slice($error->getTrace(), 0, 4) as $step) {
                    $way_in[] = ($step['class'] ?? "") .
                        ($step['type'] ?? "") . ($step['function'] ?? "") .
                        " at " . basename($step['file'] ?? "?") . ":" .
                        ($step['line'] ?? "?");
                }
                error_log("Deferred request failed: " .
                    $error->getMessage() . " in " .
                    basename($error->getFile()) . ":" .
                    $error->getLine() . " via " . implode(" <- ", $way_in));
                $body = "Internal Server Error";
                $this->header_data =
                    ($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1') .
                    " 500 Internal Server Error\x0D\x0A";
                $this->content_type = "text/plain";
            }
        } else {
            $body = $task->body;
        }
        if ($error === null && $task->producer !== null &&
            $task->send['protocol'] !== 'h1') {
            $this->completeDeferredProducer($task);
            return;
        }
        $from_file = ($error === null && !empty($task->file) &&
            is_file($task->file));
        $status = $this->responseStatusCode();
        foreach ($this->response_loggers as $response_logger) {
            $response_logger($status, $from_file ? filesize($task->file) :
                strlen($body));
        }
        /* A reply whose body is a file is sent from the file rather than
           from a string, so its size costs a fixed amount of memory
           instead of its own length. */
        if ($from_file) {
            $this->completeDeferredFile($task);
            return;
        }
        if ($task->send['protocol'] === 'h1') {
            $out_data = $this->finalizeDeferredResponse($body, true);
            $this->emitDeferredH1($task->send, $out_data);
            return;
        }
        if ($task->send['protocol'] === 'h2') {
            $body = $this->finalizeDeferredResponse($body, false);
            $this->emitDeferredH2($task->send, $body);
            return;
        }
        if ($task->send['protocol'] === 'h3') {
            $body = $this->finalizeDeferredResponse($body, false);
            $task->send['listener']->emitDeferredResponse(
                $task->send['connection'], $task->send['stream_id'],
                $body);
        }
    }
    /**
     * completeDeferredProducer finishes a deferred request whose route
     * handed its body to stream() rather than printing it.
     * completeDeferredResponse calls this method once the route's fiber
     * has ended. The method first sends the headers the route set. It
     * then gives the route's generator to the HTTP/2 or HTTP/3 sender,
     * which draws each piece of the body when the client is ready for it,
     * on the request's own stream. stream() wrote the access log line
     * when the route called it.
     *
     * @param object $task the deferred request, carrying where to send and
     *      the generator that yields its body
     * @return void
     */
    protected function completeDeferredProducer($task)
    {
        $this->finalizeDeferredResponse("", false);
        if ($task->send['protocol'] === 'h3') {
            $task->send['listener']->emitDeferredPieces(
                $task->send['connection'], $task->send['stream_id'],
                $task->producer, null);
            return;
        }
        $this->emitDeferredH2($task->send, "", $task->producer);
    }
    /**
     * Marks the current request, which is being served over HTTP/3, as
     * one whose response may be deferred, recording what its task would
     * need to send the finished page later. Called by the HTTP/3 listener
     * just before it runs the route, and cleared again right after with
     * endDeferrableH3() whether or not the route deferred.
     *
     * @param object $listener the HTTP/3 listener that will do the send
     * @param object $connection the live QUIC connection
     * @param int $stream_id the request's QUIC stream id
     * @return void
     */
    public function beginDeferrableH3($listener, $connection, $stream_id)
    {
        $this->deferrable_h3 = ['listener' => $listener,
            'connection' => $connection, 'stream_id' => $stream_id];
    }
    /**
     * Clears the HTTP/3 deferred-response details set by
     * beginDeferrableH3(); a route that did defer has already had them
     * copied onto its task by then, so clearing here only stops them
     * leaking into the next request.
     * @return void
     */
    public function endDeferrableH3()
    {
        $this->deferrable_h3 = null;
    }
    /**
     * The status line for a response whose code set headers but never said
     * what the status was. Sending a Location says the thing asked for is
     * somewhere else, and sending a Refresh says the reader is to be sent
     * on shortly, so those are answered 301 and 302; anything else was a
     * reply to what was asked, and is answered 200.
     *
     * Only a line beginning a header of that name counts. Looking for the
     * word anywhere in the headers read whatever a header happened to be
     * carrying as though it were a header itself, so a file whose name
     * merely contained "location" was announced as having moved, and a
     * browser handed a redirect with a picture inside it showed nothing.
     *
     * @return string the status line, ready to stand in front of the
     *      headers already gathered
     */
    private function statusLineForHeaders()
    {
        $protocol = $_SERVER['SERVER_PROTOCOL'] ?? "HTTP/1.1";
        if (preg_match('/^Location:/mi', $this->header_data)) {
            /* Sent on after doing something, not moved for good. A
               permanent move is one a browser may remember and act on
               without asking again, which is right for an address that
               has changed for ever and wrong for a page that sends the
               reader on after handling what they asked. Signing out is
               the plain case: told the address had moved for good, a
               browser stopped asking for it and went straight to where
               it had been sent last time, so signing out never happened
               again. */
            return $protocol . " 302 Found\x0D\x0A";
        }
        if (preg_match('/^Refresh:/mi', $this->header_data)) {
            return $protocol . " 302 Found\x0D\x0A";
        }
        return $protocol . " 200 OK\x0D\x0A";
    }
    /**
     * Finishes off a deferred response the same way getResponseData()
     * finishes a normal one: saves the session, adds a status line and a
     * default content type if the route set none, advertises HTTP/3 when
     * configured, and (for HTTP/1.1) prepends the headers and a correct
     * Content-Length. Kept separate from getResponseData() on purpose so
     * the ordinary request path is left exactly as it was.
     *
     * @param string $body the page the deferred handler printed
     * @param int|null $body_length how long the body is, for a
     *      body that travels from a file rather than as the
     *      string given here; the string's own length when not
     *      given
     * @param bool $include_headers true to return headers plus body (the
     *      HTTP/1.1 wire form), false to return just the body with the
     *      header buffer filled in (what the HTTP/2 framer wants)
     * @param bool $chunked true for a body whose length is not known yet,
     *      which HTTP/1.1 then sends in chunks, each with its own length:
     *      the headers say Transfer-Encoding: chunked in place of a
     *      Content-Length
     * @return string the finished response, or just its body
     */
    protected function finalizeDeferredResponse($body, $include_headers,
        $body_length = null, $chunked = false)
    {
        if ($this->current_session != "" &&
            !empty($_COOKIE[$this->current_session])) {
            $session_id = $_COOKIE[$this->current_session];
            $this->writeSessionData($session_id, $_SESSION);
        }
        if (!str_starts_with($this->header_data, "HTTP/")) {
            $this->header_data = $this->statusLineForHeaders() .
                $this->header_data;
        }
        if (!$this->content_type) {
            $this->header_data .= "Content-Type: text/html\x0D\x0A";
        }
        if ($this->h3_advertise_port > 0
            && ($_SERVER['SERVER_PROTOCOL'] ?? '') !== 'HTTP/3'
            && stripos($this->header_data, "\nAlt-Svc:") === false
            && stripos($this->header_data, "\rAlt-Svc:") === false) {
            $this->header_data .= 'Alt-Svc: h3=":'
                . $this->h3_advertise_port . '"; ma=86400'
                . "\x0D\x0A";
        }
        if ($include_headers) {
            $this->header_data = preg_replace(
                '/^Content-Length:[^\r\n]*\r\n/im', '',
                $this->header_data);
            if ($chunked) {
                return $this->header_data .
                    "Transfer-Encoding: chunked\x0D\x0A\x0D\x0A" . $body;
            }
            return $this->header_data . "Content-Length: " .
                (($body_length === null) ? strlen($body) : $body_length) .
                "\x0D\x0A\x0D\x0A" . $body;
        }
        return $body;
    }
    /**
     * Queues a finished deferred response on an HTTP/1.1 connection, the
     * same way the normal H1 path does, so the event loop's writer drains
     * it to the client.
     *
     * @param array $send the request's send details (its stream key and
     *      socket)
     * @param string $out_data the finished response bytes
     * @return void
     */
    protected function emitDeferredH1($send, $out_data)
    {
        $key = $send['key'];
        if (!empty($this->out_streams[self::CONNECTION][$key])) {
            return;
        }
        $this->out_streams[self::CONNECTION][$key] = $send['socket'];
        $this->out_streams[self::DATA][$key] = $out_data;
        $this->out_streams[self::DATA_OFFSET][$key] = 0;
        $this->out_streams[self::CONTEXT][$key] = $_SERVER;
        $this->out_streams[self::MODIFIED_TIME][$key] = time();
    }
    /**
     * Sends a finished deferred response on an HTTP/2 stream, building the
     * HEADERS frame and the DATA frames the same way the normal H2 path
     * does (lowercased header names, a default content type and length if
     * the route set none, body split and flow-controlled by sendH2Body).
     *
     * @param array $send the request's send details (stream key,
     *      connection, stream id, and HPACK encoder)
     * @param string $body the response body
     * @param \Generator|null $pieces yields the body a piece at a
     *      time, for a body too large to hold as one string; the
     *      $body argument is ignored when this is given
     * @param int|null $size how long the body is, needed when it
     *      arrives in pieces rather than as one string; null with pieces
     *      for a body still being made, which is sent with no length
     * @return void
     */
    protected function emitDeferredH2($send, $body, $pieces = null,
        $size = null)
    {
        $key = $send['key'];
        $connection = $send['connection'];
        $stream_id = $send['stream_id'];
        $hpack_encode = $send['hpack_encode'];
        $conn = $this->connection($key);
        if ($conn === null) {
            /* The client disconnected while this deferred response was
               still pending, so its connection object is already gone.
               Returning here skips queuing headers and a body that
               could never be sent -- which also avoids leaving
               orphaned bytes in the out-stream buffer that would never
               drain -- and avoids faulting on the missing protocol
               state when the body send tries to use it. */
            return;
        }
        $status = "200";
        if (preg_match("/HTTP\/[\d.]+ (\d+)/",
                $this->header_data, $matches)) {
            $status = $matches[1];
        }
        $resp_headers_data = [[":status", $status]];
        $forbidden = ["connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade"];
        $has_content_type = false;
        $has_content_length = false;
        $header_lines = explode("\r\n", $this->header_data);
        array_shift($header_lines);
        foreach ($header_lines as $line) {
            $colon = strpos($line, ":");
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = trim(substr($line, $colon + 1));
            if ($name === "" || $name[0] === ":"
                || in_array($name, $forbidden)) {
                continue;
            }
            if ($name === "content-type") {
                $has_content_type = true;
            }
            if ($name === "content-length") {
                $has_content_length = true;
            }
            $resp_headers_data[] = [$name, $value];
        }
        if (!$has_content_type) {
            $resp_headers_data[] =
                ["content-type", "text/html; charset=utf-8"];
        }
        /* A body given in pieces with no size is still being made, so
           its length is not known and the stream's end marks where it
           stops. */
        if (!$has_content_length && ($pieces === null || $size !== null)) {
            $resp_headers_data[] = ["content-length",
                (string)(($size === null) ? strlen($body) : $size)];
        }
        $resp_headers = new HeaderFrame($stream_id, $resp_headers_data);
        $resp_headers->flags->add("END_HEADERS");
        $out = $resp_headers->serialize($hpack_encode);
        $this->queueResponseData($key, $connection, $out);
        $this->sendH2BodyPaced($key, $connection, $conn, $stream_id,
            $body, $pieces);
    }
    /**
     * Used to export info (but not change) about running sessions
     *
     * @return array map session id => session record (with TIME and
     *      DATA fields); the live internal storage, callers must
     *      not mutate it
     */
    public function getSessions()
    {
        return $this->sessions;
    }
    /**
     * Used  by usual and internal requests to compute response  string of the
     * web server to the web client's request. In the case of internal requests,
     * it is sometimes usesful to return just the body of the response without
     * HTTP headers
     *
     * @param bool $include_headers whether to include HTTP headers at beginning
     *      of response
     * @return string HTTP response to web client request
     */
    public function getResponseData($include_headers = true)
    {
        $this->header_data = "";
        $this->current_session = "";
        $_SESSION = [];
        $this->content_type = false;
        $this->streaming_response_logged = false;
        ob_start();
        try {
            /* A WebSocket upgrade stays in this process, since its frames
               arrive here for as long as the connection lasts, and so do a
               request with nowhere to send a deferred reply, such as an
               internal request, and one the site's FRONT_ONLY check says
               streams its reply. */
            if ($this->worker_count > 0 && $this->worker_listener !== null &&
                strtolower($_SERVER['HTTP_UPGRADE'] ?? '') !== 'websocket' &&
                $this->deferredSendContext() !== null &&
                ($this->front_only === null || !($this->front_only)())) {
                $usage = getrusage();
                $this->relayToWorker();
                $this->noteFrontWork("relayed", $usage);
            } else {
                $usage = getrusage();
                try {
                    $this->process();
                } finally {
                    $this->noteFrontWork($this->worker_count > 0 ? "kept" :
                        "served", $usage);
                }
            }
        } catch (WebException $we) {
            $msg = $we->getMessage();
            $cmd = substr($msg, 0, strlen('restart'));
            if (in_array($cmd, ["restart", "stop"])) {
                if ($cmd == 'restart') {
                    $session_path = substr($msg, strlen('restart') + 1);
                    $this->saveSessionsForRestart($session_path);
                    $this->restart = $msg;
                }
                $this->stop = true;
            }
        }
        $out_data = ob_get_contents();
        ob_end_clean();
        if ($this->deferred_request !== null) {
            /* The route called deferResponse(): its real output is
               produced across later loop passes and sent when its task
               finishes, so tell the caller to send nothing now. */
            $this->deferred_request = null;
            return self::RESPONSE_DEFERRED;
        }
        if ($this->is_streaming) {
            /*
                Route used $site->flush(). Headers and body
                already went out the socket. Drain any final
                bytes the route emitted after its last flush,
                then send the terminating chunk / END_STREAM.
                Return empty so the caller's normal write path
                doesn't try to send the same response again.
             */
            if ($out_data !== '' && $out_data !== false) {
                /* streaming is h1-only (see flush()); is_streaming
                   can only be set on an h1 request */
                $this->writeStreamingChunk_H1($out_data);
            }
            $this->endStreaming();
            return "";
        }
        if ($this->header_data == "UPGRADE") {
            $out_data = "";
            $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                " 101 Switching Protocols\x0D\x0A" .
                "Upgrade: HTTP/2\x0D\x0A" .
                "Connection: Upgrade\x0D\x0A";
            $out_data = $this->header_data;
            return $out_data;
        }
        if ($this->current_session != "" &&
            !empty($_COOKIE[$this->current_session])) {
            $session_id = $_COOKIE[$this->current_session];
            $this->writeSessionData($session_id, $_SESSION);
        }
        $redirect = false;
        if (!str_starts_with($this->header_data, "HTTP/")) {
            $this->header_data = $this->statusLineForHeaders() .
                $this->header_data;
        }
        if (!$this->content_type && !$redirect) {
            $this->header_data .= "Content-Type: text/html\x0D\x0A";
        }
        if ($this->h3_advertise_port > 0
            && ($_SERVER['SERVER_PROTOCOL'] ?? '') !== 'HTTP/3'
            && stripos($this->header_data, "\nAlt-Svc:") === false
            && stripos($this->header_data, "\rAlt-Svc:") === false) {
            /*
                Tell the client that this origin also speaks H3
                on the listener's UDP port. The client races H3
                against the current TCP connection on the next
                request and remembers the result for ma seconds.
                Skip if the route already set its own Alt-Svc
                or if this response is itself going out over H3.
             */
            $this->header_data .= 'Alt-Svc: h3=":'
                . $this->h3_advertise_port . '"; ma=86400'
                . "\x0D\x0A";
        }
        $body_size = strlen($out_data);
        $this->logLargeResponse($body_size);
        /* every reply passes here once, whichever protocol sends it, so
           this is where the response loggers are told how it turned out,
           unless a streamed body already logged its own access line
           (getResponseData sees an empty body for a streamed reply, so
           its length here would be zero) */
        if (!$this->streaming_response_logged) {
            $status = $this->responseStatusCode();
            foreach ($this->response_loggers as $response_logger) {
                $response_logger($status, $body_size);
            }
        }
        if ($include_headers) {
            /* the computed length is authoritative; drop any
               Content-Length the route set itself (resource range
               replies do) so the response carries exactly one */
            $this->header_data = preg_replace(
                '/^Content-Length:[^\r\n]*\r\n/im', '',
                $this->header_data);
            $out_data = $this->header_data .
                    "Content-Length: ". $body_size .
                    "\x0D\x0A\x0D\x0A" .  $out_data;
        }
        return $out_data;
    }
    /**
     * Checks whether a request URI path portion matches an Atto
     * route. A route may contain {variable} placeholders (each
     * capturing a single path segment, no slashes) and * wildcards
     * (matching any text including slashes). Match is anchored:
     * the path must equal the route shape end-to-end.
     *
     * Anchored: route '/foo/{bar}' matches '/foo/x' but not
     * '/wrap/foo/x' or '/foo/x/extra'. Segment-bounded:
     * '/files/{name}' matches '/files/note' but not
     * '/files/sub/note'; use '/files/*' for multi-segment capture.
     *
     * @param string $request_path part of the request URI path
     * @param string $route route pattern to test
     * @return array|bool captured variables on match (empty array
     *      if no captures), or false if no match
     */
    protected function checkMatch($request_path, $route)
    {
        $add_vars = [];
        $matches = false;
        /*
            Two distinct magic strings so * and {var} can be
            substituted with different regex fragments after
            preg_quote escapes the literal portions of the route.
            VAR_MAGIC becomes ([^/]+) (single-segment capture);
            STAR_MAGIC becomes (.*) (multi-segment wildcard).
         */
        $var_magic = "PDTVARTP";
        $star_magic = "PDTSTARTP";
        if (preg_match_all('/\*|\{[a-zA-Z][a-zA-Z0-9_]*\}/', $route,
            $matches) > 0) {
            $route_regex = preg_replace_callback(
                '/\*|\{[a-zA-Z][a-zA-Z0-9_]*\}/',
                function ($match) use ($var_magic, $star_magic) {
                    return ($match[0] === '*') ? $star_magic : $var_magic;
                },
                $route);
            $route_regex = preg_quote($route_regex, "#");
            $route_regex = str_replace($var_magic, "([^/]+)",
                $route_regex);
            $route_regex = str_replace($star_magic, "(.*)",
                $route_regex);
            if (preg_match("#^{$route_regex}$#", $request_path,
                $request_matches) > 0) {
                $num_matches = count($matches[0]);
                array_shift($request_matches);
                for ($i = 0; $i < $num_matches; $i++) {
                    $match_var = trim($matches[0][$i], "{}");
                    if ($match_var != "*") {
                        $add_vars[$match_var] = $request_matches[$i];
                    }
                }
                return $add_vars;
            }
        } else if ($request_path == $route) {
            return $add_vars;
        }
        return false;
    }
    /**
     * Handles processing timers on this Atto Web Site. This method is called
     * from the event loop in see listen and checks to see if any callbacks
     * associated with timers need to be called.
     */
    protected function processTimers()
    {
        if ($this->timer_alarms->isEmpty()) {
            return;
        }
        $now = microtime(true);
        $top = $this->timer_alarms->top();
        while ($now > $top[0]) {
            $this->timer_alarms->extract();
            $key = (string) $top[1];
            if (!empty($this->timers[$key])) {
                list($repeating, $time, $callback) =
                    $this->timers[$key];
                $started = microtime(true);
                $callback();
                $ran = microtime(true) - $started;
                if ($ran > self::SLOW_TIMER) {
                    $where = new \ReflectionFunction($callback);
                    error_log("[website-slow-timer] " .
                        round($ran * self::MILLISECONDS_PER_SECOND) .
                        "ms in the timer set at " . $where->getFileName() .
                        ":" . $where->getStartLine());
                }
                if ($repeating) {
                    /* the callback may have cleared its own timer */
                    if (isset($this->timers[$key])) {
                        $this->timer_alarms->insert([$now + $time, $key]);
                    }
                } else {
                    unset($this->timers[$key]);
                }
            }
            if ($this->timer_alarms->isEmpty()) {
                return;
            }
            $top = $this->timer_alarms->top();
        }
    }
    /**
     * Processes incoming streams with data. If the server has detected a
     * new connection, then a stream is set-up. For other streams,
     * request data is processed as it comes in. Once the request is
     * complete, superglobals are set up and process() is used to route
     * the request which is output buffered. When this is complete, an
     * output stream is instantiated to send this data asynchronously
     * back to the browser. HTTP/2 connections are handled differently:
     * parseH2Request reads and writes directly on the connection rather
     * than going through the out_streams async write path, since H2
     * framing handles its own flow control.
     *
     * @param resource $server socket server used to listen for incoming
     *      connections
     * @param array $in_streams_with_data streams with request data to be
     *      processed
     */
    protected function processRequestStreams($server, $in_streams_with_data)
    {
        foreach ($in_streams_with_data as $in_stream) {
            $stream_key = (int) $in_stream;
            if (isset($this->listeners[$stream_key])) {
                $this->processServerRequest(
                    $this->listeners[$stream_key]);
                continue;
            }
            $meta = stream_get_meta_data($in_stream);
            $key = $stream_key;
            if ($meta['eof']) {
                $this->shutdownHttpStream($key);
                continue;
            }
            $len = strlen($this->in_streams[self::DATA][$key] ?? '');
            $max_len = $this->default_server_globals['MAX_REQUEST_LEN'];
            $too_long = $len >= $max_len;
            if (!empty(
                $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'])) {
                /* The connection was answered with an error such as 413,
                   so what comes now is the rest of the refused request.
                   It is read and thrown away, which also keeps select
                   from finding the socket readable on every pass, and
                   the connection is closed once the client closes its
                   side. */
                stream_set_blocking($in_stream, false);
                $discarded = @fread($in_stream,
                    $this->default_server_globals['MAX_IO_LEN']);
                if ($discarded === false || feof($in_stream)) {
                    $this->shutdownHttpStream($key);
                } else if ($discarded !== "") {
                    $this->in_streams[self::MODIFIED_TIME][$key] = time();
                }
                continue;
            }
            /*
                Per-iteration protocol routing. Look up the
                Transport for this Connection's negotiated
                protocol and let it handle the readable event.
                A missing Connection here means the stream was
                torn down between select() and now; fall through
                to H1Transport, whose parseH1Request detects the
                missing state and cleans up.
             */
            $conn = $this->connection($key);
            $proto = $conn?->protocol ?? 'h1';
            if (!isset($this->transports[$proto])) {
                $proto = 'h1';
            }
            if ($this->no_wrap_requests) {
                /* Asked to let a failure out. What goes wrong while a
                   request is handled then ends the server, which is
                   what someone tracking such a failure down wants to
                   see. */
                $this->read_made_progress = true;
                $this->transports[$proto]->onReadable($key, $conn,
                    $in_stream, $too_long);
                continue;
            }
            try {
                $this->read_made_progress = true;
                $this->transports[$proto]->onReadable($key, $conn,
                    $in_stream, $too_long);
            } catch (\Throwable $throwable) {
                /* one request must never take the whole
                   single-process server down with it (for years a
                   header value a frame encoder could not handle
                   was fatal to the site); log the failure and
                   tear down only the offending connection */
                error_log("Uncaught " . get_class($throwable) .
                    " processing connection $key: " .
                    $throwable->getMessage() . " at " .
                    $throwable->getFile() . ":" .
                    $throwable->getLine());
                $this->shutdownHttpStream($key);
                continue;
            }
            if ($this->read_made_progress &&
                isset($this->in_streams[self::CONNECTION][$key])) {
                $this->in_streams[self::MODIFIED_TIME][$key] = time();
            }
        }
    }
    /**
     * Reads, parses, and dispatches one H1 request iteration on
     * the connection identified by $key. Pulls up to MAX_IO_LEN
     * bytes off the socket, hands them to parseRequest to assemble
     * the full request head and body, and on a complete request
     * either upgrades the connection to WebSocket (if the route
     * matches and the headers ask for it) or generates the HTTP
     * response, queueing it on out_streams for async drain.
     *
     * Public entry point because H1Transport calls it from outside
     * the class.
     *
     * @param int $key stream key for the connection
     * @param resource $in_stream readable socket resource
     * @param bool $too_long true if buffered data already exceeds
     *      MAX_REQUEST_LEN; in that case skip the read and force a
     *      413 response
     */
    public function parseH1Request($key, $in_stream, $too_long)
    {
        $max_len = $this->default_server_globals['MAX_REQUEST_LEN'];
        $len = strlen($this->in_streams[self::DATA][$key]);
        if (!$too_long) {
            stream_set_blocking($in_stream, false);
            /* A peer can reset the TLS connection while we are still
               reading its request, which surfaces as a "Connection
               reset by peer" warning from stream_get_contents. That
               is a normal client disconnect, not a server fault, so
               swallow just that notice for the read and let any other
               warning through. The write side suppresses the same
               notice when draining a response. */
            set_error_handler(function ($error_number, $error_text) {
                return stripos($error_text, "reset by peer") !== false
                    || stripos($error_text, "SSL operation failed")
                    !== false
                    || stripos($error_text, "SSL: Success") !== false;
            });
            /* Over an encrypted stream a read hands back at most one
               decrypted record, and bytes already decrypted past it sit
               in the crypto layer's own buffer where select cannot see
               them. So the read loops until a pass comes back empty or
               the bound is met, the same way the frame path below does;
               a single read left the tail of a larger body stranded and
               the request never finished. */
            $data = "";
            $sought = min(
                $this->default_server_globals['MAX_IO_LEN'],
                $max_len - $len);
            while ($sought > 0) {
                $piece = stream_get_contents($in_stream, $sought);
                if ($piece === false) {
                    if ($data === "") {
                        $data = false;
                    }
                    break;
                }
                if ($piece === "") {
                    break;
                }
                $data .= $piece;
                $sought = min(
                    $this->default_server_globals['MAX_IO_LEN'],
                    $max_len - $len - strlen($data));
            }
            restore_error_handler();
            /* select reported this socket readable, so a read that
               comes back with no bytes means the peer has closed
               (end of file) or the TLS layer faulted mid-stream (for
               example a "bad record mac" alert, which surfaces as a
               false return). Either way the connection is finished;
               tear it down now. Leaving it in place would keep it
               perpetually readable, spinning the event loop at full
               CPU, and because the read path refreshes the
               connection's activity time every pass it would never
               age out of cullDeadStreams. */
            if ($data === false ||
                ($data === "" && feof($in_stream))) {
                $this->shutdownHttpStream($key);
                return;
            }
            /* A readable socket that hands back no bytes yet is not at
               end of file and did not error (for instance a peer that
               sent only a partial TLS record) made no progress this
               pass. Leave its activity time untouched so it ages out on
               the idle timeout rather than holding the connection open
               indefinitely. */
            if ($data === "") {
                $this->read_made_progress = false;
            }
        } else {
            $data = "";
            $this->initializeBadRequestResponse($key,
                self::PAYLOAD_TOO_LARGE);
        }
        if (!$too_long && !$this->parseRequest($key, $data)) {
            return;
        }
        /*
            Detect WebSocket upgrade requests after parseRequest
            has populated the HTTP_* headers. If the client
            requested an upgrade and we have a matching ws()
            route, complete the handshake and switch the
            connection to WebSocket mode instead of producing a
            normal HTTP response.
         */
        if (empty($this->in_streams[self::CONTEXT][$key][
                'BAD_RESPONSE'])
            && $this->isWebSocketUpgrade($key)
            && $this->handleWebSocketUpgrade($key, $in_stream)) {
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
            return;
        }
        if (!empty($this->in_streams[self::CONTEXT][$key][
                'PRE_BAD_RESPONSE'])) {
            $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE']
                = true;
        }
        /*
            Make the H1 connection available to $site->flush() so
            a route that opts into streaming can write to the
            socket directly. Cleared after dispatch regardless of
            whether the route streamed.
         */
        $this->streaming_socket = $in_stream;
        $this->streaming_context = ['protocol' => 'h1'];
        $out_data = $this->getResponseData();
        $this->streaming_socket = null;
        $this->streaming_context = [];
        if ($out_data === self::RESPONSE_DEFERRED) {
            /* The route deferred itself; its response is queued by the
               cooperative task when it finishes. Still reset for the
               next keep-alive request, but send nothing here. (A client
               that pipelines a second request before the deferred one is
               sent is not yet handled; browsers wait for the response.) */
            if (empty($this->in_streams[self::CONTEXT][$key][
                    'BAD_RESPONSE'])) {
                $this->initRequestStream($key);
            }
            return;
        }
        if (empty($this->in_streams[self::CONTEXT][$key][
                'BAD_RESPONSE'])) {
            /*
                Reset per-request context for the next keep-alive
                request. Listener-attached state and H2 protocol
                state live on the persistent Connection object
                and survive this reset automatically; setGlobals
                re-overlays them onto $_SERVER for the next
                request.
             */
            $this->initRequestStream($key);
        }
        if (empty($this->out_streams[self::CONNECTION][$key])) {
            $this->out_streams[self::CONNECTION][$key] = $in_stream;
            $this->out_streams[self::DATA][$key] = $out_data;
            $this->out_streams[self::DATA_OFFSET][$key] = 0;
            $this->out_streams[self::CONTEXT][$key] = $_SERVER;
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        }
    }
    /**
     * Accepts a new incoming connection from a server socket and
     * determines the HTTP protocol version, then dispatches to the
     * appropriate per-protocol initialization. The
     * connection-and-detection details are handled by
     * ConnectionAcceptor; this method is responsible for the
     * post-detection wiring into the WebSite event loop and for
     * dispatching to initH2Request or initRequestStream based on
     * the detected client protocol.
     *
     * @param Listener $listener Listener instance whose server
     *      socket reported readable
     */
    protected function processServerRequest($listener)
    {
        if ($this->timer_alarms->isEmpty()) {
            $timeout = ini_get("default_socket_timeout");
        } else {
            $next_alarm = $this->timer_alarms->top();
            $timeout = max(min($next_alarm[0] - microtime(true),
                        ini_get("default_socket_timeout")), 0);
        }
        $acceptor = $this->getConnectionAcceptor();
        list($connection, $additional_context) =
            $listener->accept($acceptor, $timeout);
        if ($connection === null) {
            return;
        }
        if ($connection->protocol === 'h3' ||
            $connection->protocol === 'h3-quiche') {
            /*
                H3 connections have no PHP stream resource; the
                listener's UDP socket carries traffic for all of
                them. The H3 listener (FFI or pure-PHP) already
                registered this connection in its own CID-keyed
                map and drove the first packet through the
                receive path. Nothing more to do at the WebSite
                event-loop level.
             */
            return;
        }
        $resource = $connection->resource();
        $is_secure = $connection->is_secure;
        $key = (int) $resource;
        $this->in_streams[self::CONNECTION][$key] = $resource;
        $client_http = $additional_context["CLIENT_HTTP"];
        if ($client_http === 'handshake') {
            /*
                TLS handshake not yet done. Persist the connection
                with its listener attributes and peer addresses so
                the handshake transport can finish protocol setup
                once stepCrypto completes, and return to the event
                loop, which will wake on this socket's I/O and step
                the handshake. Nothing protocol-specific is set up
                yet because the protocol is unknown until the
                decrypted first bytes are read after the handshake.
             */
            $connection->listener_port =
                $listener->globals['SERVER_PORT'] ?? '';
            $connection->listener_name =
                $listener->globals['SERVER_NAME'] ?? '';
            $connection->https = 'on';
            $remote_name = stream_socket_get_name($resource, true);
            $server_name = stream_socket_get_name($resource, false);
            list($connection->remote_addr,
                $connection->remote_port) =
                $this->splitAddressPort($remote_name);
            list($connection->server_addr,
                $connection->server_port) =
                $this->splitAddressPort($server_name);
            $this->connections[$key] = $connection;
            return;
        }
        /*
            Persist the Connection object for this stream key.
            The Connection holds the I/O resource handle, the
            negotiated protocol, the listener attributes
            (listener_port, listener_name, https), the detailed
            client-protocol string (client_http), and (for H2)
            per-connection HPACK encoder/decoder and stream
            registry. Subsequent code fetches the Connection via
            $this->connection($key) and reads these fields
            without indexing the untyped in_streams[CONTEXT].
         */
        $connection->client_http = $client_http;
        $connection->listener_port =
            $listener->globals['SERVER_PORT'] ?? '';
        $connection->listener_name =
            $listener->globals['SERVER_NAME'] ?? '';
        if ($is_secure) {
            /*
                Standard CGI HTTPS=on convention so generic PHP
                code that checks $_SERVER['HTTPS'] sees the
                expected value on TLS connections. setGlobals
                overlays this onto $_SERVER right before request
                dispatch.
             */
            $connection->https = 'on';
        }
        /*
            Resolve peer and local socket addresses once at accept
            time and stash them on the Connection. initRequestStream
            previously called stream_socket_get_name on every
            keep-alive reset; pulling that out and reading from
            the Connection saves the syscall and gives the values
            a stable home.
         */
        $remote_name = stream_socket_get_name($resource, true);
        $server_name = stream_socket_get_name($resource, false);
        list($connection->remote_addr, $connection->remote_port) =
            $this->splitAddressPort($remote_name);
        list($connection->server_addr, $connection->server_port) =
            $this->splitAddressPort($server_name);
        $this->connections[$key] = $connection;
        $this->promoteConnection($key, $connection, $client_http,
            $additional_context);
    }
    /**
     * Finishes setting up an accepted connection once its protocol
     * is known: records the protocol, runs the per-protocol init
     * (HTTP/2 SETTINGS and HPACK state, or the HTTP/1 request
     * stream) and seeds any leftover bytes from protocol detection.
     * Called for a plaintext connection straight from accept, and
     * for a TLS connection by the handshake transport once the
     * handshake has completed and the decrypted first bytes have
     * been read. Reads listener attributes from the Connection,
     * which both callers have already populated.
     *
     * @param int $key stream key of the connection
     * @param Connection $connection the connection being promoted
     * @param string $client_http detected client protocol string
     * @param array $additional_context detection context, may carry
     *      a LEFTOVER of already-read bytes
     * @return void
     */
    protected function promoteConnection($key, $connection,
        $client_http, $additional_context)
    {
        $resource = $connection->resource();
        if ($client_http == "HTTP/2.0" || $client_http == "h2c") {
            $connection->protocol = 'h2';
        } else {
            $connection->protocol = 'h1';
        }
        $connection->client_http = $client_http;
        if ($client_http == "HTTP/2.0") {
            try {
                /*
                    TLS: magic was already consumed by the
                    detection read in ConnectionAcceptor
                 */
                $client_settings = $this->initH2Request(
                    $resource, false);
                $connection->protocol_state['hpack_decode']
                    = new HPack();
                $connection->protocol_state['hpack_encode']
                    = new HPack();
                $this->initH2SendWindows($connection,
                    $client_settings);
                /*
                    Server push state. enable_push starts true
                    (RFC 7540 sec 6.5.2 default for SETTINGS_
                    ENABLE_PUSH is 1) and is flipped to false if
                    the client sends ENABLE_PUSH=0 in its
                    SETTINGS frame. next_push_stream_id is the
                    next even server-initiated stream id to
                    allocate when WebSite::push is called.
                    Server-initiated streams are even (sec
                    5.1.1); start at 2.

                    The initial SETTINGS may already disable
                    push: nghttp2 clients run with --no-push
                    advertise ENABLE_PUSH=0 in the very first
                    frame, before any application code calls
                    push(). Apply that now so push() returns
                    false from the start of the connection.
                 */
                $enable_push = true;
                if (isset($client_settings[0x02])) {
                    $enable_push = ($client_settings[0x02] === 1);
                }
                $connection->protocol_state['enable_push']
                    = $enable_push;
                $connection->protocol_state['next_push_stream_id']
                    = 2;
                $this->initRequestStream($key,
                    $additional_context);
            } catch (\Exception $e) {
                $this->shutdownHttpStream($key);
            }
        } else if ($client_http == "h2c") {
            try {
                /*
                    Cleartext: STREAM_PEEK was used so the magic
                    is still in the buffer
                 */
                $client_settings = $this->initH2Request(
                    $resource, true);
                $connection->protocol_state['hpack_decode']
                    = new HPack();
                $connection->protocol_state['hpack_encode']
                    = new HPack();
                $this->initH2SendWindows($connection,
                    $client_settings);
                $enable_push = true;
                if (isset($client_settings[0x02])) {
                    $enable_push = ($client_settings[0x02] === 1);
                }
                $connection->protocol_state['enable_push']
                    = $enable_push;
                $connection->protocol_state['next_push_stream_id']
                    = 2;
                $this->initRequestStream($key,
                    $additional_context);
            } catch (\Exception $e) {
                $this->shutdownHttpStream($key);
            }
        } else {
            $this->initRequestStream($key, $additional_context);
            /*
                For TLS connections where the detection read
                consumed bytes that turned out to be HTTP/1.1,
                prepopulate the stream data so parseRequest sees
                them.
             */
            if (!empty($additional_context["LEFTOVER"])) {
                $this->in_streams[self::DATA][$key] =
                    $additional_context["LEFTOVER"];
            }
        }
    }
    /**
     * Advances a connection still in the TLS-handshake-pending
     * state by one non-blocking step, called from the event loop
     * when the socket is readable. On the first contact it peeks
     * the first byte to auto-detect plaintext on a TLS port (a TLS
     * ClientHello starts with 0x16 per RFC 8446 sec 5.1; anything
     * else is treated as cleartext and bypasses TLS, the same
     * behavior the old inline accept had, so local utilities can
     * still speak HTTP to a TLS port). It then steps the handshake:
     * on completion the protocol is detected and the connection
     * promoted; while more I/O is needed it is left pending; on
     * failure or once the handshake deadline passes it is closed.
     *
     * @param int $key stream key of the pending connection
     * @param Connection|null $conn the pending connection
     * @return void
     */
    public function stepHandshake($key, $conn)
    {
        if ($conn === null) {
            $this->shutdownHttpStream($key);
            return;
        }
        $deadline =
            $conn->protocol_state['handshake_deadline'] ?? 0;
        if ($deadline > 0 && microtime(true) > $deadline) {
            $this->shutdownHttpStream($key);
            return;
        }
        $acceptor = $this->getConnectionAcceptor();
        if (empty($conn->protocol_state['handshake_peeked'])) {
            $peek = @stream_socket_recvfrom($conn->resource(), 1,
                STREAM_PEEK);
            if ($peek === false || $peek === '') {
                /*
                    A peer that closed before sending a byte leaves the
                    socket readable at every select, and peeking does
                    not mark the stream at its end, so it is closed
                    here rather than stepped again until the handshake
                    deadline with the loop never sleeping.
                 */
                if (feof($conn->resource())) {
                    $this->front_work["closed_before_first_byte"] =
                        ($this->front_work["closed_before_first_byte"] ??
                        0) + 1;
                    $this->shutdownHttpStream($key);
                }
                return;
            }
            $conn->protocol_state['handshake_peeked'] = true;
            if ($peek[0] !== "\x16") {
                /*
                    Cleartext on the TLS port: skip the handshake,
                    detect the plaintext protocol, and promote.
                 */
                $conn->is_secure = false;
                $conn->https = '';
                $additional_context =
                    $acceptor->detectProtocol($conn);
                $conn->protocol_state = [];
                $this->promoteConnection($key, $conn,
                    $additional_context['CLIENT_HTTP'],
                    $additional_context);
                return;
            }
        }
        if (empty($conn->protocol_state['handshake_done'])) {
            $handshake_error = '';
            $result = $acceptor->stepCrypto($conn, $handshake_error);
            if ($result === 0) {
                return;
            }
            if ($result === false) {
                /*
                    Close silently on a failed handshake. A peer
                    that aborts mid-handshake is common and routine
                    under load; logging each one floods the log
                    (the SSL error storm the blocking handshake
                    produced) with no useful diagnostic.
                 */
                $this->shutdownHttpStream($key);
                return;
            }
            $conn->protocol_state['handshake_done'] = true;
            $conn->protocol_state['detect_buffer'] = '';
        }
        /*
            Handshake done: read the first decrypted bytes
            non-blocking and decide HTTP/2 versus HTTP/1.1 from
            them. PHP does not expose the ALPN result, and TLS
            bytes cannot be peeked (STREAM_PEEK works on the raw
            socket, not the decrypted stream), so the bytes are
            consumed into a buffer and handed back to the parser:
            an H2 client sends the 24-byte preface, an H1 client a
            request line. The protocol is decided as soon as the
            buffer is unambiguous; until then more reads are
            awaited, bounded by the same handshake deadline so a
            client that completes TLS but sends nothing is reaped
            rather than blocking.
         */
        $magic_len = strlen(self::H2_CLIENT_MAGIC);
        $remaining = $magic_len -
            strlen($conn->protocol_state['detect_buffer']);
        if ($remaining > 0) {
            $chunk = $conn->read($remaining);
            if ($chunk !== false && $chunk !== '') {
                $conn->protocol_state['detect_buffer'] .= $chunk;
            }
        }
        $buffer = $conn->protocol_state['detect_buffer'];
        $classification = $acceptor->classifySecureFirstBytes(
            $buffer);
        if ($classification === null) {
            return;
        }
        if ($classification === 'h2') {
            $additional_context = ["CLIENT_HTTP" => "HTTP/2.0"];
        } else {
            $additional_context = ["CLIENT_HTTP" => "HTTP/1.1",
                "LEFTOVER" => $buffer];
        }
        $conn->protocol_state = [];
        $this->promoteConnection($key, $conn,
            $additional_context['CLIENT_HTTP'], $additional_context);
    }
    /**
     * Lazily constructs the ConnectionAcceptor used by
     * processServerRequest. The acceptor is wired with the H2
     * client magic and with a callback that reinstalls our
     * CUSTOM_ERROR_HANDLER after stream_socket_enable_crypto
     * clears it.
     *
     * @return ConnectionAcceptor cached single instance
     */
    protected function getConnectionAcceptor()
    {
        if ($this->connection_acceptor === null) {
            $site = $this;
            $post_tls = function () use ($site) {
                set_error_handler($site->default_server_globals[
                    'CUSTOM_ERROR_HANDLER'] ?? null);
            };
            $this->connection_acceptor = new ConnectionAcceptor(
                self::H2_CLIENT_MAGIC, null, $post_tls);
        }
        return $this->connection_acceptor;
    }
    /**
     * Determines HTTP version from the ALPN protocol negotiated during
     * the TLS handshake. This is the correct method for TLS connections.
     * By the time this is called, stream_socket_enable_crypto has
     * already completed so the negotiated protocol is available.
     *
     * @param string $alpns the ALPN protocol string from stream context,
     *      e.g. "h2" or "http/1.1", or null if ALPN was not negotiated
     * @return array context array with CLIENT_HTTP key set
     */
    protected function checkHttpTypeFromAlpn($alpns)
    {
        if (is_string($alpns)) {
            $alpn_parts = preg_split("/\s*,\s*/", $alpns);
            if (in_array('h2', $alpn_parts)) {
                return ["CLIENT_HTTP" => "HTTP/2.0"];
            } else if (in_array('http/1.1', $alpn_parts)) {
                return ["CLIENT_HTTP" => "HTTP/1.1"];
            }
        } else if ($alpns == null) {
            return ["CLIENT_HTTP" => "HTTP/1.1"];
        }
        return ["CLIENT_HTTP" => "unknown"];
    }
    /**
     * Determines HTTP version by inspecting the first bytes of a
     * plaintext (non-TLS) connection. Used only for cleartext
     * connections. Never call this on a TLS connection before
     * stream_socket_enable_crypto as the bytes will be an
     * unintelligible ClientHello.
     *
     * @param string $stream_start first bytes peeked from connection
     * @return array context array with CLIENT_HTTP key set
     */
    protected function checkHttpType($stream_start)
    {
        /*
            A request over HTTP/2 without TLS opens with the fixed
            preface that RFC 9113 names, so seeing it settles which
            protocol the connection speaks.
         */
        if (str_starts_with($stream_start, self::H2_CLIENT_MAGIC)) {
            return ["CLIENT_HTTP" => "h2c"];
        }
        if (preg_match(
            "/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT|" .
            "PROPFIND|PROPPATCH|MKCALENDAR|MKCOL|COPY|MOVE|LOCK|UNLOCK|" .
            "REPORT)" .
            " \S+ HTTP\/1\.1/",
            $stream_start)) {
            return ["CLIENT_HTTP" => "HTTP/1.1"];
        }
        return ["CLIENT_HTTP" => "unknown"];
    }
    /**
     * Handles the HTTP/2 connection preface exchange. Reads the
     * client SETTINGS frame, sends the server SETTINGS frame and
     * a SETTINGS ACK, then returns with the connection left open.
     * Any further frames (WINDOW_UPDATE, PRIORITY, HEADERS) are
     * handled by parseH2Request in the normal event loop. Used
     * for both TLS and cleartext h2c connections.
     *
     * @param resource $connection client connection ready for
     *      H2 traffic
     * @param bool $read_magic whether to read and verify the
     *      24-byte client magic string. Set to false when the
     *      caller has already consumed it (TLS detection via
     *      fread). Set to true for cleartext h2c where
     *      STREAM_PEEK was used and the magic is still buffered.
     * @return array the peer's initial SETTINGS dictionary
     *      (identifier => value), so the caller can mirror those
     *      settings into per-connection state (ENABLE_PUSH,
     *      HEADER_TABLE_SIZE, etc.)
     */
    protected function initH2Request($connection,
        $read_magic = false)
    {
        stream_set_blocking($connection, true);
        if ($read_magic) {
            $magic = $this->readExactly($connection,
                strlen(self::H2_CLIENT_MAGIC));
            if ($magic !== self::H2_CLIENT_MAGIC) {
                throw new \Exception(
                    "Invalid HTTP/2 client connection preface");
            }
        }
        $hdr = $this->readExactly($connection,
            self::H2_FRAME_HEADER_LEN);
        [$client_settings, $settings_len] =
            Frame::parseFrameHeader($hdr);
        if ($settings_len > self::H2_MAX_FRAME_SIZE) {
            throw new \Exception(
                "Initial SETTINGS frame exceeds max size: "
                . $settings_len);
        }
        if (!($client_settings instanceof SettingsFrame)) {
            throw new \Exception("Expected SETTINGS frame, got "
                . (is_object($client_settings) ?
                get_class($client_settings) : "a frame of unknown type"));
        }
        $client_settings->parseBody(
            $this->readExactly($connection, $settings_len));
        /*
            Server-advertised settings — sent explicitly so the
            client doesn't have to assume defaults:
              0x03 MAX_CONCURRENT_STREAMS=100 caps in-flight
                requests per connection (resource exhaustion).
              0x04 INITIAL_WINDOW_SIZE is the upload window: how
                much a client may send on a stream before waiting
                for the server to acknowledge it has read the data.
                Raised above the 64KB default so large file posts
                keep the pipe full instead of stalling between
                small bursts.
              0x05 MAX_FRAME_SIZE=16384 matches H2_MAX_FRAME_SIZE
                guard in parseH2Request.
         */
        $server_settings = new SettingsFrame(0, [
            0x03 => self::H2_MAX_CONCURRENT_STREAMS,
            0x04 => self::H2_ADVERTISED_WINDOW,
            0x05 => self::H2_MAX_FRAME_SIZE,
            0x08 => 1,
        ]);
        $this->writeFrameWhole($connection,
            $server_settings->serialize());
        $ack = new SettingsFrame(0, []);
        $ack->flags->add('ACK');
        $this->writeFrameWhole($connection, $ack->serialize());
        /*
            The larger upload window advertised above only applies to
            individual streams. The whole connection has its own
            receive window that starts at the 64KB default and caps
            the total upload data in flight across all streams, so by
            itself the per-stream raise would still be held back by it.
            Send a connection-level window update (stream id 0) to
            raise the connection window to the same size, so a single
            large upload can actually use the bigger window.
         */
        $connection_window_growth = self::H2_ADVERTISED_WINDOW -
            self::H2_DEFAULT_WINDOW;
        if ($connection_window_growth > 0) {
            $connection_window_update = new WindowUpdateFrame(0,
                $connection_window_growth);
            $this->writeFrameWhole($connection,
                $connection_window_update->serialize());
        }
        stream_set_blocking($connection, false);
        return $client_settings->settings;
    }
    /**
     * Processes one incoming HTTP/2 frame on an established connection.
     * Called from processRequestStreams each time the socket is readable.
     * HEADERS frames are dispatched as requests via setGlobals and
     * getResponseData, matching the HTTP/1.1 path exactly. PING and
     * SETTINGS frames are answered inline. GOAWAY closes the connection.
     *
     * @param int $key stream id of the connection in in_streams
     * @param resource $connection the client socket
     * @return bool true if a response was written, false otherwise
     */
    public function parseH2Request($key, $connection)
    {
        /*
            Per-connection H2 state lives on the Connection object
            (HPACK encoder/decoder, last-seen stream id, half-open
            streams awaiting END_STREAM, and the inbound byte
            buffer). The Connection is created by
            processServerRequest right after accept; if it is
            missing here, we are processing a frame for a stream
            that has already been torn down and should bail.
         */
        $conn = $this->connection($key);
        if ($conn === null) {
            $this->shutdownHttpStream($key);
            return false;
        }
        $state = &$conn->protocol_state;
        /*
            Read whatever is available without blocking and append it to
            the inbound buffer, draining to empty on each wakeup rather
            than taking a single chunk. Buffering frames this way means a
            client that sends a partial frame and stalls leaves its bytes
            buffered and does not hold the single event loop. Draining
            fully matters over TLS: OpenSSL decrypts a whole record at a
            time into its own buffer, while stream_select watches the raw
            socket rather than that buffer, so if one read leaves
            decrypted bytes behind, the next stream_select can report
            nothing to read and those bytes stay unseen until some later,
            unrelated socket activity wakes the loop. When the
            left-behind bytes are a whole frame that arrived right after
            a request, such as the flow-control WINDOW_UPDATE a browser
            sends just after a stream's headers to enlarge the response
            window, the server never learns it may send more and the
            transfer stalls part way until a keep-alive ping seconds
            later happens to wake the read. Each read is capped at the
            chunk size and the loop ends as soon as a read comes back
            empty, so a peer that keeps sending cannot hold the loop
            here: at most one socket buffer's worth is taken per wakeup.
         */
        $chunk = "";
        $read_error = false;
        while (true) {
            $piece = @fread($connection, self::H2_READ_CHUNK_SIZE);
            if ($piece === false) {
                $read_error = ($chunk === "");
                break;
            }
            if ($piece === "") {
                break;
            }
            $chunk .= $piece;
        }
        if ($read_error ||
            ($chunk === "" && feof($connection)
            && empty($this->out_streams[self::DATA][$key])
            && empty($this->out_streams[self::DATA_FILE][$key])
            && empty($state['pending_send'])
            && empty($state['streaming_gen']))) {
            $this->shutdownHttpStream($key);
            return false;
        }
        if (!isset($state['input_buffer'])) {
            $state['input_buffer'] = "";
        }
        $state['input_buffer'] .= $chunk;
        /*
            Drain every complete frame now buffered. A frame is
            complete once the 9-byte header plus its declared
            payload are present; otherwise the partial bytes stay
            buffered for the next readable event. A single read may
            carry several frames, so loop until the buffer holds
            less than a whole frame.
         */
        while (true) {
            $buffer = $state['input_buffer'];
            if (strlen($buffer) < self::H2_FRAME_HEADER_LEN) {
                return false;
            }
            $hdr = substr($buffer, 0, self::H2_FRAME_HEADER_LEN);
            [$frame, $payload_len] = Frame::parseFrameHeader($hdr);
            if ($payload_len > self::H2_MAX_FRAME_SIZE) {
                /*
                    RFC 7540 sec 4.2: a frame size error is a
                    connection error. Send GOAWAY with FRAME_SIZE_
                    ERROR (0x6) and tear down before allocating the
                    oversized payload. The announced payload is not
                    drained because the connection is being closed.
                 */
                $goaway = new GoAwayFrame(0, 0, 0x6, "");
                $this->writeFrameWhole($connection, $goaway->serialize());
                $this->shutdownHttpStream($key);
                return false;
            }
            $frame_len = self::H2_FRAME_HEADER_LEN + $payload_len;
            if (strlen($buffer) < $frame_len) {
                return false;
            }
            $payload = $payload_len > 0
                ? substr($buffer, self::H2_FRAME_HEADER_LEN,
                    $payload_len)
                : "";
            $state['input_buffer'] = substr($buffer, $frame_len);
            if ($frame === null) {
                continue;
            }
            $this->processH2Frame($key, $connection,
                $conn, $frame, $payload, $payload_len);
            /*
                processH2Frame may dispatch a request, handle a
                routine control frame, or tear the connection down. A
                single read can carry frames for several streams at
                once, so keep draining the buffer to handle them all
                rather than stopping after the first. Were it to stop
                after the first, the later streams' frames would sit
                buffered with nothing left to wake the loop and read
                them, and those requests would hang until the client
                gave up. Stop only once the connection is gone, so we
                do not touch freed state.
             */
            if ($this->connection($key) === null) {
                return false;
            }
        }
    }
    /**
     * Processes one fully-acquired HTTP/2 frame. The frame header
     * and payload have already been read (non-blocking) and parsed
     * by parseH2Request; this method handles the frame according to
     * its type: control frames (GOAWAY, PING, SETTINGS, WINDOW_
     * UPDATE, RST_STREAM), and HEADERS/CONTINUATION/DATA that make
     * up a request. Returns false when the connection was torn down
     * or no request is ready, or the result of dispatchH2Request
     * when a complete request has been assembled.
     *
     * @param int $key connection key in $this->in_streams
     * @param resource $connection client socket
     * @param Connection $conn the persistent connection object
     * @param Frame $frame the parsed frame (type-specific subclass)
     * @param string $payload the frame's decoded payload bytes
     * @param int $payload_len the frame payload length
     * @return bool processing result; true only when a response was
     *      dispatched, false otherwise
     */
    protected function processH2Frame($key, $connection, $conn,
        $frame, $payload, $payload_len)
    {
        $state = &$conn->protocol_state;
        if ($frame instanceof GoAwayFrame) {
            $code = (strlen($payload) >= 8) ?
                unpack('N', substr($payload, 4, 4))[1] : 0;
            if ($code != 0) {
                error_log("[website-h2] connection $key closed by the " .
                    "client, error code $code");
            }
            $this->shutdownHttpStream($key);
            return false;
        }
        if ($frame instanceof PingFrame) {
            $pong = new PingFrame(0, $payload);
            $pong->flags->add('ACK');
            $this->writeFrameWhole($connection, $pong->serialize());
            return false;
        }
        if ($frame instanceof SettingsFrame
            && !$frame->flags->contains('ACK')) {
            /*
                Apply peer settings. HEADER_TABLE_SIZE (0x01)
                tunes the HPACK encoder's table to whatever the
                decoder advertised. ENABLE_PUSH (0x02) is the
                client telling us whether to use PUSH_PROMISE
                (sec 6.5.2: 0 disables, 1 enables, anything else
                is a PROTOCOL_ERROR; default 1). The other
                advertised settings (MAX_CONCURRENT_STREAMS,
                INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_
                LIST_SIZE) are accepted but ignored.
             */
            $hpack_encode = $state['hpack_encode'] ?? null;
            if ($hpack_encode !== null
                && isset($frame->settings[0x01])) {
                $hpack_encode->setMaxTableSize($frame->settings[0x01]);
            }
            if (isset($frame->settings[0x02])) {
                $state['enable_push'] =
                    ($frame->settings[0x02] === 1);
            }
            if (isset($frame->settings[
                self::H2_SETTING_INITIAL_WINDOW])) {
                /*
                    RFC 7540 sec 6.9.2: a changed
                    SETTINGS_INITIAL_WINDOW_SIZE adjusts every
                    open stream's send window by the delta (which
                    can drive a window negative; the pump treats
                    non-positive credit as none) and sets the
                    window new streams start with.
                 */
                $new_initial = $frame->settings[
                    self::H2_SETTING_INITIAL_WINDOW];
                $delta = $new_initial -
                    ($state['peer_initial_window'] ??
                    self::H2_DEFAULT_WINDOW);
                $state['peer_initial_window'] = $new_initial;
                foreach (($state['stream_send_windows'] ?? [])
                    as $open_id => $window) {
                    $state['stream_send_windows'][$open_id] =
                        $window + $delta;
                }
                if ($delta > 0) {
                    $this->pumpH2AllPendingSend($key, $connection,
                        $conn);
                }
            }
            $ack = new SettingsFrame(0, []);
            $ack->flags->add('ACK');
            $this->writeFrameWhole($connection, $ack->serialize());
            return false;
        }
        if ($frame instanceof DataFrame) {
            /*
                RFC 7540 sec 6.1: DATA frames carry request body
                bytes. Atto buffers them per-stream alongside the
                context from HEADERS, then dispatches the assembled
                request when END_STREAM is seen. parseFrameHeader
                gave us the frame shell; parseBody decodes the body
                bytes (handles PADDED flag).
             */
            $frame->parseBody($payload);
            $stream_id = $frame->stream_id;
            if (isset($state['ws_carrier_streams'][$stream_id])) {
                /* This stream carries a WebSocket opened by an
                   extended CONNECT. Its DATA frames are WebSocket
                   frame bytes, not a request body, so they go to the
                   WebSocket parser. The client credits are replenished
                   so a long-lived socket does not stall its window. */
                $consumed = strlen($frame->data);
                if ($consumed > 0) {
                    $stream_update = new WindowUpdateFrame(
                        $stream_id, $consumed);
                    $conn_update = new WindowUpdateFrame(0, $consumed);
                    if (!$this->writeFrameWhole($connection,
                        $stream_update->serialize()
                        . $conn_update->serialize())) {
                        $this->shutdownHttpStream($key);
                        return false;
                    }
                }
                $this->feedH2WebSocket($key, $stream_id, $frame->data,
                    $frame->flags->contains('END_STREAM'));
                return false;
            }
            if (!isset($state['pending_streams'][$stream_id])) {
                /*
                    DATA on a stream we never saw HEADERS on, or
                    one already dispatched. RFC 7540 sec 5.1: DATA
                    on a stream not in open/half-closed(local) is
                    a STREAM_ERROR. We tear down the connection —
                    Atto does not track per-stream error recovery,
                    so dropping the whole connection on a misbehaving
                    stream is an accepted simplification.
                 */
                $goaway = new GoAwayFrame(0,
                    $state['last_stream_id'] ?? 0, 0x1, "");
                $this->writeFrameWhole($connection, $goaway->serialize());
                $this->shutdownHttpStream($key);
                return false;
            }
            /* The body grows in place in the connection's state. Taking
               a copy of the stream's entry, adding to it and storing it
               back copies the whole body on every frame, so the time to
               take a body grows with the square of its size. */
            $state['pending_streams'][$stream_id]['body'] .= $frame->data;
            /*
                RFC 7540 sec 6.9: replenish the per-stream and
                connection-level receive windows after each DATA
                frame. Default initial window is 65535 bytes; once
                filled, the peer stops sending DATA until we issue
                WINDOW_UPDATE frames returning credit. Atto buffers
                the whole body before dispatch (no streaming), so
                we credit immediately for the consumed bytes:
                stream-level update for the stream-id, connection-
                level update for stream-id 0. Without this, H2
                POSTs >65535 bytes (large form posts, multipart file
                uploads) stall until client timeout.
             */
            $consumed = strlen($frame->data);
            if ($consumed > 0) {
                $stream_update = new WindowUpdateFrame(
                    $stream_id, $consumed);
                $conn_update = new WindowUpdateFrame(
                    0, $consumed);
                if (!$this->writeFrameWhole($connection,
                    $stream_update->serialize()
                    . $conn_update->serialize())) {
                    $this->shutdownHttpStream($key);
                    return false;
                }
            }
            if (strlen($state['pending_streams'][$stream_id]['body'])
                    > $this->default_server_globals[
                        'MAX_REQUEST_LEN']) {
                /*
                    Body bigger than MAX_REQUEST_LEN. Tear down
                    rather than buffer further.
                 */
                $goaway = new GoAwayFrame(0,
                    $state['last_stream_id'] ?? 0, 0xb, "");
                $this->writeFrameWhole($connection, $goaway->serialize());
                $this->shutdownHttpStream($key);
                return false;
            }
            if ($frame->flags->contains('END_STREAM')) {
                $context = $state['pending_streams'][$stream_id]['context'];
                $context['CONTENT'] =
                    $state['pending_streams'][$stream_id]['body'];
                unset($state['pending_streams'][$stream_id]);
                return $this->dispatchH2Request($key, $connection,
                    $stream_id, $context);
            }
            return false;
        }
        if ($frame instanceof WindowUpdateFrame) {
            /*
                RFC 7540 sec 6.9: the client returns send credit.
                Stream id 0 credits the connection-level window,
                otherwise the named stream's window. After
                crediting, queue any pending response bytes the
                new credit allows. A malformed increment tears the
                connection down like other malformed frames.
             */
            try {
                $frame->parseBody($payload);
            } catch (\Exception $exception) {
                $goaway = new GoAwayFrame(0,
                    $state['last_stream_id'] ?? 0,
                    self::H2_ERROR_PROTOCOL, "");
                set_error_handler(null);
                fwrite($connection, $goaway->serialize());
                restore_error_handler();
                $this->shutdownHttpStream($key);
                return false;
            }
            $increment = $frame->windowIncrement();
            if ($frame->stream_id == 0) {
                $state['send_window'] = ($state['send_window'] ??
                    self::H2_DEFAULT_WINDOW) + $increment;
                $this->pumpH2AllPendingSend($key, $connection,
                    $conn);
            } else if (isset($state['stream_send_windows'][
                $frame->stream_id])) {
                $state['stream_send_windows'][$frame->stream_id]
                    += $increment;
                $this->pumpH2PendingSend($key, $connection, $conn,
                    $frame->stream_id);
            } else if (isset($state['closed_streams'][
                $frame->stream_id])) {
                /*
                    A WINDOW_UPDATE for a stream the server has
                    already finished sending and closed. RFC 7540
                    sec 6.9 lets a closed stream's WINDOW_UPDATE be
                    ignored, and it must be: a browser keeps sending
                    these as it drains a completed response, so
                    holding the credit (as if for a not-yet-started
                    stream) would strand one entry per closed stream
                    and, on a page that streams many ranges, build up
                    until the guard below mistook it for an attack
                    and closed the connection.
                 */
                return false;
            } else {
                /*
                    A peer may grant a stream's flow-control window
                    immediately after opening the stream, before the
                    server has begun the response and registered the
                    stream's send window. Hold the credit so it is
                    applied when the window is initialized, rather
                    than dropping it (which would leave the stream
                    stuck at the peer's initial window even though the
                    peer had granted much more). Only as many distinct
                    streams as the connection may have open at once can
                    legitimately have credit waiting this way; a client
                    that stashes credit for more distinct stream ids
                    than that is crediting streams it never opened,
                    which would grow this map without bound (its small
                    entries are not counted by the per-connection byte
                    ceiling), so that is treated as a protocol error.
                 */
                if (!isset($state['pending_stream_window_credit'][
                    $frame->stream_id]) &&
                    count($state['pending_stream_window_credit'] ?? [])
                    >= self::H2_MAX_CONCURRENT_STREAMS) {
                    $goaway = new GoAwayFrame(0,
                        $state['last_stream_id'] ?? 0,
                        self::H2_ERROR_PROTOCOL, "");
                    $this->writeFrameWhole($connection, $goaway->serialize());
                    $this->shutdownHttpStream($key);
                    return false;
                }
                $state['pending_stream_window_credit'][
                    $frame->stream_id] =
                    ($state['pending_stream_window_credit'][
                    $frame->stream_id] ?? 0) + $increment;
            }
            return false;
        }
        if ($frame instanceof RstStreamFrame) {
            $code = (strlen($payload) == 4) ? unpack('N', $payload)[1] :
                -1;
            error_log("[website-h2] connection $key stream " .
                "{$frame->stream_id} reset by the client, error code " .
                "$code" . (isset($state['pending_send'][$frame->stream_id]) ?
                ", response not fully sent" : ""));
            /*
                RFC 7540 sec 6.4: the client no longer wants this
                stream; drop any response bytes still waiting on
                send credit so they neither hold memory nor get
                sent to a reset stream. Discarding a parked
                streaming generator lets its finally block run,
                releasing any file handle it held.
             */
            unset($state['pending_send'][$frame->stream_id]);
            unset($state['stream_send_windows'][
                $frame->stream_id]);
            unset($state['pending_stream_window_credit'][
                $frame->stream_id]);
            unset($state['streaming_gen'][$frame->stream_id]);
            $this->markH2StreamClosed($state, $frame->stream_id);
            return false;
        }
        if (!($frame instanceof HeaderFrame)) {
            return false;
        }
        /*
            RFC 7540 sec 5.1.1: stream IDs initiated by a peer must
            be strictly greater than any previous stream ID that
            peer initiated on this connection. A frame whose stream
            id is at or below the connection's high-water mark is
            a protocol error and the connection must be closed.
            Client-initiated streams are odd-numbered; we accept
            even numbers too for permissiveness but track them
            against the same high-water mark.
         */
        $client_stream_id = $frame->stream_id;
        $high_water = $state['last_stream_id'] ?? 0;
        if ($client_stream_id <= $high_water) {
            $goaway = new GoAwayFrame(0, $high_water, 0x1, "");
            $this->writeFrameWhole($connection, $goaway->serialize());
            $this->shutdownHttpStream($key);
            return false;
        }
        $state['last_stream_id'] = $client_stream_id;
        $hpack_decode = $state['hpack_decode'] ?? new HPack();
        $hpack_encode = $state['hpack_encode'] ?? new HPack();
        $context = $frame->parseBody($payload, $hpack_decode);
        /*
            HeaderFrame::parseBody builds its context fresh from
            the HEADERS frame and so does not see the
            per-connection keys (IS_SECURE, LISTENER_PORT,
            LISTENER_NAME, HTTPS) which now live on the Connection
            object, or REMOTE_ADDR/REMOTE_PORT/SERVER_ADDR/
            SERVER_PORT which initRequestStream populated in
            in_streams[CONTEXT]. Pull both sources together here
            so the per-stream context dispatched via
            dispatchH2Request carries the full picture. The
            freshly-parsed request keys win on conflict.
         */
        $propagate = [
            'IS_SECURE' => $conn->is_secure,
            'LISTENER_PORT' => $conn->listener_port,
            'LISTENER_NAME' => $conn->listener_name,
            'CLIENT_HTTP' => $conn->client_http,
            'REMOTE_ADDR' => $conn->remote_addr,
            'REMOTE_PORT' => $conn->remote_port,
            'SERVER_ADDR' => $conn->server_addr,
            'SERVER_PORT' => $conn->server_port,
        ];
        if ($conn->https !== '') {
            $propagate['HTTPS'] = $conn->https;
        }
        $context = array_merge($propagate, $context);
        if (($context['REQUEST_METHOD'] ?? '') === 'CONNECT'
            && ($context['REQUEST_PROTOCOL'] ?? '') === 'websocket') {
            /* RFC 8441: a WebSocket rides an extended CONNECT stream
               rather than its own connection. The handshake runs
               against this stream and, when a route matches, the
               stream stays open to carry WebSocket frames inside h2
               DATA frames both ways. */
            return $this->handleH2WebSocketConnect($key, $connection,
                $conn, $client_stream_id, $context);
        }
        /*
            Refuse the stream if this connection is already at its
            stream count or its buffered-byte ceiling. The header
            block was decoded above so the shared HPACK table stays
            in step, and the stream id was recorded as the new high
            water mark, but the request is not parked or dispatched:
            a single client that pipelines requests faster than it
            reads the replies, or asks for more at once than the
            connection can hold, cannot grow the server's per-
            connection memory without bound. RST_STREAM with
            REFUSED_STREAM tells the client the request was not acted
            on so it may retry once the connection drains.
         */
        /* A stream whose producer has nothing left to give is finished,
           whatever the client did with it. A media player that asks for
           a range and then stops reading leaves one of these behind, and
           counting those toward the ceiling meant a page holding a few
           recordings had no room left to send anything. */
        foreach (($state['streaming_gen'] ?? []) as $done_id => $producer) {
            if (!($producer instanceof \Generator) ||
                !$producer->valid()) {
                unset($state['streaming_gen'][$done_id]);
            }
        }
        $open_streams = count($state['pending_streams'] ?? []) +
            count($state['pending_send'] ?? []) +
            count($state['streaming_gen'] ?? []);
        $backlog = $this->h2ConnectionBacklog($key, $state);
        if ($open_streams >= self::H2_MAX_CONCURRENT_STREAMS ||
            $backlog >= self::H2_MAX_CONN_BUFFER) {
            $refusal = new RstStreamFrame($client_stream_id,
                self::H2_ERROR_REFUSED_STREAM);
            set_error_handler(null);
            fwrite($connection, $refusal->serialize());
            restore_error_handler();
            return false;
        }
        if (!$frame->flags->contains('END_STREAM')) {
            /*
                HEADERS without END_STREAM means a request body is
                arriving in subsequent DATA frames. Park the
                context against the stream id; DATA frames will
                accumulate the body and the eventual END_STREAM
                will trigger dispatchH2Request.
             */
            $state['pending_streams'][$client_stream_id] = [
                'context' => $context, 'body' => ''];
            return false;
        }
        return $this->dispatchH2Request($key, $connection,
            $client_stream_id, $context);
    }
    /**
     * Adds up the response and request bytes the server is currently
     * holding in memory for one HTTP/2 connection. This is the
     * unsent bytes already queued on the connection's outbound
     * buffer, plus each stream's not-yet-sent response body, plus
     * each stream's request body that is still arriving. The total
     * is what the stream-acceptance check compares against the
     * per-connection ceiling so one slow-reading client cannot tie
     * up an unbounded amount of memory.
     *
     * @param int $key connection key in the out_streams arrays
     * @param array $state the connection's protocol_state holding
     *      the per-stream pending send and request buffers
     * @return int total buffered bytes held for this connection
     */
    protected function h2ConnectionBacklog($key, $state)
    {
        $backlog = strlen($this->out_streams[self::DATA][$key]
            ?? "") - ($this->out_streams[self::DATA_OFFSET][$key] ?? 0);
        foreach (($state['pending_send'] ?? []) as $pending) {
            $backlog += strlen($pending['data'] ?? "") -
                ($pending['offset'] ?? 0);
        }
        foreach (($state['pending_streams'] ?? []) as $pending) {
            $backlog += strlen($pending['body'] ?? "");
        }
        return $backlog;
    }
    /**
     * Seeds the outbound HTTP/2 flow-control bookkeeping for a
     * freshly established connection: the connection-level send
     * window, the initial window each new stream starts with
     * (from the client's SETTINGS_INITIAL_WINDOW_SIZE when sent),
     * and the empty per-stream window and pending-body maps.
     *
     * @param object $connection the Connection whose
     *      protocol_state to seed
     * @param array $client_settings the client's initial SETTINGS
     *      dictionary (identifier => value)
     */
    protected function initH2SendWindows($connection,
        $client_settings)
    {
        $connection->protocol_state['send_window'] =
            self::H2_DEFAULT_WINDOW;
        $connection->protocol_state['peer_initial_window'] =
            $client_settings[self::H2_SETTING_INITIAL_WINDOW]
            ?? self::H2_DEFAULT_WINDOW;
        $connection->protocol_state['stream_send_windows'] = [];
        $connection->protocol_state['pending_send'] = [];
        $connection->protocol_state['pending_stream_window_credit'] =
            [];
        $connection->protocol_state['closed_streams'] = [];
    }
    /**
     * Records that the server has finished with a stream, either
     * because its response is complete or because the client reset
     * it, so a flow-control WINDOW_UPDATE that turns up for that
     * stream afterwards is recognized as belonging to a closed
     * stream and ignored rather than mistaken for credit granted
     * ahead of a not-yet-started response. A browser sends
     * WINDOW_UPDATE frames as it consumes a response, and some of
     * them arrive after the server has already sent the whole body
     * and closed the stream. Without this record each such late
     * update would be stashed as pending credit for a stream that
     * will never send again, and a page that streams many ranges in
     * a row (a playing video fetched a chunk at a time) would
     * accumulate one stranded entry per range until the
     * pending-credit guard mistook the buildup for a misbehaving
     * peer and dropped the connection, stalling the video. Only the
     * most recent closed streams are remembered, capped at the most
     * a connection may have open at once, since a client does not
     * send window updates for a stream it closed long ago; the
     * lowest (oldest) ids are dropped once the cap is passed.
     *
     * @param array $state connection protocol state, by reference
     * @param int $stream_id the stream that has just closed
     */
    protected function markH2StreamClosed(&$state, $stream_id)
    {
        $state['closed_streams'][$stream_id] = true;
        if (count($state['closed_streams'])
            > self::H2_MAX_CONCURRENT_STREAMS) {
            ksort($state['closed_streams'], SORT_NUMERIC);
            $state['closed_streams'] = array_slice(
                $state['closed_streams'],
                -self::H2_MAX_CONCURRENT_STREAMS, null, true);
        }
    }
    /**
     * Appends serialized response bytes for connection $key to its
     * out_streams entry (creating the entry when this is the first
     * queued data) so processResponseStreams drains them
     * asynchronously across event-loop iterations. Appending rather
     * than overwriting keeps concurrent streams' frames in dispatch
     * order in one outbound buffer, which also preserves HPACK
     * dynamic-table encoding order.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the bytes go out on
     * @param string $out serialized frame bytes to queue
     */
    protected function queueResponseData($key, $connection, $out)
    {
        if (!empty($this->out_streams[self::CONNECTION][$key])) {
            $this->out_streams[self::DATA][$key] .= $out;
        } else {
            $this->out_streams[self::CONNECTION][$key] = $connection;
            $this->out_streams[self::DATA][$key] = $out;
            $this->out_streams[self::DATA_OFFSET][$key] = 0;
            $this->out_streams[self::CONTEXT][$key] = [];
        }
        $this->out_streams[self::MODIFIED_TIME][$key] = time();
        $this->logOutboundBuffer(strlen($out),
            strlen($this->out_streams[self::DATA][$key]));
    }
    /**
     * Starts sending an HTTP/2 response body on stream $stream_id,
     * honoring outbound flow control (RFC 7540 sec 5.2): the
     * stream gets a send window equal to the client's advertised
     * initial window, the body is recorded as pending, and as many
     * DATA frames as current credit allows are queued right away.
     * The remainder goes out from pumpH2PendingSend as the client
     * returns credit with WINDOW_UPDATE frames.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the frames go out on
     * @param object $conn Connection holding protocol_state
     * @param int $stream_id stream the body belongs to
     * @param string $body response body bytes
     */
    protected function sendH2Body($key, $connection, $conn,
        $stream_id, $body)
    {
        if ($conn === null) {
            /* No connection object means the peer is gone: there is no
               protocol state to update and nowhere to send the body,
               so do nothing rather than fault on the null. */
            return;
        }
        $state = &$conn->protocol_state;
        if (!isset($state['send_window'])) {
            $this->initH2SendWindows($conn, []);
        }
        $state['stream_send_windows'][$stream_id] =
            ($state['peer_initial_window'] ?? self::H2_DEFAULT_WINDOW) +
            ($state['pending_stream_window_credit'][$stream_id] ?? 0);
        unset($state['pending_stream_window_credit'][$stream_id]);
        $state['pending_send'][$stream_id] =
            ['data' => $body, 'offset' => 0, 'complete' => true];
        $this->pumpH2PendingSend($key, $connection, $conn,
            $stream_id);
    }
    /**
     * Sends a complete HTTP/2 response body, pacing it across the
     * event loop when it is larger than the client's per-stream
     * receive window. A body that fits the window is handed to
     * sendH2Body and sent in one burst. A larger body cannot all
     * leave at once: only the first window-sized slice would go and
     * the rest would sit waiting for the client to return credit it
     * does not always send for a response it already knows the length
     * of. So the larger body is registered as a streaming producer
     * that the event loop advances in frame-sized blocks as the
     * client takes the data, the same mechanism that serves large
     * files, which keeps the stream re-driven every loop turn instead
     * of parked after the first slice.
     *
     * @param int $key connection key
     * @param resource $connection client socket
     * @param object $conn Connection holding protocol_state
     * @param int $stream_id stream the response belongs to
     * @param string $body the complete response body
     * @param \Generator|null $pieces yields the body a piece at
     *      a time; used instead of slicing $body when given
     */
    protected function sendH2BodyPaced($key, $connection, $conn,
        $stream_id, $body, $pieces = null)
    {
        if ($conn === null) {
            return;
        }
        if (!isset($conn->protocol_state['send_window'])) {
            $this->initH2SendWindows($conn, []);
        }
        $stream_window =
            $conn->protocol_state['peer_initial_window']
            ?? self::H2_DEFAULT_WINDOW;
        if ($pieces === null && strlen($body) <= $stream_window) {
            $this->sendH2Body($key, $connection, $conn, $stream_id,
                $body);
            return;
        }
        $producer = ($pieces !== null) ? $pieces :
            (function () use ($body) {
            $body_len = strlen($body);
            for ($pos = 0; $pos < $body_len;
                $pos += self::H2_MAX_FRAME_SIZE) {
                yield substr($body, $pos, self::H2_MAX_FRAME_SIZE);
            }
        })();
        $state = &$conn->protocol_state;
        $state['stream_send_windows'][$stream_id] = $stream_window +
            ($state['pending_stream_window_credit'][$stream_id] ?? 0);
        unset($state['pending_stream_window_credit'][$stream_id]);
        $state['pending_send'][$stream_id] =
            ['data' => "", 'offset' => 0, 'complete' => false];
        $state['streaming_gen'][$stream_id] = $producer;
        $this->refillOneStreamingGenerator($key, $connection, $conn,
            $stream_id, $producer);
    }
    /**
     * Appends another chunk of a streamed response body to a
     * stream's pending send buffer and pumps what the flow-control
     * windows allow. Unlike sendH2Body, which takes a whole body at
     * once, this is called repeatedly as a streaming producer yields
     * chunks across event-loop turns, so the whole body is never
     * held in memory at once. The already-sent prefix is dropped
     * from the buffer on each call so a long response stays bounded
     * by roughly one pump slice. END_STREAM is withheld until $last
     * is true, which marks the entry complete so pumpH2PendingSend
     * closes the stream once the final bytes drain.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the frames go out on
     * @param object $conn Connection holding protocol_state
     * @param int $stream_id H2 stream id being streamed
     * @param string $chunk next body bytes to queue, possibly empty
     * @param bool $last whether this is the final chunk of the body
     */
    protected function appendH2Body($key, $connection, $conn,
        $stream_id, $chunk, $last)
    {
        $state = &$conn->protocol_state;
        if (!isset($state['send_window'])) {
            $this->initH2SendWindows($conn, []);
        }
        if (!isset($state['pending_send'][$stream_id])) {
            $state['stream_send_windows'][$stream_id] =
                ($state['peer_initial_window']
                ?? self::H2_DEFAULT_WINDOW) +
                ($state['pending_stream_window_credit'][$stream_id]
                ?? 0);
            unset($state['pending_stream_window_credit'][$stream_id]);
            $state['pending_send'][$stream_id] =
                ['data' => "", 'offset' => 0, 'complete' => false];
        }
        $pending = &$state['pending_send'][$stream_id];
        /* drop the already-sent prefix so the buffer stays bounded */
        if ($pending['offset'] > 0) {
            $pending['data'] = substr($pending['data'],
                $pending['offset']);
            $pending['offset'] = 0;
        }
        $pending['data'] .= $chunk;
        if ($last) {
            $pending['complete'] = true;
        }
        unset($pending);
        $this->pumpH2PendingSend($key, $connection, $conn,
            $stream_id);
    }
    /**
     * Advances every parked streaming-response generator whose
     * stream's outbound buffer has drained below one pump slice,
     * pulling the next body chunk from the generator and appending
     * it. Run once per event-loop iteration so a streamed response
     * is produced lazily, paced by how fast the peer takes data and
     * returns flow-control credit, while other streams on the same
     * connection keep being served (the generator is parked between
     * iterations rather than blocking the route). A generator that
     * has finished is removed and its stream's final chunk marked,
     * letting pumpH2PendingSend close the stream once it drains. It
     * first has unparkGrowingFiles put back any HTTP/1.1 connection
     * whose growing file has more to send.
     */
    protected function refillStreamingGenerators()
    {
        $this->unparkGrowingFiles();
        foreach ($this->connections as $key => $conn) {
            if (empty($conn->protocol_state['streaming_gen'])) {
                continue;
            }
            $connection = $this->in_streams[self::CONNECTION][$key]
                ?? null;
            if ($connection === null) {
                unset($conn->protocol_state['streaming_gen']);
                continue;
            }
            foreach ($conn->protocol_state['streaming_gen']
                as $stream_id => $generator) {
                /*
                    Only draw from a generator when this stream has
                    less than a pump slice already buffered and
                    unsent. Without this guard the refill pulls and
                    pumps another small chunk on every event-loop
                    iteration, which keeps the connection perpetually
                    in the writable set so stream_select never blocks
                    and the loop spins at high CPU, starving other
                    work during a burst of requests (a scrub). With
                    it, once a slice is queued the generator is left
                    alone until that slice drains, so the loop sleeps
                    between drains instead of spinning.
                 */
                $state = &$conn->protocol_state;
                $pending_unsent = 0;
                if (isset($state['pending_send'][$stream_id])) {
                    $pending_unsent = strlen(
                        $state['pending_send'][$stream_id]['data'])
                        - $state['pending_send'][$stream_id]['offset'];
                }
                $queued_unsent =
                    strlen($this->out_streams[self::DATA][$key] ?? "")
                    - ($this->out_streams[self::DATA_OFFSET][$key]
                    ?? 0);
                /*
                    When a stream's flow-control window is exhausted
                    the pump simply sends nothing for it and the
                    stream stays parked here, holding at most about a
                    pump slice of buffered body, until the peer sends
                    a WINDOW_UPDATE (which re-pumps it through the
                    WINDOW_UPDATE handler) or the connection closes
                    (which discards the parked generator). A browser
                    pacing a media element legitimately leaves a
                    stream's window at zero for seconds between reads,
                    so the server waits rather than resetting, which
                    would surface to the player as a broken transfer
                    and trigger a re-request.
                 */
                unset($state);
                if ($pending_unsent + $queued_unsent
                    >= self::H2_PUMP_SLICE) {
                    continue;
                }
                $this->refillOneStreamingGenerator($key, $connection,
                    $conn, $stream_id, $generator);
            }
        }
    }
    /**
     * Refills a single parked streaming generator for one stream:
     * while its outbound buffer holds less than a pump slice and the
     * generator has more to give, pulls the next chunk and appends
     * it; when the generator is exhausted, appends a final empty
     * chunk marking the body complete and unparks it. Keeping the
     * refill bounded by one slice caps the memory a streamed
     * response holds and lets the loop move on to other work. A
     * generator that yields false has nothing to give yet and is left
     * parked until the next pass.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the frames go out on
     * @param object $conn Connection holding protocol_state
     * @param int $stream_id H2 stream id being streamed
     * @param \Generator $generator the parked response producer
     */
    protected function refillOneStreamingGenerator($key, $connection,
        $conn, $stream_id, $generator)
    {
        $state = &$conn->protocol_state;
        while ($generator->valid()) {
            /*
                Stop pulling from the generator once a slice's worth
                of body is already buffered and unsent for this
                stream (either still in pending_send or queued in the
                connection's outbound buffer). This caps the memory a
                streamed response holds to about one slice regardless
                of how fast the generator can produce, while leaving
                enough queued that the pump always has data to send.
             */
            $pending_unsent = 0;
            if (isset($state['pending_send'][$stream_id])) {
                $pending_unsent =
                    strlen($state['pending_send'][$stream_id]['data'])
                    - $state['pending_send'][$stream_id]['offset'];
            }
            $queued_unsent =
                strlen($this->out_streams[self::DATA][$key] ?? "")
                - ($this->out_streams[self::DATA_OFFSET][$key] ?? 0);
            if ($pending_unsent + $queued_unsent
                >= self::H2_PUMP_SLICE) {
                return;
            }
            $chunk = $generator->current();
            $generator->next();
            $last = !$generator->valid();
            if ($chunk === false && !$last &&
                $generator->current() === false) {
                /* The producer has nothing yet, as a file still being
                   written may not; it is asked again on a later pass. */
                return;
            }
            if ($chunk === null || $chunk === false) {
                $chunk = "";
            }
            $this->appendH2Body($key, $connection, $conn, $stream_id,
                $chunk, $last);
        }
        if (!$generator->valid()) {
            /* generator produced nothing new but is done; ensure the
               stream is marked complete so it can close */
            if (isset($state['pending_send'][$stream_id])
                && empty($state['pending_send'][$stream_id][
                'complete'])) {
                $this->appendH2Body($key, $connection, $conn,
                    $stream_id, "", true);
            }
            unset($conn->protocol_state['streaming_gen'][$stream_id]);
        }
    }
    /**
     * Pumps connection $key's streams with pending response
     * bodies, starting from a per-connection rotating cursor so
     * that, combined with the pump's one-slice outbound-buffer
     * cap, every pending stream gets its turn across successive
     * drain events and concurrent responses interleave on the
     * wire. Called when the connection's outbound buffer drains
     * and when the peer returns connection-level credit; safe to
     * call when nothing is pending or the connection is gone.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the frames go out on
     * @param object $conn Connection holding protocol_state, or
     *      null when the connection is already torn down
     */
    protected function pumpH2AllPendingSend($key, $connection,
        $conn)
    {
        if ($conn === null ||
            empty($conn->protocol_state['pending_send'])) {
            return;
        }
        $pending_ids =
            array_keys($conn->protocol_state['pending_send']);
        $num_pending = count($pending_ids);
        $cursor = $conn->protocol_state['pending_send_cursor'] ?? 0;
        for ($i = 0; $i < $num_pending; $i++) {
            $pending_id =
                $pending_ids[($cursor + $i) % $num_pending];
            $this->pumpH2PendingSend($key, $connection, $conn,
                $pending_id);
        }
        $conn->protocol_state['pending_send_cursor'] = $cursor + 1;
    }
    /**
     * Queues as many DATA frames for stream $stream_id as the
     * connection-level and stream-level send windows allow, at
     * most H2_PUMP_SLICE bytes per call so concurrent responses
     * on one connection interleave, consuming credit per payload
     * byte. END_STREAM rides the frame carrying the body's final
     * byte (or an empty frame for an empty body, which costs no
     * credit). When the body is fully queued the stream's pending
     * entry and window are dropped. Called when a response
     * starts, when the connection's outbound buffer drains, and
     * whenever the client returns credit.
     *
     * @param int $key connection identifier
     * @param resource $connection socket the frames go out on
     * @param object $conn Connection holding protocol_state
     * @param int $stream_id stream to emit pending body bytes for
     */
    protected function pumpH2PendingSend($key, $connection, $conn,
        $stream_id)
    {
        $state = &$conn->protocol_state;
        if (!isset($state['pending_send'][$stream_id])) {
            return;
        }
        $queued_unsent = strlen($this->out_streams[self::DATA][$key]
            ?? "") - ($this->out_streams[self::DATA_OFFSET][$key]
            ?? 0);
        if ($queued_unsent >= self::H2_PUMP_SLICE) {
            /*
                Backpressure: the connection's outbound buffer
                already holds a full slice the peer has not taken
                yet. Queueing more would let frequent
                WINDOW_UPDATE frames from a slowly consuming peer
                grow the buffer without bound (a multi-hundred-MB
                video response could balloon to the full body and
                exhaust process memory). The next drain that
                brings the buffer under one slice pumps again.
             */
            return;
        }
        $pending = &$state['pending_send'][$stream_id];
        $total = strlen($pending['data']);
        /*
            A streaming body is appended to over several event-loop
            turns, so "offset reached the current data length" does
            not by itself mean the body is finished. The producer
            marks the entry complete only once the final chunk has
            been appended; until then END_STREAM is withheld and the
            stream is kept pending so later appends can be pumped.
            Bodies sent whole through sendH2Body are complete from
            the start, preserving the previous behavior.
         */
        $complete = $pending['complete'] ?? true;
        $out = "";
        $sliced = 0;
        while ($pending['offset'] < $total &&
            $sliced < self::H2_PUMP_SLICE) {
            $credit = min($state['send_window'],
                $state['stream_send_windows'][$stream_id]);
            if ($credit <= 0) {
                break;
            }
            $piece = substr($pending['data'], $pending['offset'],
                min(self::H2_MAX_FRAME_SIZE, $credit,
                self::H2_PUMP_SLICE - $sliced,
                $total - $pending['offset']));
            $piece_len = strlen($piece);
            $sliced += $piece_len;
            $pending['offset'] += $piece_len;
            $state['send_window'] -= $piece_len;
            $state['stream_send_windows'][$stream_id] -= $piece_len;
            $frame = new DataFrame($stream_id, $piece);
            if ($complete && $pending['offset'] >= $total) {
                $frame->flags->add("END_STREAM");
            }
            $out .= $frame->serialize();
        }
        if ($total == 0 && $complete) {
            $end_frame = new DataFrame($stream_id, "");
            $end_frame->flags->add("END_STREAM");
            $out .= $end_frame->serialize();
        }
        if ($complete && $pending['offset'] >= $total) {
            unset($state['pending_send'][$stream_id]);
            unset($state['stream_send_windows'][$stream_id]);
            $this->markH2StreamClosed($state, $stream_id);
        }
        if ($out !== "") {
            $this->queueResponseData($key, $connection, $out);
        }
    }
    /**
     * Dispatches a fully-assembled HTTP/2 request to the user
     * route handler and writes the response back to the client.
     * Called from parseH2Request once a stream has seen its full
     * HEADERS plus optional DATA frames and the END_STREAM flag.
     * Encapsulates the response generation and serialization that
     * was previously inline in parseH2Request so that both the
     * "request fits in HEADERS alone" and "request has a body"
     * paths share the same response code.
     *
     * @param int $key connection key in $this->in_streams
     * @param resource $connection client socket
     * @param int $stream_id H2 stream id of the request
     * @param array $context request context to install in $_SERVER
     *      and friends; CONTENT key holds the request body if any
     * @return bool true after the response has been written
     */
    protected function dispatchH2Request($key, $connection,
        $stream_id, $context)
    {
        $conn = $this->connection($key);
        $hpack_encode = $conn?->protocol_state['hpack_encode']
            ?? new HPack();
        $_SESSION = [];
        $this->setGlobals($context, $conn);
        /*
            Make the H2 connection + stream available to
            $site->flush() so a route can stream a response by
            writing HEADERS and DATA frames directly. Cleared
            after dispatch.
         */
        $this->streaming_socket = $connection;
        $this->streaming_context = [
            'protocol' => 'h2',
            'stream_id' => $stream_id,
            'hpack_encode' => $hpack_encode,
            'key' => $key,
        ];
        $body = $this->getResponseData(false);
        $was_streaming = ($body === "" && $this->streaming_socket === null);
        $streaming_producer = $this->streaming_producer;
        $this->streaming_producer = null;
        $this->streaming_socket = null;
        $this->streaming_context = [];
        if ($body === self::RESPONSE_DEFERRED) {
            /* The route deferred itself; its response is framed and sent
               by the cooperative task on this same stream when it
               finishes. Send nothing here. Other streams on this
               connection keep being served meanwhile. */
            return true;
        }
        if ($was_streaming) {
            /*
                Route streamed via $site->flush(); response was
                already written to the wire and terminated by
                endStreaming(). Nothing more to send here.
             */
            return true;
        }
        $status = "200";
        if (preg_match("/HTTP\/[\d.]+ (\d+)/",
                $this->header_data, $matches)) {
            $status = $matches[1];
        }
        $resp_headers_data = [[":status", $status]];
        /*
            Parse user-set response headers from $this->header_data.
            The first line is the HTTP status line, subsequent lines
            are header_name: value pairs terminated by \r\n. HTTP/2
            requires lowercase header names (RFC 7540 sec 8.1.2) and
            forbids connection-specific headers (sec 8.1.2.2).
         */
        $forbidden = ["connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade"];
        $has_content_type = false;
        $has_content_length = false;
        $header_lines = explode("\r\n", $this->header_data);
        array_shift($header_lines);
        foreach ($header_lines as $line) {
            $colon = strpos($line, ":");
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = trim(substr($line, $colon + 1));
            if ($name === "" || $name[0] === ":"
                || in_array($name, $forbidden)) {
                continue;
            }
            if ($name === "content-type") {
                $has_content_type = true;
            }
            if ($name === "content-length") {
                $has_content_length = true;
            }
            $resp_headers_data[] = [$name, $value];
        }
        if (!$has_content_type) {
            $resp_headers_data[] =
                ["content-type", "text/html; charset=utf-8"];
        }
        if (!$has_content_length) {
            $resp_headers_data[] =
                ["content-length", (string) strlen($body)];
        }
        $resp_headers = new HeaderFrame($stream_id, $resp_headers_data);
        $resp_headers->flags->add("END_HEADERS");
        $out = $resp_headers->serialize($hpack_encode);
        /*
            Queue the HEADERS frame, then hand the body to the
            outbound flow-control engine: DATA frames are split at
            H2_MAX_FRAME_SIZE per RFC 7540 sec 4.2 and emitted only
            as far as the connection-level and stream-level send
            windows allow (sec 5.2); the remainder follows as the
            client returns credit with WINDOW_UPDATE frames. All
            frame bytes go through out_streams so
            processResponseStreams drains them asynchronously across
            event-loop iterations (a single non-blocking fwrite of a
            large buffer is only partially accepted once the kernel
            TCP send buffer fills). Finishing one response never
            closes the connection: processResponseStreams' is_h2
            branch clears only the out_streams entry.
         */
        $this->queueResponseData($key, $connection, $out);
        if ($streaming_producer !== null) {
            /*
                Streaming response: park the generator on the
                connection and prime it. refillStreamingGenerators
                advances it from the event loop as the peer takes
                data, so the body is produced incrementally and
                bounded in memory rather than sent all at once.
             */
            $conn->protocol_state['streaming_gen'][$stream_id] =
                $streaming_producer;
            $this->refillOneStreamingGenerator($key, $connection,
                $conn, $stream_id, $streaming_producer);
            return true;
        }
        $this->sendH2BodyPaced($key, $connection, $conn, $stream_id,
            $body);
        return true;
    }
    /**
     * Reads exactly $length bytes from $connection, blocking until
     * all bytes are available. Returns the binary string, or throws
     * if the connection closes before enough data arrives.
     *
     * This is the only remaining blocking reader on the connection
     * path; it is used solely by initH2Request to read the client's
     * initial SETTINGS frame at HTTP/2 establishment. The accept,
     * TLS handshake, protocol-detection, WebSocket, and per-request
     * HTTP/2 frame paths are all non-blocking (buffered across event
     * loop wakes). Converting the establishment read too would mean
     * deferring it across wakes the way the handshake step does.
     *
     * @param resource $connection client connection to read from;
     *      must be in blocking mode so fread won't return early
     * @param int $length number of bytes to read
     * @return string exactly $length binary bytes read from the
     *      connection
     */
    protected function readExactly($connection, $length)
    {
        if ($length === 0) {
            return "";
        }
        $buffer = "";
        $remaining = $length;
        while ($remaining > 0) {
            /*
                Suppress fread warning: the peer can close the
                connection mid-read without warning. PHP would
                otherwise emit a noisy SSL/broken-pipe warning
                even though the throw below already signals the
                condition cleanly to the caller's try/catch.
             */
            $chunk = @fread($connection, $remaining);
            if ($chunk === false || $chunk === "") {
                throw new \Exception(
                    "Connection closed after reading "
                    . strlen($buffer) . " of $length expected bytes");
            }
            $buffer .= $chunk;
            $remaining -= strlen($chunk);
        }
        return $buffer;
    }
    /**
     * Detects whether the most recently parsed HTTP request on a
     * connection is a WebSocket upgrade per RFC 6455 sec 4.1. A
     * valid upgrade has Upgrade: websocket, Connection: upgrade
     * (case-insensitive, possibly comma-separated for Connection),
     * and a 16-byte base64-encoded Sec-WebSocket-Key.
     *
     * @param int $key connection key in in_streams
     * @return bool true if this connection should be upgraded
     */
    protected function isWebSocketUpgrade($key)
    {
        $context = $this->in_streams[self::CONTEXT][$key];
        if (empty($context['HTTP_UPGRADE'])
            || empty($context['HTTP_CONNECTION'])
            || empty($context['HTTP_SEC_WEBSOCKET_KEY'])) {
            return false;
        }
        if (strtolower(trim($context['HTTP_UPGRADE'])) !== 'websocket') {
            return false;
        }
        $connection_lc = strtolower($context['HTTP_CONNECTION']);
        if (!str_contains($connection_lc, 'upgrade')) {
            return false;
        }
        /*
            RFC 6455 sec 4.1: Sec-WebSocket-Key is the base64
            encoding of a 16-byte random value. That is exactly 24
            characters ending with two padding characters '=='.
            Reject anything that does not match the shape so we do
            not feed garbage into sha1+base64 during the handshake
            response computation.
         */
        $client_key = trim($context['HTTP_SEC_WEBSOCKET_KEY']);
        if (!preg_match(
                '/^[A-Za-z0-9+\/]{22}==$/', $client_key)) {
            return false;
        }
        return true;
    }
    /**
     * Completes the WebSocket handshake for a connection that has
     * been validated as an upgrade request. Looks up the URI in
     * the WS routes table, sends the 101 Switching Protocols
     * response with the computed Sec-WebSocket-Accept header,
     * marks the connection as a WebSocket in its context, then
     * invokes the registered route handler exactly once with a
     * WebSocket object so it can register frame handlers and send
     * an initial greeting.
     *
     * @param int $key connection key in in_streams
     * @param resource $connection client socket
     * @return bool true on successful upgrade, false if no
     *      matching ws() route was found (caller falls back to
     *      normal HTTP processing which will produce a 404)
     */
    protected function handleWebSocketUpgrade($key, $connection)
    {
        $context = $this->in_streams[self::CONTEXT][$key];
        /*
            RFC 6455 sec 4.4: if the version is missing or not 13
            respond with 426 Upgrade Required and advertise the
            supported version so a confused client can retry. We
            send the response then close; the connection is not
            kept alive for a renegotiation since Atto handles each
            upgrade as a fresh request.
         */
        $version = trim(
            $context['HTTP_SEC_WEBSOCKET_VERSION'] ?? '');
        if ($version !== '13') {
            $body = "WebSocket version 13 required";
            $msg = "HTTP/1.1 426 Upgrade Required\r\n"
                . "Sec-WebSocket-Version: 13\r\n"
                . "Content-Type: text/plain\r\n"
                . "Content-Length: " . strlen($body) . "\r\n\r\n"
                . $body;
            @fwrite($connection, $msg);
            $this->shutdownHttpStream($key);
            return true;
        }
        if (!$this->checkWebSocketOrigin($context)) {
            $forbidden = "HTTP/1.1 403 Forbidden\r\n"
                . "Content-Type: text/plain\r\n"
                . "Content-Length: 16\r\n\r\n"
                . "Origin forbidden";
            @fwrite($connection, $forbidden);
            $this->shutdownHttpStream($key);
            return true;
        }
        $uri = $context['REQUEST_URI'] ?? '/';
        $question_pos = strpos($uri, '?');
        $path = ($question_pos === false) ? $uri
            : substr($uri, 0, $question_pos);
        if (!empty($this->base_path)
            && strpos($path, $this->base_path) === 0) {
            $path = substr($path, strlen($this->base_path));
        }
        if ($path === '') {
            $path = '/';
        }
        $callback = $this->findWsRoute($path);
        if ($callback === null) {
            return false;
        }
        $client_key = trim($context['HTTP_SEC_WEBSOCKET_KEY']);
        $accept = base64_encode(
            sha1($client_key . self::WS_MAGIC_GUID, true));
        $response = "HTTP/1.1 101 Switching Protocols\r\n"
            . "Upgrade: websocket\r\n"
            . "Connection: Upgrade\r\n"
            . "Sec-WebSocket-Accept: " . $accept . "\r\n"
            . "\r\n";
        $this->in_streams[self::DATA][$key] = "";
        $ws = new WebSocket($connection, $key, $this);
        /*
            Record the WebSocket upgrade on the persistent
            Connection object: protocol becomes 'ws',
            is_websocket flips true, and the WebSocket instance
            hangs off the Connection. The H1 dispatch loop,
            wsKeepalivePass, parseWsRequest, the response-drain
            path, and cullDeadStreams all read these here.
         */
        $open_connection = $this->connection($key);
        if ($open_connection !== null) {
            $open_connection->protocol = 'ws';
            $open_connection->is_websocket = true;
            $open_connection->ws = $ws;
        }
        $this->wsEnqueueWrite($key, $response);
        if (!$this->ws_keepalive_registered
            && $this->ws_keepalive_interval > 0) {
            $this->registerWsKeepalive();
        }
        /*
            What opened the socket is handed to the route on the socket
            itself rather than through the arrays an ordinary request
            uses. A socket outlives the request that opened it, and a
            finished response writes the session named by the cookie in
            those arrays, so a socket's cookie left sitting in them
            reaches into work that has nothing to do with it. The route
            reads the query and the cookies it was opened with from
            here, and nothing else of the request is touched.
         */
        $ws->query = [];
        parse_str($context['QUERY_STRING'] ?? '', $ws->query);
        $ws->cookies = [];
        if (!empty($context['HTTP_COOKIE'])) {
            foreach (explode(";", $context['HTTP_COOKIE']) as $sent_cookie) {
                $cookie_parts = explode("=", $sent_cookie, 2);
                if (count($cookie_parts) == 2) {
                    $ws->cookies[trim($cookie_parts[0])] =
                        trim($cookie_parts[1]);
                }
            }
        }
        try {
            $callback($ws);
        } catch (\Exception $e) {
            if ($ws->on_error !== null) {
                ($ws->on_error)($e->getMessage(), $ws);
            }
        }
        return true;
    }
    /**
     * Validates the Origin header of a WebSocket upgrade against
     * the allowed_origins list configured via setAllowedOrigins.
     * If no list is configured all origins pass. Requests with
     * no Origin header (typically non-browser clients) are
     * always allowed since the protection model targets the
     * browser same-origin policy.
     *
     * @param array $context request context with HTTP_* headers
     * @return bool true if the request should proceed, false if
     *      it should be rejected with 403
     */
    protected function checkWebSocketOrigin($context)
    {
        if (empty($this->ws_allowed_origins)) {
            return true;
        }
        if (empty($context['HTTP_ORIGIN'])) {
            return true;
        }
        return in_array($context['HTTP_ORIGIN'],
            $this->ws_allowed_origins, true);
    }
    /**
     * Completes a WebSocket opened by an HTTP/2 extended CONNECT. The
     * handshake happens in the header block rather than a 101 response:
     * a 200 on the connect stream accepts the tunnel, after which the
     * stream carries WebSocket frames inside DATA frames both ways. A
     * matching ws() route is required; without one the stream is
     * refused so the browser can fall back.
     *
     * @param int $key connection key in in_streams
     * @param resource $connection client socket
     * @param object $conn the Connection for this socket
     * @param int $stream_id the extended CONNECT stream's id
     * @param array $context request context from the CONNECT headers
     * @return bool false, matching the frame handler's contract that a
     *      handled frame wrote no ordinary response
     */
    protected function handleH2WebSocketConnect($key, $connection, $conn,
        $stream_id, $context)
    {
        if (!$this->checkWebSocketOrigin($context)) {
            $refusal = new RstStreamFrame($stream_id,
                self::H2_ERROR_REFUSED_STREAM);
            $this->writeFrameWhole($connection,
                $refusal->serialize());
            return false;
        }
        $uri = $context['REQUEST_URI'] ?? '/';
        $question_pos = strpos($uri, '?');
        $path = ($question_pos === false) ? $uri
            : substr($uri, 0, $question_pos);
        if (!empty($this->base_path)
            && strpos($path, $this->base_path) === 0) {
            $path = substr($path, strlen($this->base_path));
        }
        if ($path === '') {
            $path = '/';
        }
        $callback = $this->findWsRoute($path);
        if ($callback === null) {
            $refusal = new RstStreamFrame($stream_id,
                self::H2_ERROR_REFUSED_STREAM);
            $this->writeFrameWhole($connection,
                $refusal->serialize());
            return false;
        }
        $state = &$conn->protocol_state;
        $state['ws_carrier_streams'][$stream_id] = true;
        /*
            RFC 8441 sec 5: a 200 (no END_STREAM) on the connect
            stream accepts the tunnel. HPACK-encode the single
            :status header and send it as a HEADERS frame; the stream
            stays open for the DATA frames that follow.
         */
        $hpack_encode = $state['hpack_encode'] ?? new HPack();
        $state['hpack_encode'] = $hpack_encode;
        $headers = new HeaderFrame($stream_id, [[':status', '200']]);
        $headers->flags->add('END_HEADERS');
        $this->writeFrameWhole($connection,
            $headers->serialize($hpack_encode));
        $ws = new WebSocket($connection, $key, $this);
        $ws->h2_stream_id = $stream_id;
        $conn->is_websocket = true;
        if (!isset($conn->h2_websockets)
            || !is_array($conn->h2_websockets)) {
            $conn->h2_websockets = [];
        }
        $conn->h2_websockets[$stream_id] = $ws;
        if (!$this->ws_keepalive_registered
            && $this->ws_keepalive_interval > 0) {
            $this->registerWsKeepalive();
        }
        /* What opened the socket is handed to the socket itself, never
           through the arrays an ordinary request uses, for the reason
           given where a socket is upgraded from HTTP/1.1: a socket
           outlives its request, and a cookie left in those arrays
           reaches into work that has nothing to do with it. */
        $ws->query = [];
        parse_str($context['QUERY_STRING'] ?? '', $ws->query);
        $ws->cookies = [];
        if (!empty($context['HTTP_COOKIE'])) {
            foreach (explode(";", $context['HTTP_COOKIE'])
                as $sent_cookie) {
                $cookie_parts = explode("=", $sent_cookie, 2);
                if (count($cookie_parts) == 2) {
                    $ws->cookies[trim($cookie_parts[0])] =
                        trim($cookie_parts[1]);
                }
            }
        }
        try {
            $callback($ws);
        } catch (\Exception $problem) {
            if ($ws->on_error !== null) {
                ($ws->on_error)($problem->getMessage(), $ws);
            }
        }
        return false;
    }
    /**
     * Feeds inbound bytes from a WebSocket-carrier stream's DATA
     * frames to the WebSocket frame parser for that stream, and
     * dispatches whole frames. A DATA frame that ends the stream is
     * treated as the client closing the socket.
     *
     * @param int $key connection key in in_streams
     * @param int $stream_id the carrier stream's id
     * @param string $data raw WebSocket bytes from the DATA frame
     * @param bool $ended whether the DATA frame carried END_STREAM
     */
    protected function feedH2WebSocket($key, $stream_id, $data, $ended)
    {
        $conn = $this->connection($key);
        $ws = $conn?->h2_websockets[$stream_id] ?? null;
        if ($ws === null) {
            return;
        }
        $ws->input_buffer .= $data;
        $ws->last_pong_time = time();
        $keep_open = true;
        while ($keep_open) {
            $parsed = WebSocketFrame::parseBuffer($ws->input_buffer);
            if ($parsed === null) {
                break;
            }
            $ws->input_buffer = substr($ws->input_buffer,
                $parsed['consumed']);
            $keep_open = $this->dispatchWsFrame($key, $ws,
                $parsed['frame']);
        }
        /* A browser leaving a page closes the WebSocket with a close
           frame, which carries no HTTP/2 end-of-stream flag, so the
           carrier has to be let go when the socket itself closes as
           well as when the stream ends. Without this the stream, the
           socket and its push timer stayed behind, and the timer went
           on writing to a connection that was gone. */
        if ($ended || !$keep_open || $ws->closed) {
            /* A close frame has already run the socket's close callback
               in dispatchWsFrame, so it is only run here for the other
               ways a carrier ends. */
            if ($ws->on_close !== null && !$ws->closed) {
                ($ws->on_close)($ws);
            }
            unset($conn->protocol_state['ws_carrier_streams'][$stream_id]);
            unset($conn->h2_websockets[$stream_id]);
            /* The ending frame joins the same queue the close echo went
               into, so it leaves after that echo rather than ahead of
               it, which would end the stream under a frame still to
               come. */
            $end_frame = new DataFrame($stream_id, "");
            $end_frame->flags->add('END_STREAM');
            $this->wsEnqueueWrite($key, $end_frame->serialize());
        }
    }
    /**
     * Queues WebSocket frame bytes to be sent inside an HTTP/2 DATA
     * frame on a carrier stream. The DATA frame is built now and
     * handed to the same out_streams buffer the rest of the h2 write
     * path drains, so ordering with any other bytes on the connection
     * is preserved.
     *
     * @param int $key connection key in in_streams
     * @param int $stream_id the carrier stream's id
     * @param string $ws_frame the built WebSocket frame
     */
    public function wsEnqueueH2Write($key, $stream_id, $ws_frame)
    {
        /* A DATA frame's payload may not exceed the peer's maximum
           frame size, so a WebSocket frame larger than that is sent
           as several DATA frames on the same stream. The WebSocket
           frame itself is unbroken; only its carriage is split. */
        $offset = 0;
        $total = strlen($ws_frame);
        do {
            $piece = substr($ws_frame, $offset,
                self::H2_MAX_FRAME_SIZE);
            $data_frame = new DataFrame($stream_id, $piece);
            $this->wsEnqueueWrite($key, $data_frame->serialize());
            $offset += self::H2_MAX_FRAME_SIZE;
        } while ($offset < $total);
    }

    /**
     * Sends already-built WebSocket frame bytes to a socket by whichever
     * way that socket runs: wrapped in HTTP/2 data frames when it rides
     * an extended CONNECT stream, or straight to the connection when it
     * is an HTTP/1.1 upgrade. Control frames answered deep in the frame
     * dispatch go through here, since writing them raw onto an HTTP/2
     * connection corrupts its framing.
     *
     * @param int $key connection key in in_streams
     * @param object $ws the socket the frame belongs to
     * @param string $ws_frame the built WebSocket frame
     */
    protected function wsSendFrame($key, $ws, $ws_frame)
    {
        if ($ws->h2_stream_id !== 0) {
            $this->wsEnqueueH2Write($key, $ws->h2_stream_id, $ws_frame);
            return;
        }
        $this->wsEnqueueWrite($key, $ws_frame);
    }
    /**
     * Says whether a drained connection is one that carries nothing but
     * a WebSocket, so its finished write needs no further work beyond
     * clearing the entry. Only a connection upgraded from HTTP/1.1 is
     * such a one. An HTTP/2 connection can carry sockets and ordinary
     * replies at the same time, and both are frames in one buffer, so it
     * keeps to the HTTP/2 path where the rest of a large reply is sent.
     * Treating it as a socket left a big reply unsent after its first
     * slice and the reader waited on it forever.
     *
     * @param object $conn the connection whose write just drained, or
     *      null when it has already been taken down
     * @return bool true when the socket path is the right one
     */
    protected function usesSocketDrain($conn)
    {
        if ($conn === null) {
            return false;
        }
        if ($conn->protocol === 'h2') {
            return false;
        }
        return (bool)$conn->is_websocket;
    }
    /**
     * Appends a binary blob (already-built WebSocket frame, or
     * the 101 handshake response) to the out_streams buffer for
     * a connection. The event loop drains the buffer to the
     * socket as it becomes writable, handling partial writes
     * via processResponseStreams. Sets up the out_streams entry
     * if none exists yet for this key.
     *
     * @param int $key connection key
     * @param string $data binary bytes to send
     */
    public function wsEnqueueWrite($key, $data)
    {
        if (empty($this->in_streams[self::CONNECTION][$key])) {
            /* The connection was torn down before this write. A push
               that fires in the gap between a socket closing and its
               timer being cleared lands here; there is nothing to
               write to, so the write is dropped rather than reaching
               into a connection array that no longer holds the key. */
            return;
        }
        if (empty($this->out_streams[self::CONNECTION][$key])) {
            $this->out_streams[self::CONNECTION][$key] =
                $this->in_streams[self::CONNECTION][$key];
            $this->out_streams[self::DATA][$key] = $data;
            $this->out_streams[self::DATA_OFFSET][$key] = 0;
            /*
                The drain code in processResponseStreams reads
                the WebSocket flag from the Connection object,
                so out_streams[CONTEXT] no longer needs an
                IS_WEBSOCKET marker. An empty array is enough
                to satisfy code that looks up the entry.
             */
            $this->out_streams[self::CONTEXT][$key] = [];
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        } else {
            $this->out_streams[self::DATA][$key] .= $data;
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
        }
    }
    /**
     * Registers the periodic keepalive timer that walks all
     * established WebSocket connections, sends a PING to those
     * that have not received any frame in the last
     * ws_keepalive_interval seconds, and closes those that have
     * not received any frame in the last ws_keepalive_timeout
     * seconds. Called once on the first successful WebSocket
     * upgrade.
     */
    protected function registerWsKeepalive()
    {
        $this->ws_keepalive_registered = true;
        $this->setTimer($this->ws_keepalive_interval, function () {
            $this->wsKeepalivePass();
        }, true);
    }
    /**
     * One pass of the keepalive scan. Sends a PING to each
     * idle WebSocket and closes any that are past the
     * keepalive timeout without a recent frame from the client.
     */
    protected function wsKeepalivePass()
    {
        $now = time();
        foreach ($this->connections as $key => $conn) {
            if (!$conn->is_websocket) {
                continue;
            }
            /* A connection holds either one socket from an HTTP/1.1
               upgrade or any number carried on HTTP/2 connect streams,
               and both kinds want the same keepalive. */
            $sockets = [];
            if ($conn->ws !== null) {
                $sockets[] = $conn->ws;
            }
            foreach (($conn->h2_websockets ?? []) as $carried) {
                $sockets[] = $carried;
            }
            foreach ($sockets as $ws) {
                if ($ws->closed) {
                    continue;
                }
                if ($now - $ws->last_pong_time
                    > $this->ws_keepalive_timeout) {
                    $this->shutdownHttpStream($key);
                    if ($ws->on_close !== null) {
                        ($ws->on_close)($ws);
                    }
                    continue;
                }
                if ($now - $ws->last_pong_time
                    >= $this->ws_keepalive_interval) {
                    $ws->last_ping_time = $now;
                    $this->wsSendFrame($key, $ws,
                        WebSocketFrame::build(self::WS_OPCODE_PING,
                            ""));
                }
            }
        }
    }
    /**
     * Looks up a registered ws() route that matches the given
     * path. Supports the same {var_name} placeholder and *
     * wildcard syntax as get/post routes; matched placeholders
     * are written into $_REQUEST so the handler can read them.
     *
     * @param string $path request URI path with base_path stripped
     * @return callable|null matched callback, or null if no
     *      ws() route matches
     */
    protected function findWsRoute($path)
    {
        if (empty($this->routes['WS'])) {
            return null;
        }
        foreach ($this->routes['WS'] as $route_pattern => $callback) {
            if ($route_pattern === $path) {
                return $callback;
            }
            $regex = preg_replace('/\{([^}]+)\}/',
                '(?P<$1>[^/]+)', $route_pattern);
            $regex = str_replace('*', '.*', $regex);
            $regex = '#^' . $regex . '$#';
            if (preg_match($regex, $path, $matches)) {
                foreach ($matches as $name => $value) {
                    if (!is_int($name)) {
                        $_REQUEST[$name] = $value;
                        $_GET[$name] = $value;
                    }
                }
                return $callback;
            }
        }
        return null;
    }
    /**
     * Reads one WebSocket frame from an established connection
     * and dispatches it. Text and binary frames are buffered into
     * the WebSocket fragment buffer and, when the FIN bit arrives,
     * delivered to the registered onMessage callback. Ping frames
     * are answered with a pong inline. Close frames trigger the
     * onClose callback and shut down the stream. Frames exceeding
     * WS_MAX_MESSAGE_SIZE cause the connection to be closed with
     * status code 1009.
     *
     * @param int $key connection key in in_streams
     * @param resource $connection client socket to read from
     */
    public function parseWsRequest($key, $connection)
    {
        $conn = $this->connection($key);
        $ws = $conn?->ws;
        if ($ws === null) {
            $this->shutdownHttpStream($key);
            return;
        }
        $chunk = @fread($connection, self::WS_READ_CHUNK_SIZE);
        if ($chunk === false || ($chunk === '' && feof($connection))) {
            if ($ws->on_close !== null) {
                ($ws->on_close)($ws);
            }
            $this->shutdownHttpStream($key);
            return;
        }
        if ($chunk === '') {
            return;
        }
        $ws->input_buffer .= $chunk;
        /*
            Any bytes from the client count as proof of life for
            the keepalive timer, not just PONG frames.
         */
        $ws->last_pong_time = time();
        /*
            Parse every complete frame now buffered. A single
            readable event may carry several frames, and a frame
            may span several events; parseBuffer returns null when
            the buffer does not yet hold a whole frame, leaving the
            partial bytes for the next event.
         */
        while (true) {
            $parsed = WebSocketFrame::parseBuffer($ws->input_buffer);
            if ($parsed === null) {
                break;
            }
            $ws->input_buffer = substr($ws->input_buffer,
                $parsed['consumed']);
            $keep_open = $this->dispatchWsFrame($key, $ws,
                $parsed['frame']);
            if (!$keep_open) {
                break;
            }
        }
    }
    /**
     * Handles one fully parsed inbound WebSocket frame: enforces
     * the masking and size rules, answers control frames (close,
     * ping), and assembles text and binary messages across
     * continuation frames, invoking the registered onMessage
     * callback when a message is complete. Returns whether the
     * connection should stay open for further frames; a close,
     * protocol error, or oversize message returns false so the
     * caller stops parsing the buffer.
     *
     * @param int $key stream key of the connection
     * @param WebSocket $ws the per-connection WebSocket handle
     * @param array $frame parsed frame from parseBuffer
     * @return bool true to keep processing further frames, false to
     *      stop (the connection was closed or failed)
     */
    protected function dispatchWsFrame($key, $ws, $frame)
    {
        if (!empty($frame['too_large'])) {
            if ($ws->on_error !== null) {
                ($ws->on_error)("Message exceeds maximum size", $ws);
            }
            $ws->close(1009, "Message too big");
            return false;
        }
        if (!$frame['masked']) {
            /*
                Per RFC 6455 sec 5.1 every client to server frame
                must be masked. An unmasked frame is a protocol
                error and the connection must be closed.
             */
            $ws->close(1002, "Unmasked client frame");
            return false;
        }
        $opcode = $frame['opcode'];
        if ($opcode === self::WS_OPCODE_CLOSE) {
            if (!$ws->closed) {
                $ws->closed = true;
                $this->wsSendFrame($key, $ws,
                    WebSocketFrame::build(self::WS_OPCODE_CLOSE,
                        $frame['payload']));
            }
            if ($ws->on_close !== null) {
                ($ws->on_close)($ws);
            }
            return false;
        }
        if ($opcode === self::WS_OPCODE_PING) {
            $this->wsSendFrame($key, $ws,
                WebSocketFrame::build(self::WS_OPCODE_PONG,
                    $frame['payload']));
            return true;
        }
        if ($opcode === self::WS_OPCODE_PONG) {
            return true;
        }
        if ($opcode === self::WS_OPCODE_TEXT
            || $opcode === self::WS_OPCODE_BINARY) {
            $ws->fragment_buffer = $frame['payload'];
            $ws->fragment_opcode = $opcode;
        } else if ($opcode === self::WS_OPCODE_CONTINUATION) {
            if (strlen($ws->fragment_buffer) + $frame['length']
                > self::WS_MAX_MESSAGE_SIZE) {
                $ws->close(1009, "Message too big");
                return false;
            }
            $ws->fragment_buffer .= $frame['payload'];
        } else {
            /*
                Reserved opcode. RFC 6455 sec 5.2 says the receiver
                must fail the connection.
             */
            $ws->close(1002, "Unknown opcode");
            return false;
        }
        if ($frame['fin']) {
            $message = $ws->fragment_buffer;
            $ws->fragment_buffer = "";
            if ($ws->on_message !== null) {
                try {
                    ($ws->on_message)($message, $ws);
                } catch (\Exception $error) {
                    if ($ws->on_error !== null) {
                        ($ws->on_error)($error->getMessage(), $ws);
                    }
                }
            }
        }
        return true;
    }
    /**
     * Gets info about an incoming request stream and uses this to set up
     * an initial stream context. This context is used to populate the $_SERVER
     * variable when the request is later processed.
     *
     * @param int $key id of request stream to initialize context for
     * @param array $additional_context any additional key value field to
     *   set for the stream's context
     */
    protected function initRequestStream($key, $additional_context = [])
    {
        /*
            Peer and local socket addresses live on the persistent
            Connection (resolved once at accept). Falling back to
            stream_socket_get_name here covers any legacy entry
            point that calls initRequestStream without first
            registering a Connection (none in tree, but defensive).
         */
        $conn = $this->connection($key);
        if ($conn !== null) {
            $remote_addr = $conn->remote_addr;
            $remote_port = $conn->remote_port;
            $server_addr = $conn->server_addr;
            $server_port = $conn->server_port;
        } else {
            $resource = $this->in_streams[self::CONNECTION][$key];
            $remote_name = stream_socket_get_name($resource, true);
            $server_name = stream_socket_get_name($resource, false);
            list($remote_addr, $remote_port) =
                $this->splitAddressPort($remote_name);
            list($server_addr, $server_port) =
                $this->splitAddressPort($server_name);
        }
        $this->in_streams[self::CONTEXT][$key] = array_merge(
            [
                'REQUEST_HEAD_PARSED' => false,
                'REQUEST_METHOD' => false,
                "REMOTE_ADDR" => $remote_addr,
                "REMOTE_PORT" => $remote_port,
                "REQUEST_TIME" => time(),
                "REQUEST_TIME_FLOAT" => microtime(true),
                "SERVER_ADDR" => $server_addr,
                "SERVER_PORT" => $server_port,
            ],
            $additional_context
        );
        $this->in_streams[self::DATA][$key] = "";
        $this->in_streams[self::MODIFIED_TIME][$key] = time();
    }
    /**
     * Splits a socket name string returned by stream_socket_get_name
     * into separate address and port components. Handles IPv4 and
     * hostname forms ("1.2.3.4:80", "host.example.com:80") as well
     * as the bracketed IPv6 form ("[::1]:80"). For IPv6 the
     * brackets are stripped from the address so downstream code that
     * compares to bare addresses (inet_pton, allowlists) works
     * uniformly across address families.
     *
     * @param string $name socket name as returned by
     *      stream_socket_get_name
     * @return array two-element list [address, port] with both
     *      values as strings
     */
    protected function splitAddressPort($name)
    {
        if ($name === false || $name === null || $name === "") {
            return ["", ""];
        }
        if (str_starts_with($name, "[")) {
            $close = strpos($name, "]");
            if ($close === false) {
                return [$name, ""];
            }
            $addr = substr($name, 1, $close - 1);
            $rest = substr($name, $close + 1);
            $port = ($rest !== "" && $rest[0] === ":")
                ? substr($rest, 1) : "";
            return [$addr, $port];
        }
        $colon = strrpos($name, ":");
        if ($colon === false) {
            return [$name, ""];
        }
        return [substr($name, 0, $colon),
            substr($name, $colon + 1)];
    }
    /**
     * Reads the next piece of a file-backed reply into the send buffer,
     * and lets the file go once every byte of it has been read. A reply
     * that is a file on disk is sent this way rather than read into a
     * string, so its size costs the server a fixed amount of memory
     * rather than its own length.
     *
     * @param string $key which connection is being sent to
     * @return void
     */
    protected function refillFromFile($key)
    {
        $backing = $this->out_streams[self::DATA_FILE][$key] ?? null;
        if (empty($backing)) {
            return;
        }
        $context = $this->out_streams[self::CONTEXT][$key] ?? [];
        $read_this_pass = self::OUT_FILE_STEP;
        if (empty($context['MACHINE_REQUEST'])) {
            /* Every file being sent takes a turn of this loop, so one
               block of IP addresses opening several at once would take
               several turns and leave less of the link for every other
               reader. An IP block keeps one turn however many files it
               opens, and those files divide that turn between them. A
               file the request marks as MACHINE_REQUEST, one going to
               another machine of the same site, keeps a whole turn. */
            $receiving_ip_block = self::ipBlock(
                $context['REMOTE_ADDR'] ?? "");
            $files_this_ip_block = $this->ipBlockFileSends(
                $receiving_ip_block);
            if ($files_this_ip_block > 1) {
                $read_this_pass = max((int)($read_this_pass /
                    $files_this_ip_block), 1);
            }
        }
        $piece = fread($backing["handle"], $read_this_pass);
        $writer = $backing["growing"] ?? null;
        if ($writer !== null) {
            $this->refillFromGrowingFile($key, $backing, $piece);
            return;
        }
        if ($piece === false || $piece === "") {
            $this->letGoOfSendFile($key, $backing);
            return;
        }
        $this->out_streams[self::DATA][$key] = $piece;
        $this->out_streams[self::DATA_OFFSET][$key] = 0;
        if (feof($backing["handle"])) {
            $this->letGoOfSendFile($key, $backing);
        }
    }
    /**
     * refillFromGrowingFile puts the next piece of a file that is still
     * being written into an HTTP/1.1 send buffer, as one chunk of a
     * chunked reply: the piece's length in hexadecimal, a line end, the
     * piece and a line end. refillFromFile calls it with the piece it
     * read. When the writer has finished and nothing is left, the empty
     * last chunk ends the reply and the file is let go. When the writer
     * has not finished and nothing new is there, the connection is
     * parked in $parked_files, out of the write set, so the loop does not
     * go round with nothing to write.
     *
     * @param string $key which connection is being sent to
     * @param array $backing what was recorded about the file, whose
     *      growing entry is the deferred task writing it
     * @param string|bool $piece what was just read from the file
     * @return void
     */
    protected function refillFromGrowingFile($key, $backing, $piece)
    {
        if ($piece !== false && $piece !== "") {
            $this->out_streams[self::DATA][$key] = dechex(strlen($piece)) .
                "\x0D\x0A" . $piece . "\x0D\x0A";
            $this->out_streams[self::DATA_OFFSET][$key] = 0;
            $this->out_streams[self::MODIFIED_TIME][$key] = time();
            return;
        }
        if (!empty($backing["growing"]->growing_done)) {
            $this->out_streams[self::DATA][$key] = "0\x0D\x0A\x0D\x0A";
            $this->out_streams[self::DATA_OFFSET][$key] = 0;
            $this->letGoOfSendFile($key, $backing);
            return;
        }
        $this->out_streams[self::DATA][$key] = "";
        $this->out_streams[self::DATA_OFFSET][$key] = 0;
        $this->parked_files[$key] =
            $this->out_streams[self::CONNECTION][$key];
        unset($this->out_streams[self::CONNECTION][$key]);
    }
    /**
     * unparkGrowingFiles puts back into the write set each HTTP/1.1
     * connection refillFromGrowingFile parked, once its file has bytes
     * not yet sent or its writer has finished, so the next pass sends
     * them or ends the reply. A connection that has closed meanwhile has
     * its file let go. refillStreamingGenerators calls it on each pass
     * of the loop.
     *
     * @return void
     */
    protected function unparkGrowingFiles()
    {
        foreach ($this->parked_files as $key => $socket) {
            $backing = $this->out_streams[self::DATA_FILE][$key] ?? null;
            if (empty($backing)) {
                unset($this->parked_files[$key]);
                continue;
            }
            if (!isset($this->in_streams[self::CONNECTION][$key])) {
                unset($this->parked_files[$key]);
                $this->letGoOfSendFile($key, $backing);
                continue;
            }
            $stat = fstat($backing["handle"]);
            $sent_up_to = ftell($backing["handle"]);
            if (empty($backing["growing"]->growing_done) &&
                ($stat === false || $stat["size"] <= $sent_up_to)) {
                continue;
            }
            unset($this->parked_files[$key]);
            $this->out_streams[self::CONNECTION][$key] = $socket;
        }
    }
    /**
     * Closes a file that has been sent and, where it was made only to be
     * sent, deletes it. A pack built for a git pull is such a file: once
     * the client has it there is nothing left to keep.
     *
     * @param string $key which connection was being sent to
     * @param array $backing what was recorded about the file
     * @return void
     */
    protected function letGoOfSendFile($key, $backing)
    {
        fclose($backing["handle"]);
        unset($this->out_streams[self::DATA_FILE][$key]);
        if (!empty($backing["remove_after"]) && is_file($backing["path"])) {
            unlink($backing["path"]);
        }
    }
    /**
     * Says that the rest of a reply is the given file, so it is drained
     * from disk a piece at a time rather than held in memory. Used for a
     * reply built as a file, such as the pack a git pull asks for.
     *
     * @param string $key which connection is being sent to
     * @param string $path the file holding the rest of the reply
     * @param bool $remove_after whether to delete the file once every byte
     *      of it has gone out, for a file made only to be sent
     * @param object|null $writer the deferred task still writing the file,
     *      whose growing_done field says when it has finished; the file is
     *      then sent in chunks as it grows. null for a finished file.
     * @return bool whether the file could be opened
     */
    protected function sendRestFromFile($key, $path, $remove_after = false,
        $writer = null)
    {
        $handle = fopen($path, "rb");
        if ($handle === false) {
            return false;
        }
        $this->out_streams[self::DATA_FILE][$key] = ["path" => $path,
            "handle" => $handle, "remove_after" => $remove_after,
            "growing" => $writer];
        return true;
    }
    /**
     * ipBlockFileSends counts the files this server is part way
     * through sending to one block of IP addresses.
     *
     * A file being sent takes a turn of the write loop each pass, so
     * several files going to the same place at once take several turns
     * and leave less of the link for every other reader. refillFromFile
     * asks this so it can divide one block's turn among the files that
     * block is being sent. A whole IP block is counted rather than a
     * single IP address because one client can make its requests from
     * many IP addresses in the same block. Files a request marks as
     * MACHINE_REQUEST, sent to another machine of the same site, are not
     * counted, since they are not what this limits.
     *
     * @param string $ip_block the leading bytes of an IP address, as
     *      ipBlock gives them
     * @return int how many file sends to that IP block are in progress
     */
    public function ipBlockFileSends($ip_block)
    {
        $found = 0;
        foreach ($this->out_streams[self::DATA_FILE] as $key => $backing) {
            $context = $this->out_streams[self::CONTEXT][$key] ?? [];
            if (!empty($context['MACHINE_REQUEST'])) {
                continue;
            }
            $receiving_ip_address = $context['REMOTE_ADDR'] ?? "";
            if ($receiving_ip_address !== "" &&
                self::ipBlock($receiving_ip_address) === $ip_block) {
                $found++;
            }
        }
        return $found;
    }
    /**
     * ipBlock gives the part of an IP address that says which block of
     * IP addresses it belongs to.
     *
     * An internet provider hands out IP addresses in blocks, so one
     * client can make its requests from many IP addresses that differ
     * only in their last part. Keeping the leading bytes puts all of
     * those under one count. Three bytes are kept of an IPv4 address,
     * which is four bytes long, and eight of an IPv6 address, which is
     * sixteen: those are the smallest blocks a provider hands out as a
     * unit.
     *
     * @param string $ip_address the IP address a request came from,
     *      written the way a person writes one
     * @return string the leading bytes of that IP address, or the
     *      string given where it cannot be read as an IP address
     */
    public static function ipBlock($ip_address)
    {
        $bytes = @inet_pton($ip_address);
        if ($bytes === false) {
            return $ip_address;
        }
        $keep = (strlen($bytes) == self::IPV4_ADDRESS_BYTES) ?
            self::IPV4_BLOCK_BYTES : self::IPV6_BLOCK_BYTES;
        return substr($bytes, 0, $keep);
    }
    /**
     * Used to send response data to out stream for which responses have not
     * been written.
     *
     * @param array $out_streams_with_data rout streams that are ready
     *      to send more response data
     */
    protected function processResponseStreams($out_streams_with_data)
    {
        foreach ($out_streams_with_data as $out_stream) {
            $key = (int)$out_stream;
            if (!isset($this->out_streams[self::DATA][$key])) {
                /*
                    The select snapshot was taken before this
                    iteration; request-side processing in the same
                    event-loop tick can tear a connection down
                    (peer hung up, malformed frame) after select
                    reported it writable. Nothing to send for a
                    dismantled entry.
                 */
                continue;
            }
            $data = $this->out_streams[self::DATA][$key];
            $offset =
                $this->out_streams[self::DATA_OFFSET][$key] ?? 0;
            $unsent = strlen($data) - $offset;
            if ($unsent <= 0 &&
                !empty($this->out_streams[self::DATA_FILE][$key])) {
                /* The rest of this reply is a file, so the next piece of
                   it is read in only once what came before has gone out.
                   A reply larger than the server's memory travels this
                   way a piece at a time. */
                $this->refillFromFile($key);
                $data = $this->out_streams[self::DATA][$key];
                $offset =
                    $this->out_streams[self::DATA_OFFSET][$key] ?? 0;
                $unsent = strlen($data) - $offset;
            }
            //suppress connection reset notices
            set_error_handler(null);
            /*
                fwrite needs the bytes as a string, so the slice we
                hand it has to be copied out of the buffer. Copy at
                most one MAX_IO_LEN block per pass instead of the
                whole unsent tail: a multi-hundred-megabyte response
                would otherwise duplicate its entire remaining body
                here, and that copy on top of the buffer already in
                memory was large enough to exhaust the process (a
                ~1.5 GB response in production did exactly this). The
                socket only drains a bounded amount per writable
                event anyway, so capping the slice costs no
                throughput; $offset still advances (with periodic
                compaction below) so $data is never rewritten per
                pass.
             */
            $chunk_len = min($unsent,
                $this->default_server_globals['MAX_IO_LEN']);
            $tail = substr($data, $offset, $chunk_len);
            $written = @fwrite($out_stream, $tail);
            restore_error_handler();
            $remaining = ($written === false) ? 0
                : max(0, $unsent - $written);
            // a reply whose rest is still in a file is not finished
            if ($written !== false && $remaining == 0 &&
                !empty($this->out_streams[self::DATA_FILE][$key])) {
                $remaining = 1;
            }
            if ($written > 0) {
                $offset += $written;
                $this->out_streams[self::DATA_OFFSET][$key] =
                    $offset;
                /*
                    Periodic compaction: when the head pointer
                    has crossed OUT_DATA_COMPACT_THRESHOLD and at
                    least half the buffer is consumed prefix,
                    drop the consumed prefix in one shot. This
                    keeps memory bounded on long-lived
                    connections regardless of how slowly the
                    peer drains.
                 */
                if ($offset >= self::OUT_DATA_COMPACT_THRESHOLD
                    && $offset * 2 >= strlen($data)) {
                    $this->out_streams[self::DATA][$key] =
                        substr($data, $offset);
                    $this->out_streams[self::DATA_OFFSET][$key] =
                        0;
                }
                $this->out_streams[self::MODIFIED_TIME][$key] = time();
            }
            if ($remaining == 0) {
                $context = $this->out_streams[self::CONTEXT][$key]
                    ?? [];
                $connection = $this->connection($key);
                $is_h2 = $connection?->protocol === 'h2';
                $is_ws = $this->usesSocketDrain($connection);
                if ($is_ws) {
                    /*
                        WebSocket: drain complete, but the
                        underlying connection stays open for
                        future frames. Just remove this entry
                        from out_streams; the in_streams entry
                        is unaffected. If the WebSocket has
                        been marked closed, this drain was the
                        outbound CLOSE frame, so now it is safe
                        to tear down the connection.
                     */
                    $ws = $connection->ws;
                    unset($this->out_streams[self::CONNECTION][$key],
                        $this->out_streams[self::DATA][$key],
                        $this->out_streams[self::DATA_OFFSET][$key],
                        $this->out_streams[self::DATA_FILE][$key],
                        $this->out_streams[self::CONTEXT][$key],
                        $this->out_streams[self::MODIFIED_TIME][$key]);
                    if ($ws?->closed) {
                        $this->shutdownHttpStream($key);
                    }
                } else if ($is_h2) {
                    /*
                        H2: a single connection multiplexes many
                        streams, so finishing one response never
                        means closing the connection. The drained
                        buffer may also just be the latest slice of
                        bigger responses still pending on this
                        connection: queue each pending stream's next
                        slice (round robin, so a large response and
                        a page of small ones interleave), and only
                        clear the out_streams entry once nothing is
                        left to queue. in_streams keeps the
                        connection alive for the next frame either
                        way.
                     */
                    $this->pumpH2AllPendingSend($key, $out_stream,
                        $connection);
                    if ((strlen($this->out_streams[self::DATA][$key]
                        ?? "") - ($this->out_streams[
                        self::DATA_OFFSET][$key] ?? 0)) <= 0) {
                        /*
                            Nothing unsent after pumping (the DATA
                            string may still hold a fully consumed
                            prefix; what matters is bytes past the
                            head pointer). Clear the entry so the
                            connection stops selecting writable;
                            otherwise an idle kept-alive connection
                            spins the event loop at full speed
                            until the peer hangs up.
                         */
                        $this->shutdownHttpWriteStream($key);
                    }
                } else if ((!empty($context['HTTP_CONNECTION']) &&
                    strtolower($context['HTTP_CONNECTION']) == 'close') ||
                    empty($context['SERVER_PROTOCOL']) ||
                    $context['SERVER_PROTOCOL'] == 'HTTP/1.0') {
                    if (empty($context["PRE_BAD_RESPONSE"])) {
                        $this->shutdownHttpStream($key);
                    } else {
                        /* An error response is sent in full before the
                           client stops sending, so only this side is
                           closed: the client reads the response, then
                           closes, and processRequestStreams closes the
                           rest. Closing both sides with request bytes
                           still arriving would reset the connection,
                           and the client could lose the response. */
                        @stream_socket_shutdown($out_stream,
                            STREAM_SHUT_WR);
                        $this->shutdownHttpWriteStream($key);
                    }
                } else {
                    $this->shutdownHttpWriteStream($key);
                }
            }
        }
    }
    /**
     * Takes the string $data recently read from the request stream with
     * id $key, tacks that on to the previous received data. If this completes
     * an HTTP request then the request headers and request are parsed
     *
     * @param int $key id of request stream to process data for
     * @param string $data from request stream
     * @return bool whether the request is complete
     */
    protected function parseRequest($key, $data)
    {
        $this->in_streams[self::DATA][$key] .= $data;
        if (strlen($this->in_streams[self::DATA][$key]) <
            self::LEN_LONGEST_HTTP_METHOD + 1) {
            return false;
        }
        $context = $this->in_streams[self::CONTEXT][$key];
        if (!isset($context['REQUEST_HEAD_PARSED']))
            $context['REQUEST_HEAD_PARSED'] = false;
        if (!$context['REQUEST_METHOD']) {
            $request_start = substr($this->in_streams[self::DATA][$key], 0,
                self::LEN_LONGEST_HTTP_METHOD + 1);
            $start_parts = explode(" ", $request_start);
            if (!in_array($start_parts[0], $this->http_methods)) {
                $this->initializeBadRequestResponse($key);
                return true;
            }
        }

        $data = $this->in_streams[self::DATA][$key];
        $eol = "\x0D\x0A"; /*
            spec says use CRLF, but hard to type as human on Mac or Linux
            so relax spec for inputs. (Follow spec exactly for output)
        */
        if (!$context['REQUEST_HEAD_PARSED']) {
            if (!str_contains($data, "\x0D\x0A\x0D\x0A") &&
                !str_contains($data, "\x0D\x0D")) {
                return false;
            }
            if (($end_head_pos = strpos($data, "$eol$eol")) === false) {
                $eol = \PHP_EOL;
                $end_head_pos = strpos($data, "$eol$eol");
            }
            $context['REQUEST_HEAD_PARSED'] = true;
            $next_line_pos = strpos($data, $eol);
            $first_line = substr($this->in_streams[self::DATA][$key], 0,
                $next_line_pos);
            $first_lines_regex = "/^(CONNECT|COPY|DELETE|ERROR|GET|HEAD|".
                "LOCK|MKCALENDAR|MKCOL|MOVE|OPTIONS|POST|PROPFIND|".
                "PROPPATCH|PUT|REPORT|TRACE|UNLOCK)".
                "\s+([^\s]+)\s+(HTTP\/\d+\.\d+)/";
            if (!preg_match($first_lines_regex, $first_line, $matches)) {
                $this->initializeBadRequestResponse($key);
                return true;
            }
            list(, $context['REQUEST_METHOD'], $context['REQUEST_URI'],
                $context['SERVER_PROTOCOL']) = $matches;

            if (($question_pos = strpos($context['REQUEST_URI'],"?"))===false) {
                $context['PHP_SELF'] = $context['REQUEST_URI'];
                $context['QUERY_STRING'] = "";
            } else {
                $context['PHP_SELF'] = substr($context['REQUEST_URI'], 0,
                    $question_pos);
                $context['QUERY_STRING'] = substr($context['REQUEST_URI'],
                    $question_pos + 1);
            }
            $context['SCRIPT_FILENAME'] =
                $this->default_server_globals['DOCUMENT_ROOT'] .
                $context['PHP_SELF'];
            $header_line_regex = "/^([^\:]+)\:(.+)/";
            while($next_line_pos < $end_head_pos) {
                $last_pos = $next_line_pos + 2;
                $next_line_pos = strpos($data, $eol, $last_pos);
                if ($next_line_pos == $last_pos) {
                    break;
                }
                $line = substr($data, $last_pos, $next_line_pos - $last_pos);
                if (!preg_match($header_line_regex, $line, $matches)) {
                    $this->initializeBadRequestResponse($key);
                    return true;
                }
                $prefix = "HTTP_";
                $header = str_replace("-", "_", strtoupper(trim($matches[1])));
                $value = trim($matches[2]);
                if (in_array($header, ['CONTENT_TYPE', 'CONTENT_LENGTH'])) {
                    $prefix = "";
                }
                $context[$prefix . $header] = $value;
            }

            $this->in_streams[self::CONTEXT][$key] = $context;
            if (empty($context['CONTENT_LENGTH']) &&
                !$this->isChunkedRequest($context)) {
                $context['CONTENT'] = "";
                $this->setGlobals($context, $this->connection($key));
                return true;
            } else if (($context['CONTENT_LENGTH'] ?? 0) >
                $this->default_server_globals['MAX_REQUEST_LEN'] -
                $end_head_pos) {
                $this->initializeBadRequestResponse($key,
                    self::PAYLOAD_TOO_LARGE);
                return true;
            }
        }
        $data = $this->in_streams[self::DATA][$key];
        $content_pos = strpos($data, "$eol$eol") + strlen("$eol$eol");
        if ($this->isChunkedRequest($context)) {
            $content = $this->decodeChunkedBody(substr($data, $content_pos));
            if ($content === false) {
                return false;
            }
            if ($content === null) {
                $this->initializeBadRequestResponse($key);
                return true;
            }
            $context['CONTENT'] = $content;
            $context['CONTENT_LENGTH'] = strlen($content);
            $this->setGlobals($context, $this->connection($key));
            return true;
        }
        if (strlen($data) - $content_pos < $context['CONTENT_LENGTH']) {
            return false;
        }
        $context['CONTENT'] = substr($data, $content_pos);
        $this->setGlobals($context, $this->connection($key));
        return true;
    }
    /**
     * isChunkedRequest says whether an HTTP/1.1 request sends its body in
     * chunks, as its Transfer-Encoding header names chunked. A client
     * sends a body this way when it does not know the length in advance;
     * git does so for a push larger than its one megabyte post buffer.
     *
     * @param array $context the request's headers, as parseH1Request
     *      reads them
     * @return bool whether the body is chunked
     */
    protected function isChunkedRequest($context)
    {
        return stripos($context['HTTP_TRANSFER_ENCODING'] ?? "",
            "chunked") !== false;
    }
    /**
     * decodeChunkedBody joins the chunks of a request body sent with
     * Transfer-Encoding: chunked (RFC 9112, the HTTP/1.1 specification,
     * section 7.1). Each chunk is its length in hexadecimal on a line of
     * its own, then that many bytes and a line end; a chunk of length 0
     * ends the body, followed by any trailer lines and an empty line.
     *
     * @param string $raw the bytes received after the request's headers
     * @return string|bool|null the joined body; false when the body has
     *      not all arrived yet; null when the bytes are not chunks
     */
    protected function decodeChunkedBody($raw)
    {
        $body = "";
        $pos = 0;
        $total = strlen($raw);
        while (true) {
            $line_end = strpos($raw, "\x0D\x0A", $pos);
            if ($line_end === false) {
                return false;
            }
            $size_text = trim(explode(";", substr($raw, $pos,
                $line_end - $pos), 2)[0]);
            if ($size_text === "" || !ctype_xdigit($size_text)) {
                return null;
            }
            $size = hexdec($size_text);
            $pos = $line_end + 2;
            if ($size == 0) {
                if (substr($raw, $pos, 2) === "\x0D\x0A") {
                    return $body;
                }
                return (strpos($raw, "\x0D\x0A\x0D\x0A", $pos) === false) ?
                    false : $body;
            }
            if ($pos + $size + 2 > $total) {
                return false;
            }
            $body .= substr($raw, $pos, $size);
            $pos += $size + 2;
        }
    }
    /**
     * Initializes superglobals before process() in CLI mode.
     * Values come from the request stream's context (request
     * headers etc). Posted form bodies are parsed into $_POST
     * and $_FILES.
     *
     * @param array $context request data. Request headers appear
     *      with HTTP_ prefix (e.g. $context['HTTP_COOKIE']);
     *      Content-Type and Content-Length without prefix
     *      (CGI convention). Body is in $context['CONTENT'].
     * @param Connection|null $conn live Connection for this request
     *      (used to overlay listener-attached fields like
     *      IS_SECURE, LISTENER_PORT, LISTENER_NAME, HTTPS onto
     *      $_SERVER). Null is allowed for synthetic internal
     *      requests with no real connection.
     */
    public function setGlobals($context, $conn = null)
    {
        if ($conn !== null) {
            /*
                Overlay listener-attached connection fields onto
                the request context so $_SERVER carries them.
                Keeping these on the Connection (not in
                in_streams[CONTEXT]) means a keep-alive reset
                between H1 requests doesn't have to manually
                preserve them; the Connection survives the
                reset and the next setGlobals re-overlays them.
             */
            $context['IS_SECURE'] = $conn->is_secure;
            $context['LISTENER_PORT'] = $conn->listener_port;
            $context['LISTENER_NAME'] = $conn->listener_name;
            $context['CLIENT_HTTP'] = $conn->client_http;
            if (!empty($conn->server_addr)) {
                $context['SERVER_ADDR'] = $conn->server_addr;
            }
            if ($conn->https !== '') {
                $context['HTTPS'] = $conn->https;
            }
        }
        if (!empty($this->served_domains)) {
            /* Name this request by the served domain the visitor used.
               The Host header is attacker-controllable, so it is only
               adopted as SERVER_NAME when it is one of the served
               domains; anything else, including a missing or forged
               Host, falls back to the first served domain. Set on the
               context before the merges below so $_SERVER carries it. */
            $request_host = strtolower($this->hostWithoutPort(
                $context['HTTP_HOST'] ?? ''));
            if ($request_host !== '' &&
                in_array($request_host, $this->served_domains, true)) {
                $context['SERVER_NAME'] = $request_host;
            } else {
                $context['SERVER_NAME'] = $this->served_domains[0];
            }
        }
        $_SERVER = array_merge($this->default_server_globals, $context);
        /* The stream's context is made once per connection, so the
           arrival time it holds is the connection's; each request gets
           its own. */
        $_SERVER['REQUEST_TIME_FLOAT'] = microtime(true);
        $_SERVER['REQUEST_TIME'] = (int)$_SERVER['REQUEST_TIME_FLOAT'];
        parse_str($context['QUERY_STRING'], $_GET);
        $_POST = [];
        /*
            $_FILES is process-global; PHP doesn't auto-reset it
            per request under the CLI server. Wipe to avoid the
            previous request's metadata leaking into this one.
         */
        $_FILES = [];
        if (!empty($context['CONTENT']) &&
            !empty($context['CONTENT_TYPE']) &&
            str_contains($context['CONTENT_TYPE'], "multipart/form-data")) {
            preg_match('/boundary=(.*)/', $context['CONTENT_TYPE'], $matches);
            $boundary = $matches[1];
            $raw_form_parts = preg_split("/-+$boundary/", $context['CONTENT']);
            array_pop($raw_form_parts);
            /*
                Cap parts at MAX_INPUT_VARS so a hostile multipart
                with millions of tiny parts can't exhaust CPU or
                memory. Legitimate forms never approach this.
             */
            $max_input_vars = $this->default_server_globals[
                'MAX_INPUT_VARS'] ?? 1000;
            if (count($raw_form_parts) > $max_input_vars) {
                $raw_form_parts = array_slice(
                    $raw_form_parts, 0, $max_input_vars);
            }
            foreach ($raw_form_parts as $raw_part) {
                $head_content = explode("\x0D\x0A\x0D\x0A", $raw_part, 2);
                if (count($head_content) != 2) {
                    continue;
                }
                list($head, $content) = $head_content;
                $head_parts = explode("\x0D\x0A", $head);
                $name = "";
                $file_name = "";
                $content_type = "";
                foreach ($head_parts as $head_part) {
                    /*
                        Non-greedy capture so 'evil"; x="y' can't
                        match past the first closing quote and
                        smuggle extra attributes.
                     */
                    if (preg_match(
                        "/\s*Content-Disposition\:\s*form-data\;\s*" .
                        "name\s*=\s*[\"\'](.*?)[\"\']\s*\;\s*filename=".
                        "\s*[\"\'](.*?)[\"\']\s*/i", $head_part, $matches)) {
                        list(, $name, $file_name) = $matches;
                    } else if (preg_match(
                        "/\s*Content-Disposition\:\s*form-data\;\s*" .
                        "name\s*=\s*[\"\'](.*?)[\"\']/i", $head_part,
                        $matches)) {
                        $name = $matches[1];
                    }
                    if (preg_match( "/\s*Content-Type\:\s*([^\s]+)/i",
                        $head_part, $matches)) {
                        $content_type = trim($matches[1]);
                    }
                }
                if (empty($name)) {
                    continue;
                }
                if (empty($file_name)) {
                    /* We support up to 3D arrays in form variables. A key
                       may hold more than letters, digits and underscores:
                       a hyphen is ordinary in a name a page makes up for
                       itself, and matching only word characters dropped
                       every such field silently. */
                    if (preg_match("/^(\w+)\[([^\]]+)\]\[([^\]]+)\]" .
                        "\[([^\]]+)\]$/",
                        $name, $matches)) {
                        $_POST[$matches[1]][$matches[2]][$matches[3]][
                            $matches[4]] = $content;
                    } else if (preg_match("/^(\w+)\[([^\]]+)\]" .
                        "\[([^\]]+)\]$/", $name, $matches)) {
                        $_POST[$matches[1]][$matches[2]][$matches[3]] =
                            $content;
                    } else if (preg_match("/^(\w+)\[([^\]]+)\]$/", $name,
                        $matches)) {
                        $_POST[$matches[1]][$matches[2]] = $content;
                    } else {
                        $_POST[$name] = rtrim($content, "\x0D\x0A");
                    }
                    continue;
                }
                /*
                    tmp_name is conventionally a filesystem path
                    move_uploaded_file() validates. Atto keeps
                    uploads in memory ('data' field), so there's
                    no real path. A synthetic non-path token
                    avoids the footgun where unsuspecting code
                    might require($_FILES[...]['tmp_name']) and
                    dereference an attacker-controlled filename.
                 */
                $tmp_token = "atto-mem-upload-"
                    . bin2hex(random_bytes(8));
                /*
                    The line ending before a boundary belongs to the
                    boundary, not to the part above it, so it is taken
                    off here. Left on, every uploaded file arrived two
                    bytes longer than it was sent, which a picture or
                    any other file read by its bytes will not survive.
                    Exactly one ending is removed, since a file whose
                    own last bytes are a line ending is entitled to
                    keep them.
                 */
                if (substr($content, -2) === "\x0D\x0A") {
                    $content = substr($content, 0, -2);
                }
                /*
                    full_path mirrors the key mod_php has set on
                    every $_FILES entry since PHP 8.1: for a normal
                    file upload it equals the client filename (only
                    a webkitdirectory upload differs, carrying a
                    relative path). Handlers such as
                    SocialComponent::handleResourceUploads require
                    it, so emit it here or every upload through the
                    Atto server fails its presence check.
                 */
                $file_array = ['name' => $file_name,
                    'tmp_name' => $tmp_token,
                    'type' => $content_type, 'error' => 0,
                    'data' => $content,
                    'size' => strlen($content),
                    'full_path' => $file_name];
                $file_fields = ['name', 'tmp_name', 'type', 'error',
                    'data', 'size', 'full_path'];
                /*
                    A multi-file upload arrives as separate parts named
                    field[0], field[1], and so on, or as repeated parts
                    all named field[] where the form left the brackets
                    empty, which is what a plain HTML multiple file
                    input sends. PHP under Apache or Nginx turns either
                    into a single $_FILES['field'] whose 'name',
                    'tmp_name', etc. are arrays indexed by position, and
                    the upload handlers read that shape. Reproduce it
                    here: peel off the bracket index, counting from the
                    files already gathered where the brackets are empty,
                    and store each file's parts at that index under the
                    base field name. A plain field name with no brackets
                    keeps the simple single-file shape, and two parts
                    that really do share one name still collect into
                    arrays as before.
                 */
                if (preg_match('/^(\w+)\[(\w*)\]$/', $name, $matches)) {
                    $base_name = $matches[1];
                    if (empty($_FILES[$base_name])) {
                        $_FILES[$base_name] = [];
                        foreach ($file_fields as $field) {
                            $_FILES[$base_name][$field] = [];
                        }
                    }
                    $file_index = ($matches[2] === "") ?
                        count($_FILES[$base_name]['name']) : $matches[2];
                    foreach ($file_fields as $field) {
                        if (!is_array($_FILES[$base_name][$field])) {
                            $_FILES[$base_name][$field] =
                                [$_FILES[$base_name][$field]];
                        }
                        $_FILES[$base_name][$field][$file_index] =
                            $file_array[$field];
                    }
                } else if (empty($_FILES[$name])) {
                    $_FILES[$name] = $file_array;
                } else {
                    foreach ($file_fields as $field) {
                        if (!is_array($_FILES[$name][$field])) {
                            $_FILES[$name][$field] = [$_FILES[$name][$field]];
                        }
                        $_FILES[$name][$field][] = $file_array[$field];
                    }
                }
            }
        } else if (!empty($context['CONTENT'])) {
            parse_str($context['CONTENT'], $_POST);
        }
        $_SERVER = array_merge($this->default_server_globals, $context);
        $_SERVER['REQUEST_TIME_FLOAT'] = microtime(true);
        $_SERVER['REQUEST_TIME'] = (int)$_SERVER['REQUEST_TIME_FLOAT'];
        $_COOKIE = [];
        if (!empty($_SERVER['HTTP_COOKIE'])) {
            $sent_cookies = explode(";", $_SERVER['HTTP_COOKIE']);
            foreach ($sent_cookies as  $cookie) {
                /*
                    Split on only the first = so cookie values that
                    contain = (commonly base64 padding) are preserved
                    intact. RFC 6265 cookie-value may contain any
                    octet except control chars, whitespace, and a
                    handful of separators; = is allowed.
                 */
                $cookie_parts = explode("=", $cookie, 2);
                if (count($cookie_parts) == 2) {
                    $_COOKIE[trim($cookie_parts[0])] = trim($cookie_parts[1]);
                }
            }
        }
        $_REQUEST = array_merge($_GET, $_POST, $_COOKIE);
    }
    /**
     * Cleans a configured list of served host names into a plain
     * lower-cased list. The input may already be a list, or a single
     * string with the names separated by commas or whitespace.
     * Surrounding spaces are trimmed and empty entries dropped, so a
     * trailing comma or a blank line does not produce an empty name.
     *
     * @param mixed $source the configured names, as a list or a
     *      comma- or whitespace-separated string
     * @return array the host names, lower-cased, in their given order
     */
    protected function normalizeServedDomains($source)
    {
        if (is_string($source)) {
            $source = preg_split('/[\s,]+/', $source);
        }
        if (!is_array($source)) {
            return [];
        }
        $names = [];
        foreach ($source as $name) {
            $name = strtolower(trim((string)$name));
            if ($name !== '') {
                $names[] = $name;
            }
        }
        return $names;
    }
    /**
     * Returns the bare host from an HTTP authority, dropping any
     * trailing port. A bracketed IPv6 literal such as [::1]:8080 keeps
     * its brackets and loses only the port; a plain name or IPv4
     * address such as host:8080 loses the port after the last colon.
     *
     * @param string $authority the Host header value, possibly with a
     *      port
     * @return string the host alone, without a port
     */
    protected function hostWithoutPort($authority)
    {
        $authority = trim((string)$authority);
        if ($authority === '') {
            return '';
        }
        if ($authority[0] === '[') {
            $close = strpos($authority, ']');
            return ($close !== false) ? substr($authority, 0, $close + 1) :
                $authority;
        }
        $colon = strrpos($authority, ':');
        return ($colon !== false) ? substr($authority, 0, $colon) : $authority;
    }
    /**
     * Outputs HTTP error response message in the case that no specific error
     * handler was set
     *
     * @param string $route the route of the error. Internally, when an HTTP
     *      error occurs it is usually given a route of the form /response code.
     *      For example, /404 for a NOT FOUND error.
     */
    protected function defaultErrorHandler($route = "")
    {
        $request_uri = (empty($route) || $route == '/400') ?
            0 : trim($route, "/");
        $error = ($request_uri < 100 || $request_uri > 600) ?
            "400 BAD REQUEST" : $request_uri . " ERROR";
        $message = $_SERVER['SERVER_PROTOCOL'] . " ". $error;
        $this->header($message);
        echo $message;
    }
    /**
     * Used to set up PHP superglobals, $_GET, $_POST, etc in the case that
     * a 400 BAD REQUEST response occurs, or a 413 PAYLOAD TOO LARGE one
     * for a request longer than MAX_REQUEST_LEN. The connection's own
     * context is marked too, so parseH1Request does not reset the
     * connection for a next request: what the client goes on sending is
     * the rest of the request just refused, which processRequestStreams
     * reads and throws away until the client closes.
     *
     * @param int $key id of stream that bad request came from
     * @param int $status the response code, 400 unless the request was too
     *      long
     */
    protected function initializeBadRequestResponse($key, $status = 400)
    {
        if (isset($this->in_streams[self::CONTEXT][$key])) {
            $this->in_streams[self::CONTEXT][$key]['PRE_BAD_RESPONSE'] =
                true;
        }
        $_COOKIE = [];
        $_SESSION = [];
        $_FILES = [];
        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        $_SERVER = array_merge($this->default_server_globals,
            $this->in_streams[self::CONTEXT][$key],
            ['REQUEST_METHOD' => 'ERROR', 'REQUEST_URI' => '/' . $status,
             'SERVER_PROTOCOL' => 'HTTP/1.0',
             'PRE_BAD_RESPONSE' => true]);
    }
    /**
     * Returns the soonest pending TLS-handshake deadline across
     * all live connections, or null when none are mid-handshake.
     * The main loop uses this to bound its select wait so a
     * stalled handshake is reaped on time even when no other
     * socket has activity to wake the loop.
     *
     * @return float|null soonest handshake deadline as a
     *      microtime value, or null if no handshakes are pending
     */
    protected function nextHandshakeDeadline()
    {
        $soonest = null;
        foreach ($this->connections as $conn) {
            if ($conn->protocol !== 'handshake') {
                continue;
            }
            $deadline =
                $conn->protocol_state['handshake_deadline'] ?? 0;
            if ($deadline > 0 &&
                ($soonest === null || $deadline < $soonest)) {
                $soonest = $deadline;
            }
        }
        return $soonest;
    }
    /**
     * Used to close connections and remove from stream arrays streams that
     * have not had traffic in the last CONNECTION_TIMEOUT seconds. The
     * stream socket server is exempt from being culled, as are any streams
     * whose ids are in $this->immortal_stream_keys.
     */
    protected function cullDeadStreams()
    {
        $keys = array_merge(array_keys($this->in_streams[self::CONNECTION]),
            array_keys($this->out_streams[self::CONNECTION]));
        foreach ($keys as $key) {
            if (in_array($key, $this->immortal_stream_keys)) {
                continue;
            }
            if (empty($this->in_streams[self::CONNECTION][$key])) {
                $this->shutdownHttpStream($key);
                continue;
            }
            $meta = stream_get_meta_data(
                $this->in_streams[self::CONNECTION][$key]);
            $connection = $this->connection($key);
            if ($connection?->is_websocket) {
                /*
                    WebSockets have their own keepalive timer in
                    wsKeepalivePass; do not close them based on
                    the generic HTTP idle timeout. EOF still
                    applies so dead TCP connections are reaped.
                 */
                if ($meta['eof']) {
                    $this->shutdownHttpStream($key);
                }
                continue;
            }
            if ($connection?->protocol === 'handshake') {
                /*
                    A connection still completing its TLS handshake
                    has no request modified-time yet, so the generic
                    idle timeout would reap it immediately. Reap it
                    only on EOF or once its handshake deadline has
                    passed, matching stepHandshake.
                 */
                $deadline =
                    $connection->protocol_state['handshake_deadline']
                    ?? 0;
                if ($meta['eof'] ||
                    ($deadline > 0 && microtime(true) > $deadline)) {
                    $this->shutdownHttpStream($key);
                }
                continue;
            }
            $in_time = empty($this->in_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->in_streams[self::MODIFIED_TIME][$key];
            $out_time = empty($this->out_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->out_streams[self::MODIFIED_TIME][$key];
            $modified_time = max($in_time, $out_time);
            if ($this->hasReplyInFlight($key)) {
                /*
                    A reply still being produced or sent is not an idle
                    connection. While a client downloads it sends nothing,
                    so the inbound time stays at the request's start; and
                    each time the outbound buffer empties between slices
                    the write stream is cleared, which takes the outbound
                    time with it. Without this a long download is closed
                    part way through however fast it is going.
                 */
                $modified_time = time();
            }
            if ($meta['eof'] || (empty($this->relayed_by_connection[$key]) &&
                time() - $modified_time > $this->default_server_globals[
                'CONNECTION_TIMEOUT'])) {
                $this->shutdownHttpStream($key);
            }
        }
    }
    /**
     * Reports whether a reply is still on its way out on this connection,
     * either because a streamed body has more to produce, because bytes
     * already produced have not all been sent, or because a deferred
     * request on it is still doing its work. Used so the sweep for idle
     * connections leaves a download alone: the peer sends nothing while it
     * reads, so by the usual measure such a connection looks silent.
     *
     * @param int $key connection identifier
     * @return bool true when something is still to be produced or sent
     */
    protected function hasReplyInFlight($key)
    {
        $unsent = strlen($this->out_streams[self::DATA][$key] ?? "") -
            ($this->out_streams[self::DATA_OFFSET][$key] ?? 0);
        if ($unsent > 0 || !empty($this->deferred_running[$key])) {
            return true;
        }
        $conn = $this->connection($key);
        if ($conn === null) {
            return false;
        }
        if (!empty($conn->protocol_state['streaming_gen'])) {
            return true;
        }
        foreach ($conn->protocol_state['pending_send'] ?? [] as $pending) {
            if (strlen($pending['data'] ?? "") -
                ($pending['offset'] ?? 0) > 0) {
                return true;
            }
        }
        return false;
    }
    /**
     * Returns the live Connection object for the given stream key,
     * or null if no Connection has been registered (or the
     * connection has already been torn down). Code that needs
     * typed per-connection state — protocol, HPACK encoders, H2
     * stream registry — should fetch the Connection here and
     * read its protocol_state instead of indexing into the
     * untyped in_streams[CONTEXT] array.
     *
     * @param int $key id of stream to look up
     * @return Connection|null connection object, or null if the
     *      key is unknown
     */
    public function connection($key)
    {
        return $this->connections[$key] ?? null;
    }
    /**
     * Closes stream with id $key and removes it from in_streams and
     * outstreams arrays.
     *
     * @param int $key id of stream to delete
     */
    public function shutdownHttpStream($key)
    {
        $this->cancelRelayedRequests($key);
        if (!empty($this->in_streams[self::CONNECTION][$key])) {
            set_error_handler(null);
            @stream_socket_shutdown($this->in_streams[self::CONNECTION][$key],
                STREAM_SHUT_RDWR);
            restore_error_handler();
        }
        /* A file still being sent has a handle open on it. Dropping
           the record of that send without closing the handle left one
           open for every connection that went away mid-file, and a
           server that ran long enough could open no more. */
        if (!empty($this->out_streams[self::DATA_FILE][$key]["handle"]) &&
            is_resource($this->out_streams[self::DATA_FILE][$key][
            "handle"])) {
            fclose($this->out_streams[self::DATA_FILE][$key]["handle"]);
        }
        unset($this->in_streams[self::CONNECTION][$key],
            $this->in_streams[self::CONTEXT][$key],
            $this->in_streams[self::DATA][$key],
            $this->in_streams[self::MODIFIED_TIME][$key],
            $this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::DATA_OFFSET][$key],
            $this->out_streams[self::DATA_FILE][$key],
            $this->out_streams[self::MODIFIED_TIME][$key],
            $this->connections[$key]
        );
    }
    /**
     * Removes a stream from outstream arrays. Since an HTTP connection can
     * handle several requests from a single client, this method does not close
     * the connection. It might be run after a request response pair, while
     * waiting for the next request.
     *
     * @param int $key id of stream to remove from outstream arrays.
     */
    protected function shutdownHttpWriteStream($key)
    {
        /* A file still being sent has a handle open on it. Dropping
           the record of that send without closing the handle left one
           open for every connection that went away mid-file, and a
           server that ran long enough could open no more. */
        if (!empty($this->out_streams[self::DATA_FILE][$key]["handle"]) &&
            is_resource($this->out_streams[self::DATA_FILE][$key][
            "handle"])) {
            fclose($this->out_streams[self::DATA_FILE][$key]["handle"]);
        }
        unset($this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::DATA_OFFSET][$key],
            $this->out_streams[self::DATA_FILE][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]
        );
    }
}
/**
 * Function to call instead of exit() to indicate that the script
 * processing the current web page is done processing. Use this rather
 * that exit(), as exit() will also terminate WebSite.
 *
 * @param string $err_msg error message to send on exiting
 * @throws WebException
 */
function webExit($err_msg = "")
{
    if (php_sapi_name() == 'cli') {
        throw new WebException($err_msg);
    } else {
        exit($err_msg);
    }
}
/**
 * Exception generated when a running WebSite script calls webExit()
 */
class WebException extends \Exception
{
}
/**
 * A thin wrapper around a single network connection. For HTTP/1.1
 * and HTTP/2 connections this wraps a TCP stream resource (possibly
 * with TLS enabled) and exposes one logical stream identified by
 * stream id 0. The wrapper is deliberately small: it gives callers
 * read/write/close methods that look the same regardless of the
 * underlying transport, but for code that genuinely needs the raw
 * resource (the H2 frame parser, stream_select in the event loop,
 * stream_socket_get_name) the resource() method is available.
 *
 * Subclasses extend this for transports that do not map cleanly to
 * a single TCP stream. H3QuicheConnection wraps a quiche_conn
 * pointer and overrides protocol/state semantics for QUIC streams;
 * H3Connection (pure-PHP) carries equivalent state in PHP.
 */
class Connection
{
    /**
     * Application protocol negotiated for this connection. One of
     * 'h1', 'h2', 'ws' for an upgraded WebSocket, or 'h3' once
     * QUIC support lands. Set by processServerRequest after
     * ConnectionAcceptor's protocol detection. Empty string until
     * detected.
     * @var string
     */
    public $protocol = '';
    /**
     * Detailed client-protocol string from ConnectionAcceptor:
     * 'HTTP/1.1', 'HTTP/2.0', 'h2c', or 'unknown'. Carried in
     * addition to $protocol because some code paths need the
     * literal version string (response status lines) while
     * others only care about the family. Set once at accept
     * time and never changed.
     * @var string
     */
    public $client_http = '';
    /**
     * Bind name of the listener that accepted this connection
     * (e.g. SERVER_NAME). Used to populate $_SERVER fields and
     * for any routing logic that switches on hostname.
     * @var string
     */
    public $listener_name = '';
    /**
     * TCP port of the listener that accepted this connection
     * (e.g. 8080). Distinct from REMOTE_PORT (the peer port).
     * @var string
     */
    public $listener_port = '';
    /**
     * Peer IP address as reported by stream_socket_get_name. IPv6
     * addresses are stored without surrounding brackets so that
     * inet_pton and address allowlist comparisons work uniformly.
     * Set once at accept time and never changed for the lifetime
     * of the connection.
     * @var string
     */
    public $remote_addr = '';
    /**
     * Peer TCP port as reported by stream_socket_get_name. Set
     * once at accept time and never changed.
     * @var string
     */
    public $remote_port = '';
    /**
     * Local-side bind address as reported by stream_socket_get_name.
     * Set once at accept time and never changed.
     * @var string
     */
    public $server_addr = '';
    /**
     * Local-side TCP port as reported by stream_socket_get_name.
     * Set once at accept time and never changed.
     * @var string
     */
    public $server_port = '';
    /**
     * 'on' if this connection was accepted on a TLS-enabled
     * listener and TLS handshake succeeded; empty string
     * otherwise. Mirrors $_SERVER['HTTPS'] semantics so generic
     * PHP code that expects that variable still works.
     * @var string
     */
    public $https = '';
    /**
     * True once this H1 connection has been upgraded to a
     * WebSocket via the Sec-WebSocket-Accept handshake. Once
     * set, subsequent reads are dispatched to parseWsRequest
     * rather than the H1 request parser. Connection::$protocol
     * is also retagged to 'ws' at upgrade time.
     * @var bool
     */
    public $is_websocket = false;
    /**
     * The WebSocket message handler/codec for an upgraded WS
     * connection, or null on H1/H2 connections that never
     * upgraded. Holds frame-decoding state and the user's
     * onMessage / onClose callbacks; persists for the lifetime
     * of the WS connection.
     * @var WebSocket|null
     */
    public $ws = null;
    /**
     * WebSocket handles opened over HTTP/2 extended CONNECT streams
     * on this connection, indexed by carrier stream id. A single h2
     * connection can carry more than one, unlike the one-per-
     * connection $ws of an HTTP/1.1 upgrade.
     * @var array
     */
    public $h2_websockets = [];
    /**
     * Protocol-specific state, indexed by short keys whose
     * meaning depends on protocol. For 'h2' this currently holds:
     *
     *   'hpack_encode' => HPack instance for outgoing HEADERS
     *   'hpack_decode' => HPack instance for inbound HEADERS
     *   'last_stream_id' => highest seen client stream id
     *   'pending_streams' => array of half-open client streams
     *       awaiting END_STREAM (HEADERS + DATA accumulation)
     *
     * Storing these here, rather than in WebSite's
     * in_streams[CONTEXT] array, keeps connection-lifetime state
     * with the connection object itself and provides a single
     * place an H3 subclass can override.
     * @var array
     */
    public $protocol_state = [];
    /**
     * Constructs a Connection wrapping a stream resource.
     *
     * @param resource $resource underlying stream resource (TCP,
     *      possibly TLS-wrapped)
     * @param bool $is_secure whether this connection's transport is
     *      TLS-wrapped; used by code paths that need to decide
     *      between cleartext and secure behavior independently of
     *      the listener that accepted it
     */
    public function __construct(public $resource, public $is_secure = false)
    {
    }
    /**
     * Returns the underlying raw stream resource. Use this only
     * when interacting with PHP stream functions that take a
     * resource directly such as stream_select or
     * stream_socket_get_name. Most data-flow paths should call
     * read and write instead.
     *
     * @return resource the open stream resource
     */
    public function resource()
    {
        return $this->resource;
    }
    /**
     * Returns the logical stream id for this connection. For TCP
     * the entire connection is one byte stream so the stream id
     * is always 0. A future QuicConnection would return the
     * actual QUIC stream id here.
     *
     * @return int 0 for TCP-backed connections
     */
    public function streamId()
    {
        return 0;
    }
    /**
     * Reads up to $length bytes from the connection. Honors the
     * current blocking mode of the underlying stream.
     *
     * @param int $length the most bytes to read
     * @return string|false bytes read, empty string at EOF or
     *      when no data is available in non-blocking mode, or
     *      false on error
     */
    public function read($length)
    {
        return @fread($this->resource, $length);
    }
    /**
     * Writes $data to the connection.
     *
     * @param string $data bytes to write
     * @return int|false number of bytes written, or false on
     *      error. Callers must handle short writes by retrying
     *      with the unwritten remainder.
     */
    public function write($data)
    {
        return @fwrite($this->resource, $data);
    }
    /**
     * Sets blocking mode on the underlying stream.
     *
     * @param bool $blocking true for blocking, false for
     *      non-blocking
     */
    public function setBlocking($blocking)
    {
        stream_set_blocking($this->resource, $blocking);
    }
    /**
     * Returns whether the underlying stream has reached end of
     * file (the peer closed the connection).
     *
     * @return bool true if EOF, false otherwise
     */
    public function isEof()
    {
        $meta = @stream_get_meta_data($this->resource);
        return !empty($meta['eof']);
    }
    /**
     * Returns stream metadata as reported by
     * stream_get_meta_data, or an empty array if the stream is
     * no longer open.
     *
     * @return array stream metadata
     */
    public function getMeta()
    {
        $meta = @stream_get_meta_data($this->resource);
        return is_array($meta) ? $meta : [];
    }
    /**
     * Returns the local or remote name of the stream as reported
     * by stream_socket_get_name.
     *
     * @param bool $remote true for remote peer, false for local
     *      bind name
     * @return string|false name string, or false on failure
     */
    public function name($remote = true)
    {
        return @stream_socket_get_name($this->resource, $remote);
    }
    /**
     * Closes the underlying stream resource and releases the
     * connection. Safe to call more than once.
     */
    public function close()
    {
        if (is_resource($this->resource)) {
            @fclose($this->resource);
        }
    }
    /**
     * Shuts down one or both halves of the underlying stream
     * without fully closing the resource. Used for graceful
     * close handshakes (e.g. send the response then half-close
     * the write side to signal end-of-response).
     *
     * @param int $how one of STREAM_SHUT_RD, STREAM_SHUT_WR,
     *      STREAM_SHUT_RDWR
     * @return bool true on success
     */
    public function shutdown($how = STREAM_SHUT_RDWR)
    {
        if (is_resource($this->resource)) {
            return @stream_socket_shutdown($this->resource, $how);
        }
        return false;
    }
}
/**
 * Encapsulates the protocol-detection portion of accepting a
 * connection: handles stream_socket_accept, the optional TLS
 * handshake, and the read of the first bytes that determines
 * whether the client is speaking HTTP/2, HTTP/1.1, or h2c. Returns
 * a Connection wrapping the accepted resource together with an
 * additional_context array carrying CLIENT_HTTP, IS_SECURE, and
 * any LEFTOVER bytes consumed during detection.
 *
 * Pulling this out of WebSite::processServerRequest gives the
 * accept-and-detect step a single home and a clear contract.
 * A future H3 transport would have a sibling class with the same
 * accept method but different detection logic for QUIC packets.
 */
class ConnectionAcceptor
{
    /**
     * Seconds a connection may remain in the TLS-handshake-pending
     * state before the event loop reaps it, so a peer that opens a
     * connection and then stalls without completing the handshake
     * cannot hold a slot indefinitely.
     */
    const HANDSHAKE_TIMEOUT = 30;
    /**
     * Constructs a ConnectionAcceptor.
     *
     * @param string $h2_magic the 24-byte HTTP/2 client connection
     *      preface from RFC 7540 section 3.5; cached as a string for
     *      fast comparison rather than recomputed each accept
     * @param callable|null $error_handler optional callback invoked
     *      with an error message when TLS handshake fails; if null
     *      the message is written to stdout
     * @param callable|null $post_tls_callback optional callback
     *      invoked after a successful TLS handshake to restore the
     *      WebSite's custom error handler that
     *      stream_socket_enable_crypto temporarily clears
     */
    public function __construct(protected $h2_magic,
        protected $error_handler = null, protected $post_tls_callback = null)
    {
    }
    /**
     * Accepts a new connection from the given listener entry,
     * runs the TLS handshake if the listener is secure, then
     * inspects the first bytes to determine the HTTP protocol
     * version. Returns a [Connection, additional_context] pair
     * suitable for handing to WebSite's per-protocol init
     * routines, or [null, null] if no connection was accepted.
     *
     * @param Listener $listener listener whose server socket is
     *      ready to accept; supplies the server resource and the
     *      is_secure flag
     * @param float $timeout maximum seconds to block waiting for
     *      a connection
     * @return array [Connection|null, array|null]
     */
    public function accept($listener, $timeout)
    {
        $server = $listener->server;
        $is_secure = !empty($listener->is_secure);
        if ($is_secure) {
            stream_set_blocking($server, true);
        }
        $resource = @stream_socket_accept($server, $timeout);
        if ($is_secure) {
            stream_set_blocking($server, false);
        }
        if (!$resource) {
            return [null, null];
        }
        /*
            Put the accepted socket in non-blocking mode at once so
            no later step can block the single accept-and-serve
            loop on one slow or stalled client. A plaintext-port
            connection is detected and returned ready as before. A
            secure-port connection is returned in a handshake
            pending state: the byte peek that auto-detects
            plaintext on a TLS port and the TLS handshake itself
            are driven a step at a time from the event loop by the
            handshake transport, rather than run inline here where
            a peer that connects and then stalls would freeze every
            other connection.
         */
        stream_set_blocking($resource, false);
        if (!$is_secure) {
            $connection = new Connection($resource, false);
            $additional_context = $this->detectProtocol($connection);
            return [$connection, $additional_context];
        }
        $connection = new Connection($resource, true);
        $connection->protocol = 'handshake';
        $connection->protocol_state['handshake_deadline'] =
            microtime(true) + self::HANDSHAKE_TIMEOUT;
        return [$connection, ['CLIENT_HTTP' => 'handshake']];
    }
    /**
     * The TLS crypto method bitmask the server offers: the generic
     * TLS server method plus the 1.2 and 1.3 variants when the
     * build defines them.
     *
     * @return int crypto method flags for stream_socket_enable_crypto
     */
    protected function cryptoMethod()
    {
        $method = STREAM_CRYPTO_METHOD_TLS_SERVER;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
        }
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
        }
        return $method;
    }
    /**
     * Runs one non-blocking step of the server-side TLS handshake
     * on a connection. The socket is non-blocking so the call
     * returns at once: true when the handshake has completed,
     * false when it has failed, and 0 when it needs more socket
     * I/O and should be retried on a later select wake. The error
     * handler is scoped to this call so any SSL error text is
     * attributed to this step rather than read from the unreliable
     * process-wide last error.
     *
     * @param Connection $connection connection whose handshake to step
     * @param string $handshake_error set to the SSL error text on failure
     * @return bool|int true done, false failed, 0 needs more I/O
     */
    public function stepCrypto($connection, &$handshake_error = '')
    {
        $handshake_error = '';
        $error = null;
        set_error_handler(
            function ($errno, $errstr) use (&$error) {
                $error = $errstr;
                return true;
            });
        $result = @stream_socket_enable_crypto(
            $connection->resource(), true, $this->cryptoMethod());
        restore_error_handler();
        if ($result === true) {
            if ($this->post_tls_callback) {
                ($this->post_tls_callback)();
            }
            return true;
        }
        if ($result === 0) {
            return 0;
        }
        if ($error !== null) {
            $handshake_error = $error;
        }
        return false;
    }
    /**
     * Inspects the first bytes of a connection to decide which
     * HTTP version the client is speaking. For TLS connections
     * we read 24 bytes (the H2 client magic length) while still
     * in blocking mode and switch to non-blocking afterward; for
     * cleartext we use STREAM_PEEK so the bytes remain in the
     * receive buffer for the normal request parser. Returns an
     * additional_context array for the connection.
     *
     * @param Connection $connection accepted connection, with
     *      TLS already enabled if the listener was secure
     * @return array context with CLIENT_HTTP and possibly
     *      LEFTOVER keys
     */
    public function detectProtocol($connection)
    {
        /*
            Reached only for cleartext connections: a plaintext
            listener, or cleartext detected on a TLS port. Secure
            connections are classified from their first decrypted
            bytes by classifySecureFirstBytes. Cleartext is safe to
            peek since there is no TLS wrapping, so the bytes stay
            in the receive buffer for the request parser.
         */
        $stream_start = @stream_socket_recvfrom(
            $connection->resource(), 512, STREAM_PEEK);
        if (empty($stream_start)) {
            return ["CLIENT_HTTP" => "unknown"];
        }
        if (strncmp($stream_start, $this->h2_magic,
                strlen($this->h2_magic)) === 0) {
            return ["CLIENT_HTTP" => "h2c"];
        }
        if (preg_match("/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|"
                . "PATCH|TRACE|CONNECT) \S+ HTTP\/1\.1/",
                $stream_start)) {
            return ["CLIENT_HTTP" => "HTTP/1.1"];
        }
        return ["CLIENT_HTTP" => "unknown"];
    }
    /**
     * Classifies the first decrypted bytes of a TLS connection as
     * HTTP/2 or HTTP/1.1. Returns 'h2' when the bytes are the full
     * 24-byte HTTP/2 client connection preface, 'h1' when they have
     * already diverged from that preface, and null when more bytes
     * are still needed to decide (the buffer so far is a proper
     * prefix of the preface). Lets the caller stop reading as soon
     * as the protocol is unambiguous rather than always waiting for
     * 24 bytes.
     *
     * @param string $buffer decrypted bytes read so far
     * @return string|null 'h2', 'h1', or null if undecided
     */
    public function classifySecureFirstBytes($buffer)
    {
        $magic = $this->h2_magic;
        $magic_len = strlen($magic);
        $have = strlen($buffer);
        if ($have >= $magic_len) {
            if (strncmp($buffer, $magic, $magic_len) === 0) {
                return 'h2';
            }
            return 'h1';
        }
        if (strncmp($buffer, $magic, $have) === 0) {
            return null;
        }
        return 'h1';
    }
}
/**
 * A bound server socket plus its accept policy. WebSite holds one
 * Listener per address it is configured to listen on (e.g. one
 * for plain HTTP on 8080, another for TLS on 8443). The Listener
 * owns the server resource, the bind address, whether it is TLS,
 * and the per-listener server globals overrides (SERVER_NAME,
 * SERVER_PORT) that are stamped onto every Connection accepted
 * from it.
 *
 * Listeners are created by WebSite::openListener and registered
 * in WebSite::$listeners. The main event loop pulls the server
 * resource via Listener::resource() and adds it to the array
 * passed to stream_select; when select reports a server socket
 * readable, processRequestStreams looks up the Listener by
 * stream key and calls processServerRequest, which calls
 * Listener::accept() to produce a Connection.
 *
 * The class is designed to admit a future H3Listener subclass
 * for QUIC over UDP. That subclass would override accept() to
 * call stream_socket_recvfrom and demux the resulting datagram
 * to (or create) the QUIC connection identified by its
 * connection-id, returning a QuicConnection wrapping that
 * stream rather than a TCP-backed Connection.
 */
class Listener
{
    /**
     * Constructs a Listener.
     *
     * @param resource|null $server stream resource returned by
     *      stream_socket_server, or null if the bind failed
     *      (callers should check before adding to a select set)
     * @param string $address the bind address as understood by
     *      stream_socket_server, e.g. 'tcp://0.0.0.0:8080'; used in
     *      startup logging and to recreate the same listener after
     *      a restart
     * @param bool $is_secure true if this listener was opened with a
     *      TLS context; the accept policy uses this to decide
     *      whether to run the TLS handshake on freshly accepted
     *      connections, and the dispatch code uses it to set
     *      HTTPS=on on the Connection
     * @param array $globals per-listener overrides for
     *      default_server_globals; currently holds SERVER_NAME and
     *      SERVER_PORT so a multi-listener server can stamp the
     *      right host and port onto each accepted Connection
     *      regardless of which listener accepted it
     */
    public function __construct(public $server, public $address,
        public $is_secure = false, public $globals = [])
    {
    }
    /**
     * Returns the underlying server stream resource so the event
     * loop can include it in stream_select sets.
     *
     * @return resource|null the server socket
     */
    public function resource()
    {
        return $this->server;
    }
    /**
     * Closes the underlying server socket. Used during a graceful
     * restart so the child process can rebind the same port.
     */
    public function close()
    {
        if (is_resource($this->server)) {
            @fclose($this->server);
        }
    }
    /**
     * Accepts a new connection from this listener. For TCP this
     * delegates to ConnectionAcceptor which handles the TLS
     * handshake and protocol detection. A future H3Listener
     * subclass would override this method to implement UDP
     * recvfrom and QUIC connection demuxing instead.
     *
     * @param ConnectionAcceptor $acceptor accept-and-detect helper
     * @param float $timeout maximum seconds to block waiting
     * @return array [Connection|null, array|null] freshly built
     *      Connection plus an additional_context dict, or
     *      [null, null] if no connection was accepted
     */
    public function accept($acceptor, $timeout)
    {
        return $acceptor->accept($this, $timeout);
    }
}
/**
 * Per-protocol readable-event handler. WebSite holds one Transport
 * instance per supported protocol ('h1', 'h2', 'ws', 'h3') and
 * routes each incoming readable event to the Transport matching
 * the Connection's negotiated protocol. Transports are thin: they
 * call back into WebSite for the actual parser work. Their job is
 * to encapsulate which parser handles which protocol so adding a
 * new protocol means adding a Transport, not editing a switch in
 * the dispatcher.
 */
abstract class Transport
{
    /**
     * Constructs a Transport bound to the given WebSite.
     *
     * @param WebSite $site back-reference to the WebSite the Transport is
     *      wired into; used to call into the existing parsers and to
     *      access shared state (in_streams, default_server_globals)
     */
    public function __construct(protected $site)
    {
    }
    /**
     * Called by WebSite::processRequestStreams when stream_select
     * reports the connection's socket as readable. Implementations
     * should consume one chunk of inbound data and either dispatch
     * a complete request or buffer for the next iteration.
     *
     * @param int $key stream key of the readable connection
     * @param Connection|null $conn connection object, or null if
     *      torn down between select and dispatch
     * @param resource $in_stream the readable socket resource
     * @param bool $too_long true if buffered request data already
     *      exceeds MAX_REQUEST_LEN
     */
    abstract public function onReadable($key, $conn, $in_stream,
        $too_long);
}
/**
 * Transport for HTTP/1.x connections. Delegates to
 * WebSite::parseH1Request which handles the chunk read, parser
 * call, optional WebSocket upgrade, and response queueing onto
 * out_streams for the async write path.
 */
class H1Transport extends Transport
{
    /**
     * {@inheritDoc}
     */
    public function onReadable($key, $conn, $in_stream, $too_long)
    {
        $this->site->parseH1Request($key, $in_stream, $too_long);
    }
}
/**
 * Transport for connections still completing their TLS handshake.
 * Each readable event advances the non-blocking handshake one
 * step; when it completes the connection is promoted to its real
 * HTTP protocol, and when it fails or the handshake deadline
 * passes the connection is closed. Routing the handshake through a
 * transport lets the existing event loop drive it with no special
 * casing in the select loop, so a peer that stalls mid-handshake
 * no longer blocks any other connection.
 */
class HandshakeTransport extends Transport
{
    /**
     * {@inheritDoc}
     */
    public function onReadable($key, $conn, $in_stream, $too_long)
    {
        $this->site->stepHandshake($key, $conn);
    }
}
/**
 * Transport for HTTP/2 connections. H2 bypasses the chunk-read +
 * out_streams async write path because H2 framing handles its own
 * flow control: parseH2Request does its own blocking frame read
 * and writes the response directly. If the client somehow buffered
 * more than MAX_REQUEST_LEN unparsed bytes (e.g. an in-flight
 * partial frame larger than the limit), tear the connection down
 * rather than parse it.
 */
class H2Transport extends Transport
{
    /**
     * {@inheritDoc}
     */
    public function onReadable($key, $conn, $in_stream, $too_long)
    {
        if ($too_long) {
            $this->site->shutdownHttpStream($key);
            return;
        }
        $this->site->parseH2Request($key, $in_stream);
    }
}
/**
 * Transport for established WebSocket connections. parseWsRequest
 * reads one frame, dispatches text or binary messages to the
 * registered onMessage callback, and answers ping or close frames
 * inline. WebSocket framing has its own length limits so the
 * generic too-long flag is not consulted here.
 */
class WsTransport extends Transport
{
    /**
     * {@inheritDoc}
     */
    public function onReadable($key, $conn, $in_stream, $too_long)
    {
        $this->site->parseWsRequest($key, $in_stream);
    }
}
/**
 * Static helpers for parsing and serializing WebSocket frames per
 * RFC 6455 section 5.2. Frames consist of a 2 to 14 byte header
 * encoding FIN bit, opcode, mask bit, payload length, optional
 * masking key, and the payload itself. All client-to-server frames
 * are masked; server-to-client frames must not be masked.
 */
class WebSocketFrame
{
    /**
     * Parses one complete WebSocket frame out of an in-memory
     * byte buffer without doing any socket I/O. Returns an array
     * with the parsed frame and the number of bytes it consumed
     * from the front of the buffer, or null when the buffer does
     * not yet hold a whole frame and more bytes must be read. This
     * lets the event loop accumulate inbound bytes non-blocking
     * and parse frames as they complete, so a slow client that
     * dribbles a partial frame cannot block the loop. When the
     * declared payload length exceeds the maximum the frame is
     * reported as too_large once its header has arrived, since the
     * oversized payload itself need not be buffered to reject it.
     *
     * @param string $buffer raw inbound bytes accumulated so far
     * @return array|null ['frame' => array, 'consumed' => int] when
     *      a whole frame is available, or null if more bytes are
     *      needed. The frame array has keys 'fin' (bool), 'opcode'
     *      (int), 'masked' (bool), 'payload' (string), 'length'
     *      (int), and 'too_large' (bool).
     */
    public static function parseBuffer($buffer)
    {
        $have = strlen($buffer);
        if ($have < 2) {
            return null;
        }
        $byte1 = ord($buffer[0]);
        $byte2 = ord($buffer[1]);
        $fin = (bool)($byte1 & 0x80);
        $opcode = $byte1 & 0x0F;
        $masked = (bool)($byte2 & 0x80);
        $length = $byte2 & 0x7F;
        $offset = 2;
        if ($length === 126) {
            if ($have < $offset + 2) {
                return null;
            }
            $length = unpack('n', substr($buffer, $offset, 2))[1];
            $offset += 2;
        } else if ($length === 127) {
            if ($have < $offset + 8) {
                return null;
            }
            /*
                64-bit length: PHP integers are signed 64-bit on
                most builds; combine the two 32-bit halves. The
                maximum message size below bounds the value well
                under the sign bit in practice.
             */
            $unpacked = unpack('Nhi/Nlo', substr($buffer, $offset, 8));
            $length = ($unpacked['hi'] << 32) | $unpacked['lo'];
            $offset += 8;
        }
        if ($length > WebSite::WS_MAX_MESSAGE_SIZE) {
            return ['frame' => ['fin' => $fin, 'opcode' => $opcode,
                'masked' => $masked, 'payload' => '',
                'length' => $length, 'too_large' => true],
                'consumed' => $offset];
        }
        $mask_key = '';
        if ($masked) {
            if ($have < $offset + 4) {
                return null;
            }
            $mask_key = substr($buffer, $offset, 4);
            $offset += 4;
        }
        if ($have < $offset + $length) {
            return null;
        }
        $payload = '';
        if ($length > 0) {
            $payload = substr($buffer, $offset, $length);
            if ($masked) {
                $payload = self::unmask($payload, $mask_key);
            }
            $offset += $length;
        }
        return ['frame' => ['fin' => $fin, 'opcode' => $opcode,
            'masked' => $masked, 'payload' => $payload,
            'length' => $length, 'too_large' => false],
            'consumed' => $offset];
    }
    /**
     * Builds the binary representation of an outbound (server to
     * client) WebSocket frame. Server frames are never masked, so
     * the mask bit is always zero. Always sets FIN since this
     * server does not fragment outbound messages.
     *
     * @param int $opcode one of the WS_OPCODE_* constants
     * @param string $payload binary payload bytes
     * @return string binary serialized frame
     */
    public static function build($opcode, $payload)
    {
        $length = strlen($payload);
        $byte1 = chr(0x80 | ($opcode & 0x0F));
        if ($length < 126) {
            $header = $byte1 . chr($length);
        } else if ($length <= 0xFFFF) {
            $header = $byte1 . chr(126) . pack('n', $length);
        } else {
            $header = $byte1 . chr(127)
                . pack('NN', ($length >> 32) & 0xFFFFFFFF,
                    $length & 0xFFFFFFFF);
        }
        return $header . $payload;
    }
    /**
     * Unmasks a WebSocket payload (RFC 6455 sec 5.3) by XORing each
     * byte with the corresponding byte of the rotating 4-byte mask
     * key.
     *
     * @param string $payload masked binary payload
     * @param string $mask_key 4-byte masking key
     * @return string unmasked binary payload
     */
    private static function unmask($payload, $mask_key)
    {
        $length = strlen($payload);
        $key = str_repeat($mask_key, intdiv($length, 4) + 1);
        return $payload ^ substr($key, 0, $length);
    }
}
/**
 * Per-connection WebSocket handle passed to the user route handler.
 * Wraps a stream resource and provides high-level send and event
 * registration methods. Inbound frames are read from the event
 * loop by WebSite::parseWsRequest which dispatches text and binary
 * messages to the registered onMessage callback. Outbound writes
 * are queued through the WebSite out_streams machinery so partial
 * writes to slow clients do not block other connections.
 */
class WebSocket
{
    /**
     * User-supplied handler called with each complete inbound text
     * or binary message
     * @var callable|null
     */
    public $on_message;
    /**
     * User-supplied handler called when the connection closes
     * @var callable|null
     */
    public $on_close;
    /**
     * User-supplied handler called when a protocol error occurs
     * @var callable|null
     */
    public $on_error;
    /**
     * Buffer for accumulating fragmented messages across multiple
     * frames before the FIN bit is set
     * @var string
     */
    public $fragment_buffer = "";
    /**
     * Buffer of raw inbound bytes read from the socket but not yet
     * forming a complete frame. The event loop appends whatever is
     * available on each readable event and parseBuffer consumes
     * whole frames from the front, so a slow client that sends a
     * frame in pieces does not block the loop.
     * @var string
     */
    public $input_buffer = "";
    /**
     * Opcode of the first frame in a fragmented message; used to
     * remember whether the assembled message is text or binary
     * @var int
     */
    public $fragment_opcode = 0;
    /**
     * Whether close() has been called or a close frame received
     * @var bool
     */
    public $closed = false;
    /**
     * Unix timestamp of the most recent PONG (or any frame from
     * the client). Used by the keepalive timer to identify dead
     * connections that have not responded to recent PINGs.
     * @var int
     */
    public $last_pong_time;
    /**
     * Unix timestamp of the most recent PING sent by the server.
     * Used to compute whether enough time has elapsed without a
     * PONG to declare the connection dead.
     * @var int
     */
    public $last_ping_time = 0;
    /**
     * Constructs a WebSocket handle around an open connection.
     *
     * @param resource $connection underlying TCP (or TLS-wrapped)
     *      client socket already upgraded from HTTP/1.1 to the
     *      WebSocket protocol
     * @param int $key connection key used by the WebSite event loop
     *      to identify this connection in the in_streams arrays
     * @param WebSite $site reference to the owning WebSite instance,
     *      used to enqueue outbound frames into its out_streams
     *      buffer
     */
    public function __construct(public $connection, public $key,
        public $site)
    {
        $this->last_pong_time = time();
    }
    /**
     * When this WebSocket rides an HTTP/2 extended CONNECT stream
     * rather than a connection of its own, this holds that stream's
     * id so outbound frames are wrapped in HTTP/2 DATA frames on it.
     * Zero means the socket is a plain HTTP/1.1 upgrade written
     * straight to the connection.
     * @var int
     */
    public $h2_stream_id = 0;
    /**
     * What was asked for in the address the socket was opened with,
     * read from the handshake rather than from the arrays an ordinary
     * request uses, since a socket outlives that request.
     * @var array
     */
    public $query = [];
    /**
     * The cookies the client sent when opening the socket, kept here
     * for the same reason as the query above.
     * @var array
     */
    public $cookies = [];
    /**
     * Registers a callback invoked once for each complete inbound
     * text or binary message. The callback receives the message
     * payload as its first argument and this WebSocket as the
     * second argument.
     *
     * @param callable $callback function(string $message,
     *      WebSocket $ws)
     */
    public function onMessage(callable $callback)
    {
        $this->on_message = $callback;
    }
    /**
     * Registers a callback invoked when the connection closes,
     * either by remote close frame or by network failure.
     *
     * @param callable $callback function(WebSocket $ws)
     */
    public function onClose(callable $callback)
    {
        $this->on_close = $callback;
    }
    /**
     * Registers a callback invoked on protocol errors such as
     * messages exceeding the maximum size or malformed frames.
     *
     * @param callable $callback function(string $reason,
     *      WebSocket $ws)
     */
    public function onError(callable $callback)
    {
        $this->on_error = $callback;
    }
    /**
     * Sends a text message to the client. The payload should be a
     * valid UTF-8 string per RFC 6455 sec 5.6; this method does
     * not validate or transcode.
     *
     * @param string $message UTF-8 text payload to send
     * @return bool true if queued for delivery, false if the
     *      connection is already closed
     */
    public function send($message)
    {
        return $this->enqueue(WebSite::WS_OPCODE_TEXT, $message);
    }
    /**
     * Sends a binary message to the client.
     *
     * @param string $data binary payload to send
     * @return bool true if queued, false if already closed
     */
    public function sendBinary($data)
    {
        return $this->enqueue(WebSite::WS_OPCODE_BINARY, $data);
    }
    /**
     * Sends a close frame and marks this WebSocket as closed.
     * The actual TCP close happens after the close frame is
     * fully written and the remote endpoint reciprocates (or
     * after a timeout).
     *
     * @param int $code close status code (RFC 6455 sec 7.4)
     * @param string $reason optional UTF-8 reason text
     */
    public function close($code = 1000, $reason = "")
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        $payload = pack('n', $code) . $reason;
        $this->enqueue(WebSite::WS_OPCODE_CLOSE, $payload);
    }
    /**
     * Builds a frame for the opcode and payload and appends to
     * the WebSite out_streams buffer. The event loop drains the
     * buffer as the socket becomes writable.
     *
     * Message frames (TEXT, BINARY, CONTINUATION) are capped at
     * WS_MAX_MESSAGE_SIZE. Control frames (PING/PONG/CLOSE) are
     * exempt — RFC 6455 sec 5.5 limits them to 125 bytes anyway
     * and the caller is expected to comply.
     *
     * @param int $opcode WS_OPCODE_* constant
     * @param string $payload binary payload bytes
     * @return bool true if queued, false if closed (and not a
     *      CLOSE) or if a message frame exceeds the size cap
     */
    public function enqueue($opcode, $payload)
    {
        if ($this->closed && $opcode !== WebSite::WS_OPCODE_CLOSE) {
            return false;
        }
        if (($opcode === WebSite::WS_OPCODE_TEXT
                || $opcode === WebSite::WS_OPCODE_BINARY
                || $opcode === WebSite::WS_OPCODE_CONTINUATION)
            && strlen($payload) > WebSite::WS_MAX_MESSAGE_SIZE) {
            if ($this->on_error !== null) {
                ($this->on_error)(
                    "Outbound message exceeds WS_MAX_MESSAGE_SIZE",
                    $this);
            }
            return false;
        }
        $frame = WebSocketFrame::build($opcode, $payload);
        if ($this->h2_stream_id !== 0) {
            $this->site->wsEnqueueH2Write($this->key,
                $this->h2_stream_id, $frame);
            return true;
        }
        $this->site->wsEnqueueWrite($this->key, $frame);
        return true;
    }
}
/**
 * HTTP/2 frame handler classes
 */
class Frame
{
    // Properties
    /**
     * Map of flag-name => bit value; subclasses override with the
     * flags that apply to their specific frame type.
     * @var array
     */
    protected $defined_flags = [];
    /**
     * 8-bit frame-type identifier per RFC 7540 §6; subclasses
     * override with their wire-protocol value.
     * @var int|null
     */
    protected $type = null;
    /**
     * One of the STREAM_ASSOC_* constants describing whether this
     * frame type belongs on the connection (stream 0), on a stream
     * (stream != 0), or either.
     * @var string|null
     */
    protected $stream_association = null;
    /**
     * Decoded length of the frame payload (in bytes), set when the
     * frame header is parsed.
     * @var int
     */
    protected $payload_length;
    /**
     * Set of flag names currently active on this frame, drawn from
     * $defined_flags by parseFlags.
     * @var array
     */
    public $flags;

    // Constants
    /**
     * stream_association sentinel: frame type MUST be sent on a
     * stream (stream_id != 0); otherwise it's a connection error
     */
    const STREAM_ASSOC_HAS_STREAM = "has-stream";
    /**
     * stream_association sentinel: frame type MUST be sent on the
     * connection (stream_id == 0); otherwise it's a connection
     * error
     */
    const STREAM_ASSOC_NO_STREAM = "no-stream";
    /**
     * stream_association sentinel: frame type can be sent on
     * either the connection (stream_id == 0) or any stream
     */
    const STREAM_ASSOC_EITHER = "either";
    /**
     * RFC 7540 §6.5.2 initial value for SETTINGS_MAX_FRAME_SIZE;
     * peers may negotiate a larger value up to FRAME_MAX_ALLOWED_LEN
     */
    const FRAME_MAX_LEN = (2 ** 14);
    /**
     * RFC 7540 §6.5.2 ceiling for SETTINGS_MAX_FRAME_SIZE; the
     * frame-length field is 24 bits so no larger value can be
     * encoded
     */
    const FRAME_MAX_ALLOWED_LEN = (2 ** 24) - 1;
    /**
     * reads the stream id and flags set for the frame
     *
     * @param int $stream_id stream identifier carried in the frame
     *      header (0 for connection-level frames)
     * @param array $flags array of all flags in the frame
     */
    public function __construct(public $stream_id, $flags = [])
    {
        $this->flags = new Flags($this->defined_flags);
        foreach ($flags as $flag) {
            $this->flags->add($flag);
        }
        if (!$this->stream_id &&
            $this->stream_association == self::STREAM_ASSOC_HAS_STREAM) {
            throw new \Exception("Stream ID must be non-zero for " .
                get_class($this));
        }
        if ($this->stream_id &&
            $this->stream_association == self::STREAM_ASSOC_NO_STREAM) {
            throw new \Exception("Stream ID must be zero for " .
                get_class($this) . " with stream_id=" . $this->stream_id);
        }
    }
    /**
     * method to serialize body of the frame into binary.
     * Different implementations for each child class.
     *
     * @param object $hpack optional HPack instance used by
     *      HeaderFrame for encoding
     */
    public function serializeBody($hpack = null)
    {
        throw new \Exception("Not implemented");
    }
    /**
     * Serializes the frame into binary. Internally calls serializeBody.
     * Uses pack to serialize the frame header and concatenates with body.
     *
     * @param object $hpack optional HPack instance to pass through
     *      to serializeBody for HeaderFrame encoding
     * @return string binary serialized frame
     */
    public function serialize($hpack = null)
    {
        $body = $this->serializeBody($hpack);
        $this->payload_length = strlen($body);
        $flags = 0;
        foreach ($this->defined_flags as $flag => $flag_bit) {
            if ($this->flags->contains($flag)) {
                $flags |= $flag_bit;
            }
        }
        /*
            HTTP/2 frame header layout (9 bytes):
            - 3 bytes: payload length (24-bit big-endian)
            - 1 byte:  frame type
            - 1 byte:  flags
            - 4 bytes: stream id (31-bit, high bit reserved)
            pack() has no 24-bit format so the length is split
            manually into three C (unsigned char) fields.
         */
         $header = pack("CCCCCN",
             ($this->payload_length >> 16) & 0xFF,
             ($this->payload_length >> 8)  & 0xFF,
              $this->payload_length        & 0xFF,
             $this->type,
             $flags,
             $this->stream_id & 0x7FFFFFFF
         );
        return $header . $body;
    }
    /**
     * Parses the header of a frame from its binary representation.
     * Uses FrameFactory to determine the frame type based on the type number.
     *
     * @param string $data Binary data of the frame header in hexadecimal
     *  format.
     * @return array two-element list [Frame $frame, int $length]: a
     *      freshly-instantiated Frame subclass (resolved via
     *      FrameFactory::$frames) with payload_length and flags
     *      populated, plus the payload length the caller must
     *      consume before calling parseBody. The frame is null for a
     *      type this server does not know, such as the PRIORITY_UPDATE
     *      frame (type 0x10) a browser sends to change how soon it wants
     *      a response; RFC 9113 sec 5.5 has such a frame skipped
     */
    public static function parseFrameHeader($data)
    {
        if (strlen($data) < 9) {
            throw new \Exception("Invalid frame header: need 9 bytes, got "
                . strlen($data));
        }
        $length = (ord($data[0]) << 16)
                | (ord($data[1]) << 8)
                |  ord($data[2]);
        $type      = ord($data[3]);
        $flag_byte = ord($data[4]);
        $stream_id = unpack('N', substr($data, 5, 4))[1] & 0x7FFFFFFF;
        if (!isset(FrameFactory::$frames[$type])) {
            return [null, $length];
        }
        $frame = new FrameFactory::$frames[$type]($stream_id);
        $frame->payload_length = $length;
        $frame->parseFlags($flag_byte);
        return [$frame, $length];
    }
    /**
     * Parses all flags of the frame against the defined flags
     * which are present in each child class.
     * @param string $flag_byte Binary data representing the flag
     * byte in hexadecimal format.
     * @return Flags the frame's flags collection populated with
     *      the symbolic names of every defined flag whose bit is
     *      set in $flag_byte
     */
    public function parseFlags($flag_byte)
    {
        foreach ($this->defined_flags as $flag => $flag_bit) {
            if ($flag_byte & $flag_bit) {
                $this->flags->add($flag);
            }
        }
        return $this->flags;
    }
    /**
     * Parses the binary body of the WINDOW_UPDATE frame.
     *
     * @param string $data binary payload of the frame (4 bytes)
     */
    public function parseBody($data)
    {
        throw new \Exception("Not implemented");
    }
}
/**
 * Mapping of frame types to classes, so that frame objects can be
 * created dynamically based on the type number.
 */
class FrameFactory
{
    /**
     * Map from RFC 7540 §11.2 frame-type identifier to the
     * Frame subclass that handles it. Used by
     * parseFrameHeader to instantiate the right Frame type
     * when reading bytes off the wire.
     * @var array
     */
    public static $frames = [
        0x0 => DataFrame::class,
        0x1 => HeaderFrame::class,
        0x2 => PriorityFrame::class,
        0x3 => RstStreamFrame::class,
        0x4 => SettingsFrame::class,
        0x5 => PushPromiseFrame::class,
        0x6 => PingFrame::class,
        0x7 => GoAwayFrame::class,
        0x8 => WindowUpdateFrame::class,
        0x9 => ContinuationFrame::class,
    ];
}
/**
 * SettingsFrame class is responsible for handling the HTTP/2 SETTINGS frame,
 * helps configure communication parameters between the client and server.
 */
class SettingsFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'ACK' => 0x01
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x04;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    /**
     * Map from SETTINGS-frame parameter identifier (uint16) to the
     * canonical RFC 7540 / 8441 parameter name. Used when parsing
     * a peer's SETTINGS payload and when serialising one to send.
     */
    const PAYLOAD_SETTINGS = [
        0x01 => 'HEADER_TABLE_SIZE',
        0x02 => 'ENABLE_PUSH',
        0x03 => 'MAX_CONCURRENT_STREAMS',
        0x04 => 'INITIAL_WINDOW_SIZE',
        0x05 => 'MAX_FRAME_SIZE',
        0x06 => 'MAX_HEADER_LIST_SIZE',
        0x08 => 'ENABLE_CONNECT_PROTOCOL',
    ];
    /**
     * Constructor to create a new SettingsFrame object.
     *
     * @param int $stream_id the stream ID for this frame (default is
     *      0 since SETTINGS frames aren't tied to a stream)
     * @param array $settings parsed settings dictionary (identifier
     *      => value) after a call to parseBody, and the input to
     *      serializeBody when sending; public so callers
     *      (initH2Request, parseH2Request) can read the parsed
     *      values directly off the frame without needing a getter
     * @param array $flags any flags associated with the frame (e.g.
     *      'ACK')
     */
    public function __construct($stream_id = 0,
        public $settings = [], $flags = [])
    {
        parent::__construct($stream_id, $flags);
        if (!empty($settings) && in_array('ACK', $flags)) {
            throw new InvalidDataError(
                "Settings must be empty if ACK flag is set.");
        }
    }
    /**
     * Converts the settings into the format required for transmission.
     * Each setting is packed as 6 bytes: 2 bytes for the setting identifier
     * and 4 bytes for its value.
     * @param object $hpack HPack encoder for this connection; unused
     *      for non-HEADERS frame bodies but accepted for signature
     *      compatibility with HeaderFrame::serializeBody
     * @return string Returns the settings as serialized binary data.
     */
    public function serializeBody($hpack = null)
    {
        $body = '';
        foreach ($this->settings as $setting => $value) {
            $body .= pack('nN', $setting, $value);
        }
        return $body;
    }
    /**
     * Parses binary data of the SETTINGS frame body and extracts the settings
     * into the frame's settings array in a readable format.
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        if ($this->flags->contains('ACK') && strlen($data) > 0) {
            throw new \Exception(
                "SETTINGS ACK frame must have empty payload, got "
                . strlen($data) . " bytes");
        }
        if (strlen($data) % 6 !== 0) {
            throw new \Exception(
                "SETTINGS payload must be a multiple of 6 bytes, got "
                . strlen($data));
        }
        $this->settings = [];
        for ($i = 0; $i < strlen($data); $i += 6) {
            $identifier = unpack('n', substr($data, $i, 2))[1];
            $value      = unpack('N', substr($data, $i + 2, 4))[1];
            $this->settings[$identifier] = $value;
        }
        $this->payload_length = strlen($data);
    }
}
/**
 * HeaderFrame class is responsible for handling the HTTP/2 HEADER frame,
 * which carries header parameters related to a stream between the client and
 * server.
 */
class HeaderFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'END_HEADERS' => 0x04,
        'PADDED' => 0x08,
        'PRIORITY' => 0x20
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x01;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    /**
     * Constructor to create a new HeaderFrame object.
     *
     * @param int $stream_id the stream ID this frame belongs to
     * @param string $data raw payload bytes carried by this frame
     * @param array $flags any flags associated with the frame
     */
    public function __construct($stream_id = 0,
        public $data = [], $flags = [])
    {
        parent::__construct($stream_id, $flags);
    }
    /**
     * Serializes the header data into the format required for
     * transmission. Uses HPACK encoding to compress headers.
     *
     * @param object $hpack HPack instance for this connection. If
     *      null a fresh instance is created.
     * @return string binary HPACK-encoded header block
     */
    public function serializeBody($hpack = null)
    {
        $headers = "";
        if (!empty($this->data)) {
            if ($hpack === null) {
                $hpack = new HPack();
            }
            $headers = $hpack->encode($this->data, 4096);
        }
        return $headers;
    }
    /**
     * Parses the binary HPACK-encoded header block of a HEADERS frame
     * and returns a context array in the same format that parseRequest
     * builds, suitable for passing directly to setGlobals.
     *
     * @param string $data binary payload of the HEADERS frame
     * @param object $hpack HPack instance for this connection. If
     *      null a fresh instance is created.
     * @return array context array with REQUEST_METHOD, REQUEST_URI,
     *      SERVER_PROTOCOL, QUERY_STRING, PHP_SELF, HTTP_* headers
     */
    public function parseBody($data, $hpack = null)
    {
        if ($hpack === null) {
            $hpack = new HPack();
        }
        $offset = 0;
        $padding = 0;
        /*
            If the PADDED flag is set the first byte is the pad
            length and that many zero bytes appear at the end of
            the payload. Strip both before HPACK decoding.
         */
        if ($this->flags->contains('PADDED')) {
            $padding = ord($data[0]);
            $offset += 1;
        }
        /*
            If the PRIORITY flag is set the next 5 bytes are the
            stream dependency (4 bytes) and weight (1 byte).
            These come before the HPACK header block.
         */
        if ($this->flags->contains('PRIORITY')) {
            $offset += 5;
        }
        $hpack_data = substr($data, $offset,
            strlen($data) - $offset - $padding);
        $headers = $hpack->decodeHeaderBlockFragment($hpack_data);
        $method    = 'GET';
        $authority = 'localhost';
        $path      = '/';
        $scheme    = 'https';
        $context   = [];
        if ($headers !== null) {
            foreach ($headers as $header) {
                foreach ($header as $key => $value) {
                    if ($key === ':method') {
                        $method = strtoupper($value);
                    } else if ($key === ':protocol') {
                        /* RFC 8441: an extended CONNECT names the
                           protocol to tunnel, such as websocket, in
                           this pseudo-header. It is kept so the h2
                           dispatch can recognize a WebSocket that
                           rides the connect stream. */
                        $context['REQUEST_PROTOCOL'] = strtolower($value);
                    } else if ($key === ':path') {
                        $path = ($value !== ''
                            && $value[0] === '/') ? $value : '/';
                    } else if ($key === ':scheme') {
                        if (in_array($value, ['http', 'https'])) {
                            $scheme = $value;
                        }
                    } else if ($key === ':authority'
                        && filter_var("http://$value",
                            FILTER_VALIDATE_URL)) {
                        $authority = $value;
                    } else if (($key[0] ?? "") !== ':') {
                        $up = strtoupper(str_replace('-', '_', $key));
                        /*
                            CGI convention: Content-Type and
                            Content-Length are exposed in $_SERVER
                            WITHOUT the HTTP_ prefix that all other
                            request headers receive. H1.1 path
                            already does this; H2 must match so
                            setGlobals' multipart decoder finds
                            them at the expected key.
                         */
                        if ($up === 'CONTENT_TYPE'
                                || $up === 'CONTENT_LENGTH') {
                            $context[$up] = $value;
                            continue;
                        }
                        $http_key = 'HTTP_' . $up;
                        if ($http_key === 'HTTP_COOKIE'
                                && isset($context[$http_key])) {
                            /*
                                RFC 7540 sec 8.1.2.5: H2 clients
                                may split Cookie into multiple
                                header fields for HPACK compression.
                                Concatenate with "; " (the cookie-
                                pair delimiter) when flattening to
                                $_SERVER, otherwise only the last
                                pair survives.
                             */
                            $context[$http_key] .= '; ' . $value;
                        } else {
                            $context[$http_key] = $value;
                        }
                    }
                }
            }
        }
        $question = strpos($path, '?');
        if ($question === false) {
            $context['PHP_SELF'] = $path;
            $context['QUERY_STRING'] = '';
        } else {
            $context['PHP_SELF'] = substr($path, 0, $question);
            $context['QUERY_STRING'] = substr($path, $question + 1);
        }
        $context['REQUEST_METHOD'] = $method;
        $context['REQUEST_URI'] = $path;
        $context['SERVER_PROTOCOL']  = 'HTTP/2.0';
        $context['HTTPS'] = 'on';
        $context['HTTP_HOST'] = $authority;
        $context['CONTENT']= '';
        /*
            REMOTE_ADDR is socket-level — it must come from the
            connection context populated by initRequestStream. Do
            NOT set it here: the array_merge in parseH2Request
            prefers fresh keys, which would clobber the real IP
            with a placeholder and break an application that
            verifies $_SESSION['REMOTE_ADDR'].
         */
        $context['SCRIPT_FILENAME']  = '';
        return $context;
    }
}
/**
 * DataFrame class handles the HTTP/2 DATA frame,
 * which carries the data of a stream between the client and server.
 */
class DataFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'PADDED' => 0x08
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x0;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    /**
     * Constructor to create a new DataFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param string $data raw payload bytes carried by this frame
     * @param array $flags flags associated with the frame
     */
    public function __construct($stream_id,
        public $data = '', $flags = [])
    {
        parent::__construct($stream_id, $flags);
    }
    /**
     * Serializes the body of the frame into a binary string.
     * Converts the ASCII data to binary format for transmission.
     * @param object $hpack HPack encoder for this connection; unused
     *      for non-HEADERS frame bodies but accepted for signature
     *      compatibility with HeaderFrame::serializeBody
     * @return string the frame's $data buffer as-is (DATA frames
     *      carry raw application bytes, no encoding)
     */
    public function serializeBody($hpack = null)
    {
        return $this->data;
    }
    /**
     * Parses the binary data of the DATA frame and extracts the
     * data payload. Strips padding if the PADDED flag is set: the
     * first byte is the pad length and that many trailing bytes
     * are padding to be discarded.
     *
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        $this->payload_length = strlen($data);
        $offset = 0;
        $padding = 0;
        if ($this->flags->contains('PADDED')) {
            if ($this->payload_length < 1) {
                throw new InvalidPaddingException(
                    "PADDED frame missing pad length byte.");
            }
            $padding = ord($data[0]);
            $offset = 1;
            if ($padding + $offset > $this->payload_length) {
                throw new InvalidPaddingException(
                    "Padding is too long.");
            }
        }
        $this->data = substr($data, $offset,
            $this->payload_length - $offset - $padding);
    }
}
/**
 * PriorityFrame class handles the HTTP/2 PRIORITY frame,
 * which specifies the sender-advised priority of a stream.
 */
class PriorityFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x02;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = self::STREAM_ASSOC_HAS_STREAM;
    /**
     * 31-bit stream id this stream depends on for ordering
     * per RFC 7540 §5.3.2; 0 indicates no dependency.
     * @var int
     */
    protected $depends_on;
    /**
     * 8-bit priority weight (RFC 7540 §5.3.2) the peer
     * advised; the server is not required to honor it.
     * @var int
     */
    protected $stream_weight;
    /**
     * Whether this stream wants the exclusive dependency
     * flag set on $depends_on per RFC 7540 §5.3.1.
     * @var bool
     */
    protected $exclusive;
    /**
     * Constructor for PriorityFrame.
     *
     * @param int $stream_id the stream ID this frame belongs to
     * @param array $flags any flags for this frame
     */
    public function __construct($stream_id, $flags = [])
    {
        parent::__construct($stream_id, $flags);
        $this->depends_on = 0;
        $this->stream_weight = 0;
        $this->exclusive = false;
    }
    /**
     * Serializes the PRIORITY frame body into binary format.
     * @param object $hpack HPack encoder for this connection; unused
     *      for non-HEADERS frame bodies but accepted for signature
     *      compatibility with HeaderFrame::serializeBody
     * @return string 5-byte serialized priority data
     */
    public function serializeBody($hpack = null)
    {
        $dep = $this->depends_on
            + ($this->exclusive ? 0x80000000 : 0);
        return pack('NC', $dep, $this->stream_weight);
    }
    /**
     * Parses the binary body of a PRIORITY frame.
     *
     * @param string $data binary payload, must be exactly 5 bytes
     */
    public function parseBody($data)
    {
        if (strlen($data) != 5) {
            throw new InvalidFrameException(
                "PRIORITY must have a 5 byte body.");
        }
        $unpacked = unpack('Ndepends_on/Cstream_weight',
            substr($data, 0, 5));
        $this->depends_on = $unpacked['depends_on'] & 0x7FFFFFFF;
        $this->stream_weight = $unpacked['stream_weight'];
        $this->exclusive = (bool)($unpacked['depends_on'] >> 31);
        $this->payload_length = 5;
    }
}
/**
 * RstStreamFrame class handles the HTTP/2 RST_STREAM frame,
 * which is used to abruptly terminate a stream.
 */
class RstStreamFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x03;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    /**
     * Constructor to create a new RstStreamFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param int $error_code RFC 7540 §7 error code (NO_ERROR=0,
     *      PROTOCOL_ERROR=1, INTERNAL_ERROR=2, etc.) being reported
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id, protected $error_code = 0,
        array $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the RST_STREAM frame body into binary format.
     * The body is the 4-byte error code packed as big-endian.
     *
     * @param object $hpack unused, present for signature compatibility
     *      with HeaderFrame::serializeBody
     * @return string 4-byte serialized body
     */
    public function serializeBody($hpack = null)
    {
        return pack('N', $this->error_code);
    }
    /**
     * Parses the binary body of a RST_STREAM frame.
     *
     * @param string $data binary payload, must be exactly 4 bytes
     */
    public function parseBody($data)
    {
        if (strlen($data) != 4) {
            throw new InvalidFrameException(
                "RST_STREAM must have a 4 byte body.");
        }
        $this->error_code = unpack('N', $data)[1];
        $this->payload_length = 4;
    }
}
/**
 * PushPromiseFrame class handles the HTTP/2 PUSH_PROMISE frame,
 * which is used to notify the client of an upcoming stream.
 */
class PushPromiseFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'END_HEADERS' => 0x04,
        'PADDED' => 0x08
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x05;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    /**
     * Constructor to create a new PushPromiseFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param int $promised_stream_id server-initiated stream id the
     *      server is promising to push a response on per RFC 7540
     *      §6.6
     * @param string $data raw payload bytes carried by this frame
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id,
        protected $promised_stream_id = 0,
        protected $data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the PUSH_PROMISE frame body into binary format.
     * Layout (RFC 7540 sec 6.6, non-padded form): the 4-byte
     * promised stream id (high bit reserved zero) followed by
     * the HPACK-encoded header block fragment. Atto never sets
     * the PADDED flag for emitted PUSH_PROMISE frames so the
     * Pad Length and Padding fields are omitted entirely.
     *
     * The header block bytes are passed in pre-encoded by the
     * caller (WebSite::push) rather than encoded here. This is
     * because the connection-wide HPack encoder is owned by the
     * Connection's protocol_state and the caller already has
     * a reference to it; passing the encoded bytes through as
     * $this->data avoids threading the encoder reference into
     * every Frame instance.
     *
     * @param object $hpack unused, present for signature compatibility
     *      with HeaderFrame::serializeBody
     * @return string binary serialized body
     */
    public function serializeBody($hpack = null)
    {
        return pack('N',
            $this->promised_stream_id & 0x7FFFFFFF) . $this->data;
    }
    /**
     * Parses the binary data of an inbound PUSH_PROMISE frame.
     * Atto is a server and does not initiate connections, so it
     * never receives PUSH_PROMISE frames in practice (clients
     * MUST NOT send PUSH_PROMISE per RFC 7540 sec 8.2). The
     * parser is kept for completeness and symmetry with the
     * other Frame subclasses but only handles the non-padded
     * form; PADDED-flagged inbound promises will misparse.
     *
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        if (strlen($data) < 4) {
            throw new \Exception("Invalid PUSH_PROMISE body");
        }
        $this->promised_stream_id =
            unpack('N', substr($data, 0, 4))[1] & 0x7FFFFFFF;
        $this->data = substr($data, 4);
        if ($this->promised_stream_id == 0
            || $this->promised_stream_id % 2 != 0) {
            throw new \Exception(
                "Invalid PUSH_PROMISE promised stream id: " .
                $this->promised_stream_id);
        }
        $this->payload_length = strlen($data);
    }
}
/**
 * PingFrame class handles the HTTP/2 PING frame,
 * which is used for measuring round-trip times or verifying connection health.
 */
class PingFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'ACK' => 0x01
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x06;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    /**
     * Constructor to create a new PingFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param string $opaque_data 8 bytes of opaque round-trip-timing
     *      payload echoed back in the PING ACK per RFC 7540 §6.7
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id = 0,
        protected $opaque_data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the PING frame body into binary format.
     * @param object $hpack HPack encoder for this connection; unused
     *      for non-HEADERS frame bodies but accepted for signature
     *      compatibility with HeaderFrame::serializeBody
     * @return string The serialized binary data.
     */
    public function serializeBody($hpack = null)
    {
        if (strlen($this->opaque_data) != 8) {
            throw new InvalidDataException(
                "PING frame body must be 8 bytes");
        }
        return $this->opaque_data;
    }
    /**
     * Parses the binary data of the PING frame.
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        if (strlen($data) != 8) {
            throw new InvalidFrameException(
                "PING frame must have an 8 byte body.");
        }
        $this->opaque_data = $data;
        $this->payload_length = 8;
    }
}
/**
 * GoAwayFrame class handles the HTTP/2 GOAWAY frame,
 * which is used to indicate that the sender is gracefully
 * shutting down a connection.
 */
class GoAwayFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x07;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    /**
     * Constructor to create a new GoAwayFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param int $last_stream_id highest stream id the sender will
     *      service before closing the connection per RFC 7540 §6.8
     * @param int $error_code RFC 7540 §7 error code (NO_ERROR=0,
     *      PROTOCOL_ERROR=1, INTERNAL_ERROR=2, etc.) being reported
     * @param string $additional_data optional opaque debug data
     *      trailing the standard GOAWAY fields per RFC 7540 §6.8
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id = 0,
        protected $last_stream_id = 0, protected $error_code = 0,
        protected $additional_data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the GOAWAY frame body into a binary format.
     * @param object $hpack HPack encoder for this connection; unused
     *      for non-HEADERS frame bodies but accepted for signature
     *      compatibility with HeaderFrame::serializeBody
     * @return string The serialized binary data.
     */
    public function serializeBody($hpack = null)
    {
        $data = pack('N', $this->last_stream_id & 0x7FFFFFFF) .
                pack('N', $this->error_code);
        return $data . $this->additional_data;
    }
    /**
     * Parses the binary data of the GOAWAY frame.
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        if (strlen($data) < 8) {
            throw new InvalidFrameException("Invalid GOAWAY body.");
        }

        $this->last_stream_id = unpack('N', substr($data, 0, 4))[1] &
                                0x7FFFFFFF;
        $this->error_code = unpack('N', substr($data, 4, 4))[1];
        $this->additional_data = substr($data, 8);
        $this->payload_length = strlen($data);
    }
}
/**
 * WindowUpdateFrame class handles the HTTP/2 WINDOW_UPDATE frame,
 * which is used to implement flow control.
 */
class WindowUpdateFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x08;
    /**
     * STREAM_ASSOC_* sentinel describing which stream id this
     * frame type is permitted on (overrides
     * Frame::$stream_association).
     * @var string
     */
    protected $stream_association = '_STREAM_ASSOC_EITHER';
    /**
     * Constructor to create a new WindowUpdateFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param int $window_increment 31-bit non-zero credit being added
     *      to the flow-control window per RFC 7540 §6.9
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id,
        protected $window_increment = 0, $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the WINDOW_UPDATE frame body into binary format.
     * The body is the 4-byte window size increment with the high
     * bit (reserved) cleared.
     *
     * @param object $hpack unused, present for signature compatibility
     *      with HeaderFrame::serializeBody
     * @return string 4-byte serialized body
     */
    public function serializeBody($hpack = null)
    {
        return pack('N', $this->window_increment & 0x7FFFFFFF);
    }
    /**
     * Returns the credit this frame adds to the peer's view of a
     * flow-control window (connection-level when the frame's
     * stream id is 0, otherwise for that stream).
     *
     * @return int 31-bit window size increment
     */
    public function windowIncrement()
    {
        return $this->window_increment;
    }
    /**
     * Parses the binary body of a WINDOW_UPDATE frame.
     *
     * @param string $data binary payload, must be exactly 4 bytes
     */
    public function parseBody($data)
    {
        if (strlen($data) != 4) {
            throw new InvalidFrameException(
                "WINDOW_UPDATE body must be 4 bytes, got "
                . strlen($data));
        }
        $this->window_increment = unpack('N', $data)[1] & 0x7FFFFFFF;
        if ($this->window_increment < 1) {
            throw new InvalidDataException(
                "WINDOW_UPDATE increment must be between 1 and 2^31-1");
        }
        $this->payload_length = 4;
    }
}
/**
 * ContinuationFrame class handles the HTTP/2 CONTINUATION frame,
 * which is used to continue a sequence of header block fragments.
 */
class ContinuationFrame extends Frame
{
    /**
     * Flag-name => bit-value map for this frame type per
     * RFC 7540 §6 (overrides Frame::$defined_flags).
     * @var array
     */
    protected $defined_flags = [
        'END_HEADERS' => 0x04,
    ];
    /**
     * Wire-protocol frame-type identifier for this frame per
     * RFC 7540 §11.2 (overrides Frame::$type).
     * @var int
     */
    protected $type = 0x09;
    /**
     * Constructor to create a new ContinuationFrame object.
     *
     * @param int $stream_id the stream ID for this frame
     * @param string $data raw payload bytes carried by this frame
     * @param array $kwargs flags passed through to the parent Frame
     *      constructor
     */
    public function __construct($stream_id,
        public $data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
    }
    /**
     * Serializes the CONTINUATION frame body into binary format.
     * The body is the raw continuation of an HPACK-encoded header
     * block fragment started by a preceding HEADERS or PUSH_PROMISE
     * frame.
     *
     * @param object $hpack unused, present for signature compatibility
     *      with HeaderFrame::serializeBody
     * @return string binary serialized body
     */
    public function serializeBody($hpack = null)
    {
        return $this->data;
    }
    /**
     * Parses the binary body of a CONTINUATION frame.
     *
     * @param string $data binary payload, a header block fragment
     */
    public function parseBody($data)
    {
        $this->data = $data;
        $this->payload_length = strlen($data);
    }
}
/**
 * Exception thrown when an HTTP/2 frame fails to parse or violates
 * a structural invariant required by RFC 7540 (bad length, unknown
 * frame type on a stream that doesn't accept it, etc.).
 */
class InvalidFrameException extends \Exception {}
/**
 * Exception thrown when frame payload data fails to decode (e.g.
 * a malformed SETTINGS payload, a CONTINUATION sequence that
 * doesn't terminate, or any other data-level structural error).
 */
class InvalidDataException extends \Exception {}
/**
 * Exception thrown when a frame's PADDED flag is set but the
 * declared pad length is inconsistent with the payload (i.e. the
 * pad would extend beyond the payload bytes).
 */
class InvalidPaddingException extends \Exception {}
/**
 * Represents a single flag with a name and bit value.
 */
class Flag
{
    /**
     * Constructor for Flag.
     *
     * @param string $name symbolic name of this flag (e.g. "ACK",
     *      "END_STREAM")
     * @param int $bit bitmask of this flag within the frame-header
     *      flags byte (e.g. 0x01 for ACK)
     */
    public function __construct(public $name, public $bit)
    {
    }
}
/**
 * Flags class manages a collection of valid flags and supports
 * adding, removing, and checking for the presence of flags.
 */
class Flags
{
    /**
     * Whitelist of flag names this Flags instance accepts
     * (from the owning frame type's $defined_flags).
     * @var array
     */
    private $valid_flags;
    /**
     * Currently active flag names (subset of valid_flags).
     * @var array
     */
    private $flags;
    /**
     * Constructor for Flags.
     * @param array $defined_flags Array of defined valid flags.
     */
    public function __construct($defined_flags)
    {
        $this->valid_flags = array_keys($defined_flags);
        $this->flags = [];
    }
    /**
     * Converts the Flags object to a string by sorting
     * and joining all active flags.
     *
     * @return string comma-separated list of active flag names in
     *      sorted order (deterministic regardless of insertion
     *      order)
     */
    public function __toString()
    {
        $sorted_flags = $this->flags;
        sort($sorted_flags);
        return implode(", ", $sorted_flags);
    }
    /**
     * Checks if the specified flag is present.
     * @param string $flag The flag to check.
     * @return bool true if $flag is in the active flags list
     */
    public function contains($flag)
    {
        return in_array($flag, $this->flags);
    }
    /**
     * Adds a valid flag to the collection.
     * @param string $flag The flag to add.
     */
    public function add($flag)
    {
        if (!in_array($flag, $this->valid_flags)) {
            throw new InvalidArgumentException(sprintf(
                'Unexpected flag: %s. Valid flags are: %s',
                $flag,
                implode(', ', $this->valid_flags)
            ));
        }
        if (!in_array($flag, $this->flags)) {
            $this->flags[] = $flag;
        }
    }
    /**
     * Removes the specified flag from the collection.
     * @param string $flag The flag to remove.
     */
    public function discard($flag)
    {
        $this->flags = array_diff($this->flags, [$flag]);
    }
    /**
     * Counts the number of currently active flags.
     *
     * @return int the number of active flags
     */
    public function count()
    {
        return count($this->flags);
    }
    /**
     * Returns the array of currently active flag names.
     *
     * @return array list of flag name strings
     */
    public function getFlags()
    {
        return $this->flags;
    }
}
/**
 * Handles HPack compression for HTTP/2, utilizing static and dynamic
 * tables with Huffman encoding. Supports encoding and decoding.
 */
class HPack
{
    /**
     * RFC 7541 Appendix A static table: the 61 fixed header
     * name/value pairs every HPack endpoint shares before any
     * dynamic-table state. Indexes 1..61, each entry [name,
     * value] where value may be the empty string when only the
     * name is canonical (e.g. ":authority").
     */
    private const STATIC_TABLE = [
        1 => [':authority', ''],
        2 => [':method', 'GET'],
        3 => [':method', 'POST'],
        4 => [':path', '/'],
        5 => [':path', '/index.html'],
        6 => [':scheme', 'http'],
        7 => [':scheme', 'https'],
        8 => [':status', '200'],
        9 => [':status', '204'],
        10 => [':status', '206'],
        11 => [':status', '304'],
        12 => [':status', '400'],
        13 => [':status', '404'],
        14 => [':status', '500'],
        15 => ['accept-charset', ''],
        16 => ['accept-encoding', 'gzip, deflate'],
        17 => ['accept-language', ''],
        18 => ['accept-ranges', ''],
        19 => ['accept', ''],
        20 => ['access-control-allow-origin', ''],
        21 => ['age', ''],
        22 => ['allow', ''],
        23 => ['authorization', ''],
        24 => ['cache-control', ''],
        25 => ['content-disposition', ''],
        26 => ['content-encoding', ''],
        27 => ['content-language', ''],
        28 => ['content-length', ''],
        29 => ['content-location', ''],
        30 => ['content-range', ''],
        31 => ['content-type', ''],
        32 => ['cookie', ''],
        33 => ['date', ''],
        34 => ['etag', ''],
        35 => ['expect', ''],
        36 => ['expires', ''],
        37 => ['from', ''],
        38 => ['host', ''],
        39 => ['if-match', ''],
        40 => ['if-modified-since', ''],
        41 => ['if-none-match', ''],
        42 => ['if-range', ''],
        43 => ['if-unmodified-since', ''],
        44 => ['last-modified', ''],
        45 => ['link', ''],
        46 => ['location', ''],
        47 => ['max-forwards', ''],
        48 => ['proxy-authenticate', ''],
        49 => ['proxy-authorization', ''],
        50 => ['range', ''],
        51 => ['referer', ''],
        52 => ['refresh', ''],
        53 => ['retry-after', ''],
        54 => ['server', ''],
        55 => ['set-cookie', ''],
        56 => ['strict-transport-security', ''],
        57 => ['transfer-encoding', ''],
        58 => ['user-agent', ''],
        59 => ['vary', ''],
        60 => ['via', ''],
        61 => ['www-authenticate', '']
    ];
    /**
     * Per-instance HPACK header table. Indices 1-61 are pre-populated
     * with the static table entries from RFC 7541 Appendix A; entries
     * appended at index 62 and beyond form the dynamic table.
     * @var array
     */
    private $headers_table = [];
    /**
     * Encoder lookup hashes for the static table. Built once on
     * the first HPack instance; never updated. Maps "name\0value"
     * to a static-table index for exact matches, and name to
     * a static-table index for name-only matches.
     * @var array<string,int>
     */
    private static $static_name_value_index = null;
    /**
     * Lazy lookup map "name" => lowest static-table index
     * carrying that name. Used by encode() to pick the
     * most compact name reference.
     * @var array<string,int>|null
     */
    private static $static_name_index = null;
    /**
     * never_indexed holds the header names that have been encoded as
     * "Literal Never Indexed" and so must not be added to the
     * dynamic table by intermediaries (RFC 7541 sec 6.2.3).
     * @var array<string,bool>
     */
    private $never_indexed = [];
    /**
     * Maximum dynamic table size in octets. The RFC 7541 default
     * is 4096; the peer can change this via SETTINGS_HEADER_TABLE_SIZE.
     * @var int
     */
    private $max_table_size = 4096;
    /**
     * Running total of the dynamic table's current octet size,
     * computed per RFC 7541 sec 4.1: sum over entries of
     * length(name) + length(value) + 32. Maintained incrementally
     * by addHeader / evictEntry to avoid a full table walk on
     * every check.
     * @var int
     */
    private $current_table_size = 0;
    /**
     * Constructs a new HPack instance with a fresh dynamic table
     * pre-populated with the static table entries from RFC 7541
     * Appendix A.
     */
    public function __construct()
    {
        $this->headers_table[0] = ["not defined", ""];
        foreach (self::STATIC_TABLE as $index => $header) {
            $this->headers_table[$index] = $header;
        }
        if (self::$static_name_value_index === null) {
            self::$static_name_value_index = [];
            self::$static_name_index = [];
            foreach (self::STATIC_TABLE as $index => [$name, $value]) {
                /*
                    Static table contains duplicates by name
                    (e.g. multiple :method, :status, :path
                    entries). Record only the LOWEST index per
                    name so the encoder prefers the most-compact
                    form (smaller index = fewer continuation
                    bytes).
                 */
                $key = $name . "\0" . $value;
                if (!isset(self::$static_name_value_index[$key])) {
                    self::$static_name_value_index[$key] = $index;
                }
                if (!isset(self::$static_name_index[$name])) {
                    self::$static_name_index[$name] = $index;
                }
            }
        }
    }
    /**
     * Returns the full headers table (static plus dynamic entries).
     * Intended for debugging and inspection only.
     *
     * @return array the complete header table
     */
    public function getHeadersTable()
    {
        return $this->headers_table;
    }
    /**
     * Sets the maximum dynamic table size in octets. Called by the
     * H2 layer when the peer advertises a HEADER_TABLE_SIZE setting;
     * the encoder must honor whatever upper bound the decoder will
     * accept so emitted incremental-indexing entries do not push
     * the decoder past its limit. Evicts oldest entries until the
     * table fits within the new bound.
     *
     * @param int $size new max dynamic table size in octets
     */
    public function setMaxTableSize($size)
    {
        $this->max_table_size = max(0, (int) $size);
        while ($this->current_table_size > $this->max_table_size
                && count($this->headers_table) > count(self::STATIC_TABLE)) {
            $this->evictEntry();
        }
    }
    /**
     * Evicts the oldest dynamic entry from the table per RFC 7541
     * sec 2.3.3. The oldest entry sits at the highest dynamic
     * index in our storage; pop it and decrement the running size
     * by length(name) + length(value) + 32 (RFC 7541 sec 4.1).
     */
    private function evictEntry()
    {
        if (count($this->headers_table) > count(self::STATIC_TABLE)) {
            $entry = array_pop($this->headers_table);
            $this->current_table_size -=
                strlen($entry[0]) + strlen($entry[1]) + 32;
            if ($this->current_table_size < 0) {
                $this->current_table_size = 0;
            }
        }
    }
    /**
     * Adds a header to the dynamic table per RFC 7541 sec 2.3.3:
     * the new entry is placed at the lowest dynamic index (just
     * after the static table) and existing dynamic entries shift
     * up by one. If the entry alone exceeds max_table_size, the
     * table is cleared and the entry is not added (RFC 7541 sec
     * 4.4). Otherwise oldest entries are evicted from the highest
     * index until the new entry fits.
     *
     * @param string $name  The name of the header.
     * @param string $value The value of the header.
     */
    public function addHeader($name, $value)
    {
        $entry_size = strlen($name) + strlen($value) + 32;
        if ($entry_size > $this->max_table_size) {
            /*
                RFC 7541 sec 4.4: an entry larger than the maximum
                size causes the table to be emptied without the
                entry being inserted.
             */
            while (count($this->headers_table) > count(self::STATIC_TABLE)) {
                $this->evictEntry();
            }
            return;
        }
        while ($this->current_table_size + $entry_size
                > $this->max_table_size) {
            $this->evictEntry();
        }
        $static_table_len = count(self::STATIC_TABLE);
        /*
            array_splice with offset = static_table_len + 1
            inserts at the lowest dynamic index (62 for the
            initial table) and shifts existing dynamic entries
            up by one.
         */
        array_splice($this->headers_table,
            $static_table_len + 1, 0, [[$name, $value]]);
        $this->current_table_size += $entry_size;
    }
    /**
     * Decodes an HPACK-encoded header block from raw bytes per
     * RFC 7541. Returns an array of [name => value] pairs, or
     * null if decoding fails or the block is empty.
     *
     * @param string $input raw byte string of the header block
     * @return array|null array of decoded headers, or null
     */
    public function decodeHeaderBlockFragment($input)
    {
        $offset = 0;
        $headers = [];
        $input_length = strlen($input);
        if ($input_length <= 0) {
            return null;
        }
        while ($offset < $input_length) {
            $first_byte = ord($input[$offset]);
            if (($first_byte & 0x80) === 0x80) {
                $header = $this->decodeIndexedHeaderField(
                    $input, $offset);
                if ($header === null) {
                    break;
                }
                $offset = $header['next'];
            } else if (($first_byte & 0xC0) === 0x40) {
                $header = $this->decodeLiteralWithIncrementalIndexing(
                    $input, $offset);
                $offset = $header['next'];
            } else if (($first_byte & 0xE0) === 0x20) {
                /*
                    Dynamic table size update (RFC 7541 sec 6.3).
                    Bit pattern 001xxxxx with a 5-bit prefix
                    integer. We parse the new size correctly (so
                    later bytes are aligned) but do not actually
                    shrink the decoder's table here; eviction is
                    governed by max_table_size which the H2 layer
                    can adjust via setMaxTableSize.
                 */
                [, $offset] = $this->decodeInteger($input, $offset, 5);
                continue;
            } else if (($first_byte & 0xF0) === 0x10) {
                $header = $this->decodeLiteralNeverIndexed(
                    $input, $offset);
                $offset = $header['next'];
            } else if (($first_byte & 0xF0) === 0x00) {
                $header = $this->decodeLiteralWithoutIndexing(
                    $input, $offset);
                $offset = $header['next'];
            } else {
                return null;
            }
            if ($header) {
                $headers[] = $header['decoded'];
            }
        }
        return empty($headers) ? null : $headers;
    }
    /**
     * Decodes an indexed header field from raw bytes starting at
     * $offset. The full (name, value) pair sits at the indexed
     * position in the headers table.
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @return array|null ['decoded' => [name => value],
     *      'next' => int next byte offset], or null if the
     *      index is out of range
     */
    public function decodeIndexedHeaderField($input, $offset = 0)
    {
        /*
            Indexed header field: 1xxxxxxx with the index in the
            low 7 bits, multi-byte continuation if all 7 are 1s.
            RFC 7541 sec 6.1.
         */
        [$index, $next] = $this->decodeInteger($input, $offset, 7);
        if ($index >= 1 && $index <= count($this->headers_table) - 1) {
            [$name, $value] = $this->headers_table[$index];
        } else {
            return null;
        }
        return [
            'decoded' => [$name => $value],
            'next' => $next
        ];
    }
    /**
     * Decodes a literal with incremental indexing per RFC 7541
     * sec 6.2.1 starting at $offset in the raw byte buffer. The
     * decoded entry is appended to the dynamic table.
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @return array ['decoded' => [name => value], 'next' => int]
     */
    public function decodeLiteralWithIncrementalIndexing(
        $input, $offset = 0)
    {
        /*
            Literal with incremental indexing: 01xxxxxx where the
            6-bit prefix is the name index (0 = name as literal
            string, 1+ = name from headers_table). Multi-byte
            continuation if all 6 bits are 1s. RFC 7541 sec 6.2.1.
         */
        [$name_index, $offset] = $this->decodeInteger(
            $input, $offset, 6);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $input, $offset);
        } else if ($name_index < count($this->headers_table)) {
            $name = $this->headers_table[$name_index][0];
        } else {
            throw new \Exception(
                "Invalid name index: exceeds dynamic table size."
            );
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $input, $offset);
        /*
            HPACK RFC 7541 section 6.2.1: incremental indexing always
            appends a new entry to the dynamic table. The name index
            only identifies which existing entry to copy the name
            from and must never be overwritten. addHeader applies
            the same max-table-size eviction as the encoder so a
            malicious peer cannot grow the per-connection table
            without bound.
         */
        $this->addHeader($name, $value);
        return [
            'decoded' => [$name => $value],
            'next' => $offset
        ];
    }
    /**
     * Decodes a string literal at byte offset $offset in $input
     * per RFC 7541 sec 5.2: a 7-bit prefix integer length with
     * the high "Huffman" bit (0x80) on the first byte, followed
     * by that many octets of (optionally Huffman-encoded) string
     * data.
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @return array [string $decoded_string, int $next_offset]
     */
    private function decodeStringLiteral($input, $offset)
    {
        $first_byte = ord($input[$offset]);
        $use_huffman = ($first_byte & 0x80) !== 0;
        [$length, $offset] = $this->decodeInteger($input, $offset, 7);
        $bin = substr($input, $offset, $length);
        $offset += $length;
        $decoded = $use_huffman ? $this->huffmanDecode($bin) : $bin;
        return [$decoded, $offset];
    }
    /**
     * Decodes a literal without indexing (RFC 7541 sec 6.2.2)
     * starting at $offset in the raw byte buffer. Does not add
     * to the dynamic table.
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @return array ['decoded' => [name => value], 'next' => int]
     */
    public function decodeLiteralWithoutIndexing(
        $input, $offset = 0)
    {
        /*
            Literal without indexing: 0000xxxx with a 4-bit name
            index prefix. RFC 7541 sec 6.2.2.
         */
        [$name_index, $offset] = $this->decodeInteger(
            $input, $offset, 4);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $input, $offset);
        } else if ($name_index < count($this->headers_table)) {
            $name = $this->headers_table[$name_index][0];
        } else {
            throw new \Exception("Invalid name index: exceeds table size.");
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $input, $offset);
        return [
            'decoded' => [$name => $value],
            'next' => $offset
        ];
    }
    /**
     * Decodes a literal never indexed (RFC 7541 sec 6.2.3)
     * starting at $offset. Records the name in never_indexed
     * so future encodes will respect the directive.
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @return array ['decoded' => [name => value], 'next' => int]
     */
    public function decodeLiteralNeverIndexed(
        $input, $offset = 0)
    {
        /*
            Literal never indexed: 0001xxxx with a 4-bit name
            index prefix. Caches name in never_indexed so it
            won't be inserted into the dynamic table on later
            sees. RFC 7541 sec 6.2.3.
         */
        [$name_index, $offset] = $this->decodeInteger(
            $input, $offset, 4);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $input, $offset);
        } else if ($name_index < count($this->headers_table)) {
            $name = $this->headers_table[$name_index][0];
        } else {
            throw new \Exception("Invalid name index: exceeds table size.");
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $input, $offset);
        $this->never_indexed[$name] = true;
        return [
            'decoded' => [$name => $value],
            'next' => $offset
        ];
    }
    /**
     * Encodes an integer per RFC 7541 sec 5.1 with the given prefix
     * width. The high bits of the first byte (above the prefix
     * width) belong to the caller; this method ORs the integer's
     * encoding into the low $prefix_bits of the first byte and
     * appends continuation bytes if the value exceeds the prefix
     * capacity. Returns the binary string of encoded bytes; the
     * caller must OR in any flag bits for the first byte.
     *
     * Example: encodeInteger(78, 7) returns chr(78) since 78 fits
     * in 7 bits. encodeInteger(1337, 5) returns 3 bytes per the
     * RFC's worked example.
     *
     * @param int $value non-negative integer to encode
     * @param int $prefix_bits prefix width in bits (1-8)
     * @return string binary bytes
     */
    private function encodeInteger($value, $prefix_bits)
    {
        $max_prefix = (1 << $prefix_bits) - 1;
        if ($value < $max_prefix) {
            return chr($value);
        }
        $out = chr($max_prefix);
        $value -= $max_prefix;
        while ($value >= 128) {
            $out .= chr(($value & 0x7F) | 0x80);
            $value >>= 7;
        }
        $out .= chr($value);
        return $out;
    }
    /**
     * Decodes an integer per RFC 7541 sec 5.1 from the raw byte
     * buffer starting at $offset. The first byte's low
     * $prefix_bits carry the integer (or signal continuation
     * when all set). Returns [value, next_offset].
     *
     * @param string $input raw byte buffer
     * @param int $offset starting byte offset
     * @param int $prefix_bits prefix width in bits (1-8)
     * @return array [int $value, int $next_offset]
     */
    private function decodeInteger($input, $offset, $prefix_bits)
    {
        $max_prefix = (1 << $prefix_bits) - 1;
        $first_byte = ord($input[$offset]);
        $offset++;
        $value = $first_byte & $max_prefix;
        if ($value < $max_prefix) {
            return [$value, $offset];
        }
        $shift = 0;
        $len = strlen($input);
        while ($offset < $len) {
            $byte = ord($input[$offset]);
            $offset++;
            $value += ($byte & 0x7F) << $shift;
            $shift += 7;
            if (($byte & 0x80) === 0) {
                return [$value, $offset];
            }
            if ($shift > 28) {
                throw new \Exception(
                    "HPACK integer overflow during decode");
            }
        }
        throw new \Exception(
            "HPACK integer truncated: missing continuation byte");
    }
    /**
     * Encodes headers using the HPack format. If a header name is in
     * the never-index list, it is encoded as "Literal Never Indexed".
     * Otherwise the function checks the headers table for matches
     * and encodes using the most compact representation that applies.
     *
     * @param array $headers array of headers to encode. Each header
     *      is an array of [name, value]
     * @return string binary HPACK-encoded header block
     */
    public function encode($headers)
    {
        $encoded = '';
        $static_nv = self::$static_name_value_index;
        $static_n = self::$static_name_index;
        foreach ($headers as [$name, $value]) {
            $name = (string) $name;
            $value = (string) $value;
            if (isset($this->never_indexed[$name])) {
                $encoded .= chr(0x10);
                $encoded .= $this->encodeString($name);
                $encoded .= $this->encodeString($value);
                continue;
            }
            $key = $name . "\0" . $value;
            if (isset($static_nv[$key])) {
                /*
                    Indexed header field: 1xxxxxxx with the index
                    in the low 7 bits, multi-byte if the index is
                    >= 127. RFC 7541 sec 6.1.
                 */
                $idx = $static_nv[$key];
                $index_code = $this->encodeInteger($idx, 7);
                $encoded .= chr(ord($index_code[0]) | 0x80)
                    . substr($index_code, 1);
                continue;
            }
            if (isset($static_n[$name])) {
                /*
                    Literal with incremental indexing, indexed
                    name: 01xxxxxx with the name index in the low
                    6 bits, multi-byte if >= 63. RFC 7541 sec
                    6.2.1. The receiver appends a new
                    dynamic-table entry for this header, so we
                    must add it on our side too or our encoder's
                    view of the dynamic table will diverge from
                    the decoder's.
                 */
                $idx = $static_n[$name];
                $index_code = $this->encodeInteger($idx, 6);
                $encoded .= chr(ord($index_code[0]) | 0x40)
                    . substr($index_code, 1);
                $encoded .= $this->encodeString($value);
                $this->addHeader($name, $value);
                continue;
            }
            /*
                Literal with incremental indexing, new name:
                01000000 plus literal name plus literal value.
                Falls through here for any header whose name is
                not in the static table; the dynamic table is
                not consulted, which is correct (just slightly
                less compact than full HPACK).
             */
            $encoded .= chr(0x40);
            $encoded .= $this->encodeString($name);
            $encoded .= $this->encodeString($value);
            $this->addHeader($name, $value);
        }
        return $encoded;
    }
    /**
     * Encodes a given string using Huffman Encoding if it provides compression
     * and every byte of the string is in the Huffman table. Otherwise the
     * string is sent as a raw HPACK string literal.
     * @param string $str The input string to encode.
     * @return string HPACK-encoded string-literal bytes: a 7-bit
     *      prefix integer length (with the Huffman bit set when
     *      Huffman encoding was used) followed by the (possibly
     *      Huffman-encoded) string data
     */
    private function encodeString($str)
    {
        $huffman = $this->huffmanEncode($str);
        if ($huffman !== false && strlen($huffman) < strlen($str)) {
            /*
                Length is a 7-bit prefix integer with the high
                "Huffman" bit (0x80) set. Multi-byte if length
                >= 127. RFC 7541 sec 5.2.
             */
            $index_code = $this->encodeInteger(strlen($huffman), 7);
            $first = ord($index_code[0]) | 0x80;
            return chr($first) . substr($index_code, 1) . $huffman;
        } else {
            $index_code = $this->encodeInteger(strlen($str), 7);
            return $index_code . $str;
        }
    }
    /**
     * Per-byte Huffman code as [int $code, int $bit_len].
     * Lazily built from HUFFMAN_LOOKUP on first use. The integer
     * form lets the encoder shift bits into a 64-bit accumulator
     * and flush bytes via pack().
     * @var array<int,array{int,int}>
     */
    private static $HUFFMAN_CODES = [];
    /**
     * Precomputed byte-to-8-bit-string table for huffmanDecode.
     * Indexed by 0..255; each entry is the corresponding 8-char
     * '0'/'1' string.
     * @var array<int,string>
     */
    private static $BYTE_TO_BITS = [];
    /**
     * Encodes an ASCII string with HPACK Huffman coding (RFC 7541
     * sec 5.2). Builds the encoded output by maintaining a 64-bit
     * integer accumulator and flushing 4 bytes at a time via
     * pack('N',...) when 32+ bits are buffered. Falls back to
     * single-byte chr() for the tail. Final byte is padded with
     * 1-bits per the EOS symbol (all-ones).
     *
     * @param string $input ASCII string to encode
     * @return mixed binary Huffman-encoded byte string, or false
     *      when the input contains a byte outside the Huffman
     *      table (the caller then sends the raw string literal)
     */
    public function huffmanEncode($input)
    {
        if (empty(self::$HUFFMAN_CODES)) {
            foreach (self::$HUFFMAN_LOOKUP as $bits => $ascii) {
                self::$HUFFMAN_CODES[$ascii] = [
                    bindec((string) $bits),
                    strlen((string) $bits),
                ];
            }
        }
        $codes = self::$HUFFMAN_CODES;
        $out = '';
        $cur = 0;
        $cur_bits = 0;
        $len = strlen($input);
        for ($i = 0; $i < $len; $i++) {
            $ascii = ord($input[$i]);
            if (!isset($codes[$ascii])) {
                /* the table covers printable ASCII only; a value
                   with any other byte (a UTF-8 file name in a
                   Content-Disposition header, say) is sent as a
                   raw string literal instead, which RFC 7541 sec
                   5.2 always permits */
                return false;
            }
            [$code_bits, $code_len] = $codes[$ascii];
            $cur = ($cur << $code_len) | $code_bits;
            $cur_bits += $code_len;
            /*
                Flush 4 bytes when we have at least 32 bits. We
                cap the buffer at <= 56 bits so the next code (up
                to 30 bits in the full HPACK table) cannot cause
                a 64-bit overflow before the next flush check.
             */
            if ($cur_bits >= 32) {
                $excess = $cur_bits - 32;
                $word = ($cur >> $excess) & 0xffffffff;
                $out .= pack('N', $word);
                $cur &= (1 << $excess) - 1;
                $cur_bits = $excess;
            }
        }
        // Drain any whole bytes still in the buffer.
        while ($cur_bits >= 8) {
            $cur_bits -= 8;
            $out .= chr(($cur >> $cur_bits) & 0xff);
            $cur &= (1 << $cur_bits) - 1;
        }
        // Pad the final partial byte with 1-bits (RFC 7541 sec 5.2).
        if ($cur_bits > 0) {
            $pad = 8 - $cur_bits;
            $cur = ($cur << $pad) | ((1 << $pad) - 1);
            $out .= chr($cur & 0xff);
        }
        return $out;
    }
    /**
     * Decodes a Huffman-encoded byte string into ASCII (RFC 7541
     * sec 5.2). Builds the bit string from the input bytes via a
     * 256-entry precomputed lookup, then walks the bits looking
     * up each prefix-free code in HUFFMAN_LOOKUP.
     *
     * @param string $input binary Huffman-encoded byte string
     * @return string decoded ASCII string
     */
    public function huffmanDecode($input)
    {
        if (empty(self::$BYTE_TO_BITS)) {
            for ($b = 0; $b < 256; $b++) {
                self::$BYTE_TO_BITS[$b] =
                    str_pad(decbin($b), 8, '0', STR_PAD_LEFT);
            }
        }
        $byte_to_bits = self::$BYTE_TO_BITS;
        $lookup = self::$HUFFMAN_LOOKUP;
        $bits = '';
        $len = strlen($input);
        for ($i = 0; $i < $len; $i++) {
            $bits .= $byte_to_bits[ord($input[$i])];
        }
        $decoded = '';
        $buffer = '';
        $bit_len = strlen($bits);
        for ($i = 0; $i < $bit_len; $i++) {
            $buffer .= $bits[$i];
            if (isset($lookup[$buffer])) {
                $decoded .= chr($lookup[$buffer]);
                $buffer = '';
            }
        }
        return $decoded;
    }
    /**
     * RFC 7541 Appendix B canonical HPACK Huffman table.
     * Map from bit-string ("0"/"1" characters) to ASCII
     * code point. The bit-string form lets the decoder
     * append candidate bits and isset()-check; the bits
     * form a prefix code so the first match is the right
     * one.
     * @var array<string,int>
     */
    private static $HUFFMAN_LOOKUP = [
        '010100' => 32,           '1111111000' => 33,       '1111111001' => 34,
        '111111111010' => 35,     '1111111111001' => 36,    '010101' => 37,
        '11111000' => 38,         '11111111010' => 39,      '1111111010' => 40,
        '1111111011' => 41,       '11111001' => 42,         '11111111011' => 43,
        '11111010' => 44,         '010110' => 45,           '010111' => 46,
        '011000' => 47,           '00000' => 48,            '00001' => 49,
        '00010' => 50,            '011001' => 51,           '011010' => 52,
        '011011' => 53,           '011100' => 54,           '011101' => 55,
        '011110' => 56,           '011111' => 57,           '1011100' => 58,
        '11111011' => 59,         '111111111111100' => 60,  '100000' => 61,
        '111111111011' => 62,     '1111111100' => 63,
        '1111111111010' => 64,
        '100001' => 65,           '1011101' => 66,          '1011110' => 67,
        '1011111' => 68,          '1100000' => 69,          '1100001' => 70,
        '1100010' => 71,          '1100011' => 72,          '1100100' => 73,
        '1100101' => 74,          '1100110' => 75,          '1100111' => 76,
        '1101000' => 77,          '1101001' => 78,          '1101010' => 79,
        '1101011' => 80,          '1101100' => 81,          '1101101' => 82,
        '1101110' => 83,          '1101111' => 84,          '1110000' => 85,
        '1110001' => 86,          '1110010' => 87,          '11111100' => 88,
        '1110011' => 89,          '11111101' => 90,
        '1111111111011' => 91,
        '1111111111111110000' => 92, '1111111111100' => 93,
        '11111111111100' => 94,
        '100010' => 95,           '111111111111101' => 96,  '00011' => 97,
        '100011' => 98,           '00100' => 99,            '100100' => 100,
        '00101' => 101,           '100101' => 102,          '100110' => 103,
        '100111' => 104,          '00110' => 105,           '1110100' => 106,
        '1110101' => 107,         '101000' => 108,          '101001' => 109,
        '101010' => 110,          '00111' => 111,           '101011' => 112,
        '1110110' => 113,         '101100' => 114,          '01000' => 115,
        '01001' => 116,           '101101' => 117,          '1110111' => 118,
        '1111000' => 119,         '1111001' => 120,         '1111010' => 121,
        '1111011' => 122,         '111111111111110' => 123,
        '11111111100' => 124,
        '11111111111101' => 125,  '1111111111101' => 126
    ];
}
/**
 * Runs long pieces of work a little at a time so a single-process
 * server stays responsive.
 *
 * The atto web server handles every connection in one loop, so any
 * request that does something slow -- reading a huge mailbox, talking to
 * a mail server, hashing a password -- would freeze every other
 * connection until it finished. This scheduler lets that work run inside
 * a fiber: ordinary-looking code that, when it reaches a point where it
 * would otherwise wait, calls Fiber::suspend() to hand control back to
 * the loop and is resumed later once there is reason to. The key reason a
 * fiber is used rather than a plain generator is that suspend() works
 * from any depth in the call stack, so a low-level mail-socket read can
 * give up the loop without every controller and model method above it
 * having to be rewritten to pass a yield along. WebSite::listen() calls
 * step() once each time around the loop; each call resumes every waiting
 * fiber once and then serves the ready sockets, so the slow work and the
 * rest of the site make progress together. (When the site runs under another
 * web server such as Apache there is no atto loop and each request is its
 * own process, so WebSite::deferTask() runs the work straight through,
 * outside any fiber, and this scheduler is never used.)
 *
 * A task that finishes hands its return value to an optional completion
 * callback; a task that throws hands the exception to the same callback
 * instead, so the layer that started the task can turn it into a normal
 * error response. A task that keeps suspending without ever finishing is
 * stopped once it has used more than its work-time budget, so a buggy
 * fiber cannot quietly starve every other connection.
 *
 * @author Chris Pollett
 */
class CooperativeScheduler
{
    /**
     * Default ceiling, in seconds, on the total running time one task may
     * use across all the times it is resumed. A task that goes past this
     * is stopped with an error rather than allowed to keep taking the
     * loop's attention. Generous on purpose: it is a guard against a
     * runaway fiber, not a normal request deadline.
     */
    const DEFAULT_BUDGET = 30.0;
    /**
     * The tasks the loop is currently driving. Each entry holds the task
     * fiber, the optional completion callback, and the total running time
     * the fiber has used so far. Empty whenever no long work is in flight.
     * @var array
     */
    public $tasks = [];
    /**
     * Largest total running time, in seconds, any one task is allowed
     * before it is stopped with a budget error.
     * @var float
     */
    protected $budget;
    /**
     * @param float $budget largest total running time, in seconds, a
     *      single task may use before it is aborted; defaults to
     *      DEFAULT_BUDGET
     */
    public function __construct($budget = self::DEFAULT_BUDGET)
    {
        $this->budget = (float) $budget;
    }
    /**
     * Hands a new piece of work to the loop to run a little at a time.
     *
     * @param \Fiber $fiber the work as a not-yet-started fiber; it should
     *      call Fiber::suspend() wherever it would otherwise wait, so the
     *      loop can serve other connections in the meantime
     * @param callable|null $on_complete called once when the task
     *      finishes, as $on_complete($result, $error): $result is the
     *      fiber's return value on success (and $error null), or $error
     *      holds the thrown/abort exception on failure (and $result null)
     * @param callable|null $on_enter called with no arguments just before
     *      each resume of the fiber; a request task uses it to swap its
     *      own superglobals and output buffer into place so it resumes in
     *      its own context rather than whatever the last request left
     * @param callable|null $on_leave called with no arguments right after
     *      each resume returns or suspends (even if it threw); the partner
     *      of $on_enter, used to capture what the slice produced and put
     *      the previous context back
     * @param float|null $budget largest total running time this one task
     *      may use, in seconds; the scheduler's own limit when not given.
     *      Work that legitimately takes longer than a page render, such as
     *      building a pack for a git pull, asks for more here rather than
     *      the whole server being given a looser limit
     * @return void
     */
    public function add(\Fiber $fiber, $on_complete = null,
        $on_enter = null, $on_leave = null, $budget = null)
    {
        $this->tasks[] = [
            'fiber' => $fiber,
            'on_complete' => $on_complete,
            'on_enter' => $on_enter,
            'on_leave' => $on_leave,
            'work_time' => 0.0,
            'wait' => null,
            'budget' => ($budget === null) ? $this->budget : (float)$budget,
        ];
    }
    /**
     * Whether no task is currently in flight. The event loop uses this to
     * decide it can go back to sleeping in select() rather than spinning
     * to resume work that is not there.
     *
     * @return bool true when there is nothing to drive
     */
    public function isEmpty()
    {
        return $this->tasks === [];
    }
    /**
     * Whether any in-flight task wants to run again right away rather than
     * waiting on a socket. A task that suspended with a plain
     * Fiber::suspend() -- a CPU- or disk-bound job giving the loop a brief
     * turn between chunks of work -- wants to be resumed at once; a task
     * that suspended asking to wait for a socket to be readable or
     * writable does not, and can be polled at the slower cooperative
     * interval. The event loop uses this to choose a zero-length select
     * when there is immediate work, so a long page assembly is not slowed
     * by the poll interval, while still letting a slow socket be polled
     * gently.
     *
     * @return bool true if at least one task should be resumed without
     *      waiting
     */
    public function hasImmediateWork()
    {
        foreach ($this->tasks as $task) {
            if (!$task['fiber']->isStarted()) {
                return true;
            }
            $wait = $task['wait'];
            if (!is_array($wait) ||
                (!isset($wait['read']) && !isset($wait['write']))) {
                return true;
            }
        }
        return false;
    }
    /**
     * Resumes every in-flight task once, then drops the ones that
     * finished, threw, or ran past their budget. The event loop calls
     * this once each pass, right after it refills the streaming-response
     * generators. A fiber that has not been started yet is started; one
     * that is suspended is resumed; one that has finished hands back its
     * return value.
     *
     * A budget overrun is only noticed between resumes: a single stretch
     * of work that loops forever without suspending still cannot be
     * interrupted, because PHP does not preempt running code. The contract
     * is that a cooperative task must suspend often enough to be a good
     * citizen; the budget catches a task that suspends but never makes an
     * end of itself, not one that hangs without ever giving up the loop.
     *
     * @return void
     */
    public function step()
    {
        if ($this->tasks === []) {
            return;
        }
        $still_running = [];
        foreach ($this->tasks as $task) {
            $finished = false;
            $error = null;
            $result = null;
            if ($task['fiber']->isSuspended() && is_array($task['wait']) &&
                isset($task['wait']['until']) && !($task['wait']['until'])()) {
                $still_running[] = $task;
                continue;
            }
            $slice_start = microtime(true);
            try {
                if ($task['on_enter'] !== null) {
                    ($task['on_enter'])();
                }
                try {
                    if (!$task['fiber']->isStarted()) {
                        $task['wait'] = $task['fiber']->start();
                    } elseif ($task['fiber']->isSuspended()) {
                        $task['wait'] = $task['fiber']->resume();
                    }
                } finally {
                    if ($task['on_leave'] !== null) {
                        ($task['on_leave'])();
                    }
                }
                if ($task['fiber']->isTerminated()) {
                    $finished = true;
                    $result = $task['fiber']->getReturn();
                }
            } catch (\Throwable $throwable) {
                $finished = true;
                $error = $throwable;
            }
            $task['work_time'] += microtime(true) - $slice_start;
            $task['slices'] = ($task['slices'] ?? 0) + 1;
            if (!$finished && $task['work_time'] > $task['budget']) {
                $finished = true;
                $error = new TaskBudgetExceededException(sprintf(
                    'cooperative task exceeded its work-time budget, ' .
                    '%.1f s of work in %d slices against %.1f s',
                    $task['work_time'], $task['slices'], $task['budget']));
            }
            if ($finished) {
                if (is_callable($task['on_complete'])) {
                    $task['on_complete']($result, $error);
                }
                continue;
            }
            $still_running[] = $task;
        }
        $this->tasks = $still_running;
    }
}
/**
 * Thrown when a cooperative task uses more total running time than its
 * budget allows. It is its own type so the response layer can tell a task
 * that ran too long, which is answered to the client as a request timeout,
 * apart from a task that failed some other way, which is a server error.
 */
class TaskBudgetExceededException extends \Exception {}
