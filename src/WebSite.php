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
    /*
        Field component name constants used in input or output stream array
     */
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
    const REQUEST_HEAD = 4;
    /*
      CONNECT OPTIONS and the longest named HTTP method. It has length 7
     */
    const LEN_LONGEST_HTTP_METHOD = 7;
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
     * Keys of stream that won't disappear (for example the server socket)
     * @var array
     */
    public $immortal_stream_keys = [];
    /**
     * Used to determine portion of path to ignore
     * when checking if a route matches against the current request.
     * @var string
     */
    public $base_path;
    /**
     * Check if the current run of the website is after a restart
     * @var boolean
     */
    public $restart;
    /**
     * Used to signal stopping the website
     * @var boolean
     */
    public $stop;
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
    protected $default_server_globals;
    /**
     * Associative array http_method => array of how to handle paths for
     *  that method
     * @var array
     */
    protected $routes = ["CONNECT" => [], "DELETE"  => [], "ERROR"  => [],
        "GET" => [], "HEAD" => [], "OPTIONS"  => [], "POST"  => [],
        "PUT" => [], "TRACE" => [], "WS" => []];
    /**
     * Default values used to set up session variables
     * @var array
     */
    protected $session_configs = [ 'cookie_lifetime' => '0',
        'cookie_path' => '/', 'cookie_domain' => '', 'cookie_secure' => '',
        'cookie_httponly' => '', 'name' => 'PHPSESSID', 'save_path' => ''];
    /**
     * Array of all connection streams for which we are receiving data from
     * client together with associated stream info
     * @var array
     */
    protected $in_streams = [];
    /**
     * Array of all connection streams for which we are writing data to a
     * client together with associated stream info
     * @var array
     */
    protected $out_streams = [];
    /**
     * Middle ware callbacks to run when processing a request
     * @var array
     */
    protected $middle_wares = [];
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
     * Keeps an ordering of currently actively sessions so if run out of
     * memory know who to evict
     * @var array
     */
    protected $session_queue = [];
    /**
     * Timer function callbacks that have been declared
     * @var array
     */
    protected $timers = [];
    /**
     * Priority queue of which timers are about to go off
     * @var \SplMinHeap
     */
    protected $timer_alarms;
    /**
     * Cookie name value of the currently active request's session
     * @var string
     */
    protected $current_session = "";
    /**
     * List of HTTP methods for which routes have been declared
     * @var array
     */
    protected $http_methods;
    /**
     * Holds the header portion so far of the HTTP response
     * @var string
     */
    protected $header_data;
    /**
     * Whether the current response already has declared a Content-Type.
     * If not, WebSite will default to adding a text/html header
     * @var bool
     */
    protected $content_type;
    /**
     * Used to cache in RAM files which have been read or written by the
     * fileGetContents or filePutContents
     * @var array
     */
    protected $file_cache = ['MARKED' => [], 'UNMARKED' => [], 'PATH' => []];
    /**
     * Whether this object is being run from the command line with a listen()
     * call or if it is being run under a web server and so only used for
     * routing
     * @var bool
     */
    protected $is_cli;
    /**
     * Whether https is being used. For backward compatibility this
     * is set to true if any listener has a TLS context. The
     * per-connection secure flag lives in the connection's stream
     * context entry instead.
     * @var bool
     */
    protected $is_secure = false;
    /**
     * Array of active listeners. Each entry is an associative
     * array with keys 'server' (the stream resource returned by
     * stream_socket_server), 'is_secure' (bool), and 'globals'
     * (per-listener overrides for default_server_globals such as
     * SERVER_NAME and SERVER_PORT). Indexed by (int)$server so
     * processRequestStreams can match an incoming connection to
     * its listener via the readable key returned by stream_select.
     * @var array
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
     * @param string $base_path used to determine portion of path to ignore
     *      when checking if a route matches against the current request.
     *      If it is left blank, then a base path will be computed using
     *      the $_SERVER script name variable.
     */
    public function __construct($base_path = "")
    {
        $this->default_server_globals = ["MAX_CACHE_FILESIZE" => 2000000];
        $this->http_methods = array_keys($this->routes);
        if (empty($base_path)) {
            $pathinfo = pathinfo($_SERVER['SCRIPT_NAME']);
            $base_path = $pathinfo["dirname"];
        }
        if ($base_path == ".") {
            $base_path = "";
        }
        $this->is_cli = (php_sapi_name() == 'cli');
        if(!empty($_SERVER['HTTPS'])) {
            $this->is_secure = true;
        }
        $this->base_path = $base_path;
        $this->stop = false;
        $this->restart = false;
        ini_set('precision', 16);
        $this->timer_alarms = new \SplMinHeap();
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
     * WebSocket upgrade requests. By default all origins are
     * accepted, which is appropriate for development and for
     * services that intentionally expose themselves to any web
     * page. For production deployments behind a known origin,
     * pass an array of exact origin strings (scheme + host +
     * optional port, no trailing slash).
     *
     * Example:
     *   $site->setAllowedOrigins(['https://example.com',
     *       'https://www.example.com']);
     *
     * Requests whose Origin header is not in the list receive a
     * 403 Forbidden during the WebSocket handshake. Requests
     * lacking an Origin header (typically from non-browser
     * clients like curl, native apps, or test scripts) are
     * always allowed since the protection target is the browser
     * same-origin model.
     *
     * @param array $origins list of acceptable origin strings,
     *      or empty array to allow all origins
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
     * Cause all the current HTTP request to be processed according to the
     * middleware callbacks and routes currently set on this WebSite object.
     */
    public function process()
    {
        if (empty($_SERVER['REQUEST_URI'])) {
            $_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'];
        }
        foreach ($this->middle_wares as $middleware) {
            $middleware();
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
            header("HTTP/1.1 501 Not Implemented");
            header("Content-Type: text/plain");
            echo "WebSocket upgrades require running this script "
                . "from the command line (php index.php). The PHP "
                . "SAPI used by Apache, nginx-FPM, and CGI does not "
                . "expose the underlying TCP socket and so cannot "
                . "handle WebSocket frames. A typical deployment "
                . "runs the CLI server on an internal port behind "
                . "a reverse proxy.\n";
            return;
        }
        // Handle Upgrade Header
        if (isset($_SERVER['HTTP_UPGRADE']) &&
            $_SERVER['HTTP_UPGRADE'] === 'HTTP/2') {
            $this->header_data = "UPGRADE";
            $this->header_data = "UPGRADE";
            // $this->handleUpgradeToHttp2();
            return;
        }
        $method = empty($_SERVER['REQUEST_METHOD']) ? "ERROR" :
            $_SERVER['REQUEST_METHOD'];
        if (empty($_SERVER['QUERY_STRING'])) {
            $this->request_script = rtrim(
                substr(urldecode($_SERVER['REQUEST_URI']),
                strlen($this->base_path)), "?");
        } else {
            $this->request_script = substr(urldecode($_SERVER['REQUEST_URI']),
                strlen($this->base_path),
                -strlen($_SERVER['QUERY_STRING']) -  1);
        }
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
        if(empty($this->routes[$method])) {
            return false;
        }
        if (in_array($method . " " . $route, $_SERVER['RECURSION']) ) {
            echo "<br>\nError: Recursion detected for $method $route.\n";
            return true;
        }
        $method_routes = $this->routes[$method];
        $handled = false;
        foreach ($method_routes as $check_route => $callback) {
            if(($add_vars = $this->checkMatch($route, $check_route)) !==
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
     * Adds a new HTTP header to the list of headers that will be sent
     * with the HTTP response. If the value of $header begins with
     * HTTP/ then it is assumed that $header is the response message
     * not a header. In this case, the value of $header will become
     * the response message, replacing any existing messages if
     * present. This function defaults to PHP's built-in header()
     * function when this script is run from a non-CLI context.
     *
     * Headers containing CR or LF are rejected to prevent CRLF
     * (HTTP response splitting) injection. PHP's built-in header()
     * has had this defense since 5.1.2; Atto matches that behavior
     * for CLI mode where the header_data buffer is concatenated
     * directly into the wire output. If a header is rejected this
     * method writes a warning via trigger_error and returns false
     * without modifying header_data.
     *
     * @param string $header HTTP header or message to send with the
     *      HTTP response
     * @return bool true if the header was accepted, false if
     *      rejected for containing CRLF
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
                        (empty($header_parts[1])? "" : $header_parts[1]);
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
     * Sends an HTTP cookie header as part of the HTTP response. If this method
     * is run from a non-CLI context then this function defaults to PHP's
     * built-in function setcookie();
     *
     * Cookies returned from a particular client will appear in the $_COOKIE
     * superglobal.
     *
     * @param string $name name of cookie
     * @param string $value value associated with cookie
     * @param int $expire Unix timestamp for when the cookie expires
     * @param string $path request path associated with the cookie
     * @param string $domain request domain associated with the cookie
     * @param string $secure whether the cookie should only be sent if HTTPS in
     *      use
     * @param bool $httponly whether or not the cookie is available only over
     *      HTTP, and not available to client-side Javascript
     */
    public function setCookie($name, $value = "", $expire = 0,
        $path = "", $domain = "", $secure = false, $httponly = false)
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
                $custom_error_handler =
                    $this->default_server_globals["CUSTOM_ERROR_HANDLER"] ??
                    null;
                set_error_handler($custom_error_handler);
            }
            if ($path != "") {
                $out_cookie .= "; Path=$path";
            }
            if ($domain != "") {
                $out_cookie .= "; Domain=$domain";
            }
            if ($httponly) {
                $out_cookie .= "; HttpOnly";
            }
            $this->header($out_cookie);
        } else {
            setcookie($name, $value, $expire, $path, $domain, $secure,
                $httponly);
        }
    }
    /**
     * Starts a web session by sending a cookie with a unique ID.
     * When the client returns the cookie, session data is looked
     * up. CLI mode stores session data in RAM; under another web
     * server, defaults to session_start().
     *
     * Session IDs are random_bytes(32) hex-encoded (256-bit
     * entropy). Cookie-supplied IDs must match the format and
     * already exist in the table; otherwise a fresh ID is
     * generated. This prevents session fixation.
     *
     * Table size is capped by MAX_SESSIONS (default 10000). Each
     * request runs a soft cull of up to CULL_OLD_SESSION_NUM
     * expired entries; if still over cap, hard eviction pops the
     * oldest. Protects against memory exhaustion under a flood
     * of cookie-less requests.
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
            $cookie_value = empty($_COOKIE[$cookie_name]) ? "" :
                $_COOKIE[$cookie_name];
            $time = time();
            $lifetime = intval($options['cookie_lifetime']);
            $expires = ($lifetime > 0) ? $time + $lifetime : 0;
            /*
                For the in-memory session expiration math below we
                need a non-zero "lifetime" so that recently-touched
                sessions are not immediately culled when the cull
                loop computes $item_time + $lifetime < $time. Use a
                large default for session-scoped cookies.
             */
            $cull_lifetime = ($lifetime > 0) ? $lifetime : $time;
            /*
                Only honor the cookie-supplied session id if it
                matches our id format (64 hex chars) and the
                session already exists server-side. Anything else
                falls through to fresh session id generation. This
                prevents session fixation where an attacker plants
                a known id and tries to ride the victim's
                authenticated session.
             */
            $session_id = "";
            if ($cookie_value !== ""
                && preg_match('/^[a-f0-9]{64}$/', $cookie_value)
                && !empty($this->sessions[$cookie_value])) {
                $session_id = $cookie_value;
                $_SESSION = $this->sessions[$session_id]['DATA'];
            } else {
                $session_id = bin2hex(random_bytes(32));
                $this->sessions[$session_id] = ['DATA' => []];
                array_unshift($this->session_queue, $session_id);
                $_SESSION = [];
            }
            $this->sessions[$session_id]['TIME'] = $time;
            $last_time = count($this->session_queue) -1;
            // cull up to CULL_OLD_SESSION_NUM expired sessions
            $first_time = max(0, $last_time - $this->default_server_globals[
                'CULL_OLD_SESSION_NUM']);
            for ($i = $last_time; $i >= $first_time; $i--) {
                $delete_id = $this->session_queue[$i];
                if (!isset($this->sessions[$delete_id])) {
                    unset($this->session_queue[$i]);
                } else {
                    $item_time = $this->sessions[$delete_id]['TIME'];
                    if ($item_time + $cull_lifetime < $time) {
                        unset($this->session_queue[$i]);
                        unset($this->sessions[$delete_id]);
                    }
                }
            }
            /*
                Hard cap on total session count. The soft cull
                above only walks CULL_OLD_SESSION_NUM entries per
                request, so a flood of cookie-less requests can
                grow the session table faster than it shrinks.
                If we are still over MAX_SESSIONS after the soft
                cull, evict the oldest entries (the tail of
                session_queue, since new IDs are array_unshift'd
                onto the head) until we are back under the cap.
                Reindex the queue at the end so the next soft
                cull walks contiguous indices.
             */
            $max_sessions = $this->default_server_globals[
                'MAX_SESSIONS'] ?? 10000;
            if (count($this->sessions) > $max_sessions) {
                $this->session_queue =
                    array_values($this->session_queue);
                while (count($this->sessions) > $max_sessions
                    && !empty($this->session_queue)) {
                    $oldest_id = array_pop($this->session_queue);
                    unset($this->sessions[$oldest_id]);
                }
            } else {
                $this->session_queue =
                    array_values($this->session_queue);
            }
            $this->setCookie($cookie_name, $session_id, $expires,
                $options['cookie_path'], $options['cookie_domain'],
                $options['cookie_secure'], $options['cookie_httponly']);
            $_COOKIE[$cookie_name] = $session_id;
            $this->current_session = $cookie_name;
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
     * Reads in the file $filename and returns its contents as a string.
     * In non-CLI mode this method maps directly to PHP's built-in function
     * file_get_contents(). In CLI mode, it checks if the file exists in
     * its Marker Algorithm based RAM cache (Fiat et al 1991). If so, it
     * directly returns it. Otherwise, it reads it in using blocking I/O
     * file_get_contents() and caches it before return its string contents.
     * Note this function assumes that only the web server is performing I/O
     * with this file. filemtime() can be used to see if a file on disk has been
     * changed and then you can use $force_read = true below to force re-
     * reading the file into the cache
     *
     * @param string $filename name of file to get contents of
     * @param bool $force_read whether to force the file to be read from
     *      persistent storage rather than the cache
     * @return string contents of the file given by $filename
     */
    public function fileGetContents($filename, $force_read = false)
    {
        if ($this->isCli()) {
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
            if (isset($this->file_cache['MARKED'][$path])) {
                if ($force_read) {
                    $this->file_cache['MARKED'][$path] =
                        file_get_contents($path);
                }
                return $this->file_cache['MARKED'][$path];
            } else if (isset($this->file_cache['UNMARKED'][$path])) {
                if ($force_read) {
                    $this->file_cache['MARKED'][$path] =
                        file_get_contents($path);
                } else {
                    $this->file_cache['MARKED'][$path] =
                        $this->file_cache['UNMARKED'][$path];
                }
                unset($this->file_cache['UNMARKED'][$path]);
                return $this->file_cache['MARKED'][$path];
            }
            $data = file_get_contents($path);
            if (strlen($data) < $this->default_server_globals[
                'MAX_CACHE_FILESIZE']) {
                if (count($this->file_cache['MARKED']) +
                    ($num_unmarked = count($this->file_cache['UNMARKED'])) >=
                    $this->default_server_globals['MAX_CACHE_FILES']) {
                    $eject = mt_rand(0, $num_unmarked - 1);
                    $unmarked_paths = array_keys($this->file_cache['UNMARKED']);
                    unset(
                        $this->file_cache['UNMARKED'][$unmarked_paths[$eject]]);
                }
                $this->file_cache['MARKED'][$path] = $data;
                if (count($this->file_cache['MARKED']) >=
                    $this->default_server_globals['MAX_CACHE_FILES']) {
                    foreach ($this->file_cache['PATH'] as $name => $path) {
                        if (empty($this->file_cache['MARKED'][$path])) {
                            unset($this->file_cache['PATH'][$name]);
                        }
                    }
                    foreach ($this->file_cache['MARKED'] as $path => $data) {
                        $this->file_cache['UNMARKED'][$path] = $data;
                        unset($this->file_cache['MARKED'][$path]);
                    }
                }
            }
            return $data;
        }
        return file_get_contents($filename);
    }
    /**
     * Writes $data to the persistent file with name $filename. Saves a copy
     * in the RAM cache if there is a copy already there.
     *
     * @param string $filename name of file to write to persistent storages
     * @param string $data string of data to store in file
     * @return int number of bytes written
     */
    public function filePutContents($filename, $data)
    {
        $num_bytes = strlen($data);
        $fits_in_cache =
            $num_bytes < $this->default_server_globals['MAX_CACHE_FILESIZE'];
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
        $num_bytes = file_put_contents($filename, $data);
        @chmod($filename, 0777);
        return $num_bytes;
    }
    /**
     * Deletes the files stored in the RAM FileCache
     */
    public function clearFileCache()
    {
        $this->file_cache = ['MARKED' => [], 'UNMARKED' => [], 'PATH' => []];
    }
    /**
     * Used to move a file that was uploaded from a form on the client to the
     * desired location on the server. In non-CLI mode this calls PHP's built-in
     * move_uploaded_file() function
     *
     * @param string $filename tmp_name in $_FILES of the uploaded file
     * @param string $destination where on server the file should be moved to
     */
    public function moveUploadedFile($filename , $destination)
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
     * Returns the mime type of the provided file name if it can be determined.
     * (This function is from the seekquarry/yioop project)
     *
     * @param string $file_name (name of file including path to figure out
     *      mime type for)
     * @param bool $use_extension whether to just try to guess from the file
     *      extension rather than looking at the file
     * @return string mime type or unknown if can't be determined
     */
    public static function mimeType($file_name, $use_extension = false)
    {
        $mime_type = "unknown";
        $last_chars = "-1";
        if (!$use_extension && !file_exists($file_name)) {
            return $mime_type;
        }
        if (!$use_extension && class_exists("\finfo")) {
            $finfo = new \finfo(FILEINFO_MIME);
            $mime_type = $finfo->file($file_name);
        } else {
            $last_chars = strtolower(substr($file_name,
                strrpos($file_name, ".")));
            $mime_types = [
                ".aac" => "audio/aac",
                ".aif" => "audio/aiff",
                ".aiff" => "audio/aiff",
                ".aifc" => "audio/aiff",
                ".avi" => "video/x-msvideo",
                ".bmp" => "image/bmp",
                ".bz" => "application/bzip",
                ".ico" => "image/x-icon",
                ".css" => "text/css",
                ".csv" => "text/csv",
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
                ".mov" => "video/quicktime",
                ".mp3" => "audio/mpeg",
                ".mp4" => "video/mp4",
                ".m4a" => "audio/mp4",
                ".m4v" => "video/mp4",
                ".pdf" => "application/pdf",
                ".png" => "image/png",
                ".tex" => "text/plain",
                ".txt" => "text/plain",
                ".wav" => "audio/vnd.wave",
                ".webm" => "video/webm",
                ".zip" => "application/zip",
                ".Z" => "application/x-compress",
            ];
            if (isset($mime_types[$last_chars])) {
                $mime_type = $mime_types[$last_chars];
            }
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
            Use a string key for the timers map. PHP array keys are
            always ints or strings, so a float key like
            1777158012.190742 would be implicitly truncated to int
            (and emit a deprecation notice on PHP 8.1+). Storing
            the key as a string preserves the full microsecond
            precision and lets processTimers look it up reliably.
         */
        $key = (string) $next_time;
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
        $path = $_SERVER['PATH'] ?? $_SERVER['Path'] ?? ".";
        $default_server_globals = ["CONNECTION_TIMEOUT" => 20,
            "CULL_OLD_SESSION_NUM" => 5, "CUSTOM_ERROR_HANDLER" => null,
            "DOCUMENT_ROOT" => getcwd(),
            "GATEWAY_INTERFACE" => "CGI/1.1",  "MAX_CACHE_FILESIZE" => 2000000,
            "MAX_CACHE_FILES" => 250,  "MAX_IO_LEN" => 128 * 1024,
            "MAX_REQUEST_LEN" => 10000000, "MAX_SESSIONS" => 10000,
            "MAX_INPUT_VARS" => 1000,
            "PATH" => $path,  "PHP_PATH" => "",
            "SERVER_ADMIN" => "you@example.com", "SERVER_NAME" => "localhost",
            "SERVER_SIGNATURE" => "",
            "USER" => $_SERVER['USER'] ?? "",
            "SERVER_SOFTWARE" => "ATTO WEBSITE SERVER",
        ];
        $original_address = is_array($address) ? "multi" : $address;
        $shared_context = [];
        $shared_globals = [];
        if (is_array($config_array_or_ini_filename)) {
            if (!empty($config_array_or_ini_filename['SESSION_INFO'])) {
                $this->sessions =
                    $config_array_or_ini_filename['SESSION_INFO']['SESSIONS'];
                $this->session_queue =
                    $config_array_or_ini_filename['SESSION_INFO'][
                    'SESSION_QUEUE'];
                unset($config_array_or_ini_filename['SESSION_INFO']);
            }
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
            } else {
                $spec_address = $spec;
                $spec_context = [];
            }
            if ($spec_address === null) {
                echo "Listener spec missing address; skipping\n";
                continue;
            }
            $opened[] = $this->openListener($spec_address,
                array_replace_recursive($shared_context, $spec_context));
        }
        if (empty($opened)) {
            echo "No listeners opened, server stopping\n";
            exit();
        }
        /*
            For backward compatibility set is_secure on the WebSite
            if any listener is secure. Code paths that need to know
            per-connection should consult the listener entry instead.
         */
        foreach ($opened as $entry) {
            if ($entry['is_secure']) {
                $this->is_secure = true;
                break;
            }
        }
        $primary = $opened[0];
        $primary_globals = $primary['globals'];
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
        $this->in_streams = [self::CONNECTION => [], self::DATA => [""]];
        $this->out_streams = [self::CONNECTION => [], self::DATA => []];
        foreach ($opened as $entry) {
            $server = $entry['server'];
            $key = (int) $server;
            $this->listeners[$key] = $entry;
            $this->immortal_stream_keys[] = $key;
            $this->in_streams[self::CONNECTION][$key] = $server;
            echo "SERVER listening at " . $entry['address']
                . ($entry['is_secure'] ? " (secure)" : "") . $as_user
                . "\n";
        }
        $excepts = null;
        $num_selected = 1;
        while (!$this->stop || $num_selected > 0) {
            if ($this->stop) {
                $in_streams_with_data = $this->in_streams[self::CONNECTION];
                foreach ($this->listeners as $key => $entry) {
                    unset($in_streams_with_data[$key]);
                }
                if (count($in_streams_with_data) == 0) {
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
                $micro_timeout = intval(($timeout - floor($pre_timeout))
                    * 1000000);
            }
            $num_selected = stream_select($in_streams_with_data,
                $out_streams_with_data, $excepts, $timeout, $micro_timeout);
            $this->processTimers();
            if ($num_selected > 0) {
                $this->processRequestStreams(null,
                    $in_streams_with_data);
                $this->processResponseStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
        if ($this->restart && !empty($_SERVER['SCRIPT_NAME'])) {
            $session_path = substr($this->restart, strlen('restart') + 1);
            $php_path = $this->default_server_globals["PHP_PATH"] ?? "";
            $php = (empty($_ENV['HHVM'])) ? "$php_path/php" : "$php_path/hhvm";
            $restart_arg = is_array($original_address)
                ? "multi" : $original_address;
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
                @fclose($entry['server']);
            }
            if (strstr(PHP_OS, "WIN")) {
                $job = "start $script ";
            } else {
                $job = "$script < /dev/null > /dev/null &";
            }
            pclose(popen($job, "r"));
        }
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
        $server = stream_socket_server($bind_address, $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $server_context);
        if (!$server) {
            echo "Failed to bind address $bind_address: $errstr\n";
            return ['server' => null, 'address' => $bind_address,
                'is_secure' => $is_secure, 'globals' => []];
        }
        stream_set_blocking($server, false);
        return ['server' => $server, 'address' => $bind_address,
            'is_secure' => $is_secure,
            'globals' => ['SERVER_NAME' => $parsed['host'],
                'SERVER_PORT' => $parsed['port']]];
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
        if (strpos($stripped, "://") !== false) {
            $stripped = substr($stripped,
                strpos($stripped, "://") + 3);
        }
        if (substr($stripped, 0, 1) === "[") {
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
     * Used to handle local web page/HTTP requests made from a running
     * WebSite script  back to itself. For example, if while processing a
     * Website ROUTE, one wanted to do curl request for another local page.
     * Since WebSite is single-threaded, such a request would block until the
     * current page was done processing, but as the current page depends on the
     * blocked request, this would cause a deadlock. To avoid this WebSite's
     * should check if a request is local, and if so, call
     * processInternalRequest in lieu of making a real web request, using
     * curl, sockets, etc.
     *
     * @param string $url local page url requested
     * @param bool $include_headers whether to include HTTP response headers
     *      in the returned results as if it had be a real web request
     * @param array $post_data variables (if any) to be used in an internal
     *      HTTP POST request.
     * @return string web page that WebSite would have reqsponded with if
     *      the request had been made as a usual web request.
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
        $r = array_pop($request_context);
        $_SERVER = $r["SERVER"];
        $_GET = $r["GET"];
        $_POST = $r["POST"];
        $_REQUEST = $r["REQUEST"];
        $_COOKIE = $r["COOKIE"];
        $_SESSION = $r["SESSION"];
        $this->header_data = $r["HEADER"];
        $this->content_type = $r["CONTENT_TYPE"];
        $this->current_session = $r["CURRENT_SESSION"];
        return $out_data;
    }
    /**
     * Used to export info (but not change) about running sessions
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
    protected function getResponseData($include_headers = true)
    {
        $this->header_data = "";
        $this->current_session = "";
        $_SESSION = [];
        $this->content_type = false;
        ob_start();
        try {
            $this->process();
        } catch (WebException $we) {
            $msg = $we->getMessage();
            $cmd = substr($msg, 0, strlen('restart'));
            if (in_array($cmd, ["restart", "stop"])) {
                if ($cmd == 'restart') {
                    $session_path = substr($msg, strlen('restart') + 1);
                    if (!empty($session_path)) {
                        $session_info['SESSIONS'] = $this->sessions;
                        $session_info['SESSION_QUEUE'] = $this->session_queue;
                        file_put_contents($session_path,
                            serialize($session_info));
                    }
                    $this->restart = $msg;
                }
                $this->stop = true;
            }
        }
        $out_data = ob_get_contents();
        ob_end_clean();
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
            $this->sessions[$session_id]['DATA'] = $_SESSION;
        }
        $redirect = false;
        if (substr($this->header_data, 0, 5) != "HTTP/") {
            if (stristr($this->header_data, "Location") != false) {
                $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                    " 301 Moved Permanently\x0D\x0A" .
                $this->header_data;
            } else if (
                stristr($this->header_data, "Refresh") != false) {
                $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                    " 302 Found\x0D\x0A" .
                $this->header_data;
            } else {
                $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                    " 200 OK\x0D\x0A". $this->header_data;
            }
        }
        if (!$this->content_type && !$redirect) {
            $this->header_data .= "Content-Type: text/html\x0D\x0A";
        }
        if ($include_headers) {
            $out_data = $this->header_data .
                    "Content-Length: ". strlen($out_data) .
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
                function ($m) use ($var_magic, $star_magic) {
                    return ($m[0] === '*') ? $star_magic : $var_magic;
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
                $callback();
                if ($repeating) {
                    $next_time = $now + $time;
                    $new_key = (string) $next_time;
                    $this->timers[$new_key] =
                        [$repeating, $time, $callback];
                    unset($this->timers[$key]);
                    $this->timer_alarms->insert(
                        [$next_time, $new_key]);
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
            $len = strlen($this->in_streams[self::DATA][$key]);
            $max_len = $this->default_server_globals['MAX_REQUEST_LEN'];
            $too_long = $len >= $max_len;
            if (!empty(
                $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'])) {
                continue;
            }
            $is_h2 = isset(
                $this->in_streams[self::CONTEXT][$key]['CLIENT_HTTP'])
                && $this->in_streams[self::CONTEXT][$key]['CLIENT_HTTP']
                    == "HTTP/2.0";
            $is_ws = !empty(
                $this->in_streams[self::CONTEXT][$key]['IS_WEBSOCKET']);
            if ($is_ws) {
                /*
                    Established WebSocket connection. parseWsRequest
                    reads one frame, dispatches text/binary messages
                    to the registered onMessage callback, and answers
                    pings or close frames inline.
                 */
                $this->parseWsRequest($key,
                    $this->in_streams[self::CONNECTION][$key]);
            } else if ($is_h2) {
                /*
                    H2 connections bypass the chunk-read and out_streams
                    async write path entirely. parseH2Request does its own
                    blocking frame read and writes the response directly,
                    the same way initH2Request handled the preface.
                 */
                if ($too_long) {
                    $this->shutdownHttpStream($key);
                } else {
                    $this->parseH2Request($key,
                        $this->in_streams[self::CONNECTION][$key]);
                }
            } else {
                if (!$too_long) {
                    stream_set_blocking($in_stream, false);
                    $data = stream_get_contents($in_stream, min(
                        $this->default_server_globals['MAX_IO_LEN'],
                        $max_len - $len));
                } else {
                    $data = "";
                    $this->initializeBadRequestResponse($key);
                }
                if ($too_long || $this->parseRequest($key, $data)) {
                    /*
                        Detect WebSocket upgrade requests after
                        parseRequest has populated the HTTP_*
                        headers. If the client requested an
                        upgrade and we have a matching ws() route,
                        complete the handshake and switch the
                        connection to WebSocket mode instead of
                        producing a normal HTTP response.
                     */
                    if (empty($this->in_streams[self::CONTEXT][$key][
                            'BAD_RESPONSE'])
                        && $this->isWebSocketUpgrade($key)
                        && $this->handleWebSocketUpgrade($key,
                            $in_stream)) {
                        $this->in_streams[self::MODIFIED_TIME][$key]
                            = time();
                        continue;
                    }
                    if (!empty($this->in_streams[self::CONTEXT][$key][
                            'PRE_BAD_RESPONSE'])) {
                        $this->in_streams[self::CONTEXT][$key][
                            'BAD_RESPONSE'] = true;
                    }
                    $out_data = $this->getResponseData();
                    if (empty($this->in_streams[self::CONTEXT][$key][
                            'BAD_RESPONSE'])) {
                        /*
                            Preserve per-connection state across the
                            keep-alive reset. These keys depend only
                            on which listener accepted the connection
                            (and on the H2 HPACK decode/encode tables)
                            so they apply to every request on this
                            connection, not just the one we just
                            processed.
                         */
                        $preserve = [];
                        $current = $this->in_streams[self::CONTEXT][
                            $key] ?? [];
                        foreach (['IS_SECURE', 'LISTENER_PORT',
                                'LISTENER_NAME', 'HTTPS', 'CLIENT_HTTP',
                                'HPACK_DECODE', 'HPACK_ENCODE'] as
                                $field) {
                            if (isset($current[$field])) {
                                $preserve[$field] = $current[$field];
                            }
                        }
                        $this->initRequestStream($key, $preserve);
                    }
                    if (empty($this->out_streams[self::CONNECTION][$key])) {
                        $this->out_streams[self::CONNECTION][$key] =
                            $in_stream;
                        $this->out_streams[self::DATA][$key] = $out_data;
                        $this->out_streams[self::CONTEXT][$key] = $_SERVER;
                        $this->out_streams[self::MODIFIED_TIME][$key] =
                            time();
                    }
                }
            }
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
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
     * @param array $listener entry from $this->listeners with
     *      keys 'server' (the server resource), 'is_secure'
     *      (whether TLS is enabled on this listener), and
     *      'globals' (per-listener server globals such as
     *      SERVER_NAME and SERVER_PORT)
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
            $acceptor->accept($listener, $timeout);
        if ($connection === null) {
            return;
        }
        $resource = $connection->resource();
        $is_secure = $connection->is_secure;
        $additional_context['IS_SECURE'] = $is_secure;
        $additional_context['LISTENER_PORT'] =
            $listener['globals']['SERVER_PORT'] ?? '';
        $additional_context['LISTENER_NAME'] =
            $listener['globals']['SERVER_NAME'] ?? '';
        if ($is_secure) {
            /*
                Standard CGI HTTPS=on convention so generic PHP
                code that checks $_SERVER['HTTPS'] sees the
                expected value on TLS connections.
             */
            $additional_context['HTTPS'] = 'on';
        }
        $key = (int) $resource;
        $this->in_streams[self::CONNECTION][$key] = $resource;
        $client_http = $additional_context["CLIENT_HTTP"];
        if ($client_http == "HTTP/2.0") {
            try {
                /*
                    TLS: magic was already consumed by the
                    detection read in ConnectionAcceptor
                 */
                $this->initH2Request($resource, false);
                $additional_context['HPACK_DECODE'] = new HPack();
                $additional_context['HPACK_ENCODE'] = new HPack();
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
                $this->initH2Request($resource, true);
                $additional_context['HPACK_DECODE'] = new HPack();
                $additional_context['HPACK_ENCODE'] = new HPack();
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
                set_error_handler(null);
                $custom = $site->default_server_globals[
                    'CUSTOM_ERROR_HANDLER'] ?? null;
                set_error_handler($custom);
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
            Cleartext HTTP/2 upgrade starts with the client connection
            preface magic string
         */
        if (str_starts_with($stream_start, self::H2_CLIENT_MAGIC)) {
            return ["CLIENT_HTTP" => "h2c"];
        }
        if (preg_match(
            "/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)".
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
                . get_class($client_settings));
        }
        $client_settings->parseBody(
            $this->readExactly($connection, $settings_len));
        /*
            Server-advertised settings. We send these explicitly so
            the client knows our limits rather than relying on
            protocol defaults.
              MAX_CONCURRENT_STREAMS=100 caps how many requests a
                single client can have in flight on this connection
                so a misbehaving peer cannot exhaust resources by
                opening millions of streams.
              MAX_FRAME_SIZE=16384 matches the H2_MAX_FRAME_SIZE
                check in parseH2Request so the client knows the
                limit.
              INITIAL_WINDOW_SIZE=65535 is the HTTP/2 default,
                emitted explicitly so flow-control state on both
                sides starts in agreement.
         */
        $server_settings = new SettingsFrame(0, [
            0x03 => 100,
            0x04 => 65535,
            0x05 => self::H2_MAX_FRAME_SIZE,
        ]);
        @fwrite($connection, $server_settings->serialize());
        $ack = new SettingsFrame(0, []);
        $ack->flags->add('ACK');
        @fwrite($connection, $ack->serialize());
        stream_set_blocking($connection, false);
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
    protected function parseH2Request($key, $connection)
    {
        stream_set_blocking($connection, true);
        try {
            $hdr = $this->readExactly($connection,
                self::H2_FRAME_HEADER_LEN);
        } catch (\Exception $e) {
            stream_set_blocking($connection, false);
            $this->shutdownHttpStream($key);
            return false;
        }
        [$frame, $payload_len] = Frame::parseFrameHeader($hdr);
        if ($payload_len > self::H2_MAX_FRAME_SIZE) {
            /*
                RFC 7540 sec 4.2: a frame size error is a connection
                error. Send GOAWAY with FRAME_SIZE_ERROR (0x6) and
                tear down before allocating the oversized payload.
                We do not drain the announced payload because the
                connection is being closed anyway and reading it
                would defeat the purpose of the size check.
             */
            $goaway = new GoAwayFrame(0, 0, 0x6, "");
            @fwrite($connection, $goaway->serialize());
            stream_set_blocking($connection, false);
            $this->shutdownHttpStream($key);
            return false;
        }
        $payload = "";
        if ($payload_len > 0) {
            try {
                $payload = $this->readExactly($connection, $payload_len);
            } catch (\Exception $e) {
                /*
                    Peer closed connection between the frame header
                    and its payload. Match the cleanup pattern of
                    the header read above: drop the stream and
                    return without touching the half-read frame.
                 */
                stream_set_blocking($connection, false);
                $this->shutdownHttpStream($key);
                return false;
            }
        }
        stream_set_blocking($connection, false);
        if ($frame instanceof GoAwayFrame) {
            $this->shutdownHttpStream($key);
            return false;
        }
        if ($frame instanceof PingFrame) {
            $pong = new PingFrame(0, $payload);
            $pong->flags->add('ACK');
            @fwrite($connection, $pong->serialize());
            return false;
        }
        if ($frame instanceof SettingsFrame
            && !$frame->flags->contains('ACK')) {
            /*
                Apply settings the peer sent us. We act on
                HEADER_TABLE_SIZE (0x01) so the encoder honors the
                decoder's table size. Other settings are accepted
                but ignored: ENABLE_PUSH (we never push),
                MAX_CONCURRENT_STREAMS (a hint for clients, not us),
                INITIAL_WINDOW_SIZE and MAX_FRAME_SIZE (Atto's
                synchronous response model does not benefit from
                tracking these), MAX_HEADER_LIST_SIZE (best-effort).
             */
            $hpack_encode = $this->in_streams[self::CONTEXT][$key][
                'HPACK_ENCODE'] ?? null;
            if ($hpack_encode !== null
                && isset($frame->settings[0x01])) {
                $hpack_encode->setMaxTableSize($frame->settings[0x01]);
            }
            $ack = new SettingsFrame(0, []);
            $ack->flags->add('ACK');
            @fwrite($connection, $ack->serialize());
            return false;
        }
        if ($frame instanceof DataFrame) {
            /*
                RFC 7540 sec 6.1: DATA frames carry request body
                bytes. Atto buffers them per-stream alongside the
                request context that arrived with the HEADERS
                frame, then dispatches the assembled request once
                END_STREAM is seen. parseFrameHeader gives us the
                frame shell with stream_id and flags; the body
                bytes still need to be parsed out (handles padding
                if the PADDED flag is set).
             */
            $frame->parseBody($payload);
            $stream_id = $frame->stream_id;
            $pending = $this->in_streams[self::CONTEXT][$key][
                'H2_PENDING_STREAMS'][$stream_id] ?? null;
            if ($pending === null) {
                /*
                    DATA frame for a stream we never saw HEADERS
                    on, or one already dispatched. RFC 7540 sec
                    5.1 says receiving DATA on a stream not in
                    open or half-closed(local) state is a
                    STREAM_ERROR. We close the connection; this
                    is conservative but Atto's H2 path is
                    synchronous so we never have many concurrent
                    streams.
                 */
                $goaway = new GoAwayFrame(0,
                    $this->in_streams[self::CONTEXT][$key][
                        'H2_LAST_STREAM_ID'] ?? 0, 0x1, "");
                @fwrite($connection, $goaway->serialize());
                $this->shutdownHttpStream($key);
                return false;
            }
            $pending['body'] .= $frame->data;
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
                POSTs >65535 bytes (yioop Fetcher crawl uploads,
                multipart file uploads) stall until client timeout.
             */
            $consumed = strlen($frame->data);
            if ($consumed > 0) {
                $stream_update = new WindowUpdateFrame(
                    $stream_id, $consumed);
                $conn_update = new WindowUpdateFrame(
                    0, $consumed);
                @fwrite($connection, $stream_update->serialize()
                    . $conn_update->serialize());
            }
            if (strlen($pending['body'])
                    > $this->default_server_globals[
                        'MAX_REQUEST_LEN']) {
                /*
                    Body bigger than MAX_REQUEST_LEN. Tear down
                    rather than buffer further.
                 */
                $goaway = new GoAwayFrame(0,
                    $this->in_streams[self::CONTEXT][$key][
                        'H2_LAST_STREAM_ID'] ?? 0, 0xb, "");
                @fwrite($connection, $goaway->serialize());
                $this->shutdownHttpStream($key);
                return false;
            }
            if ($frame->flags->contains('END_STREAM')) {
                $context = $pending['context'];
                $context['CONTENT'] = $pending['body'];
                unset($this->in_streams[self::CONTEXT][$key][
                    'H2_PENDING_STREAMS'][$stream_id]);
                return $this->dispatchH2Request($key, $connection,
                    $stream_id, $context);
            }
            $this->in_streams[self::CONTEXT][$key][
                'H2_PENDING_STREAMS'][$stream_id] = $pending;
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
        $high_water = $this->in_streams[self::CONTEXT][$key][
            'H2_LAST_STREAM_ID'] ?? 0;
        if ($client_stream_id <= $high_water) {
            $goaway = new GoAwayFrame(0, $high_water, 0x1, "");
            @fwrite($connection, $goaway->serialize());
            $this->shutdownHttpStream($key);
            return false;
        }
        $this->in_streams[self::CONTEXT][$key]['H2_LAST_STREAM_ID']
            = $client_stream_id;
        $hpack_decode = $this->in_streams[self::CONTEXT][$key][
            'HPACK_DECODE'] ?? new HPack();
        $hpack_encode = $this->in_streams[self::CONTEXT][$key][
            'HPACK_ENCODE'] ?? new HPack();
        $context = $frame->parseBody($payload, $hpack_decode);
        /*
            HeaderFrame::parseBody builds its context fresh from the
            HEADERS frame and so does not see the per-connection
            keys (IS_SECURE, LISTENER_PORT, LISTENER_NAME, HTTPS)
            that processServerRequest stored in in_streams[CONTEXT].
            Merge those in here, with the freshly-parsed request
            keys winning on conflict.
         */
        $conn_context = $this->in_streams[self::CONTEXT][$key] ?? [];
        $propagate = [];
        foreach (['IS_SECURE', 'LISTENER_PORT', 'LISTENER_NAME',
                'HTTPS', 'REMOTE_ADDR', 'REMOTE_PORT', 'SERVER_ADDR',
                'SERVER_PORT'] as $field) {
            if (isset($conn_context[$field])) {
                $propagate[$field] = $conn_context[$field];
            }
        }
        $context = array_merge($propagate, $context);
        if (!$frame->flags->contains('END_STREAM')) {
            /*
                HEADERS without END_STREAM means a request body is
                arriving in subsequent DATA frames. Park the
                context against the stream id; DATA frames will
                accumulate the body and the eventual END_STREAM
                will trigger dispatchH2Request.
             */
            $this->in_streams[self::CONTEXT][$key][
                'H2_PENDING_STREAMS'][$client_stream_id] = [
                    'context' => $context, 'body' => ''];
            return false;
        }
        return $this->dispatchH2Request($key, $connection,
            $client_stream_id, $context);
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
        $hpack_encode = $this->in_streams[self::CONTEXT][$key][
            'HPACK_ENCODE'] ?? new HPack();
        $_SESSION = [];
        $this->setGlobals($context);
        $body = $this->getResponseData(false);
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
            Split body into DATA frames of at most H2_MAX_FRAME_SIZE
            bytes per RFC 7540 sec 4.2 (oversized frames are
            FRAME_SIZE_ERROR and curl/browsers drop the response).
            Default MAX_FRAME_SIZE is 16384; most clients keep it.
            Empty bodies still emit one frame so END_STREAM has a
            place to live. Outbound flow control (sec 5.2) is not
            enforced: real clients grant huge windows eagerly so
            it never bottlenecks Atto's synchronous model.
         */
        $body_len = strlen($body);
        $max = self::H2_MAX_FRAME_SIZE;
        if ($body_len === 0) {
            $resp_data = new DataFrame($stream_id, "");
            $resp_data->flags->add("END_STREAM");
            $out .= $resp_data->serialize();
        } else {
            $offset = 0;
            while ($offset < $body_len) {
                $chunk = substr($body, $offset, $max);
                $offset += strlen($chunk);
                $frame = new DataFrame($stream_id, $chunk);
                if ($offset >= $body_len) {
                    $frame->flags->add("END_STREAM");
                }
                $out .= $frame->serialize();
            }
        }
        /*
            Suppress fwrite warning: clients (especially browsers
            loading many subresources in parallel) routinely close
            the connection before we finish writing the response,
            e.g. when the user navigates away or when the browser
            cancels in-flight requests. The resulting SIGPIPE /
            broken-pipe / SSL "bad length" warnings are noise
            rather than bugs. The connection has already been
            closed by the peer; the server has nothing else to do
            and the next event-loop iteration will drop the
            half-closed stream cleanly.
         */
        @fwrite($connection, $out);
        return true;
    }
    /**
     * Reads exactly $length bytes from $connection, blocking until
     * all bytes are available. Returns the binary string, or throws
     * if the connection closes before enough data arrives.
     *
     * @param resource $connection
     * @param int $length Number of bytes to read
     * @return string
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
        if (strpos($connection_lc, 'upgrade') === false) {
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
        $this->in_streams[self::CONTEXT][$key]['IS_WEBSOCKET'] = true;
        $this->in_streams[self::DATA][$key] = "";
        $ws = new WebSocket($connection, $key, $this);
        $this->in_streams[self::CONTEXT][$key]['WS'] = $ws;
        $this->wsEnqueueWrite($key, $response);
        if (!$this->ws_keepalive_registered
            && $this->ws_keepalive_interval > 0) {
            $this->registerWsKeepalive();
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
        if (empty($this->out_streams[self::CONNECTION][$key])) {
            $this->out_streams[self::CONNECTION][$key] =
                $this->in_streams[self::CONNECTION][$key];
            $this->out_streams[self::DATA][$key] = $data;
            $this->out_streams[self::CONTEXT][$key] =
                ['IS_WEBSOCKET' => true];
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
        $contexts = $this->in_streams[self::CONTEXT] ?? [];
        foreach ($contexts as $key => $context) {
            if (empty($context['IS_WEBSOCKET'])
                || empty($context['WS'])) {
                continue;
            }
            $ws = $context['WS'];
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
                $this->wsEnqueueWrite($key,
                    WebSocketFrame::build(self::WS_OPCODE_PING,
                        ""));
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
    protected function parseWsRequest($key, $connection)
    {
        stream_set_blocking($connection, true);
        $frame = WebSocketFrame::read($connection);
        stream_set_blocking($connection, false);
        $ws = $this->in_streams[self::CONTEXT][$key]['WS'] ?? null;
        if ($frame === null) {
            if ($ws !== null && $ws->on_close !== null) {
                ($ws->on_close)($ws);
            }
            $this->shutdownHttpStream($key);
            return;
        }
        if ($ws === null) {
            $this->shutdownHttpStream($key);
            return;
        }
        /*
            Any frame from the client counts as proof of life
            for the keepalive timer, not just PONG frames.
         */
        $ws->last_pong_time = time();
        if (!empty($frame['too_large'])) {
            if ($ws->on_error !== null) {
                ($ws->on_error)("Message exceeds maximum size", $ws);
            }
            $ws->close(1009, "Message too big");
            return;
        }
        if (!$frame['masked']) {
            /*
                Per RFC 6455 sec 5.1 every client to server frame
                must be masked. An unmasked frame is a protocol
                error and the connection must be closed.
             */
            $ws->close(1002, "Unmasked client frame");
            return;
        }
        $opcode = $frame['opcode'];
        if ($opcode === self::WS_OPCODE_CLOSE) {
            if (!$ws->closed) {
                $ws->closed = true;
                $this->wsEnqueueWrite($key,
                    WebSocketFrame::build(self::WS_OPCODE_CLOSE,
                        $frame['payload']));
            }
            if ($ws->on_close !== null) {
                ($ws->on_close)($ws);
            }
            return;
        }
        if ($opcode === self::WS_OPCODE_PING) {
            $this->wsEnqueueWrite($key,
                WebSocketFrame::build(self::WS_OPCODE_PONG,
                    $frame['payload']));
            return;
        }
        if ($opcode === self::WS_OPCODE_PONG) {
            return;
        }
        if ($opcode === self::WS_OPCODE_TEXT
            || $opcode === self::WS_OPCODE_BINARY) {
            $ws->fragment_buffer = $frame['payload'];
            $ws->fragment_opcode = $opcode;
        } else if ($opcode === self::WS_OPCODE_CONTINUATION) {
            if (strlen($ws->fragment_buffer) + $frame['length']
                > self::WS_MAX_MESSAGE_SIZE) {
                $ws->close(1009, "Message too big");
                return;
            }
            $ws->fragment_buffer .= $frame['payload'];
        } else {
            /*
                Reserved opcode. RFC 6455 sec 5.2 says the receiver
                must fail the connection.
             */
            $ws->close(1002, "Unknown opcode");
            return;
        }
        if ($frame['fin']) {
            $message = $ws->fragment_buffer;
            $ws->fragment_buffer = "";
            if ($ws->on_message !== null) {
                try {
                    ($ws->on_message)($message, $ws);
                } catch (\Exception $e) {
                    if ($ws->on_error !== null) {
                        ($ws->on_error)($e->getMessage(), $ws);
                    }
                }
            }
        }
    }
    /**
     * Gets info about an incoming request stream and uses this to set up
     * an initial stream context. This context is used to populate the $_SERVER
     * variable when the request is later processed.
     *
     * @param int key id of request stream to initialize context for
     * @param array $additional_context any additional key value field to
     *   set for the stream's context
     */
    protected function initRequestStream($key, $additional_context = [])
    {
        $connection = $this->in_streams[self::CONNECTION][$key];
        $remote_name = stream_socket_get_name($connection, true);
        $server_name = stream_socket_get_name($connection, false);
        list($remote_addr, $remote_port) =
            $this->splitAddressPort($remote_name);
        list($server_addr, $server_port) =
            $this->splitAddressPort($server_name);
        $this->in_streams[self::CONTEXT][$key] = array_merge(
            [
                self::REQUEST_HEAD => false,
                'REQUEST_METHOD' => false,
                "CLIENT_HTTP" => "unknown",
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
        if (substr($name, 0, 1) === "[") {
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
            $data = $this->out_streams[self::DATA][$key];
            $custom_error_handler =
                $this->default_server_globals["CUSTOM_ERROR_HANDLER"] ?? null;
            //suppress connection reset notices
            set_error_handler(null);
            $num_bytes = @fwrite($out_stream, $data);
            set_error_handler($custom_error_handler);
            if ($num_bytes === false) {
                $remaining_bytes = 0;
            } else {
                $remaining_bytes = max(0, strlen($data) - $num_bytes);
            }
            if ($num_bytes > 0) {
                $this->out_streams[self::DATA][$key] = substr($data,
                    $num_bytes);
                $this->out_streams[self::MODIFIED_TIME][$key] = time();
            }
            if ($remaining_bytes == 0) {
                $context = $this->out_streams[self::CONTEXT][$key];
                if (!empty($context['IS_WEBSOCKET'])) {
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
                    $ws = $this->in_streams[self::CONTEXT][$key]['WS']
                        ?? null;
                    unset($this->out_streams[self::CONNECTION][$key],
                        $this->out_streams[self::DATA][$key],
                        $this->out_streams[self::CONTEXT][$key],
                        $this->out_streams[self::MODIFIED_TIME][$key]);
                    if ($ws !== null && $ws->closed) {
                        $this->shutdownHttpStream($key);
                    }
                } else if ((!empty($context['HTTP_CONNECTION']) &&
                    strtolower($context['HTTP_CONNECTION']) == 'close') ||
                    empty($context['SERVER_PROTOCOL']) ||
                    $context['SERVER_PROTOCOL'] == 'HTTP/1.0') {
                    if (empty($context["PRE_BAD_RESPONSE"])) {
                        $this->shutdownHttpStream($key);
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
        if (!isset($context[self::REQUEST_HEAD]))
            $context[self::REQUEST_HEAD] = false;
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
        if (!$context[self::REQUEST_HEAD]) {
            if (strpos($data, "\x0D\x0A\x0D\x0A") === false &&
                strpos($data, "\x0D\x0D") === false) {
                return false;
            }
            if (($end_head_pos = strpos($data, "$eol$eol")) === false) {
                $eol = \PHP_EOL;
                $end_head_pos = strpos($data, "$eol$eol");
            }
            $context[self::REQUEST_HEAD] = true;
            $next_line_pos = strpos($data, $eol);
            $first_line = substr($this->in_streams[self::DATA][$key], 0,
                $next_line_pos);
            $first_lines_regex = "/^(CONNECT|DELETE|ERROR|GET|HEAD|".
                "OPTIONS|POST|PUT|TRACE)\s+([^\s]+)\s+(HTTP\/\d+\.\d+)/";
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
            if (empty($context['CONTENT_LENGTH'])) {
                $context['CONTENT'] = "";
                $this->setGlobals($context);
                return true;
            } else if ($context['CONTENT_LENGTH'] >
                $this->default_server_globals['MAX_REQUEST_LEN'] -
                $end_head_pos) {
                $this->initializeBadRequestResponse($key);
                return true;
            }
        }
        $data = $this->in_streams[self::DATA][$key];
        $content_pos = strpos($data, "$eol$eol") + strlen("$eol$eol");
        if (strlen($data) - $content_pos < $context['CONTENT_LENGTH']) {
            return false;
        }
        $context['CONTENT'] = substr($data, $content_pos);
        $this->setGlobals($context);
        return true;
    }
    /**
     * Used to initialize the superglobals before process() is called when
     * WebSite is run in CLI-mode. The values for the globals come from the
     * request streams context which has request headers. If the request
     * had CONTENT, for example, from posted form data, this is parsed and
     * $_POST, and $_FILES superglobals set up.
     *
     * @param array $context associative array of information parsed from
     *      a web request. The content portion of the request is not yet
     *      parsed but headers are, each with a prefix field HTTP_ followed
     *      by name of the header. For example the value of a header with name
     *      Cookie should be in $context['HTTP_COOKIE']. The Content-Type
     *      and Content-Length header do no get the prefix, so should be as
     *      $context['CONTENT_TYPE'] and $context['CONTENT_LENGTH'].
     *      The request method, query_string, also appear with the HTTP_ prefix.
     *      Finally, the content of the request should be in
     *      $context['CONTENT'].
     */
    protected function setGlobals($context)
    {
        $_SERVER = array_merge($this->default_server_globals, $context);
        parse_str($context['QUERY_STRING'], $_GET);
        $_POST = [];
        /*
            $_FILES is a process-global superglobal that PHP
            does not auto-reset per request when running under
            the CLI server, so wipe it here. Without this, a
            previous request's uploaded file metadata leaks into
            the next request's $_FILES even when the new request
            has none of its own.
         */
        $_FILES = [];
        if (!empty($context['CONTENT']) &&
            !empty($context['CONTENT_TYPE']) &&
            strpos($context['CONTENT_TYPE'], "multipart/form-data") !== false) {
            preg_match('/boundary=(.*)/', $context['CONTENT_TYPE'], $matches);
            $boundary = $matches[1];
            $raw_form_parts = preg_split("/-+$boundary/", $context['CONTENT']);
            array_pop($raw_form_parts);
            /*
                Cap the number of parts processed to MAX_INPUT_VARS
                so a hostile multipart request with millions of
                small parts cannot exhaust CPU or memory in this
                loop. Parts past the cap are silently dropped; a
                legitimate form will not approach this limit.
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
                        Non-greedy capture so a multipart field name
                        like 'evil"; injection="x' does not match
                        past the first closing quote. The greedy
                        (.*) version let attackers smuggle extra
                        attributes into the parsed name.
                     */
                    if(preg_match("/\s*Content-Disposition\:\s*form-data\;\s*" .
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
                    //we support up to 3D arrays in form variables
                    if (preg_match("/^(\w+)\[(\w+)\]\[(\w+)\]\[(\w+)\]$/",
                        $name, $matches)) {
                        $_POST[$matches[1]][$matches[2]][$matches[3]][
                            $matches[4]] = $content;
                    } else if (preg_match("/^(\w+)\[(\w+)\]\[(\w+)\]$/", $name,
                        $matches)) {
                        $_POST[$matches[1]][$matches[2]][$matches[3]] =
                            $content;
                    } else if (preg_match("/^(\w+)\[(\w+)\]$/", $name,
                        $matches)) {
                        $_POST[$matches[1]][$matches[2]] = $content;
                    } else {
                        $_POST[$name] = rtrim($content, "\x0D\x0A");
                    }
                    continue;
                }
                /*
                    tmp_name is conventionally a server-generated
                    filesystem path that move_uploaded_file()
                    validates. Atto keeps uploads in memory in the
                    'data' field rather than writing temp files,
                    so there is no real path to expose. Setting
                    tmp_name to the client-supplied filename
                    creates a footgun: code that does
                    require($_FILES['x']['tmp_name']) or similar
                    would dereference an attacker-controlled
                    string. Use a synthetic non-path token
                    instead so any such code fails obviously.
                 */
                $tmp_token = "atto-mem-upload-"
                    . bin2hex(random_bytes(8));
                $file_array = ['name' => $file_name,
                    'tmp_name' => $tmp_token,
                    'type' => $content_type, 'error' => 0,
                    'data' => $content,
                    'size' => strlen($content)];
                if (empty($_FILES[$name])) {
                    $_FILES[$name] = $file_array;
                } else {
                    foreach (['name', 'tmp_name', 'type', 'error', 'data',
                        'size'] as $field) {
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
     * a 400 BAD REQUEST response occurs.
     *
     * @param int $key id of stream that bad request came from
     */
    protected function initializeBadRequestResponse($key)
    {
        $_COOKIE = [];
        $_SESSION = [];
        $_FILES = [];
        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        $_SERVER = array_merge($this->default_server_globals,
            $this->in_streams[self::CONTEXT][$key],
            ['REQUEST_METHOD' => 'ERROR', 'REQUEST_URI' => '/400',
             'SERVER_PROTOCOL' => 'HTTP/1.0',
             'PRE_BAD_RESPONSE' => true]);
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
            if (!empty($this->in_streams[self::CONTEXT][$key][
                    'IS_WEBSOCKET'])) {
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
            $in_time = empty($this->in_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->in_streams[self::MODIFIED_TIME][$key];
            $out_time = empty($this->out_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->out_streams[self::MODIFIED_TIME][$key];
            $modified_time = max($in_time, $out_time);
            if ($meta['eof'] ||
                time() - $modified_time > $this->default_server_globals[
                'CONNECTION_TIMEOUT']) {
                $this->shutdownHttpStream($key);
            }
        }
    }
    /**
     * Closes stream with id $key and removes it from in_streams and
     * outstreams arrays.
     *
     * @param int $key id of stream to delete
     */
    protected function shutdownHttpStream($key)
    {
        if (!empty($this->in_streams[self::CONNECTION][$key])) {
            set_error_handler(null);
            @stream_socket_shutdown($this->in_streams[self::CONNECTION][$key],
                STREAM_SHUT_RDWR);
            $custom_error_handler =
                $this->default_server_globals["CUSTOM_ERROR_HANDLER"] ??
                null;
            set_error_handler($custom_error_handler);
        }
        unset($this->in_streams[self::CONNECTION][$key],
            $this->in_streams[self::CONTEXT][$key],
            $this->in_streams[self::DATA][$key],
            $this->in_streams[self::MODIFIED_TIME][$key],
            $this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]
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
        unset($this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
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
 * The class is structured to admit a future Quic transport without
 * requiring callers to be aware of which transport they are on. A
 * QuicConnection subclass would override read/write to direct
 * traffic to a specific QUIC stream and would override streamId()
 * to return the QUIC stream id rather than 0.
 */
class Connection
{
    /**
     * Underlying stream resource (TCP, possibly TLS-wrapped).
     * @var resource
     */
    public $resource;
    /**
     * Whether this connection's transport is TLS-wrapped. Used by
     * code paths that need to decide between cleartext and secure
     * behavior independently of the listener that accepted it.
     * @var bool
     */
    public $is_secure;
    /**
     * Constructs a Connection wrapping a stream resource.
     *
     * @param resource $resource open stream socket
     * @param bool $is_secure whether the resource has had TLS
     *      enabled via stream_socket_enable_crypto
     */
    public function __construct($resource, $is_secure = false)
    {
        $this->resource = $resource;
        $this->is_secure = $is_secure;
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
     * Reads up to $max_bytes from the connection. Honors the
     * current blocking mode of the underlying stream.
     *
     * @param int $max_bytes maximum bytes to read
     * @return string|false bytes read, empty string at EOF or
     *      when no data is available in non-blocking mode, or
     *      false on error
     */
    public function read($max_bytes)
    {
        return @fread($this->resource, $max_bytes);
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
     * The 24-byte HTTP/2 client connection preface from RFC 7540
     * section 3.5. Cached as a string for fast comparison rather
     * than recomputed each accept.
     * @var string
     */
    protected $h2_magic;
    /**
     * Optional callback invoked with an error message when TLS
     * handshake fails. If null the message is written to stdout.
     * @var callable|null
     */
    protected $error_handler;
    /**
     * Optional callback invoked after a successful TLS handshake
     * to restore the WebSite's custom error handler that
     * stream_socket_enable_crypto temporarily clears.
     * @var callable|null
     */
    protected $post_tls_callback;
    /**
     * Constructs a ConnectionAcceptor.
     *
     * @param string $h2_magic the H2 client preface bytes
     * @param callable|null $error_handler invoked with a string
     *      error message on TLS failure
     * @param callable|null $post_tls_callback invoked after a
     *      successful TLS handshake to let the caller reinstall
     *      its custom error handler
     */
    public function __construct($h2_magic,
        $error_handler = null, $post_tls_callback = null)
    {
        $this->h2_magic = $h2_magic;
        $this->error_handler = $error_handler;
        $this->post_tls_callback = $post_tls_callback;
    }
    /**
     * Accepts a new connection from the given listener entry,
     * runs the TLS handshake if the listener is secure, then
     * inspects the first bytes to determine the HTTP protocol
     * version. Returns a [Connection, additional_context] pair
     * suitable for handing to WebSite's per-protocol init
     * routines, or [null, null] if no connection was accepted.
     *
     * @param array $listener entry from WebSite's listeners with
     *      keys 'server' (server resource) and 'is_secure'
     * @param float $timeout maximum seconds to block waiting for
     *      a connection
     * @return array [Connection|null, array|null]
     */
    public function accept($listener, $timeout)
    {
        $server = $listener['server'];
        $is_secure = !empty($listener['is_secure']);
        if ($is_secure) {
            stream_set_blocking($server, true);
        }
        $resource = @stream_socket_accept($server, $timeout);
        if ($is_secure) {
            stream_set_blocking($server, false);
        }
        if (!$resource) {
            echo "No connection accepted or timed out.\n";
            return [null, null];
        }
        if ($is_secure) {
            /*
                A listener configured for TLS may still receive
                plaintext HTTP if the operator runs a single-port
                setup where some local clients (yioop's Fetcher,
                health checks, sidecars) speak HTTP. Peek the first
                byte before invoking the TLS handshake. A TLS
                ClientHello always starts with 0x16 (ContentType =
                Handshake, RFC 8446 sec 5.1). Anything else is
                treated as cleartext and the connection bypasses
                TLS entirely. This matches the behavior of nginx
                and similar servers that accept both protocols on
                the same port.
             */
            $peek = @stream_socket_recvfrom($resource, 1, STREAM_PEEK);
            if ($peek === false || $peek === '') {
                @fclose($resource);
                return [null, null];
            }
            if ($peek[0] !== "\x16") {
                $is_secure = false;
            }
        }
        $connection = new Connection($resource, $is_secure);
        if ($is_secure) {
            if (!$this->enableTls($connection)) {
                $connection->close();
                return [null, null];
            }
        }
        $additional_context = $this->detectProtocol($connection);
        return [$connection, $additional_context];
    }
    /**
     * Enables TLS on a freshly accepted connection. Sets blocking
     * mode for the duration of the handshake, then restores
     * non-blocking on success. Reports failures through the
     * error_handler if one was supplied. The post_tls_callback
     * is invoked on success so the caller can reinstall its
     * custom error handler that PHP clears as part of the TLS
     * setup.
     *
     * @param Connection $connection freshly accepted connection
     *      to wrap with TLS
     * @return bool true on success, false if the handshake failed
     */
    protected function enableTls($connection)
    {
        $connection->setBlocking(true);
        if (!@stream_socket_enable_crypto(
                $connection->resource(), true,
                STREAM_CRYPTO_METHOD_TLS_SERVER)) {
            $ssl_error = error_get_last();
            $message = "\n\nSSL Error: "
                . ($ssl_error['message'] ?? 'unknown');
            if ($this->error_handler) {
                ($this->error_handler)($message);
            } else {
                echo $message;
            }
            return false;
        }
        if ($this->post_tls_callback) {
            ($this->post_tls_callback)();
        }
        return true;
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
    protected function detectProtocol($connection)
    {
        if ($connection->is_secure) {
            /*
                PHP does not expose the ALPN-negotiated protocol
                so after the TLS handshake we read the decrypted
                bytes while still in blocking mode. An H2 client
                always sends the 24-byte magic string as its
                first data.
             */
            $magic_len = strlen($this->h2_magic);
            $stream_start = $connection->read($magic_len);
            $connection->setBlocking(false);
            if ($stream_start === $this->h2_magic) {
                return ["CLIENT_HTTP" => "HTTP/2.0"];
            }
            return ["CLIENT_HTTP" => "HTTP/1.1",
                "LEFTOVER" => $stream_start];
        }
        /*
            Cleartext: safe to peek since there is no TLS wrapping
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
     * Reads one complete WebSocket frame from a connection,
     * blocking until all bytes are available. Unmasks the payload
     * if the mask bit is set. Returns an associative array with
     * the parsed fields, or null if the connection closes mid-frame.
     *
     * @param resource $connection client socket to read from
     * @return array|null array with keys 'fin' (bool),
     *      'opcode' (int), 'masked' (bool), 'payload' (string),
     *      and 'length' (int) on success; null on EOF
     */
    public static function read($connection)
    {
        $hdr = self::readExactly($connection, 2);
        if ($hdr === null) {
            return null;
        }
        $byte1 = ord($hdr[0]);
        $byte2 = ord($hdr[1]);
        $fin = (bool)($byte1 & 0x80);
        $opcode = $byte1 & 0x0F;
        $masked = (bool)($byte2 & 0x80);
        $length = $byte2 & 0x7F;
        if ($length === 126) {
            $ext = self::readExactly($connection, 2);
            if ($ext === null) {
                return null;
            }
            $length = unpack('n', $ext)[1];
        } else if ($length === 127) {
            $ext = self::readExactly($connection, 8);
            if ($ext === null) {
                return null;
            }
            /*
                64-bit length: PHP integers are signed 64-bit on
                most builds; clamp the high bit to avoid negative
                values. Practically we limit message size below.
             */
            $unpacked = unpack('Nhi/Nlo', $ext);
            $length = ($unpacked['hi'] << 32) | $unpacked['lo'];
        }
        if ($length > WebSite::WS_MAX_MESSAGE_SIZE) {
            return ['fin' => $fin, 'opcode' => $opcode,
                'masked' => $masked, 'payload' => '',
                'length' => $length, 'too_large' => true];
        }
        $mask_key = '';
        if ($masked) {
            $mask_key = self::readExactly($connection, 4);
            if ($mask_key === null) {
                return null;
            }
        }
        $payload = '';
        if ($length > 0) {
            $payload = self::readExactly($connection, $length);
            if ($payload === null) {
                return null;
            }
            if ($masked) {
                $payload = self::unmask($payload, $mask_key);
            }
        }
        return ['fin' => $fin, 'opcode' => $opcode,
            'masked' => $masked, 'payload' => $payload,
            'length' => $length, 'too_large' => false];
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
     * key. Implemented via string-mode XOR over the whole payload
     * for one C-level pass instead of a PHP loop.
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
    /**
     * Reads exactly $count bytes from a connection. Returns the
     * bytes on success, or null if the connection closed or the
     * read deadline expired without enough data arriving.
     *
     * Uses stream_select with a 1-second slice when fread returns
     * no data so a stalled client does not spin a CPU core. If no
     * data arrives within $deadline_seconds total wall time the
     * read aborts and the caller closes the connection.
     *
     * @param resource $connection client socket to read from
     * @param int $count number of bytes to read
     * @param int $deadline_seconds maximum wall-clock seconds to
     *      wait for the full count to arrive before giving up
     * @return string|null binary data of length $count, or null
     *      on EOF or timeout
     */
    private static function readExactly($connection, $count,
        $deadline_seconds = 30)
    {
        $data = '';
        $remaining = $count;
        $deadline = time() + $deadline_seconds;
        while ($remaining > 0) {
            $chunk = @fread($connection, $remaining);
            if ($chunk === false) {
                return null;
            }
            if ($chunk === '') {
                if (feof($connection)) {
                    return null;
                }
                if (time() >= $deadline) {
                    return null;
                }
                /*
                    Park on stream_select with a short timeout
                    rather than busy-looping on fread. This pegs
                    CPU usage at 0% on a stalled client instead
                    of 100%. Bare list assignment with by-ref
                    parameters is required by stream_select.
                 */
                $read = [$connection];
                $write = null;
                $except = null;
                @stream_select($read, $write, $except, 1);
                continue;
            }
            $data .= $chunk;
            $remaining -= strlen($chunk);
        }
        return $data;
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
     * Underlying TCP (or TLS-wrapped) connection
     * @var resource
     */
    public $connection;
    /**
     * Connection key used by the WebSite event loop to identify
     * this connection in the in_streams arrays
     * @var int
     */
    public $key;
    /**
     * Reference to the owning WebSite instance, used to enqueue
     * outbound frames into its out_streams buffer
     * @var WebSite
     */
    public $site;
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
     * @param resource $connection client socket already upgraded
     *      from HTTP/1.1 to the WebSocket protocol
     * @param int $key connection key used by the event loop
     * @param WebSite $site owning WebSite instance used for
     *      buffered outbound writes
     */
    public function __construct($connection, $key, $site)
    {
        $this->connection = $connection;
        $this->key = $key;
        $this->site = $site;
        $this->last_pong_time = time();
    }
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
     * Builds a frame for the given opcode and payload and appends
     * it to the WebSite out_streams buffer for this connection.
     * The event loop will drain the buffer to the socket as it
     * becomes writable, handling partial writes transparently.
     *
     * Outbound message frames (TEXT, BINARY, CONTINUATION) are
     * capped at WebSite::WS_MAX_MESSAGE_SIZE so a buggy or
     * malicious route handler cannot blast unbounded data at
     * the client. Control frames (PING, PONG, CLOSE) are exempt
     * from the cap since RFC 6455 sec 5.5 limits them to 125
     * bytes anyway and this method does not enforce that limit
     * (the caller is expected to comply).
     *
     * @param int $opcode WS_OPCODE_* constant
     * @param string $payload binary payload bytes
     * @return bool true if queued, false if already closed and
     *      the opcode is not CLOSE, or if the payload exceeds
     *      WS_MAX_MESSAGE_SIZE for a message frame
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
    protected $defined_flags = [];
    protected $type = null;
    protected $stream_association = null;
    protected $payload_length;
    public $stream_id;
    public $flags;

    // Constants
    const STREAM_ASSOC_HAS_STREAM = "has-stream";
    const STREAM_ASSOC_NO_STREAM = "no-stream";
    const STREAM_ASSOC_EITHER = "either";
    const FRAME_MAX_LEN = (2 ** 14); //initial
    const FRAME_MAX_ALLOWED_LEN = (2 ** 24) - 1; //max-allowed
    /**
     * reads the stream id and flags set for the frame
     *
     * @param resource $stream_id the stream number with whom
     * this frame is associated.
     * @param resource $flags array of all flags in the frame
     */
    public function __construct($stream_id, $flags = [])
    {
        $this->stream_id = $stream_id;
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
            throw new \Exception("Unknown frame type: " . $type);
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
/*
 * SettingsFrame class is responsible for handling the HTTP/2 SETTINGS frame,
 * helps configure communication parameters between the client and server.
 */
class SettingsFrame extends Frame
{
    protected $defined_flags = [
        'ACK' => 0x01
    ];
    protected $type = 0x04;
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    const PAYLOAD_SETTINGS = [
        0x01 => 'HEADER_TABLE_SIZE',
        0x02 => 'ENABLE_PUSH',
        0x03 => 'MAX_CONCURRENT_STREAMS',
        0x04 => 'INITIAL_WINDOW_SIZE',
        0x05 => 'MAX_FRAME_SIZE',
        0x06 => 'MAX_HEADER_LIST_SIZE',
        0x08 => 'ENABLE_CONNECT_PROTOCOL',
    ];
    protected $settings = [];
    /**
     * Constructor to create a new SettingsFrame object.
     * @param int $stream_id The stream ID for this frame
     * (default is 0 since SETTINGS frames aren't tied to a stream).
     * @param array $settings The settings to be included in the frame.
     * @param array $flags Any flags associated with the frame (e.g., 'ACK').
     */
    public function __construct($stream_id = 0, $settings = [], $flags = [])
    {
        parent::__construct($stream_id, $flags);
        if (!empty($settings) && in_array('ACK', $flags)) {
            throw new InvalidDataError(
                "Settings must be empty if ACK flag is set.");
        }
        $this->settings = $settings;
    }
    /**
     * Converts the settings into the format required for transmission.
     * Each setting is packed as 6 bytes: 2 bytes for the setting identifier
     * and 4 bytes for its value.
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
    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'END_HEADERS' => 0x04,
        'PADDED' => 0x08,
        'PRIORITY' => 0x20
    ];
    protected $type = 0x01;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    public $data;
    /**
     * Constructor to create a new HeaderFrame object.
     * @param int $stream_id The stream ID this frame belongs to.
     * @param array $data The header data to include in the frame.
     * @param array $flags Any flags associated with the frame.
     */
    public function __construct($stream_id = 0, $data = [], $flags = [])
    {
        parent::__construct($stream_id, $flags);
        $this->data = $data;
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
        $headers = $hpack->decodeHeaderBlockFragment(
            bin2hex($hpack_data));
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
            REMOTE_ADDR is a socket-level fact that HeaderFrame
            cannot observe; it must come from the connection
            context populated by initRequestStream. Do NOT set
            it here, otherwise array_merge in parseH2Request
            (which prefers freshly-parsed request keys over
            propagated connection-level keys) would overwrite
            the real client IP with this placeholder, breaking
            session validity checks in apps like yioop that
            verify $_SESSION['REMOTE_ADDR'] against the request.
         */
        $context['SCRIPT_FILENAME']  = '';
        return $context;
    }
}
/*
 * DataFrame class handles the HTTP/2 DATA frame,
 * which carries the data of a stream between the client and server.
 */
class DataFrame extends Frame
{
    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'PADDED' => 0x08
    ];
    protected $type = 0x0;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    public $data;
    /**
     * Constructor to create a new DataFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param string $data The data payload for the frame.
     * @param array $flags Flags associated with the frame .
     */
    public function __construct($stream_id, $data = '', $flags = [])
    {
        parent::__construct($stream_id, $flags);
        $this->data = $data;
    }
    /**
     * Serializes the body of the frame into a binary string.
     * Converts the ASCII data to binary format for transmission.
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
/*
 * PriorityFrame class handles the HTTP/2 PRIORITY frame,
 * which specifies the sender-advised priority of a stream.
 */
class PriorityFrame extends Frame
{
    protected $defined_flags = [];
    protected $type = 0x02;
    protected $stream_association = self::STREAM_ASSOC_HAS_STREAM;
    protected $depends_on;
    protected $stream_weight;
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
     *
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
/*
 * RstStreamFrame class handles the HTTP/2 RST_STREAM frame,
 * which is used to abruptly terminate a stream.
 */
class RstStreamFrame extends Frame
{
    protected $defined_flags = [];
    protected $type = 0x03;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    protected $error_code;
    /**
     * Constructor to create a new RstStreamFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param int $error_code The error code for the RST_STREAM frame.
     */
    public function __construct($stream_id, $error_code = 0,
        array $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->error_code = $error_code;
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
/*
 * PushPromiseFrame class handles the HTTP/2 PUSH_PROMISE frame,
 * which is used to notify the client of an upcoming stream.
 */
class PushPromiseFrame extends Frame
{
    protected $defined_flags = [
        'END_HEADERS' => 0x04,
        'PADDED' => 0x08
    ];
    protected $type = 0x05;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    protected $promised_stream_id;
    protected $data;
    /**
     * Constructor to create a new PushPromiseFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param int $promised_stream_id The promised stream ID.
     * @param string $data The data payload.
     */
    public function __construct($stream_id, $promised_stream_id = 0,
        $data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->promised_stream_id = $promised_stream_id;
        $this->data = $data;
    }
    /**
     * Serializes the PUSH_PROMISE frame body into binary format.
     * The body is padding length (if PADDED), promised stream id,
     * the header block fragment, then padding bytes.
     *
     * @param object $hpack unused, present for signature compatibility
     *      with HeaderFrame::serializeBody
     * @return string binary serialized body
     */
    public function serializeBody($hpack = null)
    {
        $padding_data = $this->serializePaddingData();
        $padding = str_repeat("\0", $this->pad_length);
        $data = pack('N', $this->promised_stream_id);
        return $padding_data . $data . $this->data . $padding;
    }
    /**
     * Parses the binary data of the PUSH_PROMISE frame.
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        $padding_data_length = $this->parsePaddingData($data);
        if (strlen($data) < $padding_data_length + 4) {
            throw new InvalidFrameException("Invalid PUSH_PROMISE body");
        }
        $this->promised_stream_id =
            unpack('N', substr($data, $padding_data_length, 4))[1];
        $this->data =
            substr($data, $padding_data_length + 4, -$this->pad_length);

        if ($this->promised_stream_id == 0
            || $this->promised_stream_id % 2 != 0) {
            throw new InvalidDataException(
                "Invalid PUSH_PROMISE promised stream id:
                    $this->promised_stream_id");
        }
        if ($this->pad_length && $this->pad_length >= strlen($data)) {
            throw new InvalidPaddingException("Padding is too long.");
        }
        $this->payload_length = strlen($data);
    }
}
/*
 * PingFrame class handles the HTTP/2 PING frame,
 * which is used for measuring round-trip times or verifying connection health.
 */
class PingFrame extends Frame
{
    protected $defined_flags = [
        'ACK' => 0x01
    ];
    protected $type = 0x06;
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    protected $opaque_data;
    /**
     * Constructor to create a new PingFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param string $opaque_data The opaque data (8 bytes)
     * associated with the PING frame.
     */
    public function __construct($stream_id = 0, $opaque_data = '',
        $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->opaque_data = $opaque_data;
    }
    /**
     * Serializes the PING frame body into binary format.
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
/*
 * GoAwayFrame class handles the HTTP/2 GOAWAY frame,
 * which is used to indicate that the sender is gracefully
 * shutting down a connection.
 */
class GoAwayFrame extends Frame
{
    protected $defined_flags = [];
    protected $type = 0x07;
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    protected $last_stream_id;
    protected $error_code;
    protected $additional_data;
    /**
     * Constructor to create a new GoAwayFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param int $last_stream_id last stream ID the sender will accept.
     * @param int $error_code indicating the reason for shutting down.
     * @param string $additional_data Additional debug data (optional).
     */
    public function __construct($stream_id = 0, $last_stream_id = 0,
        $error_code = 0, $additional_data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->last_stream_id = $last_stream_id;
        $this->error_code = $error_code;
        $this->additional_data = $additional_data;
    }
    /**
     * Serializes the GOAWAY frame body into a binary format.
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
/*
 * WindowUpdateFrame class handles the HTTP/2 WINDOW_UPDATE frame,
 * which is used to implement flow control.
 */
class WindowUpdateFrame extends Frame
{
    protected $defined_flags = [];
    protected $type = 0x08;
    protected $stream_association = '_STREAM_ASSOC_EITHER';
    protected $window_increment;
    /**
     * Constructor to create a new WindowUpdateFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param int $window_increment The increment to the window size.
     */
    public function __construct($stream_id, $window_increment = 0,
        $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->window_increment = $window_increment;
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
/*
 * ContinuationFrame class handles the HTTP/2 CONTINUATION frame,
 * which is used to continue a sequence of header block fragments.
 */
class ContinuationFrame extends Frame
{
    protected $defined_flags = [
        'END_HEADERS' => 0x04,
    ];
    protected $type = 0x09;
    public $data;
    /**
     * Constructor to create a new ContinuationFrame object.
     * @param int $stream_id The stream ID for this frame.
     * @param string $data The continuation frame payload.
     */
    public function __construct($stream_id, $data = '', $kwargs = [])
    {
        parent::__construct($stream_id, $kwargs);
        $this->data = $data;
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
/*
 * Exception classes for exceptions thrown in all frame classes.
 */
class InvalidFrameException extends \Exception {}
class InvalidDataException extends \Exception {}
class InvalidPaddingException extends \Exception {}
/**
 * Represents a single flag with a name and bit value.
 */
class Flag
{
    public $name;
    public $bit;
    /**
     * Constructor for Flag.
     * @param string $name The name of the flag.
     * @param int $bit The bit value associated with the flag.
     */
    public function __construct($name, $bit)
    {
        $this->name = $name;
        $this->bit = $bit;
    }
}
/**
 * Flags class manages a collection of valid flags and supports
 * adding, removing, and checking for the presence of flags.
 */
class Flags
{
    private $valid_flags;
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
/*
 * Trait for handling padding in HTTP/2 frames.
 */
trait Padding
{
    protected $pad_length;
    /**
     * Constructor for Padding trait.
     * @param int $stream_id The stream ID associated with the padding.
     * @param int $pad_length The length of the padding (default: 0).
     */
    public function __construct($stream_id, $pad_length = 0)
    {
        $this->pad_length = $pad_length;
    }
    /**
     * Serializes padding data into binary format. When the PADDED
     * flag is set, this emits a single byte giving the pad length.
     * When not set, it returns an empty string.
     *
     * @return string either a 1-byte pad length prefix or the empty
     *      string depending on whether PADDED is set
     */
    public function serializePaddingData()
    {
        if (in_array('PADDED', $this->flags)) {
            return pack('C', $this->pad_length);
        }
        return '';
    }
    /**
     * Parses padding data from binary format. When the PADDED flag
     * is set, reads the first byte of $data as the pad length.
     *
     * @param string $data binary payload whose first byte is the
     *      pad length when PADDED is set
     * @return int number of bytes consumed from the front of $data
     *      (1 if PADDED is set, 0 otherwise)
     */
    public function parsePaddingData($data)
    {
        if (in_array('PADDED', $this->flags->getFlags())) {
            if (strlen($data) < 1) {
                throw new InvalidFrameError("Invalid Padding data");
            }
            $this->pad_length = unpack('C', $data[0])[1];
            $data = substr($data, 1); // Remove the parsed byte from data
            return 1;
        }
        return 0;
    }
}
/*
 * Handles HPack compression for HTTP/2, utilizing static and dynamic
 * tables with Huffman encoding. Supports encoding and decoding.
 */
class HPack
{
    private const STATIC_TABLE = [
        1  => [':authority', ''],
        2  => [':method', 'GET'],
        3  => [':method', 'POST'],
        4  => [':path', '/'],
        5  => [':path', '/index.html'],
        6  => [':scheme', 'http'],
        7  => [':scheme', 'https'],
        8  => [':status', '200'],
        9  => [':status', '204'],
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
     * List of header names that have been encoded as
     * "Literal Never Indexed" and so must not be added to the
     * dynamic table by intermediaries (RFC 7541 sec 6.2.3).
     * @var array
     */
    private $never_index_list = [];
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
            Shift existing dynamic entries up by one. Walk from
            highest to lowest so a copy at index N+1 doesn't
            clobber the value we still need at index N.
         */
        for ($i = count($this->headers_table) - 1; $i > $static_table_len;
                $i--) {
            $this->headers_table[$i + 1] = $this->headers_table[$i];
        }
        $this->headers_table[$static_table_len + 1] = [$name, $value];
        $this->current_table_size += $entry_size;
    }
    /**
     * Decodes a header block fragment from hex.
     * @param string $hex_input Hexadecimal input to decode.
     */
    public function decodeHeaderBlockFragment($hex_input)
    {
        $offset = 0;
        $headers = [];
        $input_length = strlen($hex_input);
        if ($input_length <= 0) return null;
        while ($offset < $input_length) {
            $first_byte = hexdec(substr($hex_input, $offset, 2));
            if (($first_byte & 0x80) === 0x80) {
                $header = $this->decodeIndexedHeaderField(
                    substr($hex_input, $offset));
                if ($header === null) {
                    break;
                }
                $offset += $header['length'];
            } else if (($first_byte & 0xC0) === 0x40) {
                $header = $this->decodeLiteralWithIncrementalIndexing(
                    substr($hex_input, $offset));
                $offset += $header['length'];
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
                [, $offset] = $this->decodeInteger($hex_input, $offset, 5);
                $header = ['decoded' => [], 'length' => 0];
                continue;
            } else if (($first_byte & 0xF0) === 0x10) {
                $header = $this->decodeLiteralNeverIndexed(
                    substr($hex_input, $offset));
                $offset += $header['length'];
            } else if (($first_byte & 0xF0) === 0x00) {
                $header = $this->decodeLiteralWithoutIndexing(
                    substr($hex_input, $offset));
                $offset += $header['length'];
            } else {
                $header = null;
                return null;
            }
            if ($header) {
                $headers[] = $header['decoded'];
            }
        }
        return empty($headers) ? null : $headers;
    }
    /**
     * Decodes indexed header field from hex using $headers_table.
     * indexed header field => both name and value are present at index.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeIndexedHeaderField($hex_field)
    {
        if (strlen($hex_field) < 2) {
            throw new \Exception(
                "Invalid hex field: too short for an indexed header."
            );
        }
        /*
            Indexed header field: 1xxxxxxx with the index in the
            low 7 bits, multi-byte continuation if all 7 are 1s.
            RFC 7541 sec 6.1.
         */
        [$index, $new_offset] = $this->decodeInteger($hex_field, 0, 7);
        if ($index >= 1 && $index <= count($this->headers_table) - 1) {
            [$name, $value] = $this->headers_table[$index];
        } else {
            // Invalid index
            return null;
        }
        return [
            'decoded' => [$name => $value],
            'encoded' => ['name' => bin2hex($name),'value' => bin2hex($value)],
            'length' => $new_offset
        ];
    }
    /**
     * Decodes a literal with incremental indexing.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeLiteralWithIncrementalIndexing($hex_field)
    {
        /*
            Literal with incremental indexing: 01xxxxxx where the
            6-bit prefix is the name index (0 = name as literal
            string, 1+ = name from headers_table). Multi-byte
            continuation if all 6 bits are 1s. RFC 7541 sec 6.2.1.
         */
        [$name_index, $offset] = $this->decodeInteger($hex_field, 0, 6);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $hex_field, $offset);
        } else {
            if ($name_index < count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception(
                    "Invalid name index: exceeds dynamic table size."
                );
            }
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $hex_field, $offset);
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
            'encoded' => [
                'name' => bin2hex($name),
                'value' => bin2hex($value)
            ],
            'length' => $offset
        ];
    }
    /**
     * Decodes a string literal at the given hex offset per RFC
     * 7541 sec 5.2: a 7-bit prefix integer length with the high
     * "Huffman" bit (0x80) on the first byte, followed by that
     * many octets of (optionally Huffman-encoded) string data.
     * Used by every literal header decoder for both name and
     * value strings.
     *
     * @param string $hex_field hex-encoded field
     * @param int $offset starting hex character offset
     * @return array [string $decoded_string, int $new_offset]
     */
    private function decodeStringLiteral($hex_field, $offset)
    {
        $first_byte = hexdec(substr($hex_field, $offset, 2));
        $use_huffman = ($first_byte & 0x80) !== 0;
        [$length, $offset] = $this->decodeInteger($hex_field, $offset, 7);
        $str_hex = substr($hex_field, $offset, $length * 2);
        $offset += $length * 2;
        $bin = hex2bin($str_hex);
        $decoded = $use_huffman ? $this->huffmanDecode($bin) : $bin;
        return [$decoded, $offset];
    }
    /**
     * Decodes a literal that will never be indexed.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeLiteralWithoutIndexing($hex_field)
    {
        /*
            Literal without indexing: 0000xxxx with a 4-bit name
            index prefix. RFC 7541 sec 6.2.2.
         */
        [$name_index, $offset] = $this->decodeInteger($hex_field, 0, 4);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $hex_field, $offset);
        } else {
            if ($name_index < count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception("Invalid name index: exceeds table size.");
            }
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $hex_field, $offset);
        return [
            'decoded' => [$name => $value],
            'encoded' => ['name' => bin2hex($name), 'value' => bin2hex($value)],
            'length' => $offset
        ];
    }
    /**
     * Decodes a literal that will never be indexed. Literal header field
     * never-indexed representation starts with the '0001' 4-bit pattern.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeLiteralNeverIndexed($hex_field)
    {
        /*
            Literal never indexed: 0001xxxx with a 4-bit name
            index prefix. Caches name in never_index_list so it
            won't be inserted into the dynamic table on later
            sees. RFC 7541 sec 6.2.3.
         */
        [$name_index, $offset] = $this->decodeInteger($hex_field, 0, 4);
        if ($name_index === 0) {
            [$name, $offset] = $this->decodeStringLiteral(
                $hex_field, $offset);
        } else {
            if ($name_index < count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception("Invalid name index: exceeds table size.");
            }
        }
        [$value, $offset] = $this->decodeStringLiteral(
            $hex_field, $offset);
        $this->never_index_list[] = $name;
        return [
            'decoded' => [$name => $value],
            'encoded' => [
                'name' => bin2hex($name),
                'value' => bin2hex($value)
            ],
            'length' => $offset
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
     * Decodes an integer per RFC 7541 sec 5.1 from a hex-encoded
     * field starting at $offset. The first byte's low $prefix_bits
     * carry the integer (or signal continuation when all set).
     * Returns [value, new_offset] where new_offset is the hex
     * offset just past the decoded integer.
     *
     * @param string $hex_field hex-encoded field
     * @param int $offset starting hex character offset
     * @param int $prefix_bits prefix width in bits (1-8)
     * @return array [int $value, int $new_offset]
     */
    private function decodeInteger($hex_field, $offset, $prefix_bits)
    {
        $max_prefix = (1 << $prefix_bits) - 1;
        $first_byte = hexdec(substr($hex_field, $offset, 2));
        $offset += 2;
        $value = $first_byte & $max_prefix;
        if ($value < $max_prefix) {
            return [$value, $offset];
        }
        $shift = 0;
        $hex_len = strlen($hex_field);
        while ($offset < $hex_len) {
            $byte = hexdec(substr($hex_field, $offset, 2));
            $offset += 2;
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
        $h = 1;
        foreach ($headers as [$name, $value]) {
            $name = (string) $name;
            $value = (string) $value;
            $encoded_header = '';
            $is_indexed = false;
            $name_only_match = false;
            $matched_index = null;
            $h++;
            if (in_array($name, $this->never_index_list)) {
                $encoded_header .= chr(0x10);
                $encoded_header .= $this->encodeString($name);
                $encoded_header .= $this->encodeString($value);
                $encoded .= $encoded_header;
                continue;
            }
            foreach ($this->headers_table as $i =>
                    [$header_name, $header_value]) {
                if ($header_name === $name && $header_value === $value) {
                    /*
                        Indexed header field: 1xxxxxxx with the
                        index in the low 7 bits, multi-byte if
                        the index is >= 127. RFC 7541 sec 6.1.
                     */
                    $int_bytes = $this->encodeInteger($i, 7);
                    $first = ord($int_bytes[0]) | 0x80;
                    $encoded_header .= chr($first)
                        . substr($int_bytes, 1);
                    $is_indexed = true;
                    break;
                } elseif ($header_name === $name) {
                    $name_only_match = true;
                    $matched_index = $i;
                }
            }
            if (!$is_indexed && $name_only_match) {
                /*
                    Literal with incremental indexing, indexed
                    name: 01xxxxxx with the name index in the low
                    6 bits, multi-byte if >= 63. RFC 7541 sec
                    6.2.1. Per spec, the receiver appends a new
                    dynamic-table entry for this header, so we
                    must add it on our side too or our encoder's
                    view of the dynamic table will diverge from
                    the decoder's.
                 */
                $int_bytes = $this->encodeInteger($matched_index, 6);
                $first = ord($int_bytes[0]) | 0x40;
                $encoded_header .= chr($first)
                    . substr($int_bytes, 1);
                $encoded_header .= $this->encodeString($value);
                $this->addHeader($name, $value);
            }
            elseif (!$is_indexed && !$name_only_match) {
                /*
                    Literal with incremental indexing, new name:
                    01000000 plus literal name plus literal value.
                    Same dynamic-table sync requirement as above.
                 */
                $encoded_header .= chr(0x40);
                $encoded_header .= $this->encodeString($name);
                $encoded_header .= $this->encodeString($value);
                $this->addHeader($name, $value);
            }
            $encoded .= $encoded_header;
        }
        return $encoded;
    }
    /**
     * Encodes a given string using Huffman Encoding if it provides compression.
     * If Huffman encoding is more efficient, the encoded string is returned;
     * otherwise, the original string is returned in hexadecimal format.
     * @param string $str The input string to encode.
     */
    private function encodeString($str)
    {
        $huffman = $this->huffmanEncode($str);
        if (strlen($huffman) < strlen($str)) {
            /*
                Length is a 7-bit prefix integer with the high
                "Huffman" bit (0x80) set. Multi-byte if length
                >= 127. RFC 7541 sec 5.2.
             */
            $int_bytes = $this->encodeInteger(strlen($huffman), 7);
            $first = ord($int_bytes[0]) | 0x80;
            return chr($first) . substr($int_bytes, 1) . $huffman;
        } else {
            $int_bytes = $this->encodeInteger(strlen($str), 7);
            return $int_bytes . $str;
        }
    }
    /**
     * Inverse of HUFFMAN_LOOKUP: maps each ASCII byte to its
     * Huffman bit string. Lazily built from HUFFMAN_LOOKUP on
     * first use to avoid maintaining a second hand-written table.
     * @var array<int,string>
     */
    private static $HUFFMAN_BITS = [];
    /**
     * Encodes an ASCII string with HPACK Huffman coding (RFC 7541
     * sec 5.2). Pads incomplete final byte with 1-bits from the
     * EOS symbol (all-ones).
     *
     * @param string $input ASCII string to encode
     * @return string binary Huffman-encoded byte string
     */
    public function huffmanEncode($input)
    {
        if (empty(self::$HUFFMAN_BITS)) {
            foreach (self::$HUFFMAN_LOOKUP as $bits => $ascii) {
                self::$HUFFMAN_BITS[$ascii] = (string) $bits;
            }
        }
        $encoded = '';
        $len = strlen($input);
        for ($i = 0; $i < $len; $i++) {
            $ascii = ord($input[$i]);
            if (!isset(self::$HUFFMAN_BITS[$ascii])) {
                throw new \Exception(
                    "Character not in Huffman table: " . $input[$i]);
            }
            $encoded .= self::$HUFFMAN_BITS[$ascii];
        }
        $bit_len = strlen($encoded);
        $remainder = $bit_len & 7;
        if ($remainder !== 0) {
            $encoded .= str_repeat('1', 8 - $remainder);
        }
        $output = '';
        foreach (str_split($encoded, 8) as $byte) {
            $output .= chr(bindec($byte));
        }
        return $output;
    }
    /**
     * Decodes a Huffman-encoded byte string into ASCII (RFC 7541
     * sec 5.2). Walks bits one at a time, looking up the bit
     * buffer in the prefix-free code table.
     *
     * @param string $input binary Huffman-encoded byte string
     * @return string decoded ASCII string
     */
    public function huffmanDecode($input)
    {
        $decoded = '';
        $buffer = '';
        $length = strlen($input);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($input[$i]);
            for ($bit = 7; $bit >= 0; $bit--) {
                $buffer .= (($byte >> $bit) & 1) ? '1' : '0';
                if (isset(self::$HUFFMAN_LOOKUP[$buffer])) {
                    $decoded .= chr(self::$HUFFMAN_LOOKUP[$buffer]);
                    $buffer = '';
                }
            }
        }
        return $decoded;
    }
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
