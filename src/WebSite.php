<?php
/**
 * seekquarry\yioop\Website --
 * a small web server and web routing engine
 *
 * Copyright (C) 2018-2020  Chris Pollett chris@pollett.org
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
 * @copyright 2018-2024
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
        "PUT" => [], "TRACE" => []];
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
     * Whether https is being used
     * @var bool
     */
    protected $is_secure = false;
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
     * Magic method __call is called whenever an unknown method is called
     * for this class. In this case, we check if the method name corresponds
     * to a lower case HTTP command. In which case, we check that the arguments
     * are a two element array with a route and a callback function and add
     * the appropriate route to a routing table.
     *
     * @param string $method HTTP command to add $route_callack for in routing
     *      table
     * @param array $route_callback a two element array consisting of a routing
     *      pattern and a callback function.
     *      In the route pattern
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *      The second element of the $route_callback should be a callable
     *      function to be called in the event that the route pattern is matched
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
     * Adds a new HTTP header to the list of header that will be sent with
     * HTTP response. If the value of $header begins with HTTP/ then it
     * is assumed that $header is the response message not a header. In this
     * case, the value of $header will become the response message, replacing
     * any existing messages if present. This function defaults to PHP's
     * built-in header() function when this script is run from a non-CLI
     * context.
     *
     * @param string $header HTTP header or message to send with HTTP response
     */
    public function header($header)
    {
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
            if ($secure && !$_SERVER['HTTPS']) {
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
     * Starts a web session. This involves sending a HTTP cookie header
     * with a unique value to identify the client. When this client returns
     * the cookie, session data is looked up. When run in CLI mode session
     * data is stored in RAM. When run under a different web server, this
     * method defaults to PHP's built-in function session_start().
     *
     * @param array $options field that can be set are mainly related to the
     *  session cookie: 'name' (for cookie name), 'cookie_path',
     * 'cookie_lifetime' (in seconds from now), 'cookie_domain',
     * 'cookie_secure', 'cookie_httponly'
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
            $session_id = empty($_COOKIE[$cookie_name]) ? "" :
                 $_COOKIE[$cookie_name];
            $time = time();
            $lifetime = intval($options['cookie_lifetime']);
            $expires = max($time + $lifetime, 0);
            if ($lifetime <= 0) {
                $lifetime = $time;
            }
            if (empty($session_id)) {
                $session_id = md5($cookie_name . microtime(true) .
                    $this->default_server_globals['SERVER_SOFTWARE'] .
                    $_SERVER['REMOTE_ADDR']);
                $this->sessions[$session_id] = ['DATA' => []];
                array_unshift($this->session_queue, $session_id);
                $_SESSION = [];
            } else {
                if (empty($this->sessions[$session_id])) {
                    $this->sessions[$session_id] = ['DATA' => []];
                    array_unshift($this->session_queue, $session_id);
                }
                $_SESSION = $this->sessions[$session_id]['DATA'];
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
                    if ($item_time + $lifetime < $time) {
                        unset($this->session_queue[$i]);
                        unset($this->sessions[$delete_id]);
                    }
                }
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
    function mimeType($file_name, $use_extension = false)
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
     * @return int an id for the timer that can be used to turn it off (@see
     *      clearTimer())
     */
    public function setTimer($time, callable $callback, $repeating = true)
    {
        if (!$this->isCli()) {
            throw new \Exception("Atto WebSite Timers require CLI execution");
        }
        $next_time = microtime(true) + $time;
        $this->timers[$next_time] = [$repeating, $time, $callback];
        $this->timer_alarms->insert([$next_time, $next_time]);
        return $next_time;
    }
    /**
     * Deletes a timer for the list of active timers. (@see setTimer)
     *
     * @param int $timer_id the id of the timer to remove
     */
    public function clearTimer($timer_id)
    {
        unset($this->timers[$timer_id]);
    }
    /**
     * Starts an Atto Web Server listening at $address using the configuration
     * values provided. It also has this server's event loop. As web requests
     * come in $this->process is called to handle them. This input and output
     * tcp streams used by this method are non-blocking. Detecting traffic is
     * done using stream_select().  This maps to Unix-select calls, which
     * seemed to be the most cross-platform compatible way to do things.
     * Streaming methods could be easily re-written to support libevent
     * (doesn't work yet PHP7) or more modern event library
     *
     * @param int $address address and port to listen for web requests on
     * @param mixed $config_array_or_ini_filename either an associative
     *      array of configuration parameters or the filename of a .ini
     *      with such parameters. Things that can be set are mainly fields
     *      that might typically show up in the $_SERVER superglobal.
     *      See the $default_server_globals variable below for some of them.
     *      The SERVER_CONTENT field can be set to an array of stream
     *      context field values and these can be used to configure
     *      the server to handle SSL/TLS (one of the examples in the examples
     *      folder.)
     */
    public function listen($address, $config_array_or_ini_filename = false)
    {
        $path = (!empty($_SERVER['PATH'])) ? $_SERVER['PATH'] :
            ((!empty($_SERVER['Path'])) ? $_SERVER['Path'] : ".");
        $default_server_globals = ["CONNECTION_TIMEOUT" => 20,
            "CULL_OLD_SESSION_NUM" => 5, "CUSTOM_ERROR_HANDLER" => null,
            "DOCUMENT_ROOT" => getcwd(),
            "GATEWAY_INTERFACE" => "CGI/1.1",  "MAX_CACHE_FILESIZE" => 2000000,
            "MAX_CACHE_FILES" => 250,  "MAX_IO_LEN" => 128 * 1024,
            "MAX_REQUEST_LEN" => 10000000, "PATH" => $path,  "PHP_PATH" => "",
            "SERVER_ADMIN" => "you@example.com", "SERVER_NAME" => "localhost",
            "SERVER_SIGNATURE" => "",
            "USER" => empty($_SERVER['USER']) ? "" : $_SERVER['USER'],
            "SERVER_SOFTWARE" => "ATTO WEBSITE SERVER",
        ];
        $original_address = $address;
        if ($address >= 0 && $address < 65535) {
            /*
             both work on windows, but localhost doesn't give windows defender
             warning
            */
            $localhost = strstr(PHP_OS, "WIN") ? "localhost" : "0.0.0.0";
            // 0 binds to any incoming ipv4 address
            $port = $address;
            $address = "tcp://$localhost:$address";
            $server_globals = ["SERVER_NAME" => "localhost",
                "SERVER_PORT" => $port];
        } else {
            $server_globals = ['SERVER_NAME' => substr($address, 0,
                strrpos($address, ":")),
                'SERVER_PORT' => substr($address, strrpos($address, ":"))];
        }
        $context = [];
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
                $context = $config_array_or_ini_filename['SERVER_CONTEXT'];
                unset($config_array_or_ini_filename['SERVER_CONTEXT']);
            }
            $server_globals = array_merge($server_globals,
                $config_array_or_ini_filename);
        } else if (is_string($config_array_or_ini_filename) &&
            file_exists($config_array_or_ini_filename)) {
            $ini_data = parse_ini_file($config_array_or_ini_filename);
            if (!empty($ini_data['SERVER_CONTEXT'])) {
                $context = $ini_data['SERVER_CONTEXT'];
                unset($ini_data['SERVER_CONTEXT']);
            }
            $server_globals = array_merge($server_globals, $ini_data);
        }
        foreach ($default_server_globals as $server_global =>
            $server_value) {
            if (!empty($context[$server_global])) {
                $server_globals[$server_global] =
                    $context[$server_global];
                unset($context[$server_global]);
            }
        }
        if (!empty($context['ssl'])) {
            $this->is_secure = true;
        } else if(!empty($_SERVER['HTTPS'])) {
            $this->is_secure = true;
            $context['ssl'] = [
                "local_cert" => "server.crt",
                "local_pk" => "server.key",
                "verify_peer" => false,
                "verify_peer_name" => false,
                "allow_self_signed" => true,
                "alpn_protocols" => "h2,http/1.1"
            ];
        }
        /* Raise the default queue size for connections from 5 to 200.
           Depending on OS, this might help server handle more incoming
           request at a time.
         */
        $context["socket"]["backlog"] = empty($context["socket"]["backlog"]) ?
            200 : $context["socket"]["backlog"];
        $server_context = stream_context_create($context);
        $server = stream_socket_server($address, $errno, $errstr,
            STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $server_context);
        if (!$server) {
            echo "Failed to bind address $address\nServer Stopping\n";
            exit();
        }
        stream_set_blocking($server, false);
        $this->default_server_globals = array_merge($_SERVER,
            $default_server_globals, $server_globals);
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
        $this->immortal_stream_keys[] = (int)$server;
        $this->in_streams = [self::CONNECTION => [(int)$server => $server],
            self::DATA => [""]];
        $this->out_streams = [self::CONNECTION => [], self::DATA => []];
        $excepts = null;
        echo "SERVER listening at $address\n";
        $num_selected = 1;
        while (!$this->stop || $num_selected > 0) {
            if ($this->stop) {
                $in_streams_with_data = $this->in_streams[self::CONNECTION];
                unset($in_streams_with_data[(int)$server]);
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
                $this->processRequestStreams($server, $in_streams_with_data);
                $this->processResponseStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
        if ($this->restart && !empty($_SERVER['SCRIPT_NAME'])) {
            $session_path = substr($this->restart, strlen('restart') + 1);
            $php_path = $this->default_server_globals["PHP_PATH"] ?? "";
            $php = (empty($_ENV['HHVM'])) ? "$php_path/php" : "$php_path/hhvm";
            $script = "$php " . $_SERVER['SCRIPT_NAME'] .
                " " . $original_address . " 2 \"$session_path\"";
            if (strstr(PHP_OS, "WIN")) {
                $script = str_replace("/", "\\", $script);
            }
            foreach ($this->in_streams[self::CONNECTION] as $key => $stream) {
                if (!empty($stream)) {
                    @stream_socket_shutdown($stream, STREAM_SHUT_RDWR);
                }
            }
            fclose($server);
            if (strstr(PHP_OS, "WIN")) {
                $job = "start $script ";
            } else {
                $job = "$script < /dev/null > /dev/null &";
            }
            pclose(popen($job, "r"));
        }
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
     * Checks if a portion of a request uri path matches a Atto server route.
     *
     * @param string $request_path part of a path portion of a request uri
     * @param string $route a route that might be handled by Atto Server
     * @return bool whether the requested path matches the given route.
     */
    protected function checkMatch($request_path, $route)
    {
        $add_vars = [];
        $matches = false;
        $magic_string = "PDTSTRTP";
        if (preg_match_all('/\*|\{[a-zA-Z][a-zA-Z0-9_]*\}/', $route,
            $matches) > 0) {
            $route_regex = preg_replace('/\*|\{[a-zA-Z][a-zA-Z0-9_]*\}/',
                $magic_string, $route);
            $route_regex = preg_quote($route_regex, "/");
            $route_regex = str_replace($magic_string, "(.*)", $route_regex);
            if (preg_match_all("/$route_regex/", $request_path,
                $request_matches) > 0) {
                $num_matches = count($matches[0]);
                array_shift($request_matches);
                for ($i = 0; $i < $num_matches; $i++) {
                    $match_var = trim($matches[0][$i], "{}");
                    if ($match_var != "*") {
                        $add_vars[$match_var] = $request_matches[$i][0];
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
            if (!empty($this->timers["{$top[1]}"])) {
                list($repeating, $time, $callback) = $this->timers["{$top[1]}"];
                $callback();
                if ($repeating) {
                    $next_time = $now + $time;
                    $this->timer_alarms->insert([$next_time, $top[1]]);
                }
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
            if ($in_stream == $server) {
                $this->processServerRequest($server);
                return;
            }
            $meta = stream_get_meta_data($in_stream);
            $key = (int)$in_stream;
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
            if ($is_h2) {
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
                    if (!empty($this->in_streams[self::CONTEXT][$key][
                            'PRE_BAD_RESPONSE'])) {
                        $this->in_streams[self::CONTEXT][$key][
                            'BAD_RESPONSE'] = true;
                    }
                    $out_data = $this->getResponseData();
                    if (empty($this->in_streams[self::CONTEXT][$key][
                            'BAD_RESPONSE'])) {
                        $this->initRequestStream($key);
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
     * Accepts a new incoming connection from the server socket and
     * determines the HTTP protocol version. For TLS connections the
     * ALPN-negotiated protocol is read from the stream context after
     * the handshake. For cleartext connections the first bytes are
     * peeked. H2 and h2c connections are handed to initH2Request.
     * HTTP/1.1 and unknown connections are registered via
     * initRequestStream for the normal event loop.
     *
     * @param resource $server socket server used to listen for
     *      incoming connections
     */
    protected function processServerRequest($server)
    {
        if ($this->timer_alarms->isEmpty()) {
            $timeout = ini_get("default_socket_timeout");
        } else {
            $next_alarm = $this->timer_alarms->top();
            $timeout = max(min($next_alarm[0] - microtime(true),
                        ini_get("default_socket_timeout")), 0);
        }
        if ($this->is_secure) {
            stream_set_blocking($server, true);
        }
        $connection = stream_socket_accept($server, $timeout);
        if ($this->is_secure) {
            stream_set_blocking($server, false);
        }
        if (!$connection) {
            echo "No connection accepted or timed out.\n";
            return;
        }
        if ($this->is_secure) {
            stream_set_blocking($connection, true);
            if (!@stream_socket_enable_crypto(
                    $connection, true,
                    STREAM_CRYPTO_METHOD_TLS_SERVER)) {
                $ssl_error = error_get_last();
                echo "\n\nSSL Error: " . $ssl_error['message'];
                fclose($connection);
                return;
            }
            set_error_handler(null);
            $custom_error_handler =
                $this->default_server_globals[
                "CUSTOM_ERROR_HANDLER"] ?? null;
            set_error_handler($custom_error_handler);
            /*
                PHP does not expose the ALPN-negotiated protocol
                so after the TLS handshake we read the decrypted
                bytes while still in blocking mode. An H2 client
                always sends the 24-byte magic string as its
                first data.
             */
            $magic_len = strlen(self::H2_CLIENT_MAGIC);
            $stream_start = fread($connection, $magic_len);
            stream_set_blocking($connection, false);
            if ($stream_start === self::H2_CLIENT_MAGIC) {
                $additional_context =
                    ["CLIENT_HTTP" => "HTTP/2.0"];
            } else {
                $additional_context =
                    ["CLIENT_HTTP" => "HTTP/1.1",
                    "LEFTOVER" => $stream_start];
            }
        } else {
            /*
                Cleartext: safe to peek since there is no TLS wrapping
             */
            $stream_start = stream_socket_recvfrom($connection, 512,
                STREAM_PEEK);
            $additional_context = !empty($stream_start)
                ? $this->checkHttpType($stream_start)
                : ["CLIENT_HTTP" => "unknown"];
        }
        $key = (int) $connection;
        $this->in_streams[self::CONNECTION][$key] = $connection;
        $client_http = $additional_context["CLIENT_HTTP"];
        if ($client_http == "HTTP/2.0") {
            try {
                /*
                    TLS: magic was already consumed by fread
                    during protocol detection
                 */
                $this->initH2Request($connection, false);
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
                $this->initH2Request($connection, true);
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
                For TLS connections where the fread consumed bytes
                that turned out to be HTTP/1.1, prepopulate the
                stream data so parseRequest sees them.
             */
            if (!empty($additional_context["LEFTOVER"])) {
                $this->in_streams[self::DATA][$key] =
                    $additional_context["LEFTOVER"];
            }
        }
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
        if (!($client_settings instanceof SettingsFrame)) {
            throw new \Exception("Expected SETTINGS frame, got "
                . get_class($client_settings));
        }
        $client_settings->parseBody(
            $this->readExactly($connection, $settings_len));
        $server_settings = new SettingsFrame(0, []);
        fwrite($connection, $server_settings->serialize());
        $ack = new SettingsFrame(0, []);
        $ack->flags->add('ACK');
        fwrite($connection, $ack->serialize());
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
        $payload = $this->readExactly($connection, $payload_len);
        stream_set_blocking($connection, false);
        if ($frame instanceof GoAwayFrame) {
            $this->shutdownHttpStream($key);
            return false;
        }
        if ($frame instanceof PingFrame) {
            $pong = new PingFrame(0, $payload);
            $pong->flags->add('ACK');
            fwrite($connection, $pong->serialize());
            return false;
        }
        if ($frame instanceof SettingsFrame
            && !$frame->flags->contains('ACK')) {
            $ack = new SettingsFrame(0, []);
            $ack->flags->add('ACK');
            fwrite($connection, $ack->serialize());
            return false;
        }
        if (!($frame instanceof HeaderFrame)) {
            return false;
        }
        $hpack_decode = $this->in_streams[self::CONTEXT][$key][
            'HPACK_DECODE'] ?? new HPack();
        $hpack_encode = $this->in_streams[self::CONTEXT][$key][
            'HPACK_ENCODE'] ?? new HPack();
        $context = $frame->parseBody($payload, $hpack_decode);
        $stream_id = $frame->stream_id;
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
        $resp_data = new DataFrame($stream_id, $body);
        $resp_data->flags->add("END_STREAM");
        fwrite($connection,
            $resp_headers->serialize($hpack_encode)
            . $resp_data->serialize());
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
            $chunk = fread($connection, $remaining);
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
        $remote_col = strrpos($remote_name, ":");
        $server_name = stream_socket_get_name($connection, false);
        $server_col = strrpos($server_name, ":");
        $this->in_streams[self::CONTEXT][$key] = array_merge(
            [
                self::REQUEST_HEAD => false,
                'REQUEST_METHOD' => false,
                "CLIENT_HTTP" => "unknown",
                "REMOTE_ADDR" => substr($remote_name, 0, $remote_col),
                "REMOTE_PORT" => substr($remote_name, $remote_col + 1),
                "REQUEST_TIME" => time(),
                "REQUEST_TIME_FLOAT" => microtime(true),
                "SERVER_ADDR" => substr($server_name, 0, $server_col),
                "SERVER_PORT" => substr($server_name, $server_col + 1),
            ],
            $additional_context
        );
        $this->in_streams[self::DATA][$key] = "";
        $this->in_streams[self::MODIFIED_TIME][$key] = time();
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
                if ((!empty($context['HTTP_CONNECTION']) &&
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
        if (!empty($context['CONTENT']) &&
            !empty($context['CONTENT_TYPE']) &&
            strpos($context['CONTENT_TYPE'], "multipart/form-data") !== false) {
            preg_match('/boundary=(.*)/', $context['CONTENT_TYPE'], $matches);
            $boundary = $matches[1];
            $raw_form_parts = preg_split("/-+$boundary/", $context['CONTENT']);
            array_pop($raw_form_parts);
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
                    if(preg_match("/\s*Content-Disposition\:\s*form-data\;\s*" .
                        "name\s*=\s*[\"\'](.*)[\"\']\s*\;\s*filename=".
                        "\s*[\"\'](.*)[\"\']\s*/i", $head_part, $matches)) {
                        list(, $name, $file_name) = $matches;
                    } else if (preg_match(
                        "/\s*Content-Disposition\:\s*form-data\;\s*" .
                        "name\s*=\s*[\"\'](.*)[\"\']/i", $head_part, $matches)){
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
                $file_array = ['name' => $file_name, 'tmp_name' => $file_name,
                    'type' => $content_type, 'error' => 0, 'data' => $content,
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
                $cookie_parts = explode("=", $cookie);
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
}
/**
 * Exception generated when a running WebSite script calls webExit()
 */
class WebException extends \Exception
{
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
                    } else if ($key[0] !== ':') {
                        $context['HTTP_' . strtoupper(
                            str_replace('-', '_', $key))] = $value;
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
        $context['REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
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
     * Parses the binary data of the DATA frame and extracts the data payload.
     * @param string $data The binary data to parse.
     */
    public function parseBody($data)
    {
        $padding_data_length = $this->parsePaddingData($data);
        $this->data = substr($data, $padding_data_length,
            strlen($data) - $this->pad_length);
        $this->payload_length = strlen($data);

        if ($this->pad_length && $this->pad_length >= $this->payload_length) {
            throw new InvalidPaddingException("Padding is too long.");
        }
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
     * Maximum number of entries allowed in the dynamic table
     * before the eviction algorithm runs.
     * @var int
     */
    private $max_table_size = 100;
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
     * Evicts the first entry in the table and shifts the rest of the entries.
     * Ensures that the table maintains a size of $max_table_size.
     */
    private function evictEntry()
    {
        $static_table_len = count(self::STATIC_TABLE);
        if (count($this->headers_table) > $static_table_len) {
            foreach ($this->headers_table as $index => $header) {
                if ($index > $static_table_len + 1) {
                    $this->headers_table[$index - 1] = $header;
                }
            }
            array_pop($this->headers_table);
        }
    }
    /**
     * Adds a header to the headers_table after checking the max table size.
     *
     * @param string $name  The name of the header.
     * @param string $value The value of the header.
     */
    public function addHeader($name, $value)
    {
        $current_size = count($this->headers_table);
        while (($current_size + 1) > $this->max_table_size) {
            $this->evictEntry();
            $current_size = count($this->headers_table);
        }
        $this->headers_table[] = [$name, $value];
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
                    Bit pattern 001xxxxx. The new max size is in the
                    low 5 bits. If all 5 bits are set the size
                    continues in subsequent bytes as a multi-byte
                    integer. We parse past it but do not enforce
                    eviction beyond the existing max_table_size.
                 */
                $new_size = $first_byte & 0x1F;
                $offset += 2;
                if ($new_size == 0x1F) {
                    while ($offset < $input_length) {
                        $next_byte = hexdec(
                            substr($hex_input, $offset, 2));
                        $offset += 2;
                        if (($next_byte & 0x80) === 0) {
                            break;
                        }
                    }
                }
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
        $byte_hex = substr($hex_field, 0, 2);
        $byte = hexdec($byte_hex);
        $index = $byte & 0x7F;
        if ($index >= 1 && $index <= count($this->headers_table)) {
            [$name, $value] = $this->headers_table[$index];
        } else {
            // Invalid index
            return null;
        }
        return [
            'decoded' => [$name => $value],
            'encoded' => ['name' => bin2hex($name),'value' => bin2hex($value)],
            'length' => 2
        ];
    }
    /**
     * Decodes a literal with incremental indexing.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeLiteralWithIncrementalIndexing($hex_field)
    {
        $offset = 0;
        $first_byte_hex = substr($hex_field, $offset, 2);
        $first_byte = hexdec($first_byte_hex);
        $offset += 2;
        if (($first_byte & 0x3F) === 0x00) {
            $name_length_hex = substr($hex_field, $offset, 2);
            $name_length_byte = hexdec($name_length_hex);
            $use_huffman = ($name_length_byte & 0x80) !== 0;
            $name_length = $name_length_byte & 0x7F;
            $offset += 2;
            $name_hex = substr($hex_field, $offset, $name_length * 2);
            $offset += $name_length * 2;
            $name = $use_huffman ?
                $this->huffmanDecode(hex2bin($name_hex)) : hex2bin($name_hex);

        } else {
            $name_index = $first_byte & 0x3F;
            if ($name_index > 0 && $name_index < count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception(
                    "Invalid name index: exceeds dynamic table size."
                );
            }
        }
        $value_length_hex = substr($hex_field, $offset, 2);
        $value_length_byte = hexdec($value_length_hex);
        $use_huffman = ($value_length_byte & 0x80) !== 0;
        $value_length = $value_length_byte & 0x7F;
        $offset += 2;
        $value_hex = substr($hex_field, $offset, $value_length * 2);
        $offset += $value_length * 2;
        $value = $use_huffman ?
            $this->huffmanDecode(hex2bin($value_hex)) : hex2bin($value_hex);
        /*
            HPACK RFC 7541 section 6.2.1: incremental indexing always
            appends a new entry to the dynamic table. The name index
            only identifies which existing entry to copy the name
            from and must never be overwritten.
         */
        $this->headers_table[] = [$name, $value];
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
     * Decodes a literal that will never be indexed.
     * @param string $hex_field Hexadecimal field to decode.
     */
    public function decodeLiteralWithoutIndexing($hex_field)
    {
        $offset = 0;
        $first_byte = hexdec(substr($hex_field, $offset, 2));
        $offset += 2;
        if (($first_byte & 0x0F) === 0x00) {
            $name_length_hex = substr($hex_field, $offset, 2);
            $name_length_byte = hexdec($name_length_hex);
            $use_huffman = ($name_length_byte & 0x80) !== 0;
            $name_length = $name_length_byte & 0x7F;
            $offset += 2;
            $name_hex = substr($hex_field, $offset, $name_length * 2);
            $offset += $name_length * 2;
            $name = $use_huffman ?
                $this->huffmanDecode(hex2bin($name_hex)) : hex2bin($name_hex);
        } else {
            $name_index = $first_byte & 0x0F;

            if ($name_index > 0 && $name_index <= count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception("Invalid name index: exceeds table size.");
            }
        }
        $value_length_hex = substr($hex_field, $offset, 2);
        $value_length_byte = hexdec($value_length_hex);
        $use_huffman = ($value_length_byte & 0x80) !== 0;
        $value_length = $value_length_byte & 0x7F;
        $offset += 2;
        $value_hex = substr($hex_field, $offset, $value_length * 2);
        $offset += $value_length * 2;
        $value = $use_huffman ?
            $this->huffmanDecode(hex2bin($value_hex)) : hex2bin($value_hex);
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
        $offset = 0;
        $first_byte = hexdec(substr($hex_field, $offset, 2));
        $offset += 2;
        if (($first_byte & 0x0F) === 0x00) {
            $name_length_byte = hexdec(substr($hex_field, $offset, 2));
            $use_huffman = ($name_length_byte & 0x80) !== 0;
            $name_length = $name_length_byte & 0x7F;
            $offset += 2;
            $name_hex = substr($hex_field, $offset, $name_length * 2);
            $offset += $name_length * 2;
            $name = $use_huffman ?
                $this->huffmanDecode(hex2bin($name_hex)) : hex2bin($name_hex);
        } else {
            $name_index = $first_byte & 0x0F;
            if ($name_index > 0 && $name_index <= count($this->headers_table)) {
                $name = $this->headers_table[$name_index][0];
            } else {
                throw new \Exception("Invalid name index: exceeds table size.");
            }
        }
        $value_length_byte = hexdec(substr($hex_field, $offset, 2));
        $use_huffman = ($value_length_byte & 0x80) !== 0;
        $value_length = $value_length_byte & 0x7F;
        $offset += 2;
        $value_hex = substr($hex_field, $offset, $value_length * 2);
        $offset += $value_length * 2;
        $value = $use_huffman ?
            $this->huffmanDecode(hex2bin($value_hex)) : hex2bin($value_hex);
        $this->never_index_list[] = $name;
        return [
            'decoded' => [$name => $value],
            'encoded' => ['name' => bin2hex($name), 'value' => bin2hex($value)],
            'length' => $offset
        ];
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
                    $encoded_header .= chr(0x80 | ($i & 0x7F));
                    $is_indexed = true;
                    break;
                } elseif ($header_name === $name) {
                    $name_only_match = true;
                    $matched_index = $i;
                }
            }
            if (!$is_indexed && $name_only_match) {
                $encoded_header .= chr(0x40 | ($matched_index & 0x3F));
                $encoded_header .= $this->encodeString($value);
            }
            elseif (!$is_indexed && !$name_only_match) {
                $encoded_header .= chr(0x40);
                $encoded_header .= $this->encodeString($name);
                $encoded_header .= $this->encodeString($value);
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
            return chr(0x80 | strlen($huffman)) . $huffman;
        } else {
            return chr(strlen($str)) . $str;
        }
    }
    /**
     * Encodes an ASCII input string using HPACK Huffman encoding.
     * Looks each character up in the HUFFMAN_CODES table to get its
     * variable-length bit code, concatenates all codes into a bit
     * string, pads to a byte boundary with 1-bits (per RFC 7541
     * section 5.2), then packs the bit string into binary bytes.
     *
     * @param string $input ASCII string to encode
     * @return string binary Huffman-encoded byte string
     */
    public function huffmanEncode($input)
    {
        global $HUFFMAN_CODES;
        $encoded = '';
        foreach (str_split($input) as $char) {
            if (isset($HUFFMAN_CODES[$char])) {
                $huffman_code = $HUFFMAN_CODES[$char]['bin'];
                $encoded .= $huffman_code;
            } else {
                throw new \Exception(
                    "Character not found in Huffman table: $char");
            }
        }
        /*
            Padding is done with the MSBs of the End-Of-String
            symbol which in RFC 7541 is encoded as 11111111111111
         */
        if (strlen($encoded) % 8 !== 0) {
            $padding = 8 - (strlen($encoded) % 8);
            $encoded .= str_repeat('1', $padding);
        }
        $output = '';
        foreach (str_split($encoded, 8) as $byte) {
            $byteValue = chr(bindec($byte));
            $output .= $byteValue;
        }
        return $output;
    }
    /**
     * Decodes Huffman-encoded binary input using the HPACK Huffman
     * code table defined in $HUFFMAN_LOOKUP. Walks bits one at a time
     * from each byte using bit shifts, building up a bit-string
     * buffer that is looked up in the prefix-free code table.
     *
     * @param string $input binary Huffman-encoded byte string
     * @return string decoded ASCII string
     */
    public function huffmanDecode($input)
    {
        global $HUFFMAN_LOOKUP;
        $decoded = '';
        $buffer = '';
        $length = strlen($input);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($input[$i]);
            for ($bit = 7; $bit >= 0; $bit--) {
                $buffer .= (($byte >> $bit) & 1) ? '1' : '0';
                if (isset($HUFFMAN_LOOKUP[$buffer])) {
                    $decoded .= chr($HUFFMAN_LOOKUP[$buffer]);
                    $buffer = '';
                }
            }
        }
        return $decoded;
    }

}
$HUFFMAN_LOOKUP = [
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
    '111111111011' => 62,     '1111111100' => 63,       '1111111111010' => 64,
    '100001' => 65,           '1011101' => 66,          '1011110' => 67,
    '1011111' => 68,          '1100000' => 69,          '1100001' => 70,
    '1100010' => 71,          '1100011' => 72,          '1100100' => 73,
    '1100101' => 74,          '1100110' => 75,          '1100111' => 76,
    '1101000' => 77,          '1101001' => 78,          '1101010' => 79,
    '1101011' => 80,          '1101100' => 81,          '1101101' => 82,
    '1101110' => 83,          '1101111' => 84,          '1110000' => 85,
    '1110001' => 86,          '1110010' => 87,          '11111100' => 88,
    '1110011' => 89,          '11111101' => 90,         '1111111111011' => 91,
    '1111111111111110000' => 92, '1111111111100' => 93, '11111111111100' => 94,
    '100010' => 95,           '111111111111101' => 96,  '00011' => 97,
    '100011' => 98,           '00100' => 99,            '100100' => 100,
    '00101' => 101,           '100101' => 102,          '100110' => 103,
    '100111' => 104,          '00110' => 105,           '1110100' => 106,
    '1110101' => 107,         '101000' => 108,          '101001' => 109,
    '101010' => 110,          '00111' => 111,           '101011' => 112,
    '1110110' => 113,         '101100' => 114,          '01000' => 115,
    '01001' => 116,           '101101' => 117,          '1110111' => 118,
    '1111000' => 119,         '1111001' => 120,         '1111010' => 121,
    '1111011' => 122,         '111111111111110' => 123, '11111111100' => 124,
    '11111111111101' => 125,  '1111111111101' => 126
];
$HUFFMAN_CODES = [
    ' ' => ['ascii' => 32,  'bin' => '010100'],
    '!' => ['ascii' => 33,  'bin' => '1111111000'],
    '"' => ['ascii' => 34,  'bin' => '1111111001'],
    '#' => ['ascii' => 35,  'bin' => '111111111010'],
    '$' => ['ascii' => 36,  'bin' => '1111111111001'],
    '%' => ['ascii' => 37,  'bin' => '010101'],
    '&' => ['ascii' => 38,  'bin' => '11111000'],
    "'" => ['ascii' => 39,  'bin' => '11111111010'],
    '(' => ['ascii' => 40,  'bin' => '1111111010'],
    ')' => ['ascii' => 41,  'bin' => '1111111011'],
    '*' => ['ascii' => 42,  'bin' => '11111001'],
    '+' => ['ascii' => 43,  'bin' => '11111111011'],
    ',' => ['ascii' => 44,  'bin' => '11111010'],
    '-' => ['ascii' => 45,  'bin' => '010110'],
    '.' => ['ascii' => 46,  'bin' => '010111'],
    '/' => ['ascii' => 47,  'bin' => '011000'],
    '0' => ['ascii' => 48,  'bin' => '00000'],
    '1' => ['ascii' => 49,  'bin' => '00001'],
    '2' => ['ascii' => 50,  'bin' => '00010'],
    '3' => ['ascii' => 51,  'bin' => '011001'],
    '4' => ['ascii' => 52,  'bin' => '011010'],
    '5' => ['ascii' => 53,  'bin' => '011011'],
    '6' => ['ascii' => 54,  'bin' => '011100'],
    '7' => ['ascii' => 55,  'bin' => '011101'],
    '8' => ['ascii' => 56,  'bin' => '011110'],
    '9' => ['ascii' => 57,  'bin' => '011111'],
    ':' => ['ascii' => 58,  'bin' => '1011100'],
    ';' => ['ascii' => 59,  'bin' => '11111011'],
    '<' => ['ascii' => 60,  'bin' => '111111111111100'],
    '=' => ['ascii' => 61,  'bin' => '100000'],
    '>' => ['ascii' => 62,  'bin' => '111111111011'],
    '?' => ['ascii' => 63,  'bin' => '1111111100'],
    '@' => ['ascii' => 64,  'bin' => '1111111111010'],
    'A' => ['ascii' => 65,  'bin' => '100001'],
    'B' => ['ascii' => 66,  'bin' => '1011101'],
    'C' => ['ascii' => 67,  'bin' => '1011110'],
    'D' => ['ascii' => 68,  'bin' => '1011111'],
    'E' => ['ascii' => 69,  'bin' => '1100000'],
    'F' => ['ascii' => 70,  'bin' => '1100001'],
    'G' => ['ascii' => 71,  'bin' => '1100010'],
    'H' => ['ascii' => 72,  'bin' => '1100011'],
    'I' => ['ascii' => 73,  'bin' => '1100100'],
    'J' => ['ascii' => 74,  'bin' => '1100101'],
    'K' => ['ascii' => 75,  'bin' => '1100110'],
    'L' => ['ascii' => 76,  'bin' => '1100111'],
    'M' => ['ascii' => 77,  'bin' => '1101000'],
    'N' => ['ascii' => 78,  'bin' => '1101001'],
    'O' => ['ascii' => 79,  'bin' => '1101010'],
    'P' => ['ascii' => 80,  'bin' => '1101011'],
    'Q' => ['ascii' => 81,  'bin' => '1101100'],
    'R' => ['ascii' => 82,  'bin' => '1101101'],
    'S' => ['ascii' => 83,  'bin' => '1101110'],
    'T' => ['ascii' => 84,  'bin' => '1101111'],
    'U' => ['ascii' => 85,  'bin' => '1110000'],
    'V' => ['ascii' => 86,  'bin' => '1110001'],
    'W' => ['ascii' => 87,  'bin' => '1110010'],
    'X' => ['ascii' => 88,  'bin' => '11111100'],
    'Y' => ['ascii' => 89,  'bin' => '1110011'],
    'Z' => ['ascii' => 90,  'bin' => '11111101'],
    '[' => ['ascii' => 91,  'bin' => '1111111111011'],
    '\\' => ['ascii' => 92,  'bin' => '1111111111111110000'],
    ']' => ['ascii' => 93,  'bin' => '1111111111100'],
    '^' => ['ascii' => 94,  'bin' => '11111111111100'],
    '_' => ['ascii' => 95,  'bin' => '100010'],
    '`' => ['ascii' => 96,  'bin' => '111111111111101'],
    'a' => ['ascii' => 97,  'bin' => '00011'],
    'b' => ['ascii' => 98,  'bin' => '100011'],
    'c' => ['ascii' => 99,  'bin' => '00100'],
    'd' => ['ascii' => 100, 'bin' => '100100'],
    'e' => ['ascii' => 101, 'bin' => '00101'],
    'f' => ['ascii' => 102, 'bin' => '100101'],
    'g' => ['ascii' => 103, 'bin' => '100110'],
    'h' => ['ascii' => 104, 'bin' => '100111'],
    'i' => ['ascii' => 105, 'bin' => '00110'],
    'j' => ['ascii' => 106, 'bin' => '1110100'],
    'k' => ['ascii' => 107, 'bin' => '1110101'],
    'l' => ['ascii' => 108, 'bin' => '101000'],
    'm' => ['ascii' => 109, 'bin' => '101001'],
    'n' => ['ascii' => 110, 'bin' => '101010'],
    'o' => ['ascii' => 111, 'bin' => '00111'],
    'p' => ['ascii' => 112, 'bin' => '101011'],
    'q' => ['ascii' => 113, 'bin' => '1110110'],
    'r' => ['ascii' => 114, 'bin' => '101100'],
    's' => ['ascii' => 115, 'bin' => '01000'],
    't' => ['ascii' => 116, 'bin' => '01001'],
    'u' => ['ascii' => 117, 'bin' => '101101'],
    'v' => ['ascii' => 118, 'bin' => '1110111'],
    'w' => ['ascii' => 119, 'bin' => '1111000'],
    'x' => ['ascii' => 120, 'bin' => '1111001'],
    'y' => ['ascii' => 121, 'bin' => '1111010'],
    'z' => ['ascii' => 122, 'bin' => '1111011'],
    '{' => ['ascii' => 123, 'bin' => '111111111111110'],
    '|' => ['ascii' => 124, 'bin' => '11111111100'],
    '}' => ['ascii' => 125, 'bin' => '11111111111101'],
    '~' => ['ascii' => 126, 'bin' => '1111111111101']
];
