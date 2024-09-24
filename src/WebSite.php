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

require 'Frame.php';

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
        if (isset($_SERVER['HTTP_UPGRADE']) && $_SERVER['HTTP_UPGRADE'] === 'HTTP/2') {
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
     * Sends an HTTP cookie header as part of the HTTP response. If this method
     * is run from a non-CLI context then this function defaults to PHP's
     * built-in function setcookie();
     *
     * Cookies returned from a parituclar client will appear in the $_COOKIE
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
    public function setCookie($name, $value = "", $expire = 0, $path = "", $domain = "", $secure = false, $httponly = false)
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
                "local_cert" => "../cert.pem'", 
                "local_pk" => "../key.pem'", 
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
        stream_set_blocking($server, 0);
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
            $num_selected = stream_select($in_streams_with_data, $out_streams_with_data, $excepts, $timeout, $micro_timeout);
         
            $this->processTimers();
            if ($num_selected > 0) {
                $this->processRequestStreams($server, $in_streams_with_data);
                $this->processResponseStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
        if ($this->restart && !empty($_SERVER['SCRIPT_NAME'])) {
            $session_path = substr($this->restart, strlen('restart') + 1);
            $php = (!empty($_ENV['HHVM'])) ? "hhvm" : "php";
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
    public function processInternalRequest($url, $include_headers = false, $post_data = null)
    {
        static $request_context = [];
        if (count($request_context) > 5) {
            return "INTERNAL REQUEST FAILED DUE TO RECURSION";
        }
        $url_parts = parse_url($url);
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
     * from the event loop in @see listen and checks to see if any callbacks
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
     * request data is processed as it comes in. Once the request is complete,
     * superglobals are set up and process() is used route the request which
     * is output buffered. When this is complete, an output stream is
     * instantiated to send this data asynchronously back to the browser.
     *
     * @param resource $server socket server used to listen for incoming
     *  connections
     * @param array $in_streams_with_data streams with request data to be
     *  processed.
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
            if (!empty($this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'])){
                continue;
            }
            if (!$too_long) {
                stream_set_blocking($in_stream, false);
                $data = stream_get_contents($in_stream, min(
                    $this->default_server_globals['MAX_IO_LEN'],
                    $max_len - $len));

            } else {
                $data = "";
                $this->initializeBadRequestResponse($key);
            }
            if (isset($this->in_streams[self::CONTEXT][$key]['CLIENT_HTTP']) && $this->in_streams[self::CONTEXT][$key]['CLIENT_HTTP'] == "HTTP/2.0") {
                if($too_long || $this->parseH2Request($key, $data)) {
                    if (!empty($this->in_streams[self::CONTEXT][$key]['PRE_BAD_RESPONSE'])) {
                        $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'] = true;
                    }
                    if (empty($this->out_streams[self::CONNECTION][$key])) {
                        $this->out_streams[self::CONNECTION][$key] = $in_stream;
                        $this->out_streams[self::DATA][$key] = $out_data;
                        $this->out_streams[self::CONTEXT][$key] = $_SERVER;
                        $this->out_streams[self::MODIFIED_TIME][$key] = time();
                    }
                }
            } else {
                if ($too_long || $this->parseRequest($key, $data)) {
                    if (!empty($this->in_streams[self::CONTEXT][$key]['PRE_BAD_RESPONSE'])) {
                        $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'] = true;
                    }
                    $out_data = $this->getResponseData();
                    if (empty($this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'])) {
                        $this->initRequestStream($key);
                    }
                    if (empty($this->out_streams[self::CONNECTION][$key])) {
                        $this->out_streams[self::CONNECTION][$key] = $in_stream;
                        $this->out_streams[self::DATA][$key] = $out_data;
                        $this->out_streams[self::CONTEXT][$key] = $_SERVER;
                        $this->out_streams[self::MODIFIED_TIME][$key] = time();
                    }
                }
            }
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
        }
    }
    /**
     * Used to process any timers for WebSite and
     * used to check if the server has detected a
     * new connection. In which case, a read stream is set-up.
     *
     * @param resource $server Socket server used to listen for incoming connections.
     */
    protected function processServerRequest($server)
{
    if ($this->timer_alarms->isEmpty()) {
        $timeout = ini_get("default_socket_timeout");
    } else {
        $next_alarm = $this->timer_alarms->top();
        $timeout = max(min($next_alarm[0] - microtime(true), ini_get("default_socket_timeout")), 0);
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

    $stream_start = stream_socket_recvfrom($connection, 512, STREAM_PEEK);
    $additional_context = !empty($stream_start)
        ? $this->checkHttpType($stream_start)
        : ["CLIENT_HTTP" => "unknown"];

    if ($this->is_secure && $additional_context["CLIENT_HTTP"] !== "h2c") {
        stream_set_blocking($connection, true);
        if (!@stream_socket_enable_crypto($connection, true, STREAM_CRYPTO_METHOD_TLS_SERVER)) {
            $sslError = error_get_last();
            echo "\n\nSSL Error: " . $sslError['message'] . "\nL1387\n\n";
            return;
        }
        set_error_handler(null);
        $custom_error_handler = $this->default_server_globals["CUSTOM_ERROR_HANDLER"] ?? null;
        set_error_handler($custom_error_handler);
        stream_set_blocking($connection, false);
    }

    $key = (int) $connection;
    $this->in_streams[self::CONNECTION][$key] = $connection;

    if ($additional_context["CLIENT_HTTP"] == "unknown") {
        $stream_start = fread($connection, 1024);
        $additional_context = $this->checkHttpType($stream_start);
    }

    if ($additional_context["CLIENT_HTTP"] == "HTTP/2.0") {
        $this->parseH2InitRequest($connection);
    } else if ($additional_context["CLIENT_HTTP"] == "h2c") {
        $this->parseH2CInitRequest($connection);
    } else {
        $this->initRequestStream($key, $additional_context);
    }
}

    /**
     * Tries to determine from a connection (as it just starts, provided it
     * is TLS ClientHello message) whether ALPN extension indicate the
     * client is trying to use HTTP/2 or HTTP/3
     *
     * @param resource $connection a client connection that is just being
     *   initialized before stream_socket_enable_crypto has been called
     */
    function checkHttpType($stream_start)
    {

        $s ="from request data";
        $context = ["CLIENT_HTTP" => "HTTP/2.0"];
        if (preg_match("/HTTP\/([23])\.0/", $stream_start, $matches)) {
            if(!empty($matches[0])) {
                $context["CLIENT_HTTP"] = "h2c";
            }
        }
        if (preg_match("/^((GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP\/1\.1)/", $stream_start, $matches)) {
            $context["CLIENT_HTTP"] = "HTTP/1.1";
            // $s = "from request data";
        }
        echo "HTTP version {$context['CLIENT_HTTP']} $s\n";
        return $context;
    }

    /**
     */
    protected function parseH2InitRequest($connection)
    {
        $data = "";
        $i = 5;
        while ($i > 0) {
            $data .= fread($connection, 1024);
            $i = $i - 1;
        }
        $magic_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        $magicStrLen = strlen($magic_string);
        $rawRcvdFrames = substr($data, $magicStrLen);
        $rawSettingsHeader = substr($rawRcvdFrames, 0, 9);
    
        list($settingsHeader, $length) = SettingsFrame::parseFrameHeader($rawSettingsHeader);
        $settingsFrmData = substr($rawRcvdFrames, 9, $length);
    
        // Save settings
        try {
            $initialSettingsFrm = new SettingsFrame(0, []);
            $initialSettingsFrm->parse_body($settingsFrmData);
        } catch (Exception $e) {
            echo "Exception in creating connection preface settings frame: " . $e->getMessage();
            echo "Exception in parsing body of the received initial settings frame: " . $e->getMessage();
        }
    
        // Send initial settings frame
        try {
            $out_data = $initialSettingsFrm->serialize();
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Exception in encoding and sending connection preface settings frame: " . $e->getMessage();
        }
    
        // Receive Window Update
        $rcvdWinUpdate = substr($rawRcvdFrames, 9 + $length, 13);
    
        // Send ACK
        try {
            $frame = new SettingsFrame(0, []);
            $frame->flags->add('ACK');
            $out_data = $frame->serialize();
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Caught exception: " . $e->getMessage();
        }
    
        // Receive Header frame - GET request
        $rawHeaderFrame = substr($rawRcvdFrames, 9 + $length + 13);
        list($headerFrame, $length) = HeaderFrame::parseFrameHeader(substr($rawHeaderFrame, 0, 9));
        $headerFrame_data = substr($rawHeaderFrame, 9, $length);
    
        $url = $headerFrame->parseBody($headerFrame_data);
    
        // Get Response
        $_SESSION = [];
        $response = $this->processInternalRequest($url);
        // Create response frames
        if (strlen($response) != 0 && $response != "INTERNAL REQUEST FAILED DUE TO RECURSION") {
            $messageHeaders = [
                [":status", "200"],
                ["content-type", "text/html; charset=utf-8"],
                ["content-length", strlen($response)]
            ];
            $responseHeader = new HeaderFrame($headerFrame->stream_id, $messageHeaders, []);
            $responseHeader->flags->add("END_HEADERS");
            $responseHeaderSerialized = $responseHeader->serialize();
    
            $responseDataFrame = new DataFrame($headerFrame->stream_id, $response, []);
            $responseDataFrame->flags->add("END_STREAM");
            $responseDataFrameSerialized = $responseDataFrame->serialize();
    
            $out_data = $responseHeaderSerialized . $responseDataFrameSerialized;
        } else {
            $messageHeaders = [[":status", "404"]];
            $responseHeader = new HeaderFrame($headerFrame->stream_id, $messageHeaders, []);
            $responseHeader->flags->add("END_HEADERS");
            $responseHeader->flags->add("END_STREAM");
            $out_data = $responseHeader->serialize();
        }

        // Send Response
        try {
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Caught exception: " . $e->getMessage();
        }
    }
    
    /**
     */
    protected function parseH2CInitRequest($connection)
    {
        // Parse the settings frame received from client
        $data = stream_socket_recvfrom($connection, 256);
    
        $magic_string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        $magicStrLen = strlen($magic_string);
        $rawRcvdFrames = substr($data, $magicStrLen);
        $rawSettingsHeader = substr($rawRcvdFrames, 0, 9);
    
        list($settingsHeader, $length) = SettingsFrame::parseFrameHeader($rawSettingsHeader);
        $settingsFrmData = substr($rawRcvdFrames, 9, $length);
    
        // Save settings
        try {
            $initialSettingsFrm = new SettingsFrame(0, []);
            $initialSettingsFrm->parse_body($settingsFrmData);
        } catch (Exception $e) {
            echo "Exception in creating connection preface settings frame: " . $e->getMessage();
            echo "Exception in parsing body of the received initial settings frame: " . $e->getMessage();
        }
    
        // Send initial settings frame
        try {
            $out_data = $initialSettingsFrm->serialize();
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Exception in encoding and sending connection preface settings frame: " . $e->getMessage();
        }
    
        // Receive Window Update
        $rcvdWinUpdate = substr($rawRcvdFrames, 9 + $length, 13);
    
        // Send ACK
        try {
            $frame = new SettingsFrame(0, []);
            $frame->flags->add('ACK');
            $out_data = $frame->serialize();
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Caught exception: " . $e->getMessage();
        }
    
        // Receive Header frame - GET request
        $rawHeaderFrame = substr($rawRcvdFrames, 9 + $length + 13);
        list($headerFrame, $length) = HeaderFrame::parseFrameHeader(substr($rawHeaderFrame, 0, 9));
        $headerFrame_data = substr($rawHeaderFrame, 9, $length);
    
        $url = $headerFrame->parseBody($headerFrame_data);
    
        // Get Response
        $_SESSION = [];
        $response = $this->processInternalRequest($url);
        // Create response frames
        if (strlen($response) != 0 && $response != "INTERNAL REQUEST FAILED DUE TO RECURSION") {
            $messageHeaders = [
                [":status", "200"],
                ["content-type", "text/html; charset=utf-8"],
                ["content-length", strlen($response)]
            ];
            $responseHeader = new HeaderFrame($headerFrame->stream_id, $messageHeaders, []);
            $responseHeader->flags->add("END_HEADERS");
            $responseHeaderSerialized = $responseHeader->serialize();
    
            $responseDataFrame = new DataFrame($headerFrame->stream_id, $response, []);
            $responseDataFrame->flags->add("END_STREAM");
            $responseDataFrameSerialized = $responseDataFrame->serialize();
    
            $out_data = $responseHeaderSerialized . $responseDataFrameSerialized;
        } else {
            $messageHeaders = [[":status", "404"]];
            $responseHeader = new HeaderFrame($headerFrame->stream_id, $messageHeaders, []);
            $responseHeader->flags->add("END_HEADERS");
            $responseHeader->flags->add("END_STREAM");
            $out_data = $responseHeader->serialize();
        }
    
        // Send Response
        try {
            @fwrite($connection, $out_data);
        } catch (Exception $e) {
            echo "Caught exception: " . $e->getMessage();
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
        $remote_col = strrpos($remote_name, ":");
        $server_name = stream_socket_get_name($connection, false);
        $server_col = strrpos($server_name, ":");
        $this->in_streams[self::CONTEXT][$key] = [
            self::REQUEST_HEAD => false,
            'REQUEST_METHOD' => false,
            "REMOTE_ADDR" => substr($remote_name, 0, $remote_col),
            "REMOTE_PORT" => substr($remote_name, $remote_col + 1),
            "REQUEST_TIME" => time(),
            "REQUEST_TIME_FLOAT" => microtime(true),
            "SERVER_ADDR" => substr($server_name, 0, $server_col),
            "SERVER_PORT" => substr($server_name, $server_col + 1),
        ];
        if (empty($additional_context)) {
            $this->in_streams[self::CONTEXT][$key] = array_merge(
                $this->in_streams[self::CONTEXT][$key], 
                ["CLIENT_HTTP" => "unknown"]
            );
        }
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
                $this->out_streams[self::DATA][$key] = substr($data, $num_bytes);
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