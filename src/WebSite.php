<?php
/**
 * seekquarry\atto\Website -- a small web server and web routing engine
 * 
 *
 * Copyright (C) 2017  Chris Pollett chris@pollett.org
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license http://www.gnu.org/licenses/ GPL3
 * @link http://www.seekquarry.com/
 * @copyright 2017
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
 */
class WebSite
{
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
    const IS_FILE = 4;
    const REQUEST_HEAD = 5;
    const LEN_LONGEST_HTTP_METHOD = 7;
    public $immortal_stream_keys = [];
    public $base_path;
    protected $default_server_globals;
    protected $routes = ["CONNECT" => [], "DELETE"  => [], "ERROR"  => [],
        "GET" => [], "HEAD" => [], "OPTIONS"  => [], "POST"  => [],
        "PUT" => [], "TRACE" => []];
    protected $session_configs = [ 'cookie_lifetime' => '0',
        'cookie_path' => '/', 'cookie_domain' => '', 'cookie_secure' => '',
        'cookie_httponly' => '', 'name' => 'PHPSESSID', 'save_path' => ''];
    protected $in_streams = [];
    protected $out_streams = [];
    protected $middle_wares = [];
    protected $request_script;
    protected $sessions = [];
    protected $session_queue = [];
    protected $timers = [];
    protected $timer_alarms;
    protected $current_session = "";
    protected $http_methods;
    protected $header_data;
    protected $content_type;
    protected $file_cache = ['MARKED' => [], 'UNMARKED' => []];
    protected $is_cli;
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
        $this->default_server_globals = [];
        $this->http_methods = array_keys($this->routes);
        if (empty($base_path)) {
            $pathinfo = pathinfo($_SERVER['SCRIPT_NAME']);
            $base_path = $pathinfo['dirname'];
            $base_path = $pathinfo["dirname"];
            if ($base_path == ".") {
                $base_path = "";
            }
        }
        $this->is_cli = (php_sapi_name() == 'cli');
        if(!empty($_SERVER['HTTPS'])) {
            $this->is_secure = true;
        }
        $this->base_path = $base_path;
        ini_set('precision', 16);
        $this->timer_alarms = new \SplMinHeap();
    }
    /**
     * Returns whether this class is being used from the command-line or in a
     * web server/cgi setting
     *
     * @return boolean whther the class is being run from the command line
     */
    public function isCli()
    {
        return $this->is_cli;
    }
    /*

        HTTP/HTTPS Routing Methods

     */
    /**
     * Sets up a callback function to be called when a HTTP CONNECT command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match CONNECT command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if CONNECT request for $route
     *      made.
     */
    public function connect($route, callable $callback)
    {
        $this->addRoute("CONNECT", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP DELETE command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match DELETE command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if DELETE request for $route
     *      made.
     */
    public function delete($route, callable $callback)
    {
        $this->addRoute("DELETE", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a ERROR command is
     * made for $route is made to this web app.
     *
     * ERROR commands is a pseudo-HTTP method event which can be generated
     * whenever a server or request error is detected. For example, if a file
     * wasn't found under some path, the handler for that path might
     * call $this->trigger('ERROR', /404); to call the handler for 404 NOT
     * FOUND events.
     *
     * @param string $route request pattern to match ERROR command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if ERROR request for $route
     *      made.
     */
    public function error($route, callable $callback)
    {
        $this->addRoute("ERROR", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP GET command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match GET command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if GET request for $route
     *      made.
     */
    public function get($route, callable $callback)
    {
        $this->addRoute("GET", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP HEAD command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match HEAD command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if HEAD request for $route
     *      made.
     */
    public function head($route, callable $callback)
    {
        $this->addRoute("HEAD", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP OPTIONS command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match OPTIONS command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if OPTIONS request for $route
     *      made.
     */
    public function options($route, callable $callback)
    {
        $this->addRoute("OPTIONS", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP POST command is
     * made for $route is made to this web app. post'd variables appear in
     * $_POST superglobal. If a file upload was being done then files uploaded
     * in the $_FILES superglobal.
     *
     * @param string $route request pattern to match OPTIONS command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if POST request for $route
     *      made.
     */
    public function post($route, callable $callback)
    {
        $this->addRoute("POST", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP PUT command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match PUT command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if PUT request for $route
     *      made.
     */
    public function put($route, callable $callback)
    {
        $this->addRoute("PUT", $route, $callback);
    }
    /**
     * Sets up a callback function to be called when a HTTP TRACE command is
     * made for $route is made to this web app.
     *
     * @param string $route request pattern to match TRACE command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_GET field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if PUT request for $route
     *      made.
     */
    public function trace($route, callable $callback)
    {
        $this->addRoute("TRACE", $route, $callback);
    }
    /**
     * Used to add all the routes and callbacks of a WebSite object to the
     * current WebSite object under paths matching $route.
     *
     * @param string $route request pattern to match
     * @param Website $subsite Website object to add sub routes from
     */
    public function subsite($route, Website $subsite)
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
            throw new \Exception("Unknown Router Method");
        } else if (!is_callable($callback)) {
            throw new \Exception("Callback not callable");
        }
        if (!isset($this->routes[$method])) {
            $this->routes[$method] = [];
        }
        $this->routes[$method][$route] = $callback;
    }
    /*
        HTTP/HTTPS Processing Methods
     */
    /**
     * Adds a middle ware callback that should be called before any processing
     * on the request is done.
     *
     * @param callable $callback function to be called before processing of
     *      request
     */
    public function use(callable $callback)
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
        if (empty($this->routes[$method])) {
            $method = "ERROR";
            $route = "/404";
        }
        $route = $this->request_script;
        if (!$this->trigger($method, $route)) {
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
     */
    public function trigger($method, $route)
    {
        if (empty($_SERVER['RECURSION'])) {
            $_SERVER['RECURSION'] = [];
        }
        if(empty($this->routes[$method])) {
            return false;
        }
        if (in_array($method . " ". $route, $_SERVER['RECURSION']) ) {
            echo "<br />\nError: Recursion detected for $method $route.\n";
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
                $callback();
                $handled = true;
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
                        (empty(header_parts[1])? "" : $header_parts[1]);
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
    public function setCookie($name, $value = "", $expire = 0, $path = "",
        $domain = "", $secure = false, $httponly = false)
    {
        if ($this->isCli()) {
            if ($secure && !$_SERVER['HTTPS']) {
                return;
            }
            $out_cookie = "Set-Cookie: $name=$value";
            if ($expire != 0) {
                $out_cookie .= "; Expires=" . gmdate("D, d M Y H:i:s", $expire) .
                    " GMT";
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
            if ($lifetime == 0) {
                $lifetime = $time;
            }
            $expires = ($lifetime > 0) ? $time + $lifetime : 0;
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
                $session_id = $this->session_queue[$i];
                if (!isset($this->sessions[$session_id])) {
                    unset($this->session_queue[$i]);
                } else {
                    $item_time = $this->sessions[$session_id]['TIME'];
                    if ($item_time + $lifetime < $time) {
                        unset($this->session_queue[$i]);
                        unset($this->sessions[$session_id]);
                    }
                }
            }
            $this->setCookie($cookie_name, $session_id, $expires,
                $options['cookie_path'], $options['cookie_domain'],
                $options['cookie_secure'], $options['cookie_httponly']);
            $_COOKIE[$cookie_name] = $session_id;
            $this->current_session = $cookie_name;
        } else {
            session_start($options);
        }
    }
    /**
     * Reads in the file $filename and returns its contents as a string.
     * In non-CLI mode this method maps directly to PHP's built-in function
     * file_get_contents(). In CLI mode, it checks if the file exists in
     * its Marker Algorithm based RAM cache (Fiat et al 1991). If so, it
     * directly returns it. Otherwise, it reads it in usingthe blocking I/O
     * file_get_contents() and caches it before return its string contents.
     *
     * @param string $filename name of file to get contents of
     * @return string contents of the file given by $filename
     */
    public function fileGetContents($filename)
    {
        if ($this->isCli()) {
            $path = realpath($filename);
            if (isset($this->file_cache['MARKED'][$path])) {
                return $this->file_cache['MARKED'][$path];
            } else if (isset($this->file_cache['UNMARKED'][$path])) {
                $this->file_cache['MARKED'][$path] =
                    $this->file_cache['UNMARKED'][$path];
                unset($this->file_cache['UNMARKED'][$path]);
                return $this->file_cache['MARKED'][$path];
            }
            $data = file_get_contents($path);
            if (strlen($data) < $this->default_server_globals[
                'MAX_CACHE_FILESIZE']) {
                if (count($this->file_cache['MARKED']) >=
                    $this->default_server_globals['MAX_CACHE_FILES']) {
                    foreach($this->file_cache['MARKED'] as $path => $data) {
                        $this->file_cache['UNMARKED'][$path] = $data;
                        unset($this->file_cache['MARKED'][$path]);
                    }
                }
                if (count($this->file_cache['MARKED']) +
                    ($num_unmarked = count($this->file_cache['UNMARKED'])) >=
                    $this->default_server_globals['MAX_CACHE_FILES']) {
                    $eject = mt_rand(0, $num_unmarked - 1);
                    $unmarked_paths = array_keys($this->file_cache['UNMARKED']);
                    unset(
                        $this->file_cache['UNMARKED'][$unmarked_paths[$eject]]);
                }
                $this->file_cache['UNMARKED'][$path] = $data;
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
     */
    public function filePutContents($filename, $data)
    {
        $path = realpath($filename);
        if ($this->isCli()) {
            if (isset($this->file_cache['MARKED'][$path])) {
                $this->file_cache['MARKED'][$path] = $data;
            } else if (isset($this->file_cache['UNMARKED'][$path])) {
                $this->file_cache['UNMARKED'][$path] = $data;
            }
        }
        return file_put_contents($filename, $data);
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
            throw new \Exception("Atto Website Timers require CLI execution");
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
     *
     * @param int $address
     * @param mixed $config_array_or_ini_filename
     */
    public function listen($address, $config_array_or_ini_filename = false)
    {
        $path = (!empty($_SERVER['PATH'])) ? $_SERVER['PATH'] :
            ((!empty($_SERVER['Path'])) ? $_SERVER['Path'] : ".");
        $default_server_globals = [ "DOCUMENT_ROOT" => getcwd(),
            "GATEWAY_INTERFACE" => "CGI/1.1", "PATH" => $path,
            "SERVER_ADMIN" => "you@example.com", "SERVER_SIGNATURE" => "",
            "SERVER_SOFTWARE" => "ATTO WEBSITE SERVER",
            "MAX_REQUEST_LEN" => 10000000, "MAX_CACHE_FILESIZE" => 1000000,
            "MAX_CACHE_FILES" => 100, "CONNECTION_TIMEOUT" => 20,
            "CULL_OLD_SESSION_NUM" => 5
        ];
        if (is_int($address) && $address >= 0 && $address < 65535) {
            /*
             both work on windows, but localhost doesn't give windows defender
             warning
            */
            $localhost = strstr(PHP_OS, "WIN") ? "localhost" : "0.0.0.0";
            // 0 binds to any incoming ipv4 address
            $address = "tcp://$localhost:$address";
            $server_globals = ["SERVER_NAME" => "localhost"];
        } else {
            $server_globals = ['SERVER_NAME' => substr($address, 0,
                strrpos($address, ":"))];
        }
        $context = [];
        if (is_array($config_array_or_ini_filename)) {
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
        if (!empty($context['ssl'])) {
            $this->is_secure = true;
        }
        $server_context = stream_context_create($context);
        $server = stream_socket_server($address, $errno, $errstr,
            STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $server_context);
        stream_set_blocking($server, 0);
        $this->default_server_globals = array_merge($_SERVER,
            $default_server_globals, $server_globals);
        $this->immortal_stream_keys[] = (int)$server;
        $this->in_streams = [self::CONNECTION => [(int)$server => $server],
            self::DATA => [""]];
        $this->out_streams = [self::CONNECTION => [], self::DATA => []];
        $excepts = null;
        echo "SERVER listening at $address\n";
        while (true) {
            $in_streams_with_data = $this->in_streams[self::CONNECTION];
            $out_streams_with_data = $this->out_streams[self::CONNECTION];
            if ($this->timer_alarms->isEmpty()) {
                $timeout = null;
                $micro_timeout = 0;
            } else {
                $next_alarm = $this->timer_alarms->top();
                $pre_timeout = max(0, microtime(true) - $next_alarm[0]);
                $timeout = floor($pre_timeout);
                $micro_timeout = intval(($timeout - floor($pre_timeout)) 
                    * 1000000);
            }
            $num_selected = stream_select($in_streams_with_data,
                $out_streams_with_data, $excepts, $timeout, $micro_timeout);
            $this->processTimers();
            if ($num_selected > 0) {
                $this->readStreams($server, $in_streams_with_data);
                $this->writeStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
    }
    /**
     *
     * @param string $request_path
     * @param string $route 
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
     *
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
            if (!empty($this->timers[$top[1]])) {
                list($repeating, $time, $callback) = $this->timers[$top[1]];
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
     * @param resource $server
     * @param array $out_streams_with_data
     */
    protected function readStreams($server, $in_streams_with_data)
    {
        foreach ($in_streams_with_data as $in_stream) {
            if ($in_stream == $server) {
                if ($this->is_secure) {
                    stream_set_blocking($server, 1);
                }
                if ($this->timer_alarms->isEmpty()) {
                    $timeout = ini_get("default_socket_timeout");
                } else {
                    $next_alarm = $this->timer_alarms->top();
                    $timeout = max(min( $next_alarm[0] - microtime(true),
                        ini_get("default_socket_timeout")), 0);
                }
                $connection = stream_socket_accept($server, $timeout);
                if ($this->is_secure) {
                    stream_set_blocking($server, 0);
                }
                if ($connection) {
                    if ($this->is_secure) {
                        stream_set_blocking($connection, 1);
                        stream_socket_enable_crypto($connection, true, 
                            STREAM_CRYPTO_METHOD_TLS_SERVER);
                        stream_set_blocking($connection, 0);
                    }
                    $key = (int)$connection;
                    $this->in_streams[self::CONNECTION][$key] = $connection;
                    $this->initReadStream($key);
                }
            } else {
                $meta = stream_get_meta_data($in_stream);
                $key = (int)$in_stream;
                if ($meta['eof']) {
                    $this->shutdownHttpStream($key);
                    continue;
                }
                $len = strlen($this->in_streams[self::DATA][$key]);
                $data = stream_get_contents($in_stream,
                   $this->default_server_globals['MAX_REQUEST_LEN'] - $len);
                if ($this->parseRequest($key, $data)) {
                    $this->header_data = "";
                    $this->current_session = "";
                    $_SESSION = [];
                    $this->content_type = false;
                    ob_start();
                    $this->process();
                    $out_data = ob_get_contents();
                    ob_end_clean();
                    if ($this->current_session != "" &&
                        !empty($_COOKIE[$this->current_session])) {
                        $session_id = $_COOKIE[$this->current_session];
                        $this->sessions[$session_id]['DATA'] = $_SESSION;
                    }
                    if (substr($this->header_data, 0, 5) != "HTTP/") {
                        $this->header_data = $_SERVER['SERVER_PROTOCOL'] .
                            " 200 OK\x0D\x0A". $this->header_data;
                    }
                    if (!$this->content_type) {
                        $this->header_data .= "Content-Type: text/html\x0D\x0A";
                    }
                    $out_data = $this->header_data .
                            "Content-Length: ". strlen($out_data) .
                            "\x0D\x0A\x0D\x0A" .  $out_data;
                    $this->initReadStream($key);
                    if (empty($this->out_streams[self::CONNECTION][$key])) {
                        $this->out_streams[self::CONNECTION][$key] =
                            $in_stream;
                        $this->out_streams[self::DATA][$key] = $out_data;
                        $this->out_streams[self::CONTEXT][$key] =
                            $_SERVER;
                        $this->out_streams[self::MODIFIED_TIME][$key] = time();
                    }
                }
                $this->in_streams[self::MODIFIED_TIME][$key] = time();
            }
        }
    }
    /**
     * @param int key
     */
    protected function initReadStream($key)
    {
        $connection = $this->in_streams[self::CONNECTION][$key];
        $remote_name = stream_socket_get_name($connection, true);
        $remote_col = strrpos($remote_name, ":");
        $server_name = stream_socket_get_name($connection,
            false);
        $server_col = strrpos($server_name, ":");
        $this->in_streams[self::CONTEXT][$key] =
            [self::REQUEST_HEAD => false,
             'REQUEST_METHOD' => false,
             "REMOTE_ADDR" => substr($remote_name, 0, $remote_col),
             "REMOTE_PORT" => substr($remote_name, $remote_col + 1),
             "REQUEST_TIME" => time(),
             "REQUEST_TIME_FLOAT" => microtime(true),
             "SERVER_ADDR" => substr($server_name, 0, $server_col),
             "SERVER_PORT" => substr($server_name, $server_col + 1),
             ];
        $this->in_streams[self::DATA][$key] = "";
        $this->in_streams[self::MODIFIED_TIME][$key] = time();
    }
    /**
     * @param array $out_streams_with_data
     */
    protected function writeStreams($out_streams_with_data)
    {
        foreach ($out_streams_with_data as $out_stream) {
            $meta = stream_get_meta_data($out_stream);
            $key = (int)$out_stream;
            if ($meta['eof']) {
                $this->shutdownHttpStream($key);
                continue;
            }
            $data = $this->out_streams[self::DATA][$key];
            $num_bytes = fwrite($out_stream, $data);
            $remaining_bytes = max(0, strlen($data) - $num_bytes);
            if ($num_bytes > 0) {
                $this->out_streams[self::DATA][$key] =
                    substr($data, $num_bytes);
                $this->out_streams[self::MODIFIED_TIME][$key] = time();
            }
            if ($remaining_bytes == 0) {
                $context = $this->out_streams[self::CONTEXT][$key];
                if ((!empty($context['HTTP_CONNECTION']) &&
                    strtolower($context['HTTP_CONNECTION']) == 'close') ||
                    empty($context['SERVER_PROTOCOL']) ||
                    $context['SERVER_PROTOCOL'] == 'HTTP/1.0') {
                    $this->shutdownHttpStream($key);
                } else {
                    $this->shutdownHttpWriteStream($key);
                }
            }
        }
    }
    /**
     * @param int $key
     * @param string $data
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
     *
     * @param array $context
     */
    protected function setGlobals($context)
    {
        $_SERVER = array_merge($this->default_server_globals, $context);
        parse_str($context['QUERY_STRING'], $_GET);
        $_POST = [];
        if (!empty($context['CONTENT_TYPE']) && 
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
                        $content_type = $matches[1];
                    }
                }
                if (empty($name)) {
                    continue;
                }
                if (empty($file_name)) {
                    $_POST[$name] = $content;
                    continue;
                }
                $file_array = ['name' => $file_name, 'tmp_name' => $file_name, 
                    'type' => $content_type, 'error' => 0, 'data' => $content,
                    'size' => strlen($content)];
                if (empty($_FILES[$name])) {
                    $_FILES[$name] = $file_array;
                } else {
                    foreach(['name', 'tmp_name', 'type', 'error', 'data',
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
     *
     * @param string $route
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
     *
     * @param int $key
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
             'SERVER_PROTOCOL' => 'HTTP/1.0']);
    }
    /**
     *
     */
    protected function cullDeadStreams()
    {
        $keys = array_merge(array_keys($this->in_streams[self::CONNECTION]),
            array_keys($this->out_streams[self::CONNECTION]));
        foreach ($keys as $key) {
            if (in_array($key, $this->immortal_stream_keys)) {
                continue;
            }
            $in_time = empty($this->in_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->in_streams[self::MODIFIED_TIME][$key];
            $out_time = empty($this->out_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->out_streams[self::MODIFIED_TIME][$key];
            $modified_time = max($in_time, $out_time);
            if (time() - $modified_time > $this->default_server_globals[
                'CONNECTION_TIMEOUT']) {
                $this->shutdownHttpStream($key);
            }
        }
    }
    /**
     *
     * @param int $key
     */
    protected function shutdownHttpStream($key)
    {
        if (!empty($this->in_streams[self::CONNECTION][$key])) {
            stream_socket_shutdown($this->in_streams[self::CONNECTION][$key],
                STREAM_SHUT_RDWR);
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
     *
     * @param int $key
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

