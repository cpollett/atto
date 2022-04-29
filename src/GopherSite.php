<?php
/**
 * seekquarry\atto\GopherSite -- a small gopher server and routing engine
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
 * @license http://www.gnu.org/licenses/ GPL-3.0-or-later
 * @link http://www.seekquarry.com/
 * @copyright 2018
 * @filesource
 */

namespace seekquarry\atto;

/**
 * A single file, low dependency, pure PHP gopher server and routing engine
 * class.
 *
 * This software can be used to serve gopher apps. It is request
 * event-driven, supporting asynchronous I/O for gopher traffic. It also
 * supports timers for background events. It automatically sets up
 * subperglobals such as $_REQUEST and $_SERVER which can be useful in
 * processing requests.
 */
class GopherSite
{
    /*
        Field component name constants used in input or output stream array
     */
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
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
    protected $routes = ["ERROR"  => [], "REQUEST" => []];
    /**
     * List of Gopher methods for which routes have been declared
     * @var array
     */
    protected $gopher_methods;
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
     * Used to cache in RAM files which have been read or written by the
     * fileGetContents or filePutContents
     * @var array
     */
    protected $file_cache = ['MARKED' => [], 'UNMARKED' => [], 'PATH' => []];
    /**
     * Whether SSL is being used
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
        $this->gopher_methods = array_keys($this->routes);
        $this->default_server_globals = [];
        if (empty($base_path)) {
            $pathinfo = pathinfo($_SERVER['SCRIPT_NAME']);
            $base_path = $pathinfo['dirname'];
            $base_path = $pathinfo["dirname"];
            if ($base_path == ".") {
                $base_path = "";
            }
        }
        $this->base_path = $base_path;
        ini_set('precision', 16);
        $this->timer_alarms = new \SplMinHeap();
    }
    /*

        Gopher Routing Methods

     */
    /**
     * Sets up a callback function to be called when a ERROR command is
     * made for $route is made to this gopher app.
     *
     * ERROR commands is a pseudo-gopher event which can be generated
     * whenever a server or request error is detected. For example, if a file
     * wasn't found under some path, the handler for that path might
     * call $this->trigger('ERROR', /404); to call the handler for 404 NOT
     * FOUND events.
     *
     * @param string $route request pattern to match ERROR command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_REQUEST field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if ERROR request for $route
     *      made.
     * @param bool $raw whether to gopherize the callback's output before
     *      sending it to the client
     */
    public function error($route, callable $callback, $raw = false)
    {
        $this->addRoute("ERROR", $route, $callback, $raw);
    }
    /**
     * Sets up a callback function to be called when a selector request for
     * $route is made to this gopher app.
     *
     * @param string $route request pattern to match REQUEST command against
     *      * acts as a wildcare. {var_name} in a path can be used to set up
     *      a $_REQUEST (superglobal) field for the match.
     *      Example $routes:
     *      /foo match requests to /foo
     *      /foo*goo matches against paths like /foogoo /foodgoo /footsygoo
     *      /thread/{thread_num} would match /thread/5 and would set up
     *          a variable $_GET['thread_num'] = 5 as well as
     *          $_REQUEST['thread_num'] = 5
     *
     * @param callable $callback function to call if REQUEST for $route
     *      made.
     * @param bool $raw whether to gopherize the callback's output before
     *      sending it to the client
     */
    public function request($route, callable $callback, $raw = false)
    {
        $this->addRoute("REQUEST", $route, $callback, $raw);
    }
    /**
     * Used to add all the routes and callbacks of a GopherSite object to the
     * current GopherSite object under paths matching $route.
     *
     * @param string $route request pattern to match
     * @param GopherSite $subsite GopherSite object to add sub routes from
     */
    public function subsite($route, GopherSite $subsite)
    {
        foreach ($this->gopher_methods as $method) {
            foreach ($subsite->routes[$method] as
                $sub_route => $callback_info) {
                $this->routes[$method][$route . $sub_route] = $callback_info;
            }
        }
    }
    /**
     * Generic function for associating a function $callback to be called
     * when a Gopher request using $method method and with a uri matching
     * $route occurs.
     *
     * @param string $method the kind of a gopher request: either
     *  REQUEST (when a selector is requested) or ERROR (any error in
     *  client request).
     * @param string $route request pattern to match
     * @param callable $callback function to be called if the incoming request
     *      matches with $method and $route
     * @param bool $raw whether to gopherize the callback's output before
     *      sending it to the client
     */
    public function addRoute($method, $route, callable $callback, $raw = false)
    {
        if (!isset($this->routes[$method])) {
            throw new \Exception("Unknown Router Method");
        } else if (!is_callable($callback)) {
            throw new \Exception("Callback not callable");
        }
        if (!isset($this->routes[$method])) {
            $this->routes[$method] = [];
        }
        $this->routes[$method][$route] = [$callback, $raw];
    }
    /*
        Gopher Processing Methods
     */
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
     * Cause all the current Gopher request to be processed according to the
     * middleware callbacks and routes currently set on this GopherSite object.
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
            $route = "Method Not Found";
        }
        $route = $this->request_script;
        if (!$this->trigger($method, $route)) {
            $handled =  false;
            if ($method != 'ERROR') {
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
     * @param string $method the name of a gopher method, REQUEST or ERROR
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
        if (in_array($method . " ". $route, $_SERVER['RECURSION']) ) {
            echo "<br />\nError: Recursion detected for $method $route.\n";
            return true;
        }
        $method_routes = $this->routes[$method];
        $handled = false;
        foreach ($method_routes as $check_route => $callback_info) {
            if(($add_vars = $this->checkMatch($route, $check_route)) !==
                false) {
                list($callback, $raw) = $callback_info;
                $_GET = array_merge($_GET, $add_vars);
                $_REQUEST = array_merge($_REQUEST, $add_vars);
                $_SERVER['RECURSION'][] = $method . " ". $check_route;
                if (!$raw) {
                    $current_data = ob_get_clean();
                    ob_start();
                }
                $callback();
                if (!$raw) {
                    $new_output = ob_get_clean();
                    $new_output = $this->gopherize($new_output);
                    ob_start();
                    echo $current_data;
                    echo $new_output;
                }
                $handled = true;
            }
        }
        return $handled;
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
     *      presistent storage rather than the cache
     * @return string contents of the file given by $filename
     */
    public function fileGetContents($filename, $force_read = false)
    {
        if (!empty($this->file_cache['PATH'][$filename])) {
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
                foreach($this->file_cache['MARKED'] as $path => $data) {
                    $this->file_cache['UNMARKED'][$path] = $data;
                    unset($this->file_cache['MARKED'][$path]);
                }
            }
        }
        return $data;
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
            } else {
                $path = realpath($filename);
                $this->file_cache['PATH'][$filename] = $path;
            }
        }
        $num_bytes = file_put_contents($filename, $data);
        chmod($filename, 0777);
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
        $next_time = "".(microtime(true) + $time);
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
     * Starts an Atto Gopher Server listening at $address using the
     * configuration values provided. It also has this server's event loop. As
     * requests come in $this->process is called to handle them. This input
     * and output tcp streams used by this method are non-blocking. Detecting
     * traffic is done using stream_select().  This maps to Unix-select calls,
     * which seemed to be the most cross-platform compatible way to do things.
     * Streaming methods could be easily re-written to support libevent
     * (doesn't work yet PHP7) or more modern event library
     *
     * @param int $address address and port to listen for requests on
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
        $default_server_globals = [ "CONNECTION_TIMEOUT" => 20,
            "DOCUMENT_ROOT" => getcwd(),
            "INFORMATION_EOL" => "\tfake\tnull\t0\x0D\x0A",
            "MAX_REQUEST_LEN" => 1000, "MAX_CACHE_FILESIZE" => 2000000,
            "MAX_CACHE_FILES" => 250, "PATH" => $path,
            "SERVER_ADMIN" => "you@example.com", "SERVER_NAME" => "localhost",
            "SERVER_SIGNATURE" => "",
            "SERVER_SOFTWARE" => "ATTO GOPHER SERVER",
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
        }
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
                $this->processRequestStreams($server, $in_streams_with_data);
                $out_streams_with_data = $this->out_streams[self::CONNECTION];
                $num_selected = stream_select($in_streams_with_data,
                    $out_streams_with_data, $excepts, $timeout, $micro_timeout);
                $this->processResponseStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
    }
    /**
     * Converts a string with some lines involving gopher links, but all
     * other lines not in gopher format. Adds an i at the start of non-gopher
     * lines and adds necessary fake data and tabs as end. Line endings
     * for all lines are stripped and replaced with CRLF.
     *
     * @param string $data to be converted into gopher output
     * @return string data completely in gopher output
     */
    protected function gopherize($data)
    {
        $lines = explode(\PHP_EOL, $data);
        if (count($lines) > 0 && $lines[count($lines) - 1] == "") {
            array_pop($lines);
        }
        $out = "";
        $line_starts = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
            'g','I','T', 'h', 'i', 's'];
        foreach ($lines as $line) {
            $first = (empty($line)) ? "\0" : $line[0];
            if (!in_array($first, $line_starts) ||
                strpos($line, "\x09") === false) {
                $out .= "i" . $line .
                    $this->default_server_globals['INFORMATION_EOL'];
            } else {
                $out .= rtrim($line, "\x0A") . "\x0D\x0A";
            }
        }
        return $out . ".\x0D\x0A";
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
     * Handles processing timers on this Atto Gopher Site. This method is called
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
                $this->shutdownGopherStream($key);
                continue;
            }
            $len = strlen($this->in_streams[self::DATA][$key]);
            $max_len = $this->default_server_globals['MAX_REQUEST_LEN'];
            $too_long = $len >= $max_len;
            if (!$too_long) {
                stream_set_blocking($in_stream, 0);
                $data = stream_get_contents($in_stream, $max_len - $len);
            } else {
                $data = "";
                $this->initializeBadRequestResponse($key);
            }
            if ($too_long || $this->parseRequest($key, $data)) {
                if (!empty($this->in_streams[self::CONTEXT][$key][
                    'PRE_BAD_RESPONSE'])) {
                    $this->in_streams[self::CONTEXT][$key]['BAD_RESPONSE'] =
                        true;
                    $_SERVER['BAD_RESPONSE'] = true;
                }
                ob_start();
                $this->process();
                $out_data = ob_get_clean();
                if (empty($this->in_streams[self::CONTEXT][$key][
                    'BAD_RESPONSE'])) {
                    $this->initRequestStream($key);
                }
                if (empty($this->out_streams[self::CONNECTION][$key])) {
                    $this->out_streams[self::CONNECTION][$key] = $in_stream;
                    $this->out_streams[self::DATA][$key] = $out_data;
                    $this->out_streams[self::CONTEXT][$key] = $_SERVER;
                    $this->out_streams[self::MODIFIED_TIME][$key] = time();
                }
            }
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
        }
    }
    /**
     * Used to process any timers for GopherSite and
     * used to check if the server has detected a
     * new connection. In which case, a read stream is set-up.
     *
     * @param resource $server socket server used to listen for incoming
     *  connections
     */
    protected function processServerRequest($server)
    {
        if ($this->timer_alarms->isEmpty()) {
            $timeout = ini_get("default_socket_timeout");
        } else {
            $next_alarm = $this->timer_alarms->top();
            $timeout = max(min( $next_alarm[0] - microtime(true),
                ini_get("default_socket_timeout")), 0);
        }
        if ($this->is_secure) {
            stream_set_blocking($server, 1);
        }
        $connection = stream_socket_accept($server, $timeout);
        if ($this->is_secure) {
            stream_set_blocking($server, 0);
        }
        if ($connection) {
            if ($this->is_secure) {
                stream_set_blocking($connection, 1);
                @stream_socket_enable_crypto($connection, true,
                    STREAM_CRYPTO_METHOD_TLS_SERVER);
                stream_set_blocking($connection, 0);
            }
            $key = (int)$connection;
            $this->in_streams[self::CONNECTION][$key] = $connection;
            $this->initRequestStream($key);
        }
    }
    /**
     * Gets info about an incoming request stream and uses this to set up
     * an initial stream context. This context is used to populate the $_SERVER
     * variable when the request is later processed.
     *
     * @param int key id of request stream to initialize context for
     */
    protected function initRequestStream($key)
    {
        $connection = $this->in_streams[self::CONNECTION][$key];
        $remote_name = stream_socket_get_name($connection, true);
        $remote_col = strrpos($remote_name, ":");
        $server_name = stream_socket_get_name($connection,
            false);
        $server_col = strrpos($server_name, ":");
        $this->in_streams[self::CONTEXT][$key] =
            ["REMOTE_ADDR" => substr($remote_name, 0, $remote_col),
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
            $num_bytes = fwrite($out_stream, $data);
            $remaining_bytes = max(0, strlen($data) - $num_bytes);
            if ($num_bytes > 0) {
                $this->out_streams[self::DATA][$key] =
                    substr($data, $num_bytes);
                $this->out_streams[self::MODIFIED_TIME][$key] = time();
            }
            if ($remaining_bytes == 0) {
                $context = $this->out_streams[self::CONTEXT][$key];
                if (empty($context["PRE_BAD_RESPONSE"])) {
                    $this->shutdownGopherStream($key);
                }
            }
        }
    }
    /**
     * Takes the string $data recently read from the request stream with
     * id $key, tacks that on to the previous received data. If this completes
     * an Gopher request then the request headers and request are parsed
     *
     * @param int $key id of request stream to process data for
     * @param string $data from request stream
     * @return bool whether the request is complete
     */
    protected function parseRequest($key, $data)
    {
        $this->in_streams[self::DATA][$key] .= $data;
        $context = $this->in_streams[self::CONTEXT][$key];
        $data = $this->in_streams[self::DATA][$key];
        $eol = "\x0D\x0A"; /*
            spec says use CRLF, but hard to type as human on Mac or Linux
            so relax spec for inputs. (Follow spec exactly for output)
        */
        if (strpos($data, "\x0D") === false && strpos($data, "\x0A") === false){
            return false;
        }
        if (($request_pos = strpos($data, "$eol")) === false) {
            $eol = \PHP_EOL;
            $request_pos = strpos($data, "$eol");
            if ($request_pos === false) {
                $this->initializeBadRequestResponse($key);
                return true;
            }
        }
        $first_line = trim(substr($this->in_streams[self::DATA][$key], 0,
            $request_pos));
        if ($first_line == "") {
            $first_line = "/";
        }
        $context['REQUEST_METHOD'] = 'REQUEST';
        $context['REQUEST_URI'] = $first_line;
        if (($question_pos = strpos($context['REQUEST_URI'],"\x09"))===false) {
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
        $this->setGlobals($context);
        return true;
    }
    /**
     * Used to initialize the superglobals before process() is called.
     * The values for the globals come from the
     * request streams context which has request headers.
     *
     * @param array $context associative array of information parsed from
     *      a gopher request.
     */
    protected function setGlobals($context)
    {
        $_SERVER = array_merge($this->default_server_globals, $context);
        parse_str($context['QUERY_STRING'], $_GET);
        $_SERVER = array_merge($this->default_server_globals, $context);
        $_REQUEST = $_GET;
    }
    /**
     * Outputs Gopher error response message in the case that no specific error
     * handler was set
     *
     * @param string $route the route of the error. Internally, when an Gopher
     *      error occurs it is usually given a route of the form /response code.
     *      For example, /404 for a NOT FOUND error.
     */
    protected function defaultErrorHandler($route = "")
    {
        echo "3 '$route' doesn't exist\tfake\t\0\t0\r\n";
        echo "i This resource cannot be located.\tfake\t\0\t0\r\n";
        echo ".\r\n";
    }
    /**
     * Used to set up PHP superglobals, $_GET, etc in the case that
     * a 400 BAD REQUEST response occurs.
     *
     * @param int $key id of stream that bad request came from
     */
    protected function initializeBadRequestResponse($key)
    {
        $_GET = [];
        $_REQUEST = [];
        $_SERVER = array_merge($this->default_server_globals,
            $this->in_streams[self::CONTEXT][$key],
            ['REQUEST_METHOD' => 'ERROR', 'REQUEST_URI' => '/400',
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
                $this->shutdownGopherStream($key);
            }
        }
    }
    /**
     * Closes stream with id $key and removes it from in_streams and
     * outstreams arrays.
     *
     * @param int $key id of stream to delete
     */
    protected function shutdownGopherStream($key)
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
     * Removes a stream from outstream arrays. Since an Gopher connection can
     * handle several requests from a single client, this method does not close
     * the connection. It might be run after a request response pair, while
     * waiting for the next request.
     *
     * @param int $key id of stream to remove from outstream arrays.
     */
    protected function shutdownGopherWriteStream($key)
    {
        unset($this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]
        );
    }
}
/**
 * Used to create a gopher link line corresponding to a uri and the provided
 * link text.
 *
 * @param string $uri either a selector for the current gopher site or
 *      complete uri to either another gopher site or web url.
 * @param string $link_text the text that will appear in the hyperlink
 */
function link($uri, $link_text)
{
    $line_starts = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
        'g','I','T', 'h', 'i', 's'];
    $uri_parts = parse_url($uri);
    $link_type = 1;
    if (empty($uri_parts['path'])) {
        $path = "/";
    } else {
        $path = $uri_parts['path'];
        if (strlen($path) >= 3 && $path[0] == '/' && $path[2] == '/' &&
            in_array($path[1], $line_starts)) {
            $link_type = $path[1];
            $path = substr($path, 2);
        }
    }
    $host = empty($uri_parts['host']) ? $_SERVER['SERVER_NAME'] :
        $uri_parts['host'];
    $default_port = ($host == $_SERVER['SERVER_NAME']) ?
        $_SERVER['SERVER_PORT'] : 70;
    $port = empty($uri_parts['port']) ? $default_port :
        $uri_parts['port'];
    if (!empty($uri_parts['scheme']) &&in_array($uri_parts['scheme'],
        ['http', 'https'])) {
        $link_type = "h";
        $path = "URL:$uri";
        $host = $_SERVER['SERVER_NAME'];
        $port = $default_port;
    }
    return \PHP_EOL . $link_type . $link_text . "\t" . $path . "\t" . $host .
        "\t" . $port . \PHP_EOL;
}

/**
 * Function to call instead of exit() to indicate that the script
 * processing the current gopher page is done processing. Use this rather
 * that exit(), as exit() will also terminate GopherSite.
 *
 * @param string $err_msg error message to send on exiting
 * @throws GopherException
 */
function gopherExit($err_msg = "")
{
    if (php_sapi_name() == 'cli') {
        throw new GopherException($err_msg);
    } else {
        exit($err_msg);
    }
}
/**
 * Exception generated when a running WebSite script calls webExit()
 */
class GopherException extends \Exception {
}
