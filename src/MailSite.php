<?php
/**
 * seekquarry\atto\MailSite -- a small STMP and Mail server and routing engine
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
 * @copyright 2017
 * @filesource
 */

namespace seekquarry\atto;

/**
 * A single file, low dependency, pure PHP mail server and routing engine
 * class.
 *
 * This software can be used to serve mail apps. It is request
 * event-driven, supporting asynchronous I/O for mail traffic. It also
 * supports timers for background events. It automatically sets up
 * subperglobals such as $_REQUEST and $_SERVER which can be useful in
 * processing requests.
 */
class MailSite
{
    const CONNECTION = 0;
    const DATA = 1;
    const MODIFIED_TIME = 2;
    const CONTEXT = 3;
    public $immortal_stream_keys = [];
    public $base_path;
    public $domains = ['localhost'];
    public $mail_db;
    protected $default_server_globals;
    protected $routes = [ "APPEND" => [], "AUTH" => [], "CLOSE" => [],
        "CHECK" => [], "COPY" => [], "CREATE" => [],
        "DATA" => [], "DELETE" => [],  "ENDIDLE"=> [],"ERROR"  => [],
        "EXAMINE"  => [], "EXPUNGE" => [],
        "EXISTS" => [], "FETCH" =>[], "FLAGS" =>[], "LIST" => [], "LSUB" => [],
        "MAILFROM" => [], "RCPTTO" => [], "RECENT" => [],
        "RENAME" => [], "SEARCH" => [], "SELECT" => [], "SEND" => [],
        "STARTIDLE"=> [], "STATUS" => [],  "STORE" => [],
        "SUBSCRIBE" => [], "UNSEEN" =>[], "UIDNEXT" => [], "UIDVALIDITY" => [],
        "UNSUBSCRIBE" => []];
    protected $state_commands = [
        'SMTP' => [
            'AUTH' => ['AUTH', 'HELP'],
            'INIT' => ['EHLO', 'HELO', 'NOOP', 'QUIT', 'RSET', 'STARTTLS', 'HELP'],
            'HELO' => ['NOOP', 'QUIT', 'RSET','STARTTLS', 'HELP'],
            'TLS' => ['EHLO', 'HELO', 'NOOP', 'QUIT', 'RSET', 'HELP'],
            'EHLO_TLS' => ['AUTH', 'MAIL', 'NOOP', 'QUIT', 'RSET', 'HELP'],
            'MAIL' => ['NOOP', 'QUIT', 'RCPT', 'RSET', 'HELP'],
            'RCPT' => ['DATA', 'NOOP', 'QUIT', 'RCPT', 'RSET', 'HELP'],
            'DATA' => ['MAIL', 'NOOP', 'QUIT', 'RSET', 'HELP'],
            // 'VRFY' => ['NOOP', 'QUIT', 'RSET'],
            // 'HELP' => ['NOOP', 'QUIT', 'RSET']
        ],
        'IMAP' => [
            'APPEND' => ['APPEND'],
            'AUTH' => ['AUTH'],
            'IDLE' => ['IDLE'],
            'INIT' => ['CAPABILITY', 'NOOP', 'STARTTLS'],
            'TLS'=> ['AUTH', 'CAPABILITY',  'LOGIN', 'LOGOUT', 'NOOP'],
            'USER' => ['APPEND', 'AUTH', 'CAPABILITY', 'CHECK', 'COPY', 'CLOSE',
                'CREATE', 'DELETE', 'EXAMINE', 'EXPUNGE', 'IDLE', 'LIST',
                'LSUB', 'LOGIN', 'LOGOUT', 'NOOP', 'RENAME', 'SELECT', 'SEND',
                'STATUS', 'STORE', 'SUBSCRIBE', 'UID', 'UNSUBSCRIBE']
        ]
    ];
    protected $capabilities = [
        "INIT" => "CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED",
        "TLS" => "CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN",
        "USER" => "CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN"
    ];
    protected $mail_methods;
    protected $in_streams = [];
    protected $out_streams = [];
    protected $middle_wares = [];
    protected $request_script;
    protected $timers = [];
    protected $timer_alarms;
    protected $file_cache = ['MARKED' => [], 'UNMARKED' => []];
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
        $this->mail_methods = array_keys($this->routes);
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
    /**
     * Magic method __call is called whenever an unknown method is called
     * for this class. In this case, we check if the method name corresponds
     * to a lower case SMTP or IMAP command. In which case, we check that the
     * arguments are a two element array with a route and a callback function
     * and add the appropriate route to a routing table.
     *
     * @param string $method
     * @param array $callback a callback function.
     */
    public function __call($method, $callback)
    {
        $num_args = count($callback);
        $route_name = strtoupper($method);
        if ($num_args < 1 || $num_args > 1 ||
            !in_array($route_name, $this->mail_methods)) {
            throw new \Error("Call to undefined method \"$method\".");
        }
        $this->addRoute($route_name, $callback[0]);
    }
    /**
     * Generic function for associating a function $callback to be called
     * when a web request using $method method and with a uri matching
     * $route occurs.
     *
     * @param string $method the name of a web request method for example, "GET"
     * @param callable $callback function to be called if the incoming request
     *      matches with $method and $route
     */
    public function addRoute($method, callable $callback)
    {
        if (!isset($this->routes[$method])) {
            throw new \Exception("Unknown Router Method");
        } else if (!is_callable($callback)) {
            throw new \Exception("Callback not callable");
        }
        if (!isset($this->routes[$method])) {
            $this->routes[$method] = [];
        }
        $this->routes[$method] = $callback;
    }
    /**
     * Calls any callbacks associated with a given $method and $argument
     * provided that recursion in $method $argument call is not detected.
     *
     * @param string $method the name of a email command for example,
     *  "MAILFROM"
     * @return bool whether the $argument was handled by any callback
     */
    public function trigger($method, &$results, $context = false)
    {
        if (empty($_SERVER['RECURSION'])) {
            $_SERVER['RECURSION'] = [];
        }
        if(empty($this->routes[$method])) {
            return false;
        }
        if (in_array($method, $_SERVER['RECURSION']) ) {
            echo "<br />\nError: Recursion detected for $method $argument.\n";
            return true;
        }
        if (empty($this->routes[$method])) {
            $handled = false;
        } else {
            if ($context) {
                $this->setGlobals($context);
            }
            $callback = $this->routes[$method];
            $results = $callback();
            $handled = true;
        }
        return $handled;
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
        $next_time = (int)microtime(true) + $time;
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
     * Starts an Atto Mail Server listening at $address using the
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
    public function listen($domain = "", $config_array_or_ini_filename = false)
    {
        $path = (!empty($_SERVER['PATH'])) ? $_SERVER['PATH'] :
            ((!empty($_SERVER['Path'])) ? $_SERVER['Path'] : ".");
        $default_server_globals = [ "CONNECTION_TIMEOUT" => 30 * 60, //30min
            "DOCUMENT_ROOT" => getcwd(),
            "IMAP_PORT" => 143, "MAIL_DB" => null,
            "MAX_CACHE_FILESIZE" => 1000000, "MAX_CACHE_FILES" => 100,
            "MAX_COMMAND_LEN" => 2048,
            "MAX_REQUEST_LEN" => 10000000,
            "PATH" => $path,
            "SERVER_ADMIN" => "you@example.com", "SERVER_SIGNATURE" => "",
            "SERVER_SOFTWARE" => "ATTO MAIL SERVER",
            "SMTP_PORT" => 25,
        ];
        if ($domain == "") {
            /*
             both work on windows, but localhost doesn't give windows defender
             warning
            */
            $localhost = strstr(PHP_OS, "WIN") ? "localhost" : "0.0.0.0";
            // 0 binds to any incoming ipv4 address
            $address = "tcp://$localhost";
            $server_globals = ["SERVER_NAME" => "localhost"];
        } else {
            $server_globals = ['SERVER_NAME' => $domain];
            $address = "tcp://$domain";
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
        $this->default_server_globals = array_merge($_SERVER,
            $default_server_globals, $server_globals);
        $smtp_server_context = stream_context_create($context);
        $smtp_address = "$address:" .
            $this->default_server_globals["SMTP_PORT"];
        $smtp_server = stream_socket_server($smtp_address, $errno, $errstr,
            STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $smtp_server_context);
        if (!$smtp_server) {
            echo "Failed to bind SMTP address $smtp_address\nServer Stopping\n";
            exit();
        }
        stream_set_blocking($smtp_server, 0);
        $imap_server_context = stream_context_create($context);
        $imap_address = "$address:" .
            $this->default_server_globals["IMAP_PORT"];
        $imap_server = stream_socket_server($imap_address, $errno, $errstr,
            STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $imap_server_context);
        if (!$imap_server) {
            echo "Failed to bind IMAP address $imap_address\nServer Stopping\n";
            exit();
        }
        stream_set_blocking($imap_server, 0);
        $this->immortal_stream_keys[] = (int)$smtp_server;
        $this->immortal_stream_keys[] = (int)$imap_server;
        $this->in_streams = [self::CONNECTION => [(int)$smtp_server =>
            $smtp_server, (int)$imap_server => $imap_server],
            self::DATA => [""]];
        $this->out_streams = [self::CONNECTION => [], self::DATA => []];
        $servers = [$smtp_server, $imap_server];
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
                $this->processRequestStreams($servers, $in_streams_with_data);
                $this->processResponseStreams($out_streams_with_data);
            }
            $this->cullDeadStreams();
        }
    }

    /**
     * Handles processing timers on this Atto Mail Site. This method is called
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
     * superglobals are set up. When this is complete, an output stream is
     * instantiated to send this data asynchronously back to the browser.
     *
     * @param array $servers an array of socket servers used to listen for
     *  incoming connections
     * @param array $in_streams_with_data streams with request data to be
     *  processed.
     */
    protected function processRequestStreams($servers, $in_streams_with_data)
    {
        foreach ($in_streams_with_data as $in_stream) {
            if (in_array($in_stream, $servers)) {
                $this->processServerRequest($in_stream);
                return;
            }
            $meta = stream_get_meta_data($in_stream);
            $key = (int)$in_stream;
            if ($meta['eof']) {
                $this->shutdownStream($key);
                continue;
            }
            $len = strlen($this->in_streams[self::DATA][$key]);
            $protocol = $this->in_streams[self::CONTEXT][$key]['PROTOCOL'];
            $max_len = $this->default_server_globals['MAX_COMMAND_LEN'];
            if (($protocol == 'SMTP' &&
                $this->in_streams[self::CONTEXT][$key]['SERVER_STATE'] ==
                'DATA') || ($protocol == 'IMAP' &&
                $this->in_streams[self::CONTEXT][$key]['SERVER_STATE'] ==
                'APPEND')) {
                $max_len = $this->default_server_globals['MAX_REQUEST_LEN'];
            }
            $too_long = $len >= $max_len;
            if (!$too_long) {
                stream_set_blocking($in_stream, 0);
                $data = stream_get_contents($in_stream, $max_len - $len);
echo "C:" . $data."\n";
            } else {
                $data = "";
                $this->in_streams[self::DATA][$key] = "";
                $this->in_streams[self::CONTEXT][$key]['RESPONSE'] =
                    '500 LINE TOO LONG';
            }
            if ($too_long || $this->parseRequest($key, $data)) {
                if (empty($this->in_streams[self::CONTEXT][$key]['RESPONSE'])) {
                    // echo "here";
                    continue;
                }
                $out_data = $this->in_streams[self::CONTEXT][$key]['RESPONSE'] . "\x0D\x0A";
// echo "S:" . $out_data."\n";
echo "State:". $this->in_streams[self::CONTEXT][$key]['SERVER_STATE']."\n";

                $this->logIncomingMailRequest($out_data, $key);

                if (empty($this->out_streams[self::CONNECTION][$key])) {
                    $this->out_streams[self::CONNECTION][$key] = $in_stream;
                    $this->out_streams[self::DATA][$key] = $out_data;
                    $this->out_streams[self::CONTEXT][$key] =
                        $this->in_streams[self::CONTEXT][$key];
                    $this->out_streams[self::MODIFIED_TIME][$key] = time();
                }
            }
            $this->in_streams[self::MODIFIED_TIME][$key] = time();
        }
    }

    protected function logIncomingMailRequest($requestData, $key) {
        // Log the incoming mail request
        $logMessage = "State:". $this->in_streams[self::CONTEXT][$key]['SERVER_STATE']."\n";
        // $logMessage .= "Incoming Mail Request: " . date('Y-m-d H:i:s') . "\n";
        // $logMessage .= "From: " . $requestData['from'] . "\n";
        // $logMessage .= "To: " . $requestData['to'] . "\n";
        // $logMessage .= "Subject: " . $requestData['subject'] . "\n";
        // $logMessage .= "Body: " . $requestData['body'] . "\n";
        $logMessage .= $requestData;
        
        // Append the log to a file
        file_put_contents('mail_log.txt', $logMessage, FILE_APPEND);
    }

    /**
     * Used to process any timers for MailSite and
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
        $connection = stream_socket_accept($server, $timeout);
        if ($connection) {
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
        $server_addr = substr($server_name, 0, $server_col);
        $this->in_streams[self::CONTEXT][$key] =
            ["REMOTE_ADDR" => substr($remote_name, 0, $remote_col),
             "REMOTE_PORT" => substr($remote_name, $remote_col + 1),
             "REQUEST_TIME" => time(),
             "REQUEST_TIME_FLOAT" => microtime(true),
             "SERVER_STATE" => "INIT",
             "SERVER_ADDR" => $server_addr,
             "SERVER_PORT" => substr($server_name, $server_col + 1),
             ];
        if ($this->in_streams[self::CONTEXT][$key]['SERVER_PORT'] ==
            $this->default_server_globals["SMTP_PORT"]) {
            $this->in_streams[self::CONTEXT][$key]['PROTOCOL'] = 'SMTP';
            // initial welcome message
            $this->out_streams[self::DATA][$key] =
                "220 $server_addr " . $this->default_server_globals[
                'SERVER_SOFTWARE'] . "\x0D\x0A";
        } else {
            $this->in_streams[self::CONTEXT][$key]['PROTOCOL'] = 'IMAP';
            $this->out_streams[self::DATA][$key] =
                "* OK [".$this->capabilities['INIT']."] " .
                $this->default_server_globals['SERVER_SOFTWARE'] .
                " READY \x0D\x0A";
        }
        $this->out_streams[self::CONNECTION][$key] = $connection;
        $this->out_streams[self::CONTEXT][$key] =
            $this->in_streams[self::CONTEXT][$key];
        $this->out_streams[self::MODIFIED_TIME][$key] = time();
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
            $meta = stream_get_meta_data($out_stream);
            $key = (int)$out_stream;
            if ($meta['eof']) {
                $this->shutdownStream($key);
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
                if (in_array($context['SERVER_STATE'], ['QUIT'])) {
                    $this->shutdownStream($key);
                } else {
                    if (!empty($context['STARTING_TLS'])) {
                        stream_socket_enable_crypto(
                            $this->in_streams[self::CONNECTION][$key], true,
                            STREAM_CRYPTO_METHOD_TLS_SERVER|
                            STREAM_CRYPTO_METHOD_TLSv1_1_SERVER|
                            STREAM_CRYPTO_METHOD_TLSv1_2_SERVER);
                        stream_set_blocking(
                            $this->in_streams[self::CONNECTION][$key], 0);
                        unset(
                        $this->in_streams[self::CONTEXT][$key]['STARTING_TLS']);
                    }
                    $this->shutdownWriteStream($key);
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
        $context =  $this->in_streams[self::CONTEXT][$key];
        $protocol = $context['PROTOCOL'];
        $state = $context['SERVER_STATE'];
        if ($state == 'QUIT') {
            return false;
        }
        $allowed_commands = $this->state_commands[$protocol][$state];
echo "Current protocol:".$protocol."\r\n";
echo "Current State:".$state."\r\n";
echo "Allowed commands \r\n";
print_r($allowed_commands);

        // Check for the HELP command
        if ($protocol == 'SMTP' && str_starts_with(strtoupper($data), 'HELP')) {
            $jsonCmds = $this->parseHelp();
            $context['RESPONSE'] = $jsonCmds;
            $this->in_streams[self::CONTEXT][$key]['RESPONSE'] = $jsonCmds;
            return true;
        }
        // echo "passed";
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
                $context['RESPONSE'] = ($protocol == 'SMTP') ?
                    "500 BAD COMMAND" : "{$line_parts[0]} BAD Unknown Command";
                return true;
            }
        }
        $first_line = trim(substr($data, 0, $request_pos));
        $remainder = substr($data, $request_pos + strlen($eol));
        if ($protocol == 'SMTP' && $state == 'DATA') {
            if (strpos($data, "$eol.$eol") !== false) {
                $results = false;
                $_REQUEST['data'] = $data;
                $command = "DATA";
            }   else {
                return false;
            }
        } else if ($protocol == "SMTP") {
            $command = strtoupper(substr($first_line, 0, 4));
            if ($command == 'STAR') {
                $command = strtoupper(substr($first_line, 0, 8));
            }
        } else {
            $line_parts = preg_split("/\s+/", $first_line);
            $command = (empty($line_parts[1])) ? "" : $line_parts[1];
            $command = strtoupper($command);
            if ($line_parts[1] == 'AUTHENTICATE') {
                $command = 'AUTH';
            }
        }
        if (in_array($state, ['APPEND', 'AUTH', 'IDLE'])) {
                $command = $state;
        }
        if (in_array($command, $allowed_commands) ) {
            $parseCommand = "parse" . ucfirst(strtolower($command));
            $_REQUEST = [];
            $result = $this->$parseCommand($key, $first_line, $data, $context);
            if ($result == 'error') {
                if (empty($context['RESPONSE'])) {
                    $context['RESPONSE'] = ($protocol == 'SMTP') ?
                        "500 BAD COMMAND" :
                        "{$line_parts[0]} BAD Unknown Command";
                }
                $this->in_streams[self::DATA][$key] = $remainder;
            } else if ($result == 'not done') {
                return false;
            } else {
                $this->in_streams[self::DATA][$key] = $remainder;
            }
        } else if ($state == 'TLS') {
            $this->in_streams[self::DATA][$key] = $remainder;
            $context['RESPONSE'] = ($protocol == 'SMTP') ?
                "503 5.5.1 Error: send HELO/EHLO first" :
                "{$line_parts[0]} BAD Unknown Command";
        } else {
            $this->in_streams[self::DATA][$key] = $remainder;
            $context['RESPONSE'] = ($protocol == 'SMTP') ? "500 BAD COMMAND" :
                "{$line_parts[0]} BAD Unknown Command";
        }
        $this->in_streams[self::CONTEXT][$key] = $context;
        return true;
    }
    /**
     *
     */
    protected function parseAppend($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (!empty($context['APPEND_STATE'])) {
            $data = rtrim($data, "\x0A\x0D");
            if (strlen($data) <
                $context['APPEND_LENGTH']) {
                return 'not done';
            }
            $_REQUEST['message'] = $data;
            $context['SERVER_STATE'] = $context['APPEND_STATE'];
            unset($context['APPEND_STATE'], $context['APPEND_FLAGS'],
                $context['APPEND_DATE'], $context['APPEND_LENGTH']);
            $handled = $this->trigger("APPEND", $results, $context);
            if ($handled) {
                $context['RESPONSE'] = $results["RESPONSE"] .
                    $line_parts[0] . $results["STATUS"];
            } else {
                return "error";
            }
        } else {
            $context['RESPONSE'] = "+ Ready for literal data";
            $num_parts = count($line_parts);
            if ($num_parts < 4 || $num_parts > 6) {
                $context['RESPONSE'] = $line_parts[0] .
                    "BAD Number of Append parameters incorrect.";
                return "error";
            }
            $context['APPEND_MAILBOX'] = trim($line_parts[2], "\"'\t ");
            $context['APPEND_FLAGS'] = [];
            $context['APPEND_DATE'] = date();
            if ($num_parts == 5) {
                $optional_arg = trim($line_parts[3]);
                if ($optional_arg[0] == '(') {
                    $context['APPEND_FLAGS'] = preg_split("/\s+/",
                        trim($optional_arg, "()"));
                } else {
                    $context['APPEND_DATE'] = $optional_arg;
                }
            } else if ($num_parts == 6) {
                $context['APPEND_FLAGS'] = preg_split("/\s+/",
                    trim($line_parts[3], "()"));
                $context['APPEND_DATE'] = $line_parts[4];
            }
            $context['APPEND_STATE'] = $context['SERVER_STATE'];
            $context['APPEND_LENGTH'] = intval(
                trim($line_parts[$num_parts - 1], "{}\t "));
            $context['SERVER_STATE'] = 'APPEND';
        }
        return 'success';
    }
    /**
     *
     */
    protected function parseAuth($key, $first_line, $data, &$context)
    {
        $protocol = $context['PROTOCOL'];
        $continue = ($protocol == 'SMTP') ? "334 " : "+ ";
        $authenticate = ($protocol == 'SMTP') ? 'AUTH' : 'AUTHENTICATE';
        $msg_id = "";
        $auth_line = $first_line;
        if ($protocol == 'IMAP') {
            $line_parts = preg_split("/\s+/", $first_line, 2);
            if (empty($context['AUTH_STATE'] )) {
                if (count($line_parts) != 2) {
                    $context['RESPONSE'] = $line_parts[0] .
                        "NO [AUTHENTICATIONFAILED] Incorrect number ".
                        "of parameters: ID LOGIN login password";
                    unset($context['AUTH_MSG_ID'], $context['AUTH_STATE'],
                        $context['AUTH_USER'], $context['AUTH_USERNAME']);
                    return 'error';
                }
                $msg_id = $line_parts[0];
                $auth_line = $line_parts[1];
            }
        }
        if (!empty($context['AUTH_STATE'] ) &&
            $context['AUTH_STATE'] == 'PLAIN') {
            return $this->checkAuth($auth_line, $context,
                $context['AUTH_MSG_ID']);
        }
        if (!empty($context['AUTH_STATE'] ) &&
            $context['AUTH_STATE'] == 'LOGIN') {
            $context['AUTH_USERNAME'] = $first_line;
            $context['RESPONSE'] = $continue . base64_encode("Password:");
            $context['AUTH_STATE'] = 'LOGIN2';
            return 'success';
        }
        if (!empty($context['AUTH_STATE'] ) &&
            $context['AUTH_STATE'] == 'LOGIN2') {
            if (empty($context['AUTH_USERNAME'])) {
                $context['AUTH_USERNAME'] = "";
            }
            $username = (empty($context['AUTH_USERNAME'])) ? "" :
                 base64_decode($context['AUTH_USERNAME']);
            $password = base64_decode($first_line);
            return $this->checkAuth( base64_encode("LOGIN" . "\x00" .
                $username . "\x00". $password), $context,
                $context['AUTH_MSG_ID']);
        }
        if (preg_match("/^\s*$authenticate\s+PLAIN\s*(.*)$/i", $auth_line,
            $matches)) {
            if($login_info = trim($matches[1])) {
                return $this->checkAuth($login_info, $context, $msg_id);
            } else {
                $context['SERVER_STATE'] = 'AUTH';
                $context['RESPONSE'] = $continue;
                $context['AUTH_STATE'] = 'PLAIN';
                $context['AUTH_MSG_ID'] = $msg_id;
            }
            return 'success';
        }
        if (preg_match("/^\s*$authenticate\s+LOGIN\s*$/i", $auth_line,
            $matches)) {
            $context['SERVER_STATE'] = 'AUTH';
            $context['RESPONSE'] = $continue . base64_encode("Username:");
            $context['AUTH_STATE'] = 'LOGIN';
            $context['AUTH_MSG_ID'] = $msg_id;
            return 'success';
        }
        return "error";
    }
    /**
     *
     */
    protected function checkAuth($login_info, &$context, $msg_id = "")
    {
        $protocol = $context['PROTOCOL'];
        $context['SERVER_STATE'] = ($protocol == 'SMTP') ? 'EHLO_TLS' : 'TLS';
        $response_ok = ($protocol == 'SMTP') ?
            "235 2.7.0  Authentication Succeeded" :
            "$msg_id OK Logged in";
        $response_no = ($protocol == 'SMTP') ?
            "535 5.7.8  Authentication credentials invalid" :
            "$msg_id NO [AUTHENTICATIONFAILED] Authentication failed.";
        $login_parts = explode("\x00", base64_decode($login_info));
        if (count($login_parts) != 3) {
            $context['RESPONSE'] = $response_no;
            unset($context['AUTH_MSG_ID'], $context['AUTH_STATE'],
                $context['AUTH_USER'], $context['AUTH_USERNAME']);
            return 'error';
        }
        list($auth_id, $user, $password) = $login_parts;
        $add_request = ["auth_id" => $auth_id, "user" => $user,
            "password" => $password];
        $_REQUEST = array_merge($_REQUEST, $add_request);
        $handled = $this->trigger("AUTH", $results, $context);
        unset($context['AUTH_MSG_ID'], $context['AUTH_STATE'],
            $context['AUTH_USER'], $context['AUTH_USERNAME']);
        if ($results) {
            $context['RESPONSE'] = $response_ok;
            $context['AUTH_USER'] = $user;
            if ($protocol == 'IMAP') {
                $context['SERVER_STATE'] = "USER";
            }
            return 'success';
        } else {
            $context['RESPONSE'] = $response_no;
            if ($protocol == 'IMAP') {
                $context['SERVER_STATE'] = "TLS";
            }
            unset($context['AUTH_MSG_ID'], $context['AUTH_STATE'],
                $context['AUTH_USER'], $context['AUTH_USERNAME']);
            return 'error';
        }
    }
    /**
     *
     */
    protected function parseCapability($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 2);
        if (empty($context['AUTH_USER'])) {
            $context['RESPONSE'] = "* " . $this->capabilities[
                $context['SERVER_STATE']] .
                 "\x0D\x0A{$line_parts[0]} OK ".
                "Pre-login capabilities above, post-login ".
                "capabilities may be different.";
        } else {
            $context['RESPONSE'] = "* " . $this->capabilities[
                $context['SERVER_STATE']] . "\x0D\x0A{$line_parts[0]} OK ";
        }
        return 'success';
    }
    protected function parseCheck($key, $first_line, $data, &$context)
    {
        $context['RESPONSE'] .= " OK CHECK completed.";
        unset($context['MAILBOX'], $context['MAILBOX_ID']);
        return 'success';
    }
    protected function parseClose($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($context['MAILBOX'])) {
            $context['RESPONSE'] .= " BAD No mailbox selected.";
        } else {
            $_REQUEST['mailbox'] = $context['MAILBOX'];
            $handled = $this->trigger("EXPUNGE", $results);
            $context['RESPONSE'] .= " OK CLOSE completed.";
        }
        unset($context['MAILBOX'], $context['MAILBOX_ID']);
        return 'success';
    }
    protected function parseCopy($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 4);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($context['MAILBOX'])) {
            $context['RESPONSE'] = $line_parts[0] . " BAD No mailbox selected.";
            return "error";
        }
        if (count($line_parts) != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Incorrect number of arguments for COPY.";
            return "error";
        }
        if (!$_REQUEST['sequence-set'] =
            $this->getSequenceSetArrays($line_parts[2])) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Sequence-set parse error.";
            return "error";
        }
        $_REQUEST['mailbox'] = trim($line_parts[3], "\"'\t ");
        $handled = $this->trigger("COPY", $results);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    protected function parseCreate($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of CREATE parameters incorrect.";
        }
        $_REQUEST['mailbox'] = trim($line_parts[2], "\"'\t ");
        $handled = $this->trigger("CREATE", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseData($key, $first_line, $data, &$context)
    {
        if (!empty($context['SERVER_STATE']) && $context['SERVER_STATE'] ==
            'DATA') {
            if (empty($context['RCPTTO'])) {
                unset ($context['RCPTTO'], $context['MAILFROM']);
                $context['SERVER_STATE'] =  "EHLO_TLS";
                return 'error';
            }
            $mail_from = $context['MAILFROM'];
            $recipients = $context['RCPTTO'];
            foreach ($recipients as $recipient) {
                list($email, $is_local) = $recipient;
                if ($is_local) {
                    $_REQUEST['message'] = $data;
                    $context['APPEND_MAILBOX'] = 'INBOX';
                    $context['APPEND_FLAGS'] = ['Recent'];
                    $context['APPEND_DATE'] = time();
                    $context['MAILBOX_ID'] = -1;
                    $this->trigger("APPEND", $results, $context);
                    if ($results) {
                        $context['RESPONSE'] =
                            "250 Message accepted for delivery";
                    } else {
                        $context['RESPONSE'] = "451 local error in processing";
                        return "error";
                    }
                    $context['SERVER_STATE'] = 'EHLO_TLS';
                }
            }
            unset ($context['RCPTTO'], $context['MAILFROM']);
            $context['SERVER_STATE'] =  "EHLO_TLS";
            return 'success';
        }
        $context['RESPONSE'] = '354 Enter mail, end with "." on a line' .
            " by itself";
        $context['SERVER_STATE'] = 'DATA';
        return 'success';
    }
    protected function parseDelete($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of DELETE parameters incorrect.";
            return 'error';
        }
        $_REQUEST['mailbox'] = trim($line_parts[2], "\"'\t ");
        $handled = $this->trigger("DELETE", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseEhlo($key, $first_line, $data, &$context)
    {
        $msg = "250-STARTTLS\x0D\x0A" .
            "250 AUTH LOGIN PLAIN";
        return $this->parseGreet('EHLO', $msg, $first_line,
            $data, $context);
    }
    protected function parseExamine($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of EXAMINE parameters incorrect.";
            return 'error';
        }
        $_REQUEST['mailbox'] = trim($line_parts[2], "\"'\t ");
        $handled = $this->trigger("EXAMINE", $results);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseExpunge($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($_SERVER['MAILBOX'])) {
            $context['RESPONSE'] = $line_parts[0] . " BAD No mailbox selected.";
            return 'error';
        } else {
            $_REQUEST['mailbox'] = $_SERVER['MAILBOX'];
            $handled = $this->trigger("EXPUNGE", $results, $context);
            if ($handled) {
                $context['RESPONSE'] = $results["RESPONSE"] .
                    $line_parts[0] . $results["STATUS"];
            }
        }
        return 'success';
    }
    /**
     *
     */
    protected function parseFetch($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 4);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($_SERVER['MAILBOX'])) {
            $context['RESPONSE'] = $line_parts[0] . " BAD No mailbox selected.";
            return "error";
        }
        if (count($line_parts) != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Incorrect number of arguments for FETCH.";
            return "error";
        }
        if (!$_REQUEST['sequence-set'] =
            $this->getSequenceSetArrays($line_parts[2])) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Sequence-set parse error.";
            return "error";
        }
        $parts_requested =
            strtoupper(trim($line_parts[3], "\"'\t ()"));
        $type_names = "ALL|FAST|FULL|BODY|BODY\[(?:.*)\]|".
            "BODYSTRUCTURE|BODY.PEEK\[(?:.*)\]|BODYSTRUCTURE|ENVELOPE|FLAGS|".
            "INTERNALDATE|RFC822|RFC822\.HEADER|RFC822\.SIZE|RFC822\.TEXT|UID";
        if (!preg_match("/^($type_names)(?:\s+($type_names))+?$/",
            $parts_requested, $matches)) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD message data items parse error.";
            return "error";
        }
        array_shift($matches);
        $_REQUEST['parts_requested'] = $matches;
        if (empty($_REQUEST['uid'])) {
            $_REQUEST['uid'] = false;
        }
        $handled = $this->trigger("FETCH", $results);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    /**
     *
     */
    protected function parseGreet($command, $msg, $first_line, $data,
        &$context)
    {
        $domain = @trim(substr($first_line, 5));
        if ($this->isDomain($domain)) {
            if ($context['SERVER_STATE'] == 'INIT') {
                $context['SERVER_STATE'] = 'HELO';
            } else if ($context['SERVER_STATE'] == 'TLS') {
                $context['SERVER_STATE'] = 'EHLO_TLS';
            }
            $hyphen = ($msg) ? "-" :" ";
            $context['RESPONSE'] = "250$hyphen".$context['SERVER_ADDR'].
                "\x0D\x0A" . $msg;
        } else {
            $context['RESPONSE'] = "501 Syntax: $command hostname";
        }
        return 'success';
    }
    protected function parseHelo($key, $first_line, $data, &$context)
    {
        return $this->parseGreet('HELO', "", $first_line,
            $data, $context);
    }
    protected function parseIdle($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (!empty($context['IDLE_STATE'])) {
            $context['SERVER_STATE'] = $context['IDLE_STATE'];
            if (!empty($context['MAILBOX_ID'])) {
                $this->trigger("ENDIDLE", $results);
            }
            unset($context['IDLE_STATE']);
            if (trim(strtoupper($line_parts[0])) != 'DONE') {
                $context['RESPONSE'] = $line_parts[0] .
                    " BAD Expected DONE.";
                return 'error';
            }
        } else {
            $context['RESPONSE'] = "+ idling";
            $context['IDLE_STATE'] = $context['SERVER_STATE'];
            if (!empty($context['MAILBOX_ID'])) {
                $this->trigger("STARTIDLE", $results);
            }
            $context['SERVER_STATE'] = 'IDLE';
        }
        return 'success';
    }
    protected function parseList($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of LIST parameters incorrect.";
        }
        list(,,$reference, $mailbox) = $line_parts;
        $_REQUEST['reference'] = trim($reference, "\"'\t ");
        $_REQUEST['mailbox'] = trim($mailbox, "\"'\t ");
        $handled = $this->trigger("LIST", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseLogin($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts) != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "NO [AUTHENTICATIONFAILED] Incorrect number of parameters: ".
                "ID LOGIN login password";
            unset($context['AUTH_STATE'],
                $context['AUTH_USER'], $context['AUTH_USERNAME']);
            return 'error';
        }
        list(,,$user, $password) = $line_parts;
        $user = trim($user, "\"'");
        $password = trim($password, "\"'");
        $_REQUEST = array_merge($_REQUEST, ["user" => $user,
            "password" =>$password ]);
        $handled = $this->trigger("AUTH", $results, $context);
        unset($context['AUTH_STATE'],
            $context['AUTH_USER'], $context['AUTH_USERNAME']);
        if ($results) {
            $context['RESPONSE'] = "* ". $this->capabilities['USER'].
                "\x0D\x0A{$line_parts[0]} OK Logged in";
            $context['SERVER_STATE'] = "USER";
            $context['AUTH_USER'] = $user;
            return 'success';
        } else {
            $context['SERVER_USER'] = "TLS";
            $context['RESPONSE'] = $line_parts[0] .
                "NO [AUTHENTICATIONFAILED] Authentication failed.";
            unset($context['AUTH_STATE'],
                $context['AUTH_USER'], $context['AUTH_USERNAME']);
            return 'error';
        }
    }
    protected function parseLogout($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 2);
        $context['RESPONSE'] = "* BYE Logging out\x0D\x0A".
            $line_parts[0] . " OK Logout completed.";
        $context['SERVER_STATE'] = 'QUIT';
        return 'success';
    }
    protected function parseLsub($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of LSUB parameters incorrect.";
        }
        list(,,$reference, $mailbox) = $line_parts;
        $_REQUEST['reference'] = trim($reference, "\"'\t ");
        $_REQUEST['mailbox'] = trim($mailbox, "\"'\t ");
        $handled = $this->trigger("LSUB", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseMail($key, $first_line, $data, &$context)
    {
        $domain = trim(preg_replace("/^\s*MAIL\s+FROM\s*\:s*/i", "",
            $first_line));
        $_REQUEST['domain'] = trim($domain, "<>");
        if ($this->isDomain($domain) || $this->isEmail($domain)) {
            $handled = $this->trigger("MAILFROM", $results, $context);
            if ($results) {
                $context['RESPONSE'] = "250 2.1.0 Ok";
                $context['MAILFROM'] = $domain;
                $context['SERVER_STATE'] = "MAIL";
            } else {
                $context['RESPONSE'] = "550 Mail refused for local policy".
                    " reasons.";
            }
        } else {
            $context['RESPONSE'] = "501 Syntax error: MAIL FROM:";
        }
        return 'success';
    }
    protected function parseNoop($key, $first_line, $data, &$context)
    {
        $protocol = $context['PROTOCOL'];
        if ($protocol == 'SMTP') {
            $context['RESPONSE'] = "250 OK";
        } else {
            $line_parts = preg_split("/\s+/", $first_line, 2);
            $context['RESPONSE'] = $line_parts[0] . " OK NOOP completed.";
        }
        return 'success';
    }
    protected function parseQuit($key, $first_line, $data, &$context)
    {
        $context['RESPONSE'] = "221 2.0.0 Bye";
        $context['SERVER_STATE'] = 'QUIT';
        return 'success';
    }
    protected function parseRcpt($key, $first_line, $data, &$context)
    {
        $email = trim(preg_replace("/^\s*RCPT\s+TO\s*\:s*/i", "",
            $first_line));
        $email = trim($email, "<>");
        $_REQUEST['email'] = $email;
        if ($this->isEmail($email)) {
            $handled = $this->trigger("RCPTTO", $results, $context);
            if ($handled && !empty($results)) {
                $context['RESPONSE'] = "250 2.1.0 Ok";
                if (empty($context['RCPTTO'])) {
                    $context['RCPTTO'] = [];
                }
                $context['RCPTTO'][] = [$email, $result[0]];
                $context['SERVER_STATE'] = "RCPT";
            } else {
                $context['RESPONSE'] = "550 Mail refused for local policy".
                    " reasons.";
            }
        } else {
            $context['RESPONSE'] = "501 Syntax: RCPT TO:";
        }
        return 'success';
    }
    protected function parseRename($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of CREATE parameters incorrect.";
        }
        list(,, $oldname, $newname) = $line_parts;
        $_REQUEST['old_mailbox'] = trim($oldname, "\"'\t ");
        $_REQUEST['new_mailbox'] = trim($newname, "\"'\t ");
        $handled = $this->trigger("RENAME", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        }
        return 'success';
    }
    protected function parseRset($key, $first_line, $data, &$context)
    {
        $context['SERVER_STATE'] = "EHLO_TLS";
        unset($context['MAILFROM'], $context['RCPTTO']);
        $context['RESPONSE'] = "250 OK";
        return 'success';
    }
    protected function parseSearch($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 3);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($_SERVER['MAILBOX'])) {
            $context['RESPONSE'] = $line_parts[0] . " BAD No mailbox selected.";
            return "error";
        }
        if (count($line_parts) != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Incorrect number of arguments for SEARCH.";
            return "error";
        }
        $search_pattern = "ALL|ANSWERED|BCC\s+[^\s]+|BEFORE\s+[^\s]+|BODY" .
            "|CC\s+[^\s]+|DELETED|DRAFT|FLAGGED|FROM\s+[^\s]+".
            "|HEADER\s+[^\s]+\s+[^\s]+|KEYWORD\s+[^\s]+|LARGER\s+\d+|NEW".
            "|NOT|OLD|ON\s+[^\s]|OR|RECENT|SEEN|SENTBEFORE\s+[^\s]+".
            "|SENTON\s+[^\s]+|SENTSINCE\s+[^\s]+|SINCE\s+[^\s+]".
            "|SMALLER\s+\d+|SUBJECT\s+[^\s]+|TEXT\s+[^\s]+|TO\s+[^\s]+".
            "|UID\s+[^\s]+|UNANSWERED|UNDRAFT|UNFLAGGED|UNKEYWORD\s+[^\s]+".
            "|UNSEEN";
        if ($_REQUEST['sequence_set'] =
            $this->getSequenceSetArrays($line_parts[2])) {
            $_REQUEST['query'] = "SEQUENCE_SET";
        } else if(preg_match("/($search_pattern)/i", $line_parts[2], $matches)) {
        } else {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Invalid arguments.";
            return "error";
        }
//to do
        if (empty($_REQUEST['uid'])) {
            $_REQUEST['uid'] = false;
        }
        $handled = $this->trigger("SEARCH", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    protected function parseSelect($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of SELECT parameters incorrect.";
        }
        list(,, $_REQUEST['mailbox']) = $line_parts;
        $_REQUEST['mailbox'] = trim($_REQUEST['mailbox'], "\"'\t ");
        $handled = $this->trigger("SELECT", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
            if (!empty($_SERVER['MAILBOX'])) {
                $context['MAILBOX'] = $_SERVER['MAILBOX'];
            }
            if (!empty($_SERVER['MAILBOX_ID'])) {
                $context['MAILBOX_ID'] = $_SERVER['MAILBOX_ID'];
            }
        } else {
            return "error";
        }
        return 'success';
    }
    protected function parseStatus($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 4);
        if (count($line_parts)  != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of STATUS parameters incorrect.";
            return "error";
        }
        list(,, $mailbox, $pre_items) = $line_parts;
        $_REQUEST['mailbox'] = trim($mailbox, "\"'\t ");
        $pre_items = trim($_REQUEST['data_items']);
        if ($pre_items[0] != '(' || $pre_items[strlen($pre_items) - 1] != ')') {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD STATUS data item list does not parse.";
            return "error";
        }
        $pre_items = trim($pre_items, "()");
        $response_items = preg_split("/\s+/", $pre_items);
        $allowed_items = ['MESSAGES', 'RECENT', 'UIDNEXT', 'UIDVALIDITY',
            'UNSEEN'];
        $out_message = "";
        foreach ($response_items as $response_item) {
            if (in_array($response_item, $allowed_items)) {
                if ($response_item == 'MESSAGES') {
                    $response_item = "EXISTS";
                }
                // these may depend on $_REQUEST['mailbox']
                $test->trigger($response_item, $out);
                $out_message .= $out;
            } else {
                $context['RESPONSE'] = $line_parts[0] .
                   " BAD Invalid Argument.";
                return "error";
            }
        }
        if ($handled) {
            $context['RESPONSE'] = $out_message .
                $line_parts[0] . " OK STATUS completed.";
        }
        return 'success';
    }
    protected function parseStarttls($key, $first_line, $data, &$context)
    {
        $connection = $this->in_streams[self::CONNECTION][$key];
        stream_set_blocking($connection, 1);
        $context['SERVER_STATE'] = 'TLS';
        $context['STARTING_TLS'] = true;
        $protocol = $this->in_streams[self::CONTEXT][$key]['PROTOCOL'];
        if ($protocol == 'SMTP') {
            $context['RESPONSE'] = "220  2.0.0 Ready to start TLS";
        } else {
            $line_parts = preg_split("/\s+/", $first_line);
            $context['RESPONSE'] =
                "{$line_parts[0]} OK Begin TLS negotiation now";
        }
        return 'success';
    }
    protected function parseStore($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 5);
        $context['RESPONSE'] = $line_parts[0];
        if (empty($_SERVER['MAILBOX'])) {
            $context['RESPONSE'] = $line_parts[0] . " BAD No mailbox selected.";
            return "error";
        }
        if (count($line_parts) != 5) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Incorrect number of arguments for STORE.";
            return "error";
        }
        if (!$_REQUEST['sequence-set'] =
            $this->getSequenceSetArrays($line_parts[2])) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Sequence-set parse error.";
            return "error";
        }
        $flags_arg = $line_parts[3];
        if (!preg_match("/^[+-]?FLAGS(:?\.SILENT)?$/i", $flags_arg)) {
            $context['RESPONSE'] = $line_parts[0] .
                " BAD Illegal Flags Arguments.";
            return "error";
        }
        $_REQUEST['flag-operation'] = (in_array($flags_arg[0], ["+", "-"])) ?
            $flags_arg[0] : "";
        $_REQUEST['silent'] = false;
        if (strlen($flags_arg) >= 6 && substr($flags_arg, -6) == "SILENT") {
            $_REQUEST['silent'] = true;
        }
        $_REQUEST['flag-list'] = preg_split("/\s+/",
            trim($line_parts[4], "()"));
        if (empty($_REQUEST['uid'])) {
            $_REQUEST['uid'] = false;
        }
        $handled = $this->trigger("STORE", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    protected function getSequenceSetArrays($sequence_set)
    {
        $sequence_parts = explode(",", $sequence_set);
        $out_set = [];
        foreach ($sequence_parts as $sequence_part) {
            if ($sequence_part == "*") {
                $out_set[] = [0, '*'];
            } else if (is_numeric($sequence_part)) {
                $value = intval($sequence_part);
                $out_set[] = [$value, $value];
            } else {
                $range_parts = explode(":", $sequence_part, 2);
                if (count($range_parts) != 2) {
                    return false;
                }
                if ($range_parts[0] == $range_parts[1] &&
                    $range_parts[1] == '*') {
                    $out_set[] = [0, '*'];
                } else if ($range_parts[0] == "*" &&
                    is_numeric($range_parts[1])) {
                    $out_set[] = [intval($range_parts[1]), "*"];
                } else if ($range_parts[1] == "*" &&
                    is_numeric($range_parts[0])) {
                    $out_set[] = [intval($range_parts[0]), "*"];
                } else if (is_numeric($range_parts[0]) &&
                    is_numeric($range_parts[1])) {
                    $value0 = intval($range_parts[0]);
                    $value1 = intval($range_parts[1]);
                    $out_set[] = [min($value0, $value1), max($value0, $value1)];
                } else {
                    return false;
                }
            }
        }
        return $out_set;
    }
    protected function parseSubscribe($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of SUBSCRIBE parameters incorrect.";
            return "error";
        }
        list(,, $_REQUEST['mailbox']) = $line_parts;
        $handled = $this->trigger("SUBSCRIBE", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    /**
     *
     */
    protected function parseUid($key, $first_line, $data, &$context)
    {
        $line_parts = preg_split("/\s+/", $first_line, 4);
        if (count($line_parts)  != 4) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of UID parameters incorrect.";
            return "error";
        }
        list(,, $command, ) = $line_parts;
        $command = strtoupper($command);
        if (!in_array($command, ["COPY", "FETCH", "SEARCH", "STORE"])) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD UID command unknown.";
            return "error";
        }
        $_REQUEST["uid"] = true;
        array_shift($line_parts);
        $first_line = implode(" ", $line_parts);
        $parseCommand = "parse" . ucfirst(strtolower($command));
        return $this->$parseCommand($key, $first_line, $data, $context);
    }
    protected function parseUnsubscribe($key, $first_line, $data, $context)
    {
        $line_parts = preg_split("/\s+/", $first_line);
        if (count($line_parts)  != 3) {
            $context['RESPONSE'] = $line_parts[0] .
                "BAD Number of UNSUBSCRIBE parameters incorrect.";
            return "error";
        }
        list(,, $_REQUEST['mailbox']) = $line_parts;
        $handled = $this->trigger("UNSUBSCRIBE", $results, $context);
        if ($handled) {
            $context['RESPONSE'] = $results["RESPONSE"] .
                $line_parts[0] . $results["STATUS"];
        } else {
            return "error";
        }
        return 'success';
    }
    protected function isDomain($domain)
    {
        return filter_var('postmaster@' . $domain, FILTER_VALIDATE_EMAIL) ||
            filter_var($domain, FILTER_VALIDATE_IP) ||
            $domain == 'localhost';
    }
    protected function isEmail($email)
    {
        $email_parts = explode("@", $email, 2);
        if (!isset($email_parts[1])) {
            return false;
        }
        return filter_var($email_parts[0] . "@somewhere.com",
            FILTER_VALIDATE_EMAIL) && $this->isDomain($email_parts[1]);
    }
    /**
 * Handler for the HELP command. 
 * Contains a list of commands and their descriptions in an array.
 */
protected function parseHelp() 
{
    $commands = [
        "AUTH" => "Used for authentication during the SMTP session. It is typically used when the server requires the client to authenticate before sending emails.",
        "EHLO" => "Initiates the SMTP session with the server and requests extended SMTP capabilities. It is used to identify the client to the server and to negotiate the supported features.",
        "HELO" => "Initiates the SMTP session with the server. It is a simpler version of EHLO and is used when extended capabilities are not required.",
        "NOOP" => "Does nothing but can be used as a keep-alive mechanism during the SMTP session to prevent the connection from timing out.",
        "QUIT" => "Ends the SMTP session with the server and closes the connection. It is used to gracefully terminate the session.",
        "RSET" => "Resets the current SMTP session state. It is used to abort the current email transaction and return to the initial state.",
        "STARTTLS" => "Initiates a TLS-encrypted SMTP session. It is used to secure the connection between the client and server by encrypting the data transmission.",
        "MAIL" => "Specifies the sender's email address in the email transaction. It is used to indicate who is sending the email.",
        "RCPT" => "Specifies the recipient's email address in the email transaction. It is used to indicate who is receiving the email.",
        "DATA" => "Indicates the start of the email message body. It is used to transmit the content of the email message.",
        "VRFY" => "Verifies if a given email address is valid and exists on the server. It can be used to check the validity of email addresses before sending emails.",
        "HELP" => "Requests help information from the server. It can be used to retrieve information about available commands and their usage."
    ];
    $helpResponse = "214 - Available commands:\r\n";
    foreach ($commands as $command => $desc) {
        $helpResponse .= "[$command] \r\n\r\n $desc\r\n\r\n\r\n";
    }
    $helpResponse .= "214 End of HELP response\r\n\r\n";
    return $helpResponse;
}

    /**
     * Used to initialize the superglobals before process() is called.
     * The values for the globals come from the
     * request streams context which has request headers.
     *
     * @param array $context associative array of information parsed from
     *      a mail request.
     */
    protected function setGlobals($context)
    {
        $_SERVER = array_merge($this->default_server_globals, $context);
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
            $in_time = empty($this->in_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->in_streams[self::MODIFIED_TIME][$key];
            $out_time = empty($this->out_streams[self::MODIFIED_TIME][$key]) ?
                0 : $this->out_streams[self::MODIFIED_TIME][$key];
            $modified_time = max($in_time, $out_time);
            if (time() - $modified_time > $this->default_server_globals[
                'CONNECTION_TIMEOUT']) {
                $this->shutdownStream($key);
            }
        }
    }
    /**
     * Closes stream with id $key and removes it from in_streams and
     * outstreams arrays.
     *
     * @param int $key id of stream to delete
     */
    protected function shutdownStream($key)
    {
        if (!empty($this->in_streams[self::CONNECTION][$key])) {
            @stream_socket_shutdown($this->in_streams[self::CONNECTION][$key],
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
     * Removes a stream from outstream arrays. Since an HTTP connection can
     * handle several requests from a single client, this method does not close
     * the connection. It might be run after a request response pair, while
     * waiting for the next request.
     *
     * @param int $key id of stream to remove from outstream arrays.
     */
    protected function shutdownWriteStream($key)
    {
        unset($this->out_streams[self::CONNECTION][$key],
            $this->out_streams[self::CONTEXT][$key],
            $this->out_streams[self::DATA][$key],
            $this->out_streams[self::MODIFIED_TIME][$key]
        );
    }
}
