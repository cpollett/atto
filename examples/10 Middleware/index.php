<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();
//set up log message
openlog("PHP", LOG_PERROR, LOG_USER);
/*
    In this example, a log message is written each time a web request is made.
    To do this we make use of the use() function to register a callback
    that is called before the request is handled. 
    To run this example, comment the exit line above and type:
    php index.php
    and pointing a browser to http://localhost:8080/.
 */
$test->use(function () use ($test)
{
    $log_msg = $_SERVER['REMOTE_ADDR'] . " " .
        $_SERVER['REQUEST_METHOD'] ." ". $_SERVER['REQUEST_URI'];
    syslog(LOG_INFO, $log_msg);
});
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Middleware demo - Atto Server</title></head>
    <body>
    <h1>Middleware demo</h1>
    <div>Click reload a few times and look at the console to see the log
    messages. Messages should go to stderr.</div>
    </body>
    </html>
<?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
