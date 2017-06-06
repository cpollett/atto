<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

//exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();
openlog("PHP", LOG_PERROR, LOG_USER);
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
    <head><title>Hello World - Atto Server</title></head>
    <body>
    <h1>Hello World!</h1>
    <div>My first atto server route!</div>
    </body>
    </html>
<?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
