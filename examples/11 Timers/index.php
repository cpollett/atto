<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
/*
    An Atto WebSite consisting of a single landing page. When run from a shell
    a timer is called every 10 seconds which prints out the current memory
    usage. Note: timers can take floats, hence, fractions of a second as values.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/. Click reload several
    times to see the count go up.
 */
$test = new WebSite();

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
$test->setTimer(10, function () {
    echo "Current Memory Usage: ".memory_get_usage(). " Peak usage:" .
        memory_get_peak_usage() ."\n";
});
if($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
