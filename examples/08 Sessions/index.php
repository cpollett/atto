<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

/*
    A Simple Atto WebSite used to implement a simple counter with sessions
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/. Click reload several
    times to see the count go up.
 */
$test->get('/', function() use ($test) {
    $test->sessionStart();
    if (empty($_SESSION['COUNT'])) {
        $_SESSION['COUNT'] = 0;
    }
    $_SESSION['COUNT']++;
    ?><!DOCTYPE html>
    <html>
    <head><title>Session Example - Atto Server</title></head>
    <body>
    <h1>Session Example - Atto Server</h1>
    <div>Current Count:<?=$_SESSION['COUNT']; ?></div>
    </body>
    </html>
<?php
});
if($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
