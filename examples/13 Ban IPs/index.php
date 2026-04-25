<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    This middleware is used to check if the request is coming from a
    banned IP address, if so, the reequest method and uri is changed so as
    to generate a 403 FORBIDDEN response.
 */
$test->middleware(function () use ($test)
{
    if (empty($test->bad_ips)) {
        $test->bad_ips = [];
    }
    if(in_array($_SERVER['REMOTE_ADDR'], $test->bad_ips)) {
        $_SERVER['REQUEST_METHOD'] = "ERROR";
        $_SERVER['REQUEST_URI'] = $test->base_path . "/403";
    }
});
/*
    Default page has a simple session counter on it. When the count exceeds 5
    the request ip is banned.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/.
 */
$test->get('/', function() use ($test) {
    $test->sessionStart();
    if (empty($_SESSION['COUNT'])) {
        $_SESSION['COUNT'] = 0;
    }
    $_SESSION['COUNT']++;
    if ($_SESSION['COUNT'] >= 5) {
        $test->bad_ips[] = $_SERVER['REMOTE_ADDR'];
    }
    ?><!DOCTYPE html>
    <html>
    <head><title>Ban IP Example - Atto Server</title></head>
    <body>
    <h1>Ban IP Example - Atto Server</h1>
    <div>If you reload the page more than 5 times your IP gets blocked
    using a middleware callback.</div>
    <div>Current Count:<?=$_SESSION['COUNT']; ?></div>
    </body>
        </html>
<?php
});

$test->error('/403', function () {
    echo "bad ip address!";
}
);
if($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
