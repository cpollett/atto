<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

$test->use(function() use ($test) {
    $host_list = ["localhost:8080" => "/host1", "127.0.0.1:8080" => "/host2",
        "10.1.10.33:8080" => "/host3"];
    $host = (empty($_SERVER['HTTP_HOST']) ||
        !isset($host_list[$_SERVER['HTTP_HOST']])) ? "/host1" :
        $host_list[$_SERVER['HTTP_HOST']];
    $uri = empty($_SERVER['REQUEST_URI']) ? "/" : $_SERVER['REQUEST_URI'];
    $_SERVER['REQUEST_URI'] = $host . $uri;
});
$host1site = new Website();
$host1site->get('/', function() { 
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host1 Site - Atto Server</title></head>
    <body>
    <h1>Host1 Site - Atto Server</h1>
    <div>Welcome to the host 1 site!!</div>
    </body>
    </html>
<?php
});
$test->subsite('/host1', $host1site);

$host2site = new Website();
$host2site->get('/', function() { 
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host2 Site - Atto Server</title></head>
    <body>
    <h1>Host2 Site - Atto Server</h1>
    <div>Welcome to the host 2 site!!</div>
    </body>
    </html>
<?php
});
$test->subsite('/host2', $host2site);

$host2site = new Website();
$host2site->get('/', function() { 
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Host3 Site - Atto Server</title></head>
    <body>
    <h1>Host3 Site - Atto Server</h1>
    <div>Welcome to the host 3 site!!</div>
    </body>
    </html>
<?php
});
$test->subsite('/host3', $host2site);

if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
