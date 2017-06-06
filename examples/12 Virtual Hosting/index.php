<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();
/*
    An Atto WebSite consisting of landing pages for three different host.
    The middleware below is used to determine which host a user came in on.
    Then three subsites have been added to the $test website, one for each
    host to handle traffic to that host. To run this example, use ifconfig
    or ipconfig to dtermine your ip address on your LAN and edi the
    $host_list value for the thrid entry appropriately. In the real world
    you could use different hostnames you had paid for $host_list
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/ or
    http://127.0.0.1:8080/ or http://your_lan_ip_address:8080/.
 */
$test->use(function() use ($test) {
    $host_list = ["localhost" => "/host1", "127.0.0.1" => "/host2",
        "10.1.10.33" => "/host3"];
    $host_parts = explode(":", $_SERVER['HTTP_HOST']); //get rid of port number
    $host = (!isset($host_list[$host_parts[0]])) ? "/host1" :
        $host_list[$host_parts[0]];
    $uri = empty($_SERVER['REQUEST_URI']) ? "/" : $_SERVER['REQUEST_URI'];
    $active_uri = substr($uri, $test->base_path - 1);
    $_SERVER['REQUEST_URI'] = urldecode($test->base_path . $host . $active_uri);
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

$host3site = new Website();
$host3site->get('/', function() { 
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
$test->subsite('/host3', $host3site);
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
