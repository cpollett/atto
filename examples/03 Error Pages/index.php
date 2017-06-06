<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

//exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();
/*
    A Simple Atto WebSite used to demonstrate some eror pages
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/
 */
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Error examples - Atto Server</title></head>
    <body>
    <h1>Error examples - Atto Server</h1>
    <ul>
    <li><a href="dkjgakldsfg">A link to a non-existent page</a>.</li>
    <li><a href="local">Allowed on 127.0.0.1 but not on localhost</a>.</li>
    <li><a href="/auth">A Page Requiring Authentication</a>.</li>
    </ul>
    </body>
    </html>
<?php
});
$test->get('/local', function()  use ($test) {
    $host_parts = explode(":", $_SERVER['HTTP_HOST']); //get rid of port number
    if ($host_parts[0] != "127.0.0.1") {
        $test->trigger("ERROR", "/403");
        return;
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>127.0.0.1 - Atto Server</title></head>
    <body>
    <h1>127.0.0.1</h1>
    <div>This page is allowed to be viewed on 127.0.0.1, but forbidden
    on localhost</div>
    </body>
    </html>
<?php
});
/*
    This route is used to handle HTTP 404 not found errors
 */
$test->error('/404', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>File Not Found - Atto Server</title></head>
    <body>
    <h1>File Not Found - Atto Server</h1>
    <p>The requested file could not be found :(
    </p>
    </body>
    </html>
    <?php
});
/*
    This route is used to handle HTTP 403 not found errors
 */
$test->error('/403', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Forbidden - Atto Server</title></head>
    <body>
    <h1>Forbidden- Atto Server</h1>
    <p>You're not allowed to see that page!
    </p>
    </body>
    </html>
    <?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
