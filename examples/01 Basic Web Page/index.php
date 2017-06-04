<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // comment this line to be able to run this example.
$test = new WebSite();
/*
    A Simple Atto WebSite used to display a Hello World landing page.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/
 */
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

if($test->isCli()) {
    /*
       This line is used if the app is run from the command line
       with a line like:
       php index.php
       It causes the server to run on port 8080
     */
    $test->listen(8080);
} else {
    /* This line is for when site is run under a web server like
       Apache, nginx, lighttpd, etc. This folder contains a .htaccess
       to redirect traffic through this index.php file. So redirects
       need to be on to use this example under a different web server.
     */
    $test->process();
}
