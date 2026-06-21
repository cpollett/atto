<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
$test = new WebSite();

/*
    An Atto WebSite consisting of a form with a text field. Submitting the
    form posts it to a /post-handler page where a cookie with name
    your_number and whose value is the value posted is set. Then a
    301 redirect is performed using HTTP headers. Finally, a page is getted
    where the value of the cookie is printed.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/. Click reload several
    times to see the count go up.
 */
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Header Redirect Cookie Example - Atto Server</title></head>
    <body>
    <h1>Header Redirect Cookie Example - Atto Server</h1>
    <form method="post" action="post-handler">
        <label for="name-field">Enter a Number:</label>
       <input id="name-field" type="text" name="number" />
       <input type="submit" value="Submit" />
    </form>
    </body>
    </html>
    <?php
});

$test->post('/post-handler', function () use ($test) {
    $your_number = empty($_POST['number']) ? 0 : $_POST['number'];
    $test->setCookie("your_number", $your_number);
    $test->header("HTTP/1.1 301 Moved Permanently");
    $test->header("Location: see-your-value");
});

$test->get('/see-your-value', function() {
    $your_number = empty($_COOKIE['your_number']) ? 0 : $_COOKIE['your_number'];
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Your Number - Atto Server</title></head>
    <h1>Your Number - Atto Server</h1>
    <p>The number posted from the form was: <?= $your_number ?></p>
    <p>Since a post-redirect-get pattern was used, the browser back button
    should work okay.</p>
    </body>
    </html>
    <?php
});

if($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
