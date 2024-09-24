<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

/*
    An Atto WebSite consisting of a form with a text field. Submitting the
    form posts it to a /results page where the submitted data is printed out
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
    <head><title>Post Example - Atto Server</title></head>
    <body>
    <h1>Post Example - Atto Server</h1>
    <form method="post" action="/results">
        <label for="name-field">Enter Name:</label>
       <input id="name-field" type="text" name="name" />
       <input type="submit" value="Submit" />
    </form>
    </body>
    </html>
    <?php
});
$test->post('/results', function ()
{
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Results of Form Post - Atto Server</title></head>
    <body>
    <h1>Results of Form Post - Atto Server</h1>
    <pre>$_POST variable array:
    <?= print_r($_POST); ?>
    $_REQUEST variable array:
    <?= print_r($_REQUEST); ?>
    </pre>
    </body>
    </html>
    <?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
