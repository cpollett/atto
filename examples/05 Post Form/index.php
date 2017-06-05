<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Post Example - Atto Server</title></head>
    <body>
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
    <h1>Results of Form Post</h1>
    <pre>$_POST variable array:
    <?= print_r($_POST); ?>
    $_REQUEST variable array:
    <?= print_r($_REQUEST); ?>
    </pre>
    <?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
