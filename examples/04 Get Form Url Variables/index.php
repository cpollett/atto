<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

/*
    An Atto WebSite consisting of a form with a text field. Submitting the
    form sends it via GET method to a /results page where the submitted data
    is printed out. After commenting the exit() line above, you can run the
    example by typing:
       php index.php
    and pointing a browser to http://localhost:8080/. Click reload several
    times to see the count go up.
 */
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Get Form Example - Atto Server</title></head>
    <body>
    <form method="get" action="results" >
       <label for="name-field">Enter Name:</label>
       <input id="name-field" type="text" name="name" />
       <input type="submit" value="Submit" />
    </form>
    </body>
    </html>
    <?php
});
/*
    This page shows the values that came from the / route's form.
 */
$test->get('/results', function ()
{
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Results of Get Form - Atto Server</title></head>
    <body>
    <h1>Results of Get Form</h1>
    <pre>$_GET variable array:
    <?= print_r($_GET); ?>
    $_REQUEST variable array:
    <?= print_r($_REQUEST); ?>
    </pre>
    <p><a href="results/some_value">This link shows how variables can
    be computed from match with the url</a>.</p>
    </body>
    </html>
    <?php
});
/*
    This route is followed when a user clicks on the link on the results
    page and shows how matches against the url are turned into $_GET values.
*/
$test->get('/results/{from_the_url}', function ()
{
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Results of Get Form - Atto Server</title></head>
    <body>
    <h1>Results of Get Form</h1>
    <pre>$_GET variable array:
    <?= print_r($_GET); ?>
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
