<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

$test->get('/', function ()
{ ?>
    <!DOCTYPE html>
    <html>
    <head><title>File Upload Example - Atto Server</title></head>
    <body>
    <h1>File Upload Example - Atto Server</h1>
    <form enctype="multipart/form-data" method="post" >
       <input type="hidden" name="MAX_FILE_SIZE" value="1000000" />
       <!-- The size is also controlled by php.ini -->
       <input type="file" name="docname" />
       <input type="submit" name="bob" value="Upload" />
    </form>
    </body>
    </html>
<?php
});
$test->post('/', function () use ($test)
{
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>File After Upload - Atto Server</title></head>
    <body>
    <h1>File After Upload - Atto Server</h1>
    <h2>Posted variables:</h2>
    <pre>
    <?= print_r($_POST); ?>
    </pre>
    <h2>Uploaded file info:</h2>
    <pre>
    <?= print_r($_FILES); ?>
    </pre>
    <p>The uploaded file could then be to the desired location using
    the $test->movedUploadedFile() method.</p>
    </body>
    </html>
    <?php
});
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
