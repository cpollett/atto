<?php
require '../../src/Website.php';

use seekquarry\atto\Website;

exit(); // comment this line to be able to run this example.
$test = new WebSite();
/*
    A WebSite used to illustrate how static files can be served as part of
    an Atto site.

    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/
 */
$test->get('/', function() use ($test) {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Serve Static Files Example - Atto Server</title></head>
    <body>
    <h1>Serve Static Files - Atto Server</h1>
    <div>Here is an image which will be served by using a different
    route within this application:<br />
    <img src="images/me1.jpg" alt="a photo of me" />
    </div>
    <div>Below are a list of links to files in an images subfolder.
    The last file list does not exists.</div>
    <ul>
    <li><a href="images/me1.jpg">Photo 1</a></li>
    <li><a href="images/me2.jpg">Photo 2</a></li>
    <li><a href="images/me3.jpg">Photo 3</a></li>
    </ul>
    </body>
    </html>
    <?php
});
/*
    Static files from the images subfolder will be served using this route.

    # Notice our callback has "use ($test)" after the function (). This
      gives access to the $test object within the callback.
    # The route is '/images/{file_name}' this will match any request such
      as /images/foo and set up a file_name field in the $_GET and $_REQUEST
      superglobals with the matched text. I.e., $_REQUEST['file_name'] = foo
    # The WebSite methods header() and fileGetContents() used below correspond
      to the PHP functions header() and file_get_contents, but work for
      an Atto WebSite both under another websrever and when the site is being
      run standalone from the command line.
    # The WebSite trigger() method can be used to invoke a different route
      Here if the file is not found we trigger a route to a file not found page
 */
$test->get('/images/{file_name}', function () use ($test) {
        $file_name = __DIR__ . "/images/" . urldecode($_REQUEST['file_name']);
        if (file_exists($file_name)) {
            $test->header("Content-Type: ".mime_content_type($file_name));
            echo $test->fileGetContents($file_name);
        } else {
            $test->trigger("ERROR", "/404");
        }
    }
);
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

if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
