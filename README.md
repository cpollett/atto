Atto Web Server
===============
Atto is a single file, low dependency, pure PHP web server and web routing engine.

 * Atto can be used to route requests, and hence, serve as a micro
 framework for use under a traditional web server such as Apache, nginx,
 or lighttpd. 
 
 * Atto can be used as a standalone web server for apps 
 created using its routing facility. 
 
 * Atto is web request event-driven, supporting
 asynchronous I/O for web traffic.
 
 * Unlike similar PHP software, as a Web Server, it instantiates traditional
 PHP superglobals like $_GET, $_POST, $_REQUEST, $_COOKIE, $_SESSION,
 $_FILES, etc and endeavors to make it easy to code apps in a rapid PHP style.
 
As a standalone Web Server:

 * Atto supports timers for background events.
 * Atto handles sessions in RAM.
 * Atto has File I/O methods fileGetContents and filePutContents which cache
   files using the Marker algorithm.
 
Usage
-----------
```php
<?php
require 'path_to_atto_server_code/src/Website.php'; //this line would need to be adjusted

use seekquarry\atto\Website;

$test = new WebSite();

$test->get('/', function() {
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
$test->get('/images/{file_name}', function () use ($test) {
        $file_name = __DIR__ . "/images/" . urldecode($_REQUEST['file_name']);
        if (file_exists($file_name)) {
            $test->header("Content-Type: " . $this->mimeType($file_name));
            echo $test->fileGetContents($file_name);
        } else {
            $test->trigger("ERROR", "/404");
        }
    }
);
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
```
 
Installation
------------

Atto Server has been tested on PHP 5.5, PHP 7, and HHVM. HTTPS support does 
not currently work under HHVM.

To install the software one should have PHP installed. One can then git clone 
the project or download the ZIP file off of GitHub.

To use Atto Server in your project, add the lines:
```php
require 'path_to_atto_server_code/src/Website.php'; //this line would need to be adjusted

use seekquarry\atto\Website;
```
to the top of your project file. If you don't have the ``use`` line, then to
refer to the Website class you would need to add the whole namespace path.
For example,
```php
$test = new seekquarry\atto\Website();
```

If you use composer, you can require Atto Server using the command:
```
composer require seekquarry/atto
```
You should then do ``composer install`` or ``composer update``.
Requiring "vendor/autoload.php" should then suffice to allow 
Atto Server to be autoloaded as needed by your code.

More Examples
-------------

The examples folder of this project has a sequence of examples illustrating 
the main features of the Atto Server.

Out of paranoia, each of these files has a call to exit(); at the start of it,
so won't run unless you comment this line out.
