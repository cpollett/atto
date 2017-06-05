Atto Web Server
===============
Atto is a single file, low dependency, pure PHP web server and web routing
engine.

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
require 'atto_server_path/src/Website.php'; //this line need to be changed

use seekquarry\atto\Website;

$test = new WebSite();
/*
    A Simple Atto WebSite used to display a Hello World landing page.
    After changing the require line above, you can run the example
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
       Apache, nginx, lighttpd, etc. The enclosing folder should contain an
       .htaccess file to redirect traffic through this index.php file. So
       redirects need to be on to use this example under a different web server.
     */
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
require 'atto_server_path/src/Website.php';  //this line need to be changed

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
Requiring ``"vendor/autoload.php"`` should then suffice to allow 
Atto Server to be autoloaded as needed by your code.

More Examples
-------------

The examples folder of this project has a sequence of examples illustrating 
the main features of the Atto Server.

Out of paranoia, at the start of each of these examples there is an ``exit();``
call. This line should be removed or commented to try the example.
