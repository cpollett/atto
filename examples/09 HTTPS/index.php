<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

/*
    A Simple Atto WebSite used to display a Hello World landing page using
    HTTPS. 
    Make sure php is configured with openssl and ssl is enabled in the php.ini
    file.
    After commenting the exit() line above, you can run this example
    by typing:
       php index.php
    and pointing a browser to http://localhost:8080/
 */
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>HTTPS Hello World - Atto Server</title></head>
    <body>
    <h1>HTTPS Hello World!</h1>
    <div>My first atto server route running on HTTPS!</div>
    </body>
    </html>
<?php
});

if($test->isCli()) {
     $test->listen(8080, ['SERVER_CONTEXT' => ['ssl' => [
    'local_cert' => 'cert.pem', /* Self-signed cert - in practice get signed
                                    by some certificate authority
                                 */
    'local_pk' => 'key.pem', // Private key
    'allow_self_signed' => true,
    'verify_peer' => false
    ]]]);
} else {
    $test->process();
}
