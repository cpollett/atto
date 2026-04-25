<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

// exit(); // you need to comment this line to be able to run this example.
$test = new WebSite();

/*
    A Simple Atto WebSite used to display a Hello World landing page using
    HTTPS.
    Make sure php is configured with openssl and ssl is enabled in the php.ini
    file.
    After commenting the exit() line above, you can run this example
    by typing:
       php index.php
    and pointing a browser to https://localhost:8080/
 */
$test->get('/', function() {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>HTTPS Hello World - Atto Server</title></head>
    <body>
    <h1>HTTPS Hello World!</h1>
    <img src="/me1.jpg" alt="a photo of me" />
    <div>My first atto server route running on HTTPS!</div>
    </body>
    </html>
<?php
});
$test->get('/{file_name}', function () use ($test) {
        if(!empty($_REQUEST['file_name'])) {
            $file_name = __DIR__ . "/". urldecode($_REQUEST['file_name']);
            error_log($file_name);
            if (file_exists($file_name)) {
                $test->header("Content-Type: " . $test->mimeType($file_name));
                echo $test->fileGetContents($file_name);
            } else {
                $test->trigger("ERROR", "/404");
            }
        }
    }
);
if($test->isCli()) {
   $test->listen(8080, ['SERVER_CONTEXT' => ['ssl' => [
      'local_cert' => 'server.crt', /* Self-signed cert - in practice get signed
                                      by some certificate authority
                                   */
      'local_pk' => 'server.key', // Private key
      'allow_self_signed' => true,
      'verify_peer' => false,
      "alpn_protocols" => "h2,http/1.1"
      ]]]);
} else {
   $test->process();
}
