<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example.
               under a web server */
}
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
$test->get('/', function()  use ($test) {
    $test->preload('/me1.jpg', 'image'); // sends HTTP/2 pre-fetch header
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>HTTPS Hello World - Atto Server</title></head>
    <body>
    <h1>HTTPS Hello World!</h1>
    <img src="/me1.jpg" alt="a photo of me" />
    <div>My first atto server routes running on HTTPS! This example
        also demos support for HTTP/2 and url pre-fetching.
    </div>
    </body>
    </html>
<?php
});
/*
    SECURITY: see the matching note in examples/02 Serve Static Files.
    The {file_name} capture pattern matches embedded slashes and .. so
    the candidate path must be resolved with realpath and verified to
    be inside the images directory before serving.
 */
$test->get('/{file_name}', function () use ($test) {
        if (!empty($_REQUEST['file_name'])) {
            $base = realpath(__DIR__ . "/../../images");
            $candidate = realpath($base . "/"
                . urldecode($_REQUEST['file_name']));
            $separator = DIRECTORY_SEPARATOR;
            if ($base !== false && $candidate !== false
                && strncmp($candidate, $base . $separator,
                    strlen($base) + 1) === 0
                && is_file($candidate)) {
                $test->header("Content-Type: "
                    . $test->mimeType($candidate));
                echo $test->fileGetContents($candidate);
            } else {
                $test->trigger("ERROR", "/404");
            }
        }
    }
);
if($test->isCli()) {
   $test->listen(8080, ['SERVER_CONTEXT' => ['ssl' => [
      'local_cert' => __DIR__ . "/../../security/server.crt",
                                   /* Self-signed cert - in practice get signed
                                      by some certificate authority
                                   */
      'local_pk' => __DIR__ . "/../../security/server.key", // Private key
      'allow_self_signed' => true,
      'verify_peer' => false,
      "alpn_protocols" => "h2,http/1.1"
      ]]]);
} else {
   $test->process();
}
