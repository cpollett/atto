<?php
require '../../src/GopherSite.php';

use seekquarry\atto as G;

exit(); // you need to comment this line to be able to run this example.
$test = new G\GopherSite();
/*
    A simple GopherSite used to demonstrate the main features of the
    GopherSite class. Many of these features are similar to those of
    the WebSite class.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
    and pointing a gopher client to gopher://localhost:7070/
    Some example gopher clients: Firefox with Overbite extension,
    Lynx.
 */
/*
    Example of middleware for gopher site. These next lines set up a
    callback function which is called on every gopher request before
    processing of that request. In this case, the function logs to stderr
    the time, remote address, and requested selector
 */
openlog("PHP", LOG_PERROR, LOG_USER);
$test->use(function () use ($test)
{
    $log_msg = $_SERVER['REMOTE_ADDR'] . " " .$_SERVER['REQUEST_URI'];
    syslog(LOG_INFO, $log_msg);
});
/*
    Set up a callback to be called when the default selector requested.
    Notice when we escape into PHP's copy mode we don't have to put an i
    in front of informational lines and then add dummy tab fields at the
    end. By default, GopherSite will do this for us. Also, notice, the
    G\link() function calls are used to set up gopher link lines with
    associated text. G\link() can handle simple gopher selectors,
    as well as complete gopher or html urls.
 */
$test->request('/', function() { ?>
=====================================
= Welcome to the Atto Gopher Server =
=   Maintained by Chris Pollett     =
=====================================
<?=G\link('/I/me1.jpg', "Check out my Picture") ?>
<?=G\link('/0/bio.txt', "A Brief Bio") ?>

On This Machine
===============
<?=G\link('/1/addone/0', "Experience the natural numbers one-by-one") ?>
<?=G\link('/7/magic-eight-ball', "Ask The Magic Eight Ball a Question") ?>

Places to Visit:
================
<?=G\link("https://github.com/cpollett/atto",
    "Atto Server GitHub Repository") ?>
<?=G\link("gopher://gopher.floodgap.com/",
    "Floodgap - Gopher Central") ?>
<?=G\link("gopher://gopher.floodgap.com/1/gopher/tech",
    "Technical Info About Gopher") ?>
<?php
});
/*
    Sets up a callback that is called whenever a selector of the
    form /name.file_extension is called. Notice how the values
    that match these components are automatically mapped into PHP's
    $_REQUEST superglobal. In the case of our callback, we see if a
    file with the give name exists in the current directory and if so
    return it. Otherwise, we trigger an error. To prevent the GopherSite
    server from trying to gopherize each line of the file, we add the
    argument true after the callback.
 */
$test->request('/{name}.{file_extension}', function() use ($test) {
    $name = filter_var($_REQUEST["name"], FILTER_SANITIZE_STRING);
    $extension = filter_var($_REQUEST["file_extension"],
        FILTER_SANITIZE_STRING);
    $filename = "$name.$extension";
    if (file_exists($filename)) {
        echo $test->fileGetContents($filename);
    } else {
        $test->trigger("ERROR", "/$name.$extension");
    }
}, true);
/*
    Demo selector showing how we can use the $_REQUEST variable match part of
    the selector to change outgoing links. In this case, we use it to make
    a sequence of gopher pages corresponding to the natural numbers.
 */
$test->request('/addone/{cur_num}', function() {
    $cur_num = empty($_REQUEST['cur_num']) ? 0 : intval($_REQUEST['cur_num']);
    ?>
=====================================
= The Natural Numbers Experience    =
=====================================
You are currently visiting the number:
<?=$cur_num ?>
<?=G\link('/1/addone/' .($cur_num +1), "Experience the next number") ?>
<?=G\link('/', "Back to Root") ?>
<?php
});
/*
    This demostrates how a gopher full text search selector callback can be
    implemented using the GopherSite server. In this case, the response to
    a query is a magic 8 ball answer.
 */
$test->request('/magic-eight-ball', function() {
    $query = empty($_SERVER['QUERY_STRING']) ? "" :
        filter_var($_SERVER['QUERY_STRING'], FILTER_SANITIZE_STRING);
    $another = empty($query) ? "a" : "Another";
    $answers = ["It is certain", "It is decidedly so", "Without a doubt",
        "Yes definitely", "You may rely on it", "As I see it, yes",
        "Most likely", "Outlook good", "Yes", "Signs point to yes",
        "Reply hazy try again", "Ask again later", "Better not tell you now",
        "Cannot predict now", "Concentrate and ask again", "Don't count on it",
        "My reply is no", "My sources say no", "Outlook not so good",
        "Very doubtful"
    ];
    $answer = $answers[mt_rand(0, 19)];
    ?>
=====================================
= MAGIC EIGHT BALL                  =
=====================================
    <?php 
    if ($query) { ?>
You asked: <?=$query ?>

Magic 8 Ball replies: <?=$answer ?>
    <?php
    }
    echo G\link('/7/magic-eight-ball',
        "Ask The Magic Eight Ball $another Question");
});
/*
    Sets up a custom error callback to be displayed in case someone gets
    an error while looking at the selector /foo.foo
    If there is an error, but no custom error callback has been set, then
    GopherSite will use its default error message.
 */
$test->error("/foo.foo", function() {
?>
Hey there!
You won't find any foo.foo on this server!
<?php
});
$test->setTimer(10, function () {
    echo "Current Memory Usage: ".memory_get_usage(). " Peak usage:" .
        memory_get_peak_usage() ."\n";
});
$test->listen(7070);
