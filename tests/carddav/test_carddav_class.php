<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the CardDav class. The first group checks the
 * pure helpers in memory with no disk touched: the entity-tag
 * computation, the readers that pull a display name out of a
 * request body and tell an address-book MKCOL from a plain one,
 * the prefix stripping that turns a URL into a book path, and the
 * rule for which directory entries count as contacts. The second
 * group drives the verb handlers over a scratch folder to check
 * the lifecycle end to end: make an address book, list it, store a
 * contact, refuse a clashing create, read it back, overwrite it
 * under a matching tag, and delete it. Those handler checks touch
 * disk on purpose, since storage is what they are about.
 *
 * Run from the repo root:
 *     php tests/carddav/test_carddav_class.php
 *
 * Exits 0 on full pass, 1 on any failure.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

require __DIR__ . '/../../src/WebSite.php';
require __DIR__ . '/../../src/CardDav.php';

$tests = 0;
$pass = 0;
/**
 * Records one assertion result and prints a line for it. Keeps a
 * running count so the summary at the end can report totals.
 *
 * @param string $name short description of what is being checked
 * @param bool $cond true when the check held
 */
function ok($name, $cond)
{
    global $tests, $pass;
    $tests++;
    if ($cond) {
        $pass++;
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n";
    }
}

/**
 * A WebSite stand-in for driving CardDav handlers without a live
 * server. It records the headers a handler sends so a test can
 * read back the status, and it reads and writes files plainly so
 * there is no cache state to reason about between steps.
 */
class CardDavProbeSite extends WebSite
{
    /**
     * Headers the handler under test has sent, in order.
     * @var array
     */
    public $sent_headers = [];

    /**
     * Records a header instead of sending it to a client.
     *
     * @param string $header the header line
     */
    public function header($header)
    {
        $this->sent_headers[] = $header;
    }

    /**
     * Reads a file plainly, bypassing the caching reader so a test
     * sees exactly what is on disk.
     *
     * @param string $filename the file to read
     * @param bool $force ignored; kept to match the parent
     * @return string the file's contents
     */
    public function fileGetContents($filename, $force = false)
    {
        return file_get_contents($filename);
    }

    /**
     * Writes a file plainly, bypassing the caching writer.
     *
     * @param string $filename the file to write
     * @param string $data the bytes to write
     * @return int|false bytes written, or false on failure
     */
    public function filePutContents($filename, $data)
    {
        return file_put_contents($filename, $data);
    }

    /**
     * Clears the recorded headers before the next handler call.
     */
    public function reset()
    {
        $this->sent_headers = [];
    }

    /**
     * Reports the numeric status of the last status line the
     * handler sent, or 0 when it sent none.
     *
     * @return int the status code
     */
    public function status()
    {
        $code = 0;
        foreach ($this->sent_headers as $header) {
            if (preg_match("#^HTTP/\\d\\.\\d\\s+(\\d+)#", $header,
                $matches)) {
                $code = (int)$matches[1];
            }
        }
        return $code;
    }

    /**
     * Reports the value of the last header with the given name the
     * handler sent, or an empty string when it sent none.
     *
     * @param string $name the header name to look for
     * @return string the header value
     */
    public function headerValue($name)
    {
        $value = "";
        $prefix = strtolower($name) . ":";
        foreach ($this->sent_headers as $header) {
            if (strncasecmp($header, $prefix, strlen($prefix)) === 0) {
                $value = trim(substr($header, strlen($prefix)));
            }
        }
        return $value;
    }
}

/**
 * Sets the current request as the handlers read it, clearing the
 * conditional write headers unless the caller passes them.
 *
 * @param string $uri the request URI
 * @param string $content the request body
 * @param array $extra extra $_SERVER entries, such as HTTP_DEPTH
 */
function request($uri, $content = "", $extra = [])
{
    $_SERVER['REQUEST_URI'] = $uri;
    $_SERVER['CONTENT'] = $content;
    $_SERVER['SERVER_PROTOCOL'] = "HTTP/1.1";
    unset($_SERVER['HTTP_DEPTH'], $_SERVER['HTTP_IF_MATCH'],
        $_SERVER['HTTP_IF_NONE_MATCH']);
    foreach ($extra as $name => $value) {
        $_SERVER[$name] = $value;
    }
}

/**
 * Runs a handler with output capturing on, returning what it
 * echoed so a test can inspect the multi-status body.
 *
 * @param callable $handler the handler to run
 * @return string whatever the handler echoed
 */
function capture($handler)
{
    ob_start();
    $handler();
    return ob_get_clean();
}

$prefix = "/addressbooks";
$book_body = '<D:mkcol xmlns:D="DAV:" ' .
    'xmlns:CARD="urn:ietf:params:xml:ns:carddav"><D:set><D:prop>' .
    '<D:resourcetype><D:collection/><CARD:addressbook/></D:resourcetype>' .
    '<D:displayname>Contacts</D:displayname></D:prop></D:set></D:mkcol>';
$alice = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:alice\r\n" .
    "FN:Alice Example\r\nEMAIL:alice@example.com\r\nEND:VCARD\r\n";

/*
    -----------------------------------------------------------
    Pure helpers, no disk touched
    -----------------------------------------------------------
 */
$site = new CardDavProbeSite(".");
$scratch = sys_get_temp_dir() . "/atto_carddav_" . getmypid();
$dav = new CardDav($site, $scratch, $prefix);

/* Test 1: the entity tag is a quoted hash that tracks the bytes. */
$tag_one = $dav->computeETag("one");
$tag_two = $dav->computeETag("two");
ok("entity tag is quoted and changes with the bytes",
    $tag_one[0] === '"' && substr($tag_one, -1) === '"' &&
    $tag_one !== $tag_two);

/* Test 2: the display-name reader pulls the name from a body. */
ok("display name is read from the request body",
    $dav->parseDisplayName($book_body) === "Contacts" &&
    $dav->parseDisplayName("<D:mkcol/>") === "");

/* Test 3: an address-book MKCOL body is told from a plain one. */
ok("an address-book MKCOL body is recognized",
    $dav->bodyMakesAddressbook($book_body) === true &&
    $dav->bodyMakesAddressbook("<D:mkcol xmlns:D=\"DAV:\"/>") === false);

/* Test 4: the URL-to-path stripping. */
ok("the route prefix is stripped to a book path",
    $dav->resourceForUri("$prefix/work/alice.vcf") === "work/alice.vcf" &&
    $dav->resourceForUri($prefix) === "");

/* Test 5: which directory entries count as contacts. */
ok("only visible .vcf files count as contacts",
    $dav->isResourceName("alice.vcf") === true &&
    $dav->isResourceName(CardDav::META_FILE) === false &&
    $dav->isResourceName("..") === false &&
    $dav->isResourceName("notes.txt") === false);

/* Test 6: a path that would escape the folder is refused. */
$dav = new CardDav($site, $scratch, $prefix);
ok("a path escaping the address-book folder is refused",
    $dav->containedPath("../outside.vcf") === false);

/*
    -----------------------------------------------------------
    Verb lifecycle over a scratch address-book folder
    -----------------------------------------------------------
 */
$real_root = realpath($scratch);
$dav = new CardDav($site, $real_root, $prefix);

/* Test 7: MKCOL with an address-book body makes a book. */
$site->reset();
request("$prefix/work", $book_body);
$dav->handleMkcol();
$work = $real_root . "/work";
ok("MKCOL with an address-book body makes an address book",
    $site->status() === 201 && $dav->isAddressbook($work) &&
    $dav->displayNameFor($work) === "Contacts");

/* Test 8: MKCOL on a name that is taken answers 405. */
$site->reset();
request("$prefix/work", $book_body);
$dav->handleMkcol();
ok("MKCOL on an existing collection answers 405",
    $site->status() === 405);

/* Test 9: PUT stores a new contact and returns its tag. */
$site->reset();
request("$prefix/work/alice.vcf", $alice);
$dav->handlePut();
ok("PUT stores a new contact and answers 201 with a tag",
    $site->status() === 201 &&
    $site->headerValue("ETag") === $dav->computeETag($alice) &&
    is_file($work . "/alice.vcf"));

/* Test 10: GET serves the contact back as vCard. */
$site->reset();
request("$prefix/work/alice.vcf");
$served = capture([$dav, "handleGet"]);
ok("GET serves the contact as vCard with its tag",
    $site->status() === 200 && $served === $alice &&
    strpos($site->headerValue("Content-Type"), "text/vcard") === 0 &&
    $site->headerValue("ETag") === $dav->computeETag($alice));

/* Test 11: a create-only PUT over an existing contact is refused. */
$site->reset();
request("$prefix/work/alice.vcf", $alice, ["HTTP_IF_NONE_MATCH" => "*"]);
$dav->handlePut();
ok("a create-only PUT over an existing contact answers 412",
    $site->status() === 412);

/* Test 12: PROPFIND at depth 0 reports the book's properties. */
$site->reset();
request("$prefix/work", "", ["HTTP_DEPTH" => "0"]);
$book_reply = capture([$dav, "handlePropfind"]);
ok("PROPFIND on a book reports it as an address book",
    $site->status() === 207 &&
    strpos($book_reply, "<CARD:addressbook/>") !== false &&
    strpos($book_reply, "supported-address-data") !== false &&
    strpos($book_reply, "<CS:getctag>") !== false &&
    strpos($book_reply, "<D:displayname>Contacts</D:displayname>") !==
    false);

/* Test 13: PROPFIND at depth 1 lists the contact. */
$site->reset();
request("$prefix/work", "", ["HTTP_DEPTH" => "1"]);
$listing = capture([$dav, "handlePropfind"]);
ok("PROPFIND at depth 1 lists the contact with a tag",
    strpos($listing, "$prefix/work/alice.vcf") !== false &&
    strpos($listing, "<D:getetag>") !== false);

/* Test 14: an overwrite under the matching tag succeeds. */
$updated = str_replace("Alice Example", "Alice E.", $alice);
$site->reset();
request("$prefix/work/alice.vcf", $updated,
    ["HTTP_IF_MATCH" => $dav->computeETag($alice)]);
$dav->handlePut();
ok("an overwrite under the matching tag answers 204",
    $site->status() === 204);

/* Test 15: an overwrite under a stale tag is refused. */
$site->reset();
request("$prefix/work/alice.vcf", $alice,
    ["HTTP_IF_MATCH" => $dav->computeETag("stale")]);
$dav->handlePut();
ok("an overwrite under a stale tag answers 412",
    $site->status() === 412);

/* Test 16: DELETE removes the contact; a later GET is a 404. */
$site->reset();
request("$prefix/work/alice.vcf");
$dav->handleDelete();
$after = $site->status();
$site->reset();
request("$prefix/work/alice.vcf");
capture([$dav, "handleGet"]);
ok("DELETE removes the contact and a later GET answers 404",
    $after === 204 && $site->status() === 404);

/* Test 17: a plain MKCOL makes a folder that is not a book. */
$site->reset();
request("$prefix/plain", "");
$dav->handleMkcol();
$plain = $real_root . "/plain";
ok("a plain MKCOL makes a folder that is not an address book",
    $site->status() === 201 && is_dir($plain) &&
    !$dav->isAddressbook($plain));

/* Test 18: the status line carries the request's protocol. */
$site->reset();
request("$prefix/none.vcf");
$_SERVER['SERVER_PROTOCOL'] = "HTTP/2.0";
capture([$dav, "handleGet"]);
$line_two = "";
foreach ($site->sent_headers as $header) {
    if (strncmp($header, "HTTP/", 5) === 0) {
        $line_two = $header;
    }
}
$_SERVER['SERVER_PROTOCOL'] = "HTTP/1.1";
ok("the status line carries the request's protocol",
    strncmp($line_two, "HTTP/2.0 404 ", 13) === 0);

/**
 * Removes a file, or a folder and everything under it, so the
 * test leaves nothing behind on disk.
 *
 * @param string $path the disk path to remove
 */
function removeTree($path)
{
    if (is_dir($path)) {
        foreach (scandir($path) as $entry) {
            if ($entry !== "." && $entry !== "..") {
                removeTree($path . "/" . $entry);
            }
        }
        rmdir($path);
        return;
    }
    if (is_file($path)) {
        unlink($path);
    }
}
removeTree($scratch);

echo "\nTests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
