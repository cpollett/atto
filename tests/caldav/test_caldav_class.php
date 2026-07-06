<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the CalDav class. The first group checks the
 * pure helpers in memory with no disk touched: the entity-tag
 * computation, the small readers that pull a display name and
 * component set out of a MKCALENDAR body, the prefix stripping
 * that turns a URL into a calendar path, and the rule for which
 * directory entries count as events. The second group drives the
 * verb handlers over a scratch calendar folder to check the
 * lifecycle end to end: make a calendar, list it, store an event,
 * refuse a clashing create, read it back, overwrite it under a
 * matching tag, and delete it. Those handler checks touch disk on
 * purpose, since storage is what they are about.
 *
 * Run from the repo root:
 *     php tests/caldav/test_caldav_class.php
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
require __DIR__ . '/../../src/CalDav.php';

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
 * A WebSite stand-in for driving CalDav handlers without a live
 * server. It records the headers a handler sends so a test can
 * read back the status, and it reads and writes files plainly so
 * there is no cache state to reason about between steps.
 */
class CalDavProbeSite extends WebSite
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
     * Reports the last full status line the handler sent, or an
     * empty string when it sent none, so a test can check the
     * protocol token the status line carried.
     *
     * @return string the status line
     */
    public function statusLine()
    {
        $line = "";
        foreach ($this->sent_headers as $header) {
            if (preg_match("#^HTTP/\\d\\.\\d\\s+\\d+#", $header)) {
                $line = $header;
            }
        }
        return $line;
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

$prefix = "/calendars";

/*
    -----------------------------------------------------------
    Pure helpers: entity tags
    -----------------------------------------------------------
 */
$site = new CalDavProbeSite(".");
$scratch = sys_get_temp_dir() . "/atto_caldav_" . getmypid();
$dav = new CalDav($site, $scratch, $prefix);

/* Test 1: an entity tag is the quoted sha256 of the bytes. */
ok("entity tag is the quoted content hash",
    $dav->computeETag("hello") === '"' . hash("sha256", "hello") . '"');

/* Test 2: different bytes give a different tag. */
ok("entity tag changes with content",
    $dav->computeETag("a") !== $dav->computeETag("b"));

/*
    -----------------------------------------------------------
    Pure helpers: reading a MKCALENDAR body
    -----------------------------------------------------------
 */
$mkbody = '<?xml version="1.0" encoding="utf-8"?>' .
    '<C:mkcalendar xmlns:D="DAV:" ' .
    'xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop>' .
    '<D:displayname>Work &amp; Home</D:displayname>' .
    '<C:supported-calendar-component-set>' .
    '<C:comp name="VEVENT"/><C:comp name="VTODO"/>' .
    '</C:supported-calendar-component-set>' .
    '</D:prop></D:set></C:mkcalendar>';

/* Test 3: the display name is read and its entities decoded. */
ok("display name is read from a MKCALENDAR body",
    $dav->parseDisplayName($mkbody) === "Work & Home");

/* Test 4: a body with no display name yields an empty string. */
ok("a missing display name reads as empty",
    $dav->parseDisplayName("<C:mkcalendar/>") === "");

/* Test 5: the component set is read as the listed component names. */
ok("component set is read from a MKCALENDAR body",
    $dav->parseComponentSet($mkbody) === ["VEVENT", "VTODO"]);

/* Test 6: a body listing no components falls back to the defaults. */
ok("a missing component set falls back to defaults",
    $dav->parseComponentSet("<C:mkcalendar/>") === ["VEVENT", "VTODO"]);

/*
    -----------------------------------------------------------
    Pure helpers: URL to calendar path, and event names
    -----------------------------------------------------------
 */

/* Test 7: a path under the prefix drops the prefix. */
ok("a URL under the prefix reads as its calendar path",
    $dav->resourceForUri("/calendars/work/e1.ics") === "work/e1.ics");

/* Test 8: the bare prefix reads as the empty path. */
ok("the bare prefix reads as the empty path",
    $dav->resourceForUri("/calendars") === "");

/* Test 9: a query string is dropped from the path. */
ok("a query string is dropped from the path",
    $dav->resourceForUri("/calendars/work?export=1") === "work");

/* Test 10: a visible .ics file is an event; the metadata file,
   dot entries, and other files are not. */
ok("an .ics file counts as an event",
    $dav->isResourceName("e1.ics") === true &&
    $dav->isResourceName(".calendar.json") === false &&
    $dav->isResourceName("notes.txt") === false &&
    $dav->isResourceName("..") === false);

/*
    -----------------------------------------------------------
    Storage guard: a path cannot escape the calendar folder
    -----------------------------------------------------------
 */
if (!is_dir($scratch)) {
    mkdir($scratch, 0777, true);
}
$real_root = realpath($scratch);
$dav = new CalDav($site, $real_root, $prefix);

/* Test 11: a path inside the folder resolves inside it. */
$inside = $dav->containedPath("work");
ok("a path inside the folder is allowed",
    $inside !== false &&
    strncmp($inside, $real_root, strlen($real_root)) === 0);

/* Test 12: a path that climbs out of the folder is refused. */
ok("a path escaping the folder is refused",
    $dav->containedPath("../outside") === false);

/*
    -----------------------------------------------------------
    Lifecycle over a scratch folder: the verb handlers
    -----------------------------------------------------------
 */

/* Test 13: MKCALENDAR makes the calendar folder and its metadata. */
$site->reset();
request("$prefix/work", $mkbody);
$dav->handleMkcalendar();
$work = $real_root . "/work";
ok("MKCALENDAR creates a calendar folder with metadata",
    $site->status() === 201 && $dav->isCalendar($work) &&
    $dav->displayNameFor($work) === "Work & Home");

/* Test 14: PROPFIND on the calendar reports it as a calendar with
   its change tag and component set. */
$site->reset();
request("$prefix/work", "", ["HTTP_DEPTH" => "0"]);
$out = capture([$dav, "handlePropfind"]);
ok("PROPFIND reports the folder as a calendar",
    $site->status() === 207 &&
    strpos($out, "<C:calendar/>") !== false &&
    strpos($out, "<CS:getctag>") !== false &&
    strpos($out, '<C:comp name="VEVENT"/>') !== false);

/* Test 15: PUT with If-None-Match "*" stores a new event as 201
   and returns its entity tag. */
$event = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:1\r\n" .
    "END:VEVENT\r\nEND:VCALENDAR\r\n";
$site->reset();
request("$prefix/work/e1.ics", $event, ["HTTP_IF_NONE_MATCH" => "*"]);
$dav->handlePut();
ok("PUT creates a new event and returns its tag",
    $site->status() === 201 &&
    is_file($work . "/e1.ics") &&
    $site->headerValue("ETag") === $dav->computeETag($event));

/* Test 16: PUT with If-None-Match "*" on an event that now exists
   is refused as a precondition failure. */
$site->reset();
request("$prefix/work/e1.ics", $event, ["HTTP_IF_NONE_MATCH" => "*"]);
$dav->handlePut();
ok("a create-only PUT over an existing event fails 412",
    $site->status() === 412);

/* Test 17: GET returns the stored bytes, the calendar type, and
   the entity tag. */
$site->reset();
request("$prefix/work/e1.ics");
$out = capture([$dav, "handleGet"]);
ok("GET returns the event bytes, type, and tag",
    $site->status() === 200 && $out === $event &&
    strpos($site->headerValue("Content-Type"), "text/calendar") === 0 &&
    $site->headerValue("ETag") === $dav->computeETag($event));

/* Test 18: PROPFIND at Depth 1 lists the event with its tag. */
$site->reset();
request("$prefix/work", "", ["HTTP_DEPTH" => "1"]);
$out = capture([$dav, "handlePropfind"]);
ok("PROPFIND Depth 1 lists the event with its tag",
    strpos($out, "/calendars/work/e1.ics") !== false &&
    strpos($out, $dav->computeETag($event)) !== false);

/* Test 19: PUT with a matching If-Match overwrites as 204. */
$updated = $event . "X-EXTRA:1\r\n";
$site->reset();
request("$prefix/work/e1.ics", $updated,
    ["HTTP_IF_MATCH" => $dav->computeETag($event)]);
$dav->handlePut();
ok("PUT with a matching If-Match overwrites as 204",
    $site->status() === 204 &&
    file_get_contents($work . "/e1.ics") === $updated);

/* Test 20: PUT with a stale If-Match is refused as 412. */
$site->reset();
request("$prefix/work/e1.ics", "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
    ["HTTP_IF_MATCH" => $dav->computeETag($event)]);
$dav->handlePut();
ok("PUT with a stale If-Match fails 412",
    $site->status() === 412 &&
    file_get_contents($work . "/e1.ics") === $updated);

/* Test 21: DELETE removes the event, and a later GET is 404. */
$site->reset();
request("$prefix/work/e1.ics");
$dav->handleDelete();
$deleted = !is_file($work . "/e1.ics") && $site->status() === 204;
$site->reset();
request("$prefix/work/e1.ics");
capture([$dav, "handleGet"]);
ok("DELETE removes the event and a later GET is 404",
    $deleted && $site->status() === 404);

/*
    -----------------------------------------------------------
    The status line carries the request's own protocol
    -----------------------------------------------------------
 */

/* Test 22: the same handler labels its status line HTTP/1.1,
   HTTP/2.0, or HTTP/3.0 to match the protocol the request came in
   on, so no version is wired into the handler. OPTIONS is used
   since it always answers and does not depend on disk state. */
$site->reset();
request("$prefix/work", "", ["SERVER_PROTOCOL" => "HTTP/1.1"]);
$dav->handleOptions();
$line_one = $site->statusLine();
$site->reset();
request("$prefix/work", "", ["SERVER_PROTOCOL" => "HTTP/2.0"]);
$dav->handleOptions();
$line_two = $site->statusLine();
$site->reset();
request("$prefix/work", "", ["SERVER_PROTOCOL" => "HTTP/3.0"]);
$dav->handleOptions();
$line_three = $site->statusLine();
ok("the status line carries the request's protocol",
    strncmp($line_one, "HTTP/1.1 200 ", 13) === 0 &&
    strncmp($line_two, "HTTP/2.0 200 ", 13) === 0 &&
    strncmp($line_three, "HTTP/3.0 200 ", 13) === 0);

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
    if (file_exists($path)) {
        unlink($path);
    }
}
removeTree($real_root);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
