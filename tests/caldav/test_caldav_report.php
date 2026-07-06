<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the CalDAV REPORT verb and the iCalendar reading
 * it needs. The first group checks the pure readers in memory: the
 * date and duration parsing, the component listing, the event
 * start-and-end reading, the overlap test, and the small readers
 * that pull a component, a time range, and an href list out of a
 * REPORT body. The second group drives the two reports over a
 * scratch calendar seeded with events at known times: a
 * calendar-query narrowed by time range and by component type, and
 * a calendar-multiget naming events, one of them missing. Those
 * report checks touch disk on purpose, since reading stored events
 * is what they are about.
 *
 * Run from the repo root:
 *     php tests/caldav/test_caldav_report.php
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
 * server. It records the headers a handler sends so a test can read
 * the status, and reads and writes files plainly so there is no
 * cache state to reason about between steps.
 */
class CalDavReportProbe extends WebSite
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
     * Reads a file plainly, bypassing the caching reader.
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
     * Reports the numeric status of the last status line the handler
     * sent, or 0 when it sent none.
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
}

/**
 * Sets the current request as the handlers read it.
 *
 * @param string $uri the request URI
 * @param string $content the request body
 */
function request($uri, $content = "")
{
    $_SERVER['REQUEST_URI'] = $uri;
    $_SERVER['CONTENT'] = $content;
    $_SERVER['SERVER_PROTOCOL'] = "HTTP/1.1";
}

/**
 * Runs a handler with output capturing on, returning what it echoed
 * so a test can inspect the multi-status body.
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

/**
 * Builds a one-event VCALENDAR wrapping the given inner lines, with
 * CRLF line endings the way stored calendar objects use.
 *
 * @param string $inner the component lines to wrap
 * @return string the iCalendar text
 */
function vcalendar($inner)
{
    $eol = "\x0D\x0A";
    return "BEGIN:VCALENDAR" . $eol . $inner . $eol . "END:VCALENDAR" .
        $eol;
}

$prefix = "/calendars";
$scratch = sys_get_temp_dir() . "/atto_caldav_report_" . getmypid();
$site = new CalDavReportProbe(".");
$dav = new CalDav($site, $scratch, $prefix);

/*
    -----------------------------------------------------------
    Pure readers: dates and durations
    -----------------------------------------------------------
 */

/* Test 1: a UTC date-time parses to the right instant. */
ok("a UTC date-time parses to its instant",
    $dav->parseIcalTime("20260115T130000Z") ===
    gmmktime(13, 0, 0, 1, 15, 2026));

/* Test 2: a bare DATE parses to midnight UTC that day. */
ok("a DATE value parses to midnight UTC",
    $dav->parseIcalTime("20260115") === gmmktime(0, 0, 0, 1, 15, 2026));

/* Test 3: a whole property line parses by its value after the
   colon. */
ok("a property line parses by its value",
    $dav->parseIcalTime("DTSTART:20260115T130000Z") ===
    gmmktime(13, 0, 0, 1, 15, 2026));

/* Test 4: an unreadable value yields null. */
ok("an unreadable date yields null",
    $dav->parseIcalTime("not-a-date") === null);

/* Test 5: durations read the parts they carry. */
ok("durations read hours, minutes, and days",
    $dav->parseDuration("PT1H30M") === 5400 &&
    $dav->parseDuration("P1D") === 86400 &&
    $dav->parseDuration("PT45M") === 2700);

/*
    -----------------------------------------------------------
    Pure readers: components and event spans
    -----------------------------------------------------------
 */
$eol = "\x0D\x0A";
$timed = vcalendar("BEGIN:VEVENT" . $eol . "UID:1" . $eol .
    "DTSTART:20260115T130000Z" . $eol . "DTEND:20260115T140000Z" . $eol .
    "END:VEVENT");
$allday = vcalendar("BEGIN:VEVENT" . $eol . "UID:2" . $eol .
    "DTSTART;VALUE=DATE:20260115" . $eol . "END:VEVENT");
$todo = vcalendar("BEGIN:VTODO" . $eol . "UID:3" . $eol .
    "SUMMARY:write tests" . $eol . "END:VTODO");

/* Test 6: the component types present are read, VCALENDAR aside. */
ok("component types are read from BEGIN lines",
    $dav->icalComponents($timed) === ["VEVENT"] &&
    $dav->icalComponents($todo) === ["VTODO"]);

/* Test 7: a timed event reads its start and end. */
ok("a timed event reads its start and end",
    $dav->icalEventRange($timed) === [gmmktime(13, 0, 0, 1, 15, 2026),
    gmmktime(14, 0, 0, 1, 15, 2026)]);

/* Test 8: an all-day event covers the whole day. */
$midnight = gmmktime(0, 0, 0, 1, 15, 2026);
ok("an all-day event covers the day",
    $dav->icalEventRange($allday) ===
    [$midnight, $midnight + 86400]);

/*
    -----------------------------------------------------------
    Pure readers: matching and overlap
    -----------------------------------------------------------
 */
$jan = gmmktime(0, 0, 0, 1, 1, 2026);
$feb = gmmktime(0, 0, 0, 2, 1, 2026);
$mar = gmmktime(0, 0, 0, 3, 1, 2026);

/* Test 9: an event in the window and of the asked component
   matches. */
ok("an event in range and component matches",
    $dav->eventMatches($timed, "VEVENT", $jan, $feb) === true);

/* Test 10: an event outside the window does not match. */
ok("an event outside the window does not match",
    $dav->eventMatches($timed, "VEVENT", $feb, $mar) === false);

/* Test 11: a component mismatch does not match, range aside. */
ok("a component mismatch does not match",
    $dav->eventMatches($timed, "VTODO", null, null) === false);

/* Test 12: with no range named, a matching component matches
   whatever its time. */
ok("no range means any time matches",
    $dav->eventMatches($todo, "VTODO", null, null) === true);

/*
    -----------------------------------------------------------
    Pure readers: reading a REPORT body
    -----------------------------------------------------------
 */
$query = '<?xml version="1.0" encoding="utf-8"?>' .
    '<C:calendar-query xmlns:D="DAV:" ' .
    'xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/>' .
    '<C:calendar-data/></D:prop><C:filter>' .
    '<C:comp-filter name="VCALENDAR">' .
    '<C:comp-filter name="VEVENT">' .
    '<C:time-range start="20260101T000000Z" end="20260201T000000Z"/>' .
    '</C:comp-filter></C:comp-filter></C:filter></C:calendar-query>';

/* Test 13: the filtered component is read as the inner comp-filter. */
ok("the query component is read",
    $dav->parseQueryComponent($query) === "VEVENT");

/* Test 14: the time range is read as a pair of instants. */
ok("the query time range is read",
    $dav->parseQueryRange($query) === [$jan, $feb]);

/* Test 15: a body with no time-range reads as an open range. */
ok("a missing time range reads as open",
    $dav->parseQueryRange("<C:calendar-query/>") === [null, null]);

$multiget = '<C:calendar-multiget xmlns:D="DAV:" ' .
    'xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/>' .
    '<C:calendar-data/></D:prop>' .
    '<D:href>/calendars/cal/e1.ics</D:href>' .
    '<D:href>/calendars/cal/missing.ics</D:href>' .
    '</C:calendar-multiget>';

/* Test 16: the href list is read from a multiget body. */
ok("the multiget href list is read",
    $dav->parseHrefs($multiget) ===
    ["/calendars/cal/e1.ics", "/calendars/cal/missing.ics"]);

/*
    -----------------------------------------------------------
    REPORT over a scratch calendar seeded with events
    -----------------------------------------------------------
 */
$root = realpath($scratch);
$cal = $root . "/cal";
mkdir($cal);
file_put_contents($cal . "/" . CalDav::META_FILE,
    json_encode(["displayname" => "Cal", "components" => ["VEVENT"]]));
$e1 = vcalendar("BEGIN:VEVENT" . $eol . "UID:e1" . $eol .
    "DTSTART:20260115T130000Z" . $eol . "DTEND:20260115T140000Z" . $eol .
    "END:VEVENT");
$e2 = vcalendar("BEGIN:VEVENT" . $eol . "UID:e2" . $eol .
    "DTSTART:20260220T090000Z" . $eol . "DTEND:20260220T100000Z" . $eol .
    "END:VEVENT");
$t1 = vcalendar("BEGIN:VTODO" . $eol . "UID:t1" . $eol .
    "SUMMARY:a task" . $eol . "END:VTODO");
file_put_contents($cal . "/e1.ics", $e1);
file_put_contents($cal . "/e2.ics", $e2);
file_put_contents($cal . "/t1.ics", $t1);

/* Test 17: a time-range calendar-query returns the event in range
   with its data and not the one out of range. */
$site->reset();
request("$prefix/cal", $query);
$out = capture([$dav, "handleReport"]);
ok("calendar-query returns only the in-range event",
    $site->status() === 207 &&
    strpos($out, "/calendars/cal/e1.ics") !== false &&
    strpos($out, "/calendars/cal/e2.ics") === false &&
    strpos($out, "<C:calendar-data>") !== false &&
    strpos($out, $dav->computeETag($e1)) !== false);

/* Test 18: a component calendar-query returns only that component. */
$todo_query = '<C:calendar-query ' .
    'xmlns:C="urn:ietf:params:xml:ns:caldav"><C:filter>' .
    '<C:comp-filter name="VCALENDAR">' .
    '<C:comp-filter name="VTODO"/></C:comp-filter></C:filter>' .
    '</C:calendar-query>';
$site->reset();
request("$prefix/cal", $todo_query);
$out = capture([$dav, "handleReport"]);
ok("calendar-query by component returns only that component",
    strpos($out, "/calendars/cal/t1.ics") !== false &&
    strpos($out, "/calendars/cal/e1.ics") === false);

/* Test 19: a calendar-multiget returns the named event's data and a
   not-found entry for the missing one. */
$site->reset();
request("$prefix/cal", $multiget);
$out = capture([$dav, "handleReport"]);
ok("calendar-multiget returns named data and a 404 for the missing",
    $site->status() === 207 &&
    strpos($out, "/calendars/cal/e1.ics") !== false &&
    strpos($out, $dav->computeETag($e1)) !== false &&
    strpos($out, "/calendars/cal/missing.ics") !== false &&
    strpos($out, "404 Not Found") !== false);

/* Test 20: a REPORT body that is neither report answers 400. */
$site->reset();
request("$prefix/cal", "<D:something xmlns:D=\"DAV:\"/>");
$dav->handleReport();
ok("an unrecognized REPORT answers 400", $site->status() === 400);

/**
 * Removes a file, or a folder and everything under it, so the test
 * leaves nothing behind on disk.
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
removeTree($root);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
