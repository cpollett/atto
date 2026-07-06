<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the CalDAV request verbs REPORT and
 * MKCALENDAR that WebSite learned to route. Every check runs
 * against WebSite in memory with no socket opened and no
 * server started, so the suite stays fast: that the two verbs
 * register as routes, dispatch to a handler, fit the
 * longest-method budget, pass the HTTP/1.1 request-line sniff,
 * and parse off a full request line the way GET does. A bogus
 * verb is checked at each gate as a control, so a pass means
 * the gate is selective rather than simply permissive.
 *
 * Run from the repo root:
 *     php tests/caldav/test_caldav_verbs.php
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
 * A WebSite that can be driven through its request parser without a
 * live socket. It swaps the two steps that would otherwise touch
 * process globals or a real connection for small recorders, so a
 * test can feed raw request bytes in and read back the method,
 * body, and good-or-bad outcome the parser decided on. It also
 * exposes the protected request-line sniff for direct checking.
 */
class CalDavVerbProbe extends WebSite
{
    /**
     * Method name the parser pulled off the last request line, or
     * null when none has been parsed yet.
     * @var string|null
     */
    public $seen_method = null;
    /**
     * Request body the parser handed on for the last request.
     * @var string|null
     */
    public $seen_content = null;
    /**
     * True when the parser rejected the last request as malformed.
     * @var bool
     */
    public $was_bad = false;

    /**
     * Stands in for the real superglobal set-up. Rather than writing
     * $_SERVER and its companions, it records the method and body the
     * parser resolved so a test can assert on them.
     *
     * @param array $context the parsed request context
     * @param mixed $conn ignored; there is no live connection here
     */
    public function setGlobals($context, $conn = null)
    {
        $this->seen_method = $context['REQUEST_METHOD'] ?? null;
        $this->seen_content = $context['CONTENT'] ?? null;
    }

    /**
     * Stands in for the real bad-request path. Rather than rewriting
     * the superglobals to a 400, it flags that the parser turned the
     * request away.
     *
     * @param int $key id of the request stream being parsed
     */
    protected function initializeBadRequestResponse($key)
    {
        $this->was_bad = true;
    }

    /**
     * Runs one raw HTTP/1.1 request through the real request parser
     * and reports the method it resolved, or the string "BAD" when
     * the parser rejected it. Fills in the small amount of stream and
     * server state the parser reads that listen() would normally set.
     *
     * @param string $request the raw request bytes to parse
     * @return string the parsed method, or "BAD" on rejection
     */
    public function parseVerb($request)
    {
        $key = 1;
        $this->seen_method = null;
        $this->seen_content = null;
        $this->was_bad = false;
        $this->default_server_globals['DOCUMENT_ROOT'] = getcwd();
        $this->default_server_globals['MAX_REQUEST_LEN'] = 10000000;
        $this->in_streams[self::DATA][$key] = "";
        $this->in_streams[self::CONTEXT][$key] =
            ['REQUEST_METHOD' => false];
        $this->parseRequest($key, $request);
        if ($this->was_bad) {
            return "BAD";
        }
        return $this->seen_method;
    }

    /**
     * Exposes the protected HTTP-type sniff so a test can ask how a
     * bare opening request line is classified.
     *
     * @param string $line the opening bytes of a request
     * @return string the CLIENT_HTTP label the sniff assigned
     */
    public function sniff($line)
    {
        $result = $this->checkHttpType($line);
        return $result['CLIENT_HTTP'];
    }
}

/*
    -----------------------------------------------------------
    Route registration: the two verbs are known methods
    -----------------------------------------------------------
 */

/* Test 1: MKCALENDAR and REPORT can be registered as routes.
   addRoute refuses an unknown method by throwing, so a clean
   pair of calls is the check that the routes table lists them. */
$site = new WebSite(".");
$registered = true;
try {
    $site->addRoute("MKCALENDAR", "/calendars/*", function () {
    });
    $site->addRoute("REPORT", "/calendars/*", function () {
    });
} catch (\Throwable $error) {
    $registered = false;
}
ok("MKCALENDAR and REPORT register as routes", $registered);

/* Test 2: a bogus method is still refused, so registration is
   selective rather than accepting anything at all. */
$refused = false;
try {
    $site->addRoute("BOGUSVERB", "/calendars/*", function () {
    });
} catch (\Throwable $error) {
    $refused = true;
}
ok("an unknown verb is refused registration", $refused);

/*
    -----------------------------------------------------------
    Dispatch: a request for each verb reaches its handler
    -----------------------------------------------------------
 */

/* Test 3: triggering MKCALENDAR on a path the wildcard route
   covers runs that route's handler. */
$ran = "";
$site->addRoute("MKCALENDAR", "/cal/*", function () use (&$ran) {
    $ran = "mkcalendar";
});
$site->trigger("MKCALENDAR", "/cal/work");
ok("MKCALENDAR dispatches to its handler", $ran === "mkcalendar");

/* Test 4: the same for REPORT. */
$ran = "";
$site->addRoute("REPORT", "/cal/*", function () use (&$ran) {
    $ran = "report";
});
$site->trigger("REPORT", "/cal/work");
ok("REPORT dispatches to its handler", $ran === "report");

/*
    -----------------------------------------------------------
    Longest-method budget covers MKCALENDAR
    -----------------------------------------------------------
 */

/* Test 5: the reader's method-name budget is at least as long as
   MKCALENDAR, the longest verb atto routes. */
ok("longest-method budget fits MKCALENDAR",
    WebSite::LEN_LONGEST_HTTP_METHOD >= strlen("MKCALENDAR"));

/*
    -----------------------------------------------------------
    Request-line sniff accepts the verbs, refuses a bogus one
    -----------------------------------------------------------
 */
$probe = new CalDavVerbProbe(".");

/* Test 6: an MKCALENDAR opening line is classified as HTTP/1.1. */
ok("MKCALENDAR sniffs as HTTP/1.1",
    $probe->sniff("MKCALENDAR /calendars/ HTTP/1.1") === "HTTP/1.1");

/* Test 7: a REPORT opening line is classified as HTTP/1.1. */
ok("REPORT sniffs as HTTP/1.1",
    $probe->sniff("REPORT /calendars/ HTTP/1.1") === "HTTP/1.1");

/* Test 8: a bogus verb is not classified as HTTP/1.1. */
ok("an unknown verb does not sniff as HTTP/1.1",
    $probe->sniff("BOGUSVERB /calendars/ HTTP/1.1") !== "HTTP/1.1");

/*
    -----------------------------------------------------------
    Full request-line parse resolves the method and body
    -----------------------------------------------------------
 */
$eol = "\x0D\x0A";

/* Test 9: a complete MKCALENDAR request parses to that method. */
$request = "MKCALENDAR /calendars/work HTTP/1.1" . $eol .
    "Host: localhost" . $eol . $eol;
ok("MKCALENDAR parses off a full request line",
    $probe->parseVerb($request) === "MKCALENDAR");

/* Test 10: a complete REPORT request parses to that method and
   carries its XML body through to CONTENT. */
$body = '<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"/>';
$request = "REPORT /calendars/work HTTP/1.1" . $eol .
    "Host: localhost" . $eol .
    "Content-Type: application/xml" . $eol .
    "Content-Length: " . strlen($body) . $eol . $eol . $body;
$method = $probe->parseVerb($request);
ok("REPORT parses off a full request line", $method === "REPORT");
ok("REPORT carries its body through to CONTENT",
    $probe->seen_content === $body);

/* Test 11: a bogus verb on a full request line is rejected. */
$request = "BOGUSVERB /calendars/work HTTP/1.1" . $eol .
    "Host: localhost" . $eol . $eol;
ok("an unknown verb is rejected by the parser",
    $probe->parseVerb($request) === "BAD");

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
