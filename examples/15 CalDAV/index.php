<?php
require '../../src/WebSite.php';
require '../../src/CalDav.php';

use seekquarry\atto\WebSite;
use seekquarry\atto\CalDav;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example
               under a web server */
}
$test = new WebSite();
/*
    A CalDAV example. CalDAV (RFC 4791) is calendaring layered on top of
    WebDAV: a calendar is a folder, and each event is a small file in the
    iCalendar text format inside it. atto ships that behaviour as the
    reusable CalDav class in src/, so this example is short: it makes a
    WebSite, hands it a folder to keep calendars in and a log-in check,
    and calls register(). The class adds the calendar routes -- OPTIONS,
    PROPFIND, MKCALENDAR, GET, PUT, DELETE, and REPORT -- under /calendars,
    plus the /.well-known/caldav bootstrap a client uses to find the
    service from the base URL alone.

    After commenting the exit() line above, run it with:
        php index.php
    The share is gated behind an authenticator, so every calendar request
    logs in as the demo user alice with password secret (curl's -u below);
    without valid credentials each verb answers 401. The curl commands
    below form one self-contained round trip; each says what to expect:

        # make a calendar. Expect: 201 Created. The empty body takes the
        # default name and component set (VEVENT, VTODO); a body may carry
        # a displayname and a supported-calendar-component-set instead.
        curl -u alice:secret -X MKCALENDAR \
          http://localhost:8080/calendars/work \
          --data '<C:mkcalendar
            xmlns:C="urn:ietf:params:xml:ns:caldav"/>'

        # add an event. Expect: 201 Created (204 on overwrite). If-None-
        # Match: * makes it a create-only write. Put the iCalendar text in
        # a file and send it with --data-binary @file so CRLFs survive.
        curl -u alice:secret -X PUT -H 'If-None-Match: *' \
          --data-binary @meeting.ics \
          http://localhost:8080/calendars/work/meeting.ics

        # ask for January's events. Expect: a 207 Multi-Status carrying the
        # matching events' data. calendar-query filters by component and an
        # optional time range.
        curl -u alice:secret -X REPORT \
          http://localhost:8080/calendars/work \
          --data '<C:calendar-query
            xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop><C:calendar-data/></D:prop><C:filter>
            <C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
            <C:time-range start="20260101T000000Z"
            end="20260201T000000Z"/></C:comp-filter></C:comp-filter>
            </C:filter></C:calendar-query>'

        # read the event back. Expect: its iCalendar text.
        curl -u alice:secret \
          http://localhost:8080/calendars/work/meeting.ics

        # delete it. Expect: 204 No Content; a following GET returns 404.
        curl -u alice:secret -X DELETE \
          http://localhost:8080/calendars/work/meeting.ics

    Or point a real calendar client at it. Give the client the base URL
    http://localhost:8080/ (or http://localhost:8080/calendars/) and the
    demo log-in alice / secret; the client follows /.well-known/caldav to
    the service and reads the principal and calendar-home properties to
    find the calendars on its own. This works in Apple Calendar (macOS and
    iOS), Mozilla Thunderbird, and the Android app DAVx5.

    A plain browser visiting / gets a short page explaining the above.

    REUSE: the calendar behaviour is the CalDav class, not this file, so
    another project (for instance Yioop) attaches a calendar to its own
    WebSite the same way -- new CalDav($site, $dir, $prefix, $login) then
    register() -- swapping the authenticator below for whatever log-in it
    already runs, without touching the verb handlers.
 */
$calendar_base = __DIR__ . "/calendar_root";

/*
    Gates the calendars behind an authenticator. CalDAV runs over ordinary
    HTTP, so it is guarded the ordinary HTTP way: each request must carry
    credentials the server accepts, or it is turned away with 401 and a
    challenge the client answers by asking the user to log in. The class
    calls this before every verb and stops on false, so nothing about a
    calendar is reachable without logging in. (The /.well-known bootstrap
    is a bare redirect and is not gated; the properties it points at are.)

    This example checks HTTP Basic credentials against a fixed list, which
    keeps the moving parts visible; a real deployment swaps the body for
    whatever it already uses -- a user database, an LDAP bind, a token
    check -- without touching the class. Credentials arrive as an
    "Authorization: Basic ..." header, which atto exposes as PHP_AUTH_USER
    / PHP_AUTH_PW when it can and always as HTTP_AUTHORIZATION, so both are
    handled. hash_equals compares in constant time so a wrong guess cannot
    be timed. The 401 status line takes its protocol from the request, so
    the gate reads the same to an HTTP/1.1, HTTP/2, or HTTP/3 client.
 */
$users = ["alice" => "secret"];
$authenticate = function () use ($test, $users) {
    $user = $_SERVER['PHP_AUTH_USER'] ?? "";
    $password = $_SERVER['PHP_AUTH_PW'] ?? "";
    if ($user === "" && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
        if (preg_match('/^\s*Basic\s+(\S+)/i',
            $_SERVER['HTTP_AUTHORIZATION'], $matches)) {
            $decoded = base64_decode($matches[1], true);
            if ($decoded !== false && strpos($decoded, ":") !== false) {
                list($user, $password) = explode(":", $decoded, 2);
            }
        }
    }
    if (isset($users[$user]) && hash_equals($users[$user], $password)) {
        return true;
    }
    $protocol = $_SERVER['SERVER_PROTOCOL'] ?? "HTTP/1.1";
    $test->header($protocol . " 401 Unauthorized");
    $test->header('WWW-Authenticate: Basic realm="Atto CalDAV"');
    return false;
};

/*
    Attaches a calendar endpoint to the site: the calendars live under
    $calendar_base on disk, are served under /calendars, and are gated by
    the authenticator above. register() adds the routes, including the
    well-known bootstrap.
 */
$caldav = new CalDav($test, $calendar_base, "/calendars", $authenticate);
$caldav->register();

/*
    A plain browser landing page explaining how to talk to the calendars.
 */
$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>CalDAV Example - Atto Server</title></head>
    <body>
    <h1>CalDAV - Atto Server</h1>
    <p>This server exports calendars over CalDAV at
    <a href="/calendars/">/calendars/</a>. CalDAV is calendaring on top of
    WebDAV: a calendar is a folder, an event a small iCalendar file inside
    it. The behaviour is the <code>CalDav</code> class in
    <code>src/</code>; this example just wires it to a
    <code>WebSite</code>.</p>
    <p>The calendars are gated behind an authenticator: every request must
    log in as the demo user <code>alice</code> with password
    <code>secret</code> (curl's <code>-u</code> below), or the verb answers
    401. The curl commands below form one self-contained round trip; the
    comment on each says what to expect back:</p>
    <pre>
# make a calendar -- expect 201 Created
curl -u alice:secret -X MKCALENDAR \
  http://localhost:8080/calendars/work \
  --data '&lt;C:mkcalendar xmlns:C="urn:ietf:params:xml:ns:caldav"/&gt;'

# put an event's iCalendar text in a file
printf 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:1\r\n'\
'DTSTART:20260115T130000Z\r\nDTEND:20260115T140000Z\r\n'\
'SUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n' &gt; meeting.ics

# add it -- expect 201 Created (204 on overwrite)
curl -u alice:secret -X PUT -H 'If-None-Match: *' \
  --data-binary @meeting.ics \
  http://localhost:8080/calendars/work/meeting.ics

# ask for January's events -- expect a 207 Multi-Status with the event
curl -u alice:secret -X REPORT \
  http://localhost:8080/calendars/work \
  --data '&lt;C:calendar-query xmlns:D="DAV:"
    xmlns:C="urn:ietf:params:xml:ns:caldav"&gt;&lt;D:prop&gt;
    &lt;C:calendar-data/&gt;&lt;/D:prop&gt;&lt;C:filter&gt;
    &lt;C:comp-filter name="VCALENDAR"&gt;&lt;C:comp-filter name="VEVENT"&gt;
    &lt;C:time-range start="20260101T000000Z"
    end="20260201T000000Z"/&gt;&lt;/C:comp-filter&gt;&lt;/C:comp-filter&gt;
    &lt;/C:filter&gt;&lt;/C:calendar-query&gt;'

# read it back -- expect its iCalendar text
curl -u alice:secret http://localhost:8080/calendars/work/meeting.ics

# delete it -- expect 204; a following GET then returns 404
curl -u alice:secret -X DELETE \
  http://localhost:8080/calendars/work/meeting.ics
    </pre>
    <p>Or point a real calendar client at it. Give the client the base URL
    <code>http://localhost:8080/</code> (or
    <code>http://localhost:8080/calendars/</code>) and the demo log-in
    <code>alice</code> / <code>secret</code>; it follows
    <code>/.well-known/caldav</code> to the service and reads the principal
    and calendar-home properties to find the calendars on its own. This
    works in <b>Apple Calendar</b> (macOS and iOS), <b>Mozilla
    Thunderbird</b>, and the Android app <b>DAVx5</b>.</p>
    </body>
    </html>
    <?php
});

/*
    Once the exit() line at the top is commented out, this starts the
    server: listening on port 8080 when run from the command line, or
    handling the current request when run under another web server.
 */
if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
