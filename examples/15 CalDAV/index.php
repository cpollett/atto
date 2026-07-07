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
    A CalDAV example with a live calendar page. CalDAV (RFC 4791) is
    calendaring layered on top of WebDAV: a calendar is a folder, and each
    event is a small file in the iCalendar text format inside it. atto
    ships that behaviour as the reusable CalDav class in src/, so this
    example is short: it makes a WebSite, hands it a folder to keep
    calendars in, and calls register(). The class adds the calendar routes
    -- OPTIONS, PROPFIND, MKCALENDAR, GET, PUT, DELETE, and REPORT -- under
    /calendars, plus the /.well-known/caldav bootstrap a real client uses
    to find the service.

    After commenting the exit() line above, run it with:
        php index.php
    then open http://localhost:8080/ in a browser. The page shows a demo
    calendar that re-reads itself every few seconds by sending the server a
    CalDAV calendar-query (a REPORT) and listing what comes back. Two ways
    to add an event both land on that same calendar and show up on the next
    refresh:

      * Click one of the "add" links on the page. Each sends a CalDAV PUT
        of a small event to the demo calendar.

      * Or add one from the command line and watch the page pick it up.
        Build the event in a file first so its line endings are the CRLF
        the iCalendar format calls for (printf and this redirect work the
        same in tcsh, bash, and sh), then send the file:

            printf 'BEGIN:VCALENDAR\r\n' > lunch.ics
            printf 'BEGIN:VEVENT\r\nUID:lunch\r\n' >> lunch.ics
            printf 'DTSTART:20260115T120000Z\r\n' >> lunch.ics
            printf 'DTEND:20260115T130000Z\r\n' >> lunch.ics
            printf 'SUMMARY:Lunch (added by curl)\r\n' >> lunch.ics
            printf 'END:VEVENT\r\nEND:VCALENDAR\r\n' >> lunch.ics
            curl -X PUT --data-binary @lunch.ics \
              http://localhost:8080/calendars/demo/lunch.ics

        Within a few seconds the page lists "Lunch (added by curl)". A
        following DELETE makes it disappear the same way:

            curl -X DELETE http://localhost:8080/calendars/demo/lunch.ics

    A real calendar client works too: point Apple Calendar (macOS and iOS),
    Mozilla Thunderbird, or the Android app DAVx5 at
    http://localhost:8080/ and it follows /.well-known/caldav to the
    service and finds the demo calendar on its own.

    This demo runs the calendars open, with no log-in, so the page and the
    curl lines above work without credentials. Passing an authenticator as
    the fourth argument to CalDav gates every verb behind it instead;
    example 14 (WebDAV) shows that authenticator shape, and the class calls
    it before each verb and stops on false.

    REUSE: the calendar behaviour is the CalDav class, not this file, so
    another project (for instance Yioop) attaches a calendar to its own
    WebSite the same way -- new CalDav($site, $dir, $prefix) then
    register() -- without touching the verb handlers.
 */
$calendar_base = __DIR__ . "/calendar_root";

/*
    Seeds a demo calendar the first time the example runs so the page has
    something to show before anything is added. A calendar is just a folder
    holding a hidden metadata file (which is what marks it as a calendar)
    and any number of .ics event files, so seeding it is a couple of
    file writes.
 */
$demo = $calendar_base . "/demo";
if (!is_dir($demo)) {
    mkdir($demo, 0777, true);
    file_put_contents($demo . "/" . CalDav::META_FILE,
        json_encode(["displayname" => "Demo", "components" => ["VEVENT"]]));
    file_put_contents($demo . "/welcome.ics",
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:welcome\r\n" .
        "DTSTART:20260115T083000Z\r\nDTEND:20260115T090000Z\r\n" .
        "SUMMARY:Welcome to Atto CalDAV\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
}

/*
    Attaches the calendar endpoint to the site: the calendars live under
    $calendar_base on disk and are served under /calendars. No authenticator
    is passed, so the demo is open; register() adds the routes, including
    the well-known bootstrap.
 */
$caldav = new CalDav($test, $calendar_base, "/calendars");
$caldav->register();

/*
    The live calendar page. It is plain HTML and a little JavaScript: on a
    timer it sends the demo calendar a calendar-query REPORT, pulls the
    SUMMARY and DTSTART out of each returned event, and lists them in time
    order. The "add" links send a PUT of a fixed sample event; adding one
    from curl has the same effect. Either way the next refresh shows it.
 */
$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>CalDAV Live Calendar - Atto Server</title>
    <style>
    body { font-family: system-ui, sans-serif; max-width: 640px;
        margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { margin-bottom: 0.2rem; }
    .status { color: #666; font-size: 0.9em; margin-bottom: 1rem; }
    ul.cal { list-style: none; padding: 0; }
    ul.cal li { border: 1px solid #ddd; border-radius: 6px;
        padding: 0.5rem 0.8rem; margin: 0.4rem 0; }
    ul.cal li .when { color: #555; font-size: 0.9em; }
    .adds a { display: inline-block; margin: 0.2rem 0.4rem 0.2rem 0;
        padding: 0.3rem 0.6rem; border: 1px solid #b35900;
        border-radius: 6px; color: #b35900; text-decoration: none; }
    pre { background: #f2f2f2; padding: 0.8rem; border-radius: 6px;
        overflow-x: auto; }
    </style>
    </head>
    <body>
    <h1>Demo calendar</h1>
    <div class="status" id="status">loading&hellip;</div>

    <ul class="cal" id="events"></ul>

    <p class="adds">Add an event:
      <a href="#" onclick="return addEvent('standup',
        'Team standup', '090000', '091500')">Standup 09:00</a>
      <a href="#" onclick="return addEvent('review',
        'Design review', '140000', '150000')">Review 14:00</a>
      <a href="#" onclick="return addEvent('all-hands',
        'All hands', '160000', '170000')">All hands 16:00</a>
    </p>

    <p>Each link sends a CalDAV <code>PUT</code> to
    <code>/calendars/demo/</code>. You can do the same from the command
    line and watch the list above update within a few seconds. Build the
    event in a file first so its line endings are CRLF (this works the same
    in tcsh, bash, and sh), then send the file:</p>
    <pre>
printf 'BEGIN:VCALENDAR\r\n' &gt; lunch.ics
printf 'BEGIN:VEVENT\r\nUID:lunch\r\n' &gt;&gt; lunch.ics
printf 'DTSTART:20260115T120000Z\r\n' &gt;&gt; lunch.ics
printf 'DTEND:20260115T130000Z\r\n' &gt;&gt; lunch.ics
printf 'SUMMARY:Lunch (added by curl)\r\n' &gt;&gt; lunch.ics
printf 'END:VEVENT\r\nEND:VCALENDAR\r\n' &gt;&gt; lunch.ics
curl -X PUT --data-binary @lunch.ics \
  http://localhost:8080/calendars/demo/lunch.ics
    </pre>

    <script>
    /* One demo day, so every event and every add link sits on it. */
    var DAY = "20260115";

    /* Reads the events by sending the demo calendar a calendar-query
       REPORT and pulling SUMMARY and DTSTART out of each returned
       calendar object. */
    async function loadEvents() {
        var query =
            '<C:calendar-query xmlns:D="DAV:" ' +
            'xmlns:C="urn:ietf:params:xml:ns:caldav">' +
            '<D:prop><C:calendar-data/></D:prop><C:filter>' +
            '<C:comp-filter name="VCALENDAR">' +
            '<C:comp-filter name="VEVENT"/>' +
            '</C:comp-filter></C:filter></C:calendar-query>';
        var reply = await fetch('/calendars/demo', {
            method: 'REPORT',
            headers: { 'Content-Type': 'application/xml' },
            body: query
        });
        var text = await reply.text();
        var events = [];
        var block = /<C:calendar-data>([\s\S]*?)<\/C:calendar-data>/g;
        var found;
        while ((found = block.exec(text)) !== null) {
            var ics = found[1]
                .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
                .replace(/&amp;/g, '&');
            var summary = (ics.match(/SUMMARY:(.*)/) || [])[1] || '(no title)';
            var start = (ics.match(/DTSTART[^:]*:([0-9TZ]+)/) || [])[1] || '';
            events.push({ summary: summary.trim(), start: start.trim() });
        }
        events.sort(function (a, b) {
            return a.start.localeCompare(b.start);
        });
        return events;
    }

    /* Turns a 20260115T090000Z stamp into a readable clock time. */
    function clockOf(stamp) {
        var time = stamp.split('T')[1] || '';
        if (time.length < 4) {
            return '';
        }
        return time.slice(0, 2) + ':' + time.slice(2, 4) + ' UTC';
    }

    /* Draws the list and updates the status line. */
    function draw(events) {
        var list = document.getElementById('events');
        list.innerHTML = '';
        events.forEach(function (event) {
            var item = document.createElement('li');
            var when = document.createElement('span');
            when.className = 'when';
            when.textContent = clockOf(event.start) + ' \u2014 ';
            item.appendChild(when);
            item.appendChild(document.createTextNode(event.summary));
            list.appendChild(item);
        });
        var now = new Date().toLocaleTimeString();
        document.getElementById('status').textContent =
            events.length + ' event(s); refreshed ' + now +
            '; updates every 3s';
    }

    /* Refreshes the list from the server. */
    async function refresh() {
        try {
            draw(await loadEvents());
        } catch (error) {
            document.getElementById('status').textContent =
                'could not reach the server: ' + error;
        }
    }

    /* Adds one fixed sample event with a CalDAV PUT, then refreshes so
       it shows right away. */
    async function addEvent(uid, summary, startTime, endTime) {
        var ics =
            'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:' + uid + '\r\n' +
            'DTSTART:' + DAY + 'T' + startTime + 'Z\r\n' +
            'DTEND:' + DAY + 'T' + endTime + 'Z\r\n' +
            'SUMMARY:' + summary + '\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n';
        await fetch('/calendars/demo/' + uid + '.ics', {
            method: 'PUT',
            body: ics
        });
        refresh();
        return false;
    }

    refresh();
    setInterval(refresh, 3000);
    </script>
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
