<?php
require '../../src/WebSite.php';
require '../../src/CardDav.php';

use seekquarry\atto\WebSite;
use seekquarry\atto\CardDav;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example
               under a web server */
}
$test = new WebSite();
/*
    A CardDAV example with a live contacts page. CardDAV (RFC 6352) is
    contact management layered on top of WebDAV, the address-book sibling
    of CalDAV: an address book is a folder, and each contact is a small
    file in the vCard text format inside it. atto ships that behaviour as
    the reusable CardDav class in src/, so this example is short: it makes
    a WebSite, hands it a folder to keep address books in, and calls
    register(). The class adds the address-book routes -- OPTIONS,
    PROPFIND, MKCOL, GET, PUT, DELETE, and REPORT -- under /addressbooks,
    plus the /.well-known/carddav bootstrap a real client uses to find the
    service.

    After commenting the exit() line above, run it with:
        php index.php
    then open http://localhost:8080/ in a browser. The page shows a demo
    address book that re-reads itself every few seconds by sending the
    server a CardDAV addressbook-query (a REPORT) and listing what comes
    back. Each way of changing the book lands on it and shows up on the
    next refresh:

      * Click an "add" link on the page to add a sample contact, or a
        row's "edit" link to change its e-mail, or a row's "delete" link
        to remove it. Each is a CardDAV request: a PUT to add or change a
        card, a DELETE to remove one.

      * Or do the same from the command line and watch the page pick it
        up. Build the card in a file first so its line endings are the
        CRLF the vCard format calls for (printf and this redirect work the
        same in tcsh, bash, and sh), then send the file:

            printf 'BEGIN:VCARD\r\n' > ada.vcf
            printf 'VERSION:3.0\r\nUID:ada\r\n' >> ada.vcf
            printf 'FN:Ada Lovelace\r\n' >> ada.vcf
            printf 'EMAIL:ada@example.com\r\n' >> ada.vcf
            printf 'END:VCARD\r\n' >> ada.vcf
            curl -X PUT --data-binary @ada.vcf \
              http://localhost:8080/addressbooks/demo/ada.vcf

        Within a few seconds the page lists "Ada Lovelace". Sending a new
        version of the card to the same path changes it (the server
        answers 204 rather than 201), and a DELETE removes it:

            curl -X DELETE http://localhost:8080/addressbooks/demo/ada.vcf

    A real contacts client works too: point Apple Contacts (macOS and iOS),
    Mozilla Thunderbird, or the Android app DAVx5 at
    http://localhost:8080/ and it follows /.well-known/carddav to the
    service and finds the demo book on its own.

    This demo runs the address books open, with no log-in, so the page and
    the curl lines above work without credentials. Passing an authenticator
    as the fourth argument to CardDav gates every verb behind it instead;
    example 14 (WebDAV) shows that authenticator shape, and the class calls
    it before each verb and stops on false.

    REUSE: the contact behaviour is the CardDav class, not this file, so
    another project (for instance Yioop) attaches an address book to its
    own WebSite the same way -- new CardDav($site, $dir, $prefix) then
    register() -- without touching the verb handlers.
 */
$contact_base = __DIR__ . "/contact_root";

/*
    Seeds a demo address book the first time the example runs so the page
    has something to show before anything is added. An address book is just
    a folder holding a hidden metadata file (which is what marks it as a
    book) and any number of .vcf contact files, so seeding it is a couple
    of file writes.
 */
$demo = $contact_base . "/demo";
if (!is_dir($demo)) {
    mkdir($demo, 0777, true);
    file_put_contents($demo . "/" . CardDav::META_FILE,
        json_encode(["displayname" => "Demo"]));
    file_put_contents($demo . "/welcome.vcf",
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:welcome\r\n" .
        "FN:Atto Example\r\nEMAIL:hello@example.com\r\n" .
        "END:VCARD\r\n");
}

/*
    Attaches the address-book endpoint to the site: the books live under
    $contact_base on disk and are served under /addressbooks. No
    authenticator is passed, so the demo is open; register() adds the
    routes, including the well-known bootstrap.
 */
$carddav = new CardDav($test, $contact_base, "/addressbooks");
$carddav->register();

/*
    The live contacts page. It is plain HTML and a little JavaScript: on a
    timer it sends the demo book an addressbook-query REPORT, pulls the FN
    and EMAIL out of each returned contact, and lists them by name. The
    "add" links send a PUT of a fixed sample contact; adding one from curl
    has the same effect. Either way the next refresh shows it.
 */
$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>CardDAV Live Contacts - Atto Server</title>
    <style>
    body { font-family: system-ui, sans-serif; max-width: 640px;
        margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { margin-bottom: 0.2rem; }
    .status { color: #666; font-size: 0.9em; margin-bottom: 1rem; }
    ul.book { list-style: none; padding: 0; }
    ul.book li { border: 1px solid #ddd; border-radius: 6px;
        padding: 0.5rem 0.8rem; margin: 0.4rem 0; }
    ul.book li .email { color: #555; font-size: 0.9em; }
    ul.book li .row-action { margin-left: 0.5rem; font-size: 0.85em;
        color: #b35900; text-decoration: none; }
    .adds a { display: inline-block; margin: 0.2rem 0.4rem 0.2rem 0;
        padding: 0.3rem 0.6rem; border: 1px solid #b35900;
        border-radius: 6px; color: #b35900; text-decoration: none; }
    pre { background: #f2f2f2; padding: 0.8rem; border-radius: 6px;
        overflow-x: auto; }
    </style>
    </head>
    <body>
    <h1>Demo address book</h1>
    <div class="status" id="status">loading&hellip;</div>

    <ul class="book" id="contacts"></ul>

    <p class="adds">Add a contact:
      <a href="#" onclick="return addContact('ada',
        'Ada Lovelace', 'ada@example.com')">Ada Lovelace</a>
      <a href="#" onclick="return addContact('alan',
        'Alan Turing', 'alan@example.com')">Alan Turing</a>
      <a href="#" onclick="return addContact('grace',
        'Grace Hopper', 'grace@example.com')">Grace Hopper</a>
    </p>

    <p>Each contact in the list has an <b>edit</b> link, which asks for a
    new e-mail and sends the changed card back, and a <b>delete</b> link,
    which removes it. The add links, and both row links, are just CardDAV
    requests to <code>/addressbooks/demo/</code>: a <code>PUT</code> to add
    or change a card, a <code>DELETE</code> to remove one. You can do the
    same from the command line and watch the list above update within a few
    seconds. Build the card in a file first so its line endings are CRLF
    (this works the same in tcsh, bash, and sh), then send it:</p>
    <pre>
# add a contact -- a PUT to a new path (201 Created)
printf 'BEGIN:VCARD\r\n' &gt; ada.vcf
printf 'VERSION:3.0\r\nUID:ada\r\n' &gt;&gt; ada.vcf
printf 'FN:Ada Lovelace\r\n' &gt;&gt; ada.vcf
printf 'EMAIL:ada@example.com\r\n' &gt;&gt; ada.vcf
printf 'END:VCARD\r\n' &gt;&gt; ada.vcf
curl -X PUT --data-binary @ada.vcf \
  http://localhost:8080/addressbooks/demo/ada.vcf

# change it -- a PUT of a new version to the same path (204 No Content)
printf 'BEGIN:VCARD\r\n' &gt; ada.vcf
printf 'VERSION:3.0\r\nUID:ada\r\n' &gt;&gt; ada.vcf
printf 'FN:Ada Lovelace\r\n' &gt;&gt; ada.vcf
printf 'EMAIL:ada@newmail.example\r\n' &gt;&gt; ada.vcf
printf 'END:VCARD\r\n' &gt;&gt; ada.vcf
curl -X PUT --data-binary @ada.vcf \
  http://localhost:8080/addressbooks/demo/ada.vcf

# delete it (204 No Content)
curl -X DELETE http://localhost:8080/addressbooks/demo/ada.vcf
    </pre>

    <script>
    /* Reads the contacts by sending the demo book an addressbook-query
       REPORT with an empty filter, which returns every contact, and
       pulling the href, UID, FN, and EMAIL out of each returned
       response so a row can later be changed or deleted by its href. */
    async function loadContacts() {
        var query =
            '<C:addressbook-query xmlns:D="DAV:" ' +
            'xmlns:C="urn:ietf:params:xml:ns:carddav">' +
            '<D:prop><C:address-data/></D:prop><C:filter/>' +
            '</C:addressbook-query>';
        var reply = await fetch('/addressbooks/demo', {
            method: 'REPORT',
            headers: { 'Content-Type': 'application/xml' },
            body: query
        });
        var text = await reply.text();
        var contacts = [];
        var block = /<D:response>([\s\S]*?)<\/D:response>/g;
        var found;
        while ((found = block.exec(text)) !== null) {
            var chunk = found[1];
            var data = chunk.match(
                /<CARD:address-data>([\s\S]*?)<\/CARD:address-data>/);
            if (data === null) {
                continue;
            }
            var vcf = data[1]
                .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
                .replace(/&amp;/g, '&');
            var href = (chunk.match(/<D:href>([^<]*)<\/D:href>/) ||
                [])[1] || '';
            var uid = (vcf.match(/UID:(.*)/) || [])[1] || '';
            var name = (vcf.match(/FN:(.*)/) || [])[1] || '(no name)';
            var email = (vcf.match(/EMAIL[^:]*:(.*)/) || [])[1] || '';
            contacts.push({ href: href.trim(), uid: uid.trim(),
                name: name.trim(), email: email.trim() });
        }
        contacts.sort(function (a, b) {
            return a.name.localeCompare(b.name);
        });
        return contacts;
    }

    /* Draws the list and updates the status line. Each row carries an
       edit link (which changes the contact) and a delete link. */
    function draw(contacts) {
        var list = document.getElementById('contacts');
        list.innerHTML = '';
        contacts.forEach(function (contact) {
            var item = document.createElement('li');
            item.appendChild(document.createTextNode(contact.name));
            if (contact.email !== '') {
                var email = document.createElement('span');
                email.className = 'email';
                email.textContent = ' \u2014 ' + contact.email;
                item.appendChild(email);
            }
            item.appendChild(rowLink('edit', function () {
                return editContact(contact);
            }));
            item.appendChild(rowLink('delete', function () {
                return deleteContact(contact);
            }));
            list.appendChild(item);
        });
        var now = new Date().toLocaleTimeString();
        document.getElementById('status').textContent =
            contacts.length + ' contact(s); refreshed ' + now +
            '; updates every 3s';
    }

    /* Builds one row-action link with its click handler. */
    function rowLink(label, handler) {
        var link = document.createElement('a');
        link.href = '#';
        link.className = 'row-action';
        link.textContent = label;
        link.onclick = handler;
        return link;
    }

    /* Refreshes the list from the server. */
    async function refresh() {
        try {
            draw(await loadContacts());
        } catch (error) {
            document.getElementById('status').textContent =
                'could not reach the server: ' + error;
        }
    }

    /* Adds one fixed sample contact with a CardDAV PUT, then refreshes
       so it shows right away. */
    async function addContact(uid, name, email) {
        var vcf =
            'BEGIN:VCARD\r\nVERSION:3.0\r\nUID:' + uid + '\r\n' +
            'FN:' + name + '\r\nEMAIL:' + email + '\r\n' +
            'END:VCARD\r\n';
        await fetch('/addressbooks/demo/' + uid + '.vcf', {
            method: 'PUT',
            body: vcf
        });
        refresh();
        return false;
    }

    /* Changes a contact: asks for a new e-mail, then sends a new
       version of the card to the same path with a PUT, which the
       server takes as an overwrite (204 rather than 201), then
       refreshes so the change shows right away. */
    async function editContact(contact) {
        var email = window.prompt('New e-mail for ' + contact.name,
            contact.email);
        if (email === null) {
            return false;
        }
        var vcf =
            'BEGIN:VCARD\r\nVERSION:3.0\r\nUID:' + contact.uid + '\r\n' +
            'FN:' + contact.name + '\r\nEMAIL:' + email + '\r\n' +
            'END:VCARD\r\n';
        await fetch(contact.href, { method: 'PUT', body: vcf });
        refresh();
        return false;
    }

    /* Deletes a contact by sending a DELETE to its path, then
       refreshes so it drops off the list. */
    async function deleteContact(contact) {
        await fetch(contact.href, { method: 'DELETE' });
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
