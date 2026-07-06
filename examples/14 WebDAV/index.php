<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;

if (!defined("seekquarry\\atto\\RUN")) {
    exit(); /* you need to comment this line to be able to run this example
               under a web server */
}
$test = new WebSite();
/*
    A WebDAV example. Atto's WebSite already routes the WebDAV HTTP verbs
    (OPTIONS, PROPFIND, MKCOL, PUT, GET, DELETE, MOVE, ...) the same way it
    routes GET and POST, so a WebDAV share is just a set of route handlers
    over a folder on disk. This example serves the dav_root subfolder under
    the /dav/ path so a WebDAV client can list, read, create, upload,
    move, and delete files in it.

    After commenting the exit() line above, you can run the example by
    typing:
        php index.php
    and then talking to it with any WebDAV client. The share is gated
    behind an authenticator, so every request logs in as the demo user
    alice with password secret (curl's -u below); without valid credentials
    each verb answers 401. The curl commands below form one self-contained
    round trip; each says what it does and what to expect back:

        # make a small file locally so there is something to upload
        echo 'hello webdav' > hello.txt

        # upload it. Expect: 201 Created (204 if it already existed). Use a
        # real file with -T; curl's -T - streams chunked, which this simple
        # example does not read, so it would store an empty file.
        curl -u alice:secret -T hello.txt http://localhost:8080/dav/hello.txt

        # read it back. Expect: the file's contents, "hello webdav".
        curl -u alice:secret http://localhost:8080/dav/hello.txt

        # list the share at depth 1. Expect: a 207 Multi-Status XML body
        # listing the share and its entries, including hello.txt.
        curl -u alice:secret -X PROPFIND http://localhost:8080/dav/ -H Depth:1

        # make a folder. Expect: 201 Created (409 if it already exists).
        curl -u alice:secret -X MKCOL http://localhost:8080/dav/folder

        # delete the file. Expect: 204 No Content; a following GET of the
        # same URL then returns 404.
        curl -u alice:secret -X DELETE http://localhost:8080/dav/hello.txt

    Or mount the share in a file manager. The command-line client cadaver
    works the same on every platform: cadaver http://localhost:8080/dav/ .
    To mount it graphically: on macOS, Finder > Go > Connect to Server and
    enter http://localhost:8080/dav/ ; on Windows, File Explorer > Map
    network drive > "Connect to a Web site..." with the same URL, or
    run: net use * http://localhost:8080/dav/ ; on Linux (GNOME Files),
    Other Locations > Connect to Server with dav://localhost:8080/dav/ .

    A plain browser visiting / gets a short page explaining the above.

    SECURITY: every verb maps a client-supplied path onto disk. As in the
    static-files example, the candidate path is resolved and confirmed to
    sit strictly inside the dav_root base before anything is read, written,
    or removed, so a path like /dav/../../etc/passwd cannot escape the
    share.
 */
$dav_base = __DIR__ . "/dav_root";
if (!is_dir($dav_base)) {
    mkdir($dav_base, 0777, true);
    file_put_contents($dav_base . "/readme.txt",
        "Hello from the Atto WebDAV example.\n");
}
$dav_base = realpath($dav_base);

/*
    Gates the share behind an authenticator. WebDAV runs over ordinary
    HTTP, so it is guarded the ordinary HTTP way: each request must carry
    credentials the server accepts, or it is turned away with 401 and a
    challenge the client answers by asking the user to log in.

    This example checks HTTP Basic credentials against a fixed list, which
    keeps the moving parts visible; a real deployment would swap the body
    of this function for whatever it already uses -- a user database, an
    LDAP bind, a token check -- without touching the verb handlers, since
    each of them simply calls this first and stops on false. Every verb is
    gated, including OPTIONS, so nothing about the share is reachable
    without logging in.

    Credentials arrive as an "Authorization: Basic ..." header. atto exposes
    it as PHP_AUTH_USER / PHP_AUTH_PW when it can, and always as
    HTTP_AUTHORIZATION, so both are handled here. hash_equals compares the
    password in constant time so a wrong guess cannot be timed.

    @return bool true when the request may proceed; false after a 401 has
        been sent, in which case the caller must stop
 */
$dav_users = ["alice" => "secret"];
$dav_authenticate = function () use ($test, $dav_users) {
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
    if (isset($dav_users[$user]) &&
        hash_equals($dav_users[$user], $password)) {
        return true;
    }
    $test->header("HTTP/1.1 401 Unauthorized");
    $test->header('WWW-Authenticate: Basic realm="Atto WebDAV"');
    return false;
};

/*
    Resolves the disk path for a request and confirms it stays inside the
    share. Returns the real path (which need not exist yet, for PUT and
    MKCOL) or false when the target would escape the base. The parent of a
    not-yet-existing target is what gets checked for containment.
 */
$dav_path = function ($relative) use ($dav_base) {
    $relative = str_replace("\\", "/", urldecode($relative));
    $candidate = $dav_base . "/" . ltrim($relative, "/");
    $separator = DIRECTORY_SEPARATOR;
    $existing = realpath($candidate);
    if ($existing !== false) {
        if (strncmp($existing, $dav_base . $separator,
            strlen($dav_base) + 1) === 0 || $existing === $dav_base) {
            return $existing;
        }
        return false;
    }
    $parent = realpath(dirname($candidate));
    if ($parent !== false && (strncmp($parent, $dav_base . $separator,
        strlen($dav_base) + 1) === 0 || $parent === $dav_base)) {
        return $parent . $separator . basename($candidate);
    }
    return false;
};

/*
    Pulls the resource path out of the request URI by stripping the /dav/
    prefix (and any query string). Using the raw URI rather than a single
    {resource} route capture lets a resource sit any number of folders deep,
    and lets the bare share root /dav/ resolve to the empty path.
 */
$dav_resource = function () {
    $uri = strtok($_SERVER['REQUEST_URI'] ?? "/dav/", "?");
    if (strncmp($uri, "/dav/", 5) === 0) {
        return substr($uri, 5);
    }
    return "";
};

/*
    Builds one <D:response> element describing a single file or folder for a
    PROPFIND multi-status reply.
 */
$dav_response = function ($disk_path, $href) {
    $is_dir = is_dir($disk_path);
    $modified = gmdate("D, d M Y H:i:s \G\M\T", (int)@filemtime($disk_path));
    $type = $is_dir ? "<D:collection/>" : "";
    $length = $is_dir ? "" :
        "<D:getcontentlength>" . filesize($disk_path) .
        "</D:getcontentlength>";
    return "<D:response><D:href>" . htmlspecialchars($href) . "</D:href>" .
        "<D:propstat><D:prop>" .
        "<D:resourcetype>" . $type . "</D:resourcetype>" .
        $length .
        "<D:getlastmodified>" . $modified . "</D:getlastmodified>" .
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status>" .
        "</D:propstat></D:response>";
};

/*
    OPTIONS advertises which methods and which WebDAV compliance class the
    share supports so a client knows it is talking to a DAV server.
 */
$dav_options = function () use ($test, $dav_authenticate) {
    if (!$dav_authenticate()) {
        return;
    }
    $test->header("HTTP/1.1 200 OK");
    $test->header("DAV: 1");
    $test->header("Allow: OPTIONS, PROPFIND, GET, PUT, MKCOL, DELETE, MOVE");
    $test->header("Content-Length: 0");
};
$test->addRoute("OPTIONS", "/dav", $dav_options);
$test->addRoute("OPTIONS", "/dav/*", $dav_options);

/*
    PROPFIND returns a 207 Multi-Status listing the target and, at Depth 1
    on a folder, its immediate children.
 */
$dav_propfind = function () use ($test, $dav_path, $dav_response,
    $dav_resource, $dav_authenticate) {
    if (!$dav_authenticate()) {
        return;
    }
    $resource = $dav_resource();
    $disk_path = $dav_path($resource);
    if ($disk_path === false || !file_exists($disk_path)) {
        $test->header("HTTP/1.1 404 Not Found");
        return;
    }
    $depth = $_SERVER['HTTP_DEPTH'] ?? "1";
    $href = "/dav/" . ltrim($resource, "/");
    $body = '<?xml version="1.0" encoding="utf-8"?>' .
        '<D:multistatus xmlns:D="DAV:">';
    $body .= $dav_response($disk_path, $href);
    if (is_dir($disk_path) && $depth !== "0") {
        foreach (scandir($disk_path) as $entry) {
            if ($entry === "." || $entry === "..") {
                continue;
            }
            $child = $disk_path . "/" . $entry;
            $child_href = rtrim($href, "/") . "/" . rawurlencode($entry);
            $body .= $dav_response($child, $child_href);
        }
    }
    $body .= "</D:multistatus>";
    $test->header("HTTP/1.1 207 Multi-Status");
    $test->header("Content-Type: application/xml; charset=utf-8");
    echo $body;
};
$test->addRoute("PROPFIND", "/dav", $dav_propfind);
$test->addRoute("PROPFIND", "/dav/*", $dav_propfind);

/*
    GET serves a file's bytes; a GET on a folder is not meaningful here.
 */
$test->addRoute("GET", "/dav/*",
    function () use ($test, $dav_path, $dav_resource, $dav_authenticate) {
        if (!$dav_authenticate()) {
            return;
        }
    $disk_path = $dav_path($dav_resource());
    if ($disk_path === false || !is_file($disk_path)) {
        $test->header("HTTP/1.1 404 Not Found");
        return;
    }
    $test->header("Content-Type: " . $test->mimeType($disk_path));
    echo $test->fileGetContents($disk_path);
});

/*
    PUT writes an uploaded file. The request body is in $_SERVER['CONTENT'].
    A brand new file answers 201 Created; an overwrite answers 204.
 */
$test->addRoute("PUT", "/dav/*",
    function () use ($test, $dav_path, $dav_resource, $dav_authenticate) {
        if (!$dav_authenticate()) {
            return;
        }
    $disk_path = $dav_path($dav_resource());
    if ($disk_path === false || is_dir($disk_path)) {
        $test->header("HTTP/1.1 409 Conflict");
        return;
    }
    $existed = is_file($disk_path);
    if (file_put_contents($disk_path, $_SERVER['CONTENT'] ?? "") === false) {
        $test->header("HTTP/1.1 409 Conflict");
        return;
    }
    $test->header($existed ? "HTTP/1.1 204 No Content" :
        "HTTP/1.1 201 Created");
});

/*
    MKCOL makes a new folder (collection). 201 on success, 409 when the
    parent is missing or the name is taken.
 */
$test->addRoute("MKCOL", "/dav/*",
    function () use ($test, $dav_path, $dav_resource, $dav_authenticate) {
        if (!$dav_authenticate()) {
            return;
        }
        $disk_path = $dav_path($dav_resource());
        if ($disk_path === false || file_exists($disk_path) ||
            !is_dir(dirname($disk_path))) {
            $test->header("HTTP/1.1 409 Conflict");
            return;
        }
        $test->header(mkdir($disk_path) ? "HTTP/1.1 201 Created" :
            "HTTP/1.1 409 Conflict");
    }
);

/*
    DELETE removes a file, or a folder and everything under it. 204 on
    success.
 */
$test->addRoute("DELETE", "/dav/*",
    function () use ($test, $dav_path, $dav_resource, $dav_authenticate) {
        if (!$dav_authenticate()) {
            return;
        }
        $disk_path = $dav_path($dav_resource());
        if ($disk_path === false || !file_exists($disk_path)) {
            $test->header("HTTP/1.1 404 Not Found");
            return;
        }
        $remove = function ($path) use (&$remove) {
            if (is_dir($path)) {
                foreach (scandir($path) as $entry) {
                    if ($entry !== "." && $entry !== "..") {
                        $remove($path . "/" . $entry);
                    }
                }
                rmdir($path);
            } else {
                unlink($path);
            }
        };
        $remove($disk_path);
        $test->header("HTTP/1.1 204 No Content");
    }
);

/*
    MOVE renames a file or folder to the path named in the Destination
    header, which arrives as a full URL whose /dav/ portion is stripped.
 */
$test->addRoute("MOVE", "/dav/*",
    function () use ($test, $dav_path, $dav_resource, $dav_authenticate) {
        if (!$dav_authenticate()) {
            return;
        }
        $disk_path = $dav_path($dav_resource());
        $destination = $_SERVER['HTTP_DESTINATION'] ?? "";
        $dav_at = strpos($destination, "/dav/");
        if ($disk_path === false || !file_exists($disk_path) ||
            $dav_at === false) {
            $test->header("HTTP/1.1 409 Conflict");
            return;
        }
        $target = $dav_path(substr($destination, $dav_at + strlen("/dav/")));
        if ($target === false) {
            $test->header("HTTP/1.1 409 Conflict");
            return;
        }
        $existed = file_exists($target);
        if (!rename($disk_path, $target)) {
            $test->header("HTTP/1.1 409 Conflict");
            return;
        }
        $test->header($existed ? "HTTP/1.1 204 No Content" :
            "HTTP/1.1 201 Created");
    }
);

/*
    A plain browser landing page explaining how to talk to the share.
 */
$test->get('/', function () {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>WebDAV Example - Atto Server</title></head>
    <body>
    <h1>WebDAV - Atto Server</h1>
    <p>This server exports the <code>dav_root</code> folder over WebDAV at
    <a href="/dav/">/dav/</a>. Atto routes the WebDAV verbs the same way it
    routes GET and POST, so the whole share is the handful of route
    handlers in this file.</p>
    <p>Talk to it with any WebDAV client. The share is gated behind an
    authenticator: every request must log in as the demo user
    <code>alice</code> with password <code>secret</code> (curl's
    <code>-u</code> below), or the verb answers 401. The curl commands below
    form one self-contained round trip; the comment on each says what it
    does and what to expect back:</p>
    <pre>
# make a small file locally so there is something to upload
echo 'hello webdav' &gt; hello.txt

# upload it -- expect 201 Created (204 if it already existed)
curl -u alice:secret -T hello.txt http://localhost:8080/dav/hello.txt

# read it back -- expect the contents: hello webdav
curl -u alice:secret http://localhost:8080/dav/hello.txt

# list the share -- expect a 207 Multi-Status XML listing
curl -u alice:secret -X PROPFIND http://localhost:8080/dav/ -H Depth:1

# make a folder -- expect 201 Created (409 if it already exists)
curl -u alice:secret -X MKCOL http://localhost:8080/dav/folder

# delete the file -- expect 204; a following GET then returns 404
curl -u alice:secret -X DELETE http://localhost:8080/dav/hello.txt
    </pre>
    <p>Or mount the share in a file manager. The command-line client
    <code>cadaver http://localhost:8080/dav/</code> works the same on every
    platform. To mount it graphically: on <b>macOS</b>, Finder &rarr; Go
    &rarr; Connect to Server with <code>http://localhost:8080/dav/</code>;
    on <b>Windows</b>, File Explorer &rarr; Map network drive &rarr;
    "Connect to a Web site..." with the same URL (or
    <code>net use * http://localhost:8080/dav/</code>); on <b>Linux</b>
    (GNOME Files), Other Locations &rarr; Connect to Server with
    <code>dav://localhost:8080/dav/</code>.</p>
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
