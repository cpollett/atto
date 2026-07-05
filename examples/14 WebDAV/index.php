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
    and then talking to it with any WebDAV client. With curl:
        curl -X PROPFIND http://localhost:8080/dav/ -H 'Depth: 1'
        curl -T local.txt http://localhost:8080/dav/local.txt
        curl -X MKCOL http://localhost:8080/dav/folder/
        curl http://localhost:8080/dav/local.txt
        curl -X DELETE http://localhost:8080/dav/local.txt
    Or mount it: macOS Finder "Connect to Server" http://localhost:8080/dav/,
    or `cadaver http://localhost:8080/dav/`.

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
$dav_options = function () use ($test) {
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
    $dav_resource) {
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
    function () use ($test, $dav_path, $dav_resource) {
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
    function () use ($test, $dav_path, $dav_resource) {
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
    function () use ($test, $dav_path, $dav_resource) {
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
    function () use ($test, $dav_path, $dav_resource) {
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
    function () use ($test, $dav_path, $dav_resource) {
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
    <p>Talk to it with any WebDAV client. For example, with curl:</p>
    <pre>
curl -X PROPFIND http://localhost:8080/dav/ -H 'Depth: 1'
curl -T local.txt   http://localhost:8080/dav/local.txt
curl -X MKCOL       http://localhost:8080/dav/folder/
curl                http://localhost:8080/dav/local.txt
curl -X DELETE      http://localhost:8080/dav/local.txt
    </pre>
    <p>Or mount it: in macOS Finder use Connect to Server with
    <code>http://localhost:8080/dav/</code>, or run
    <code>cadaver http://localhost:8080/dav/</code>.</p>
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
