<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * A small, reusable CalDAV calendar endpoint that plugs into an
 * atto WebSite. CalDAV (RFC 4791) is calendaring layered on top
 * of WebDAV: a calendar is a folder, and each event or task is a
 * small file in the iCalendar text format (RFC 5545) inside it.
 * This class takes a running WebSite, a folder on disk to keep
 * calendars in, and an optional log-in check, and registers the
 * calendar routes on the site so the ordinary WebDAV verbs plus
 * the CalDAV ones create, list, read, change, and delete
 * calendars and their events.
 *
 * It is written by composition rather than by extending WebSite
 * so a project that already runs its own WebSite (for instance
 * Yioop, with its own subclass and its own log-in) can attach a
 * calendar to that site without changing which server class it
 * runs. Every step is a method with a docblock so a reuser can
 * override storage, discovery, or a single verb in a subclass
 * and leave the rest in place.
 *
 * This file is self-contained in atto's style: it names no
 * framework or configuration, reads no outside constants, and
 * loads no other atto file. The caller loads whichever WebSite
 * it wants first, then this class attaches to that instance.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * Registers and answers CalDAV calendar routes on a WebSite. A
 * calendar is a folder holding a hidden metadata file and any
 * number of .ics event files; the class turns the CalDAV verbs
 * into ordinary atto route handlers over that folder.
 */
class CalDav
{
    /**
     * Name of the hidden per-calendar metadata file. Its presence
     * in a folder is what marks that folder as a calendar (rather
     * than a plain folder); it holds the calendar's display name
     * and the component types it accepts, as a small JSON object.
     * @var string
     */
    const META_FILE = ".calendar.json";
    /**
     * Filename suffix of a single calendar object (one event or
     * task) stored as iCalendar text, per RFC 5545.
     * @var string
     */
    const RESOURCE_SUFFIX = ".ics";
    /**
     * Content type served for and expected from calendar objects.
     * @var string
     */
    const CALENDAR_TYPE = "text/calendar; charset=utf-8";
    /**
     * The DAV XML namespace, used for the WebDAV property elements.
     * @var string
     */
    const NS_DAV = "DAV:";
    /**
     * The CalDAV XML namespace (RFC 4791), used for the calendar
     * property and report elements.
     * @var string
     */
    const NS_CALDAV = "urn:ietf:params:xml:ns:caldav";
    /**
     * The calendar-server namespace, used for the getctag change
     * tag that clients poll to learn whether a calendar changed.
     * @var string
     */
    const NS_CALSERVER = "http://calendarserver.org/ns/";

    /**
     * The WebSite (or subclass) this calendar attaches to. Route
     * handlers call back into it for headers and cached file I/O.
     * @var WebSite
     */
    protected $site;
    /**
     * Absolute, resolved path of the folder that holds calendars.
     * @var string
     */
    protected $calendar_root;
    /**
     * URL path the calendars are served under, without a trailing
     * slash, for example "/calendars".
     * @var string
     */
    protected $route_prefix;
    /**
     * Log-in check run before every verb, or null to leave the
     * calendars open. When set, it returns true to let the request
     * proceed, or sends its own 401 and returns false to stop it.
     * @var callable|null
     */
    protected $authenticator;
    /**
     * Component types a new calendar accepts when the client does
     * not say. VEVENT is an appointment, VTODO a task.
     * @var array
     */
    protected $default_components = ["VEVENT", "VTODO"];

    /**
     * Attaches a calendar endpoint to a running WebSite. Creates
     * the calendar folder if it is missing and remembers where it
     * is, what URL path to serve it under, and how to check log-in.
     *
     * @param WebSite $site the site to register calendar routes on
     * @param string $calendar_root folder on disk to keep the
     *      calendars in; created if it does not yet exist
     * @param string $route_prefix URL path to serve calendars
     *      under; a trailing slash is trimmed
     * @param callable $authenticator optional log-in check run
     *      before each verb, or null to leave the calendars open
     */
    public function __construct($site, $calendar_root,
        $route_prefix = "/calendars", $authenticator = null)
    {
        $this->site = $site;
        if (!is_dir($calendar_root)) {
            mkdir($calendar_root, 0777, true);
        }
        $this->calendar_root = realpath($calendar_root);
        $prefix = rtrim($route_prefix, "/");
        if ($prefix === "") {
            $prefix = "/calendars";
        }
        $this->route_prefix = $prefix;
        $this->authenticator = $authenticator;
    }

    /**
     * Adds every calendar route to the site. Both the bare prefix
     * (the list of calendars) and any path beneath it are routed,
     * so a handler can address a calendar or an event any number
     * of folders deep. Call this once after construction.
     */
    public function register()
    {
        $prefix = $this->route_prefix;
        $verbs = [
            "OPTIONS" => "handleOptions",
            "PROPFIND" => "handlePropfind",
            "MKCALENDAR" => "handleMkcalendar",
            "GET" => "handleGet",
            "PUT" => "handlePut",
            "DELETE" => "handleDelete",
        ];
        foreach ($verbs as $verb => $method) {
            $this->site->addRoute($verb, $prefix, [$this, $method]);
            $this->site->addRoute($verb, $prefix . "/*", [$this, $method]);
        }
    }

    /**
     * Runs the log-in check, if one was given. Returns true when
     * the request may proceed. When it returns false the check has
     * already sent a 401, and the calling verb must stop.
     *
     * @return bool whether the request may proceed
     */
    public function authenticate()
    {
        if ($this->authenticator === null) {
            return true;
        }
        return (bool)call_user_func($this->authenticator);
    }

    /**
     * Sends a response status line whose protocol token is the one
     * the request arrived on, taken from SERVER_PROTOCOL, so the
     * same handler serves an HTTP/1.1, HTTP/2, or HTTP/3 client
     * without any version wired in. WebSite renders the line for
     * HTTP/1.1 and reduces it to a :status pseudo-header for the
     * later protocols; either way it keeps the numeric code. The
     * fallback is used only when no request protocol is in scope,
     * which does not happen for a request the server has parsed.
     *
     * @param int $code the numeric status
     * @param string $reason the reason phrase
     */
    protected function status($code, $reason)
    {
        $protocol = $_SERVER['SERVER_PROTOCOL'] ?? "HTTP/1.1";
        $this->site->header($protocol . " " . $code . " " . $reason);
    }

    /**
     * Pulls the calendar-relative path out of the request URI by
     * stripping the route prefix and any query string. The bare
     * prefix resolves to the empty path, meaning the whole set of
     * calendars.
     *
     * @param string $uri the request URI to read; the current
     *      request's URI when omitted
     * @return string the path under the prefix, without a leading
     *      slash
     */
    public function resourceForUri($uri = null)
    {
        if ($uri === null) {
            $uri = $_SERVER['REQUEST_URI'] ?? $this->route_prefix;
        }
        $uri = strtok($uri, "?");
        $prefix = $this->route_prefix;
        $prefix_len = strlen($prefix);
        if (strncmp($uri, $prefix, $prefix_len) === 0) {
            return ltrim(substr($uri, $prefix_len), "/");
        }
        return "";
    }

    /**
     * Resolves the disk path for a calendar-relative path and
     * confirms it stays inside the calendar folder. Returns the
     * real path, which need not exist yet (for a create), or false
     * when the target would escape the folder. For a target that
     * does not exist yet, its parent is what gets checked.
     *
     * @param string $relative calendar-relative path to resolve
     * @return string|false the contained disk path, or false when
     *      it would escape the calendar folder
     */
    public function containedPath($relative)
    {
        $relative = str_replace("\\", "/", urldecode($relative));
        $base = $this->calendar_root;
        $candidate = $base . "/" . ltrim($relative, "/");
        $separator = DIRECTORY_SEPARATOR;
        $existing = realpath($candidate);
        if ($existing !== false) {
            if ($existing === $base || strncmp($existing,
                $base . $separator, strlen($base) + 1) === 0) {
                return $existing;
            }
            return false;
        }
        $parent = realpath(dirname($candidate));
        if ($parent !== false && ($parent === $base || strncmp($parent,
            $base . $separator, strlen($base) + 1) === 0)) {
            return $parent . $separator . basename($candidate);
        }
        return false;
    }

    /**
     * Computes the entity tag for a calendar object from its
     * bytes. The tag changes exactly when the bytes change, so a
     * client can tell a stale copy from a current one and a
     * conflicting write from a safe one. It is a validator, not a
     * secret, but it is derived from client-supplied content, so a
     * collision-resistant SHA-256 is used rather than a hash with
     * known collisions. Returned already quoted, as the getetag
     * property and the ETag header want it.
     *
     * @param string $bytes the calendar object's contents
     * @return string the quoted entity tag
     */
    public function computeETag($bytes)
    {
        return '"' . hash("sha256", $bytes) . '"';
    }

    /**
     * Computes a calendar's change tag (CTag) from a summary of
     * what it holds. The tag changes when any event is added,
     * changed, or removed, so a client can poll this one value to
     * learn whether it needs to re-list the calendar at all.
     *
     * @param string $disk_path the calendar folder on disk
     * @return string the quoted change tag
     */
    public function computeCTag($disk_path)
    {
        $summary = "";
        if (is_dir($disk_path)) {
            $entries = scandir($disk_path);
            sort($entries);
            foreach ($entries as $entry) {
                if (!$this->isResourceName($entry)) {
                    continue;
                }
                $child = $disk_path . "/" . $entry;
                $summary .= $entry . ":" . (int)@filemtime($child) .
                    ":" . (int)@filesize($child) . "\n";
            }
        }
        return '"' . hash("sha256", $summary) . '"';
    }

    /**
     * Reads a calendar's display name from its metadata file,
     * falling back to the folder name when none was stored.
     *
     * @param string $disk_path the calendar folder on disk
     * @return string the display name
     */
    public function displayNameFor($disk_path)
    {
        $meta = $this->readMeta($disk_path);
        if (!empty($meta['displayname'])) {
            return $meta['displayname'];
        }
        return basename($disk_path);
    }

    /**
     * Reads a calendar's accepted component types from its
     * metadata file, falling back to the defaults when none were
     * stored.
     *
     * @param string $disk_path the calendar folder on disk
     * @return array the accepted component type names
     */
    public function componentsFor($disk_path)
    {
        $meta = $this->readMeta($disk_path);
        if (!empty($meta['components']) && is_array($meta['components'])) {
            return $meta['components'];
        }
        return $this->default_components;
    }

    /**
     * Reads and decodes a calendar's metadata file, or an empty
     * array when it is missing or unreadable.
     *
     * @param string $disk_path the calendar folder on disk
     * @return array the decoded metadata
     */
    protected function readMeta($disk_path)
    {
        $meta_path = $disk_path . "/" . self::META_FILE;
        if (!is_file($meta_path)) {
            return [];
        }
        $decoded = json_decode($this->site->fileGetContents($meta_path),
            true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * True when a directory is a calendar, that is, when it holds
     * the metadata file a MKCALENDAR wrote.
     *
     * @param string $disk_path the folder to test
     * @return bool whether the folder is a calendar
     */
    public function isCalendar($disk_path)
    {
        return is_dir($disk_path) &&
            is_file($disk_path . "/" . self::META_FILE);
    }

    /**
     * True when a directory entry is a stored calendar object,
     * that is, a visible file whose name ends in the resource
     * suffix. Hidden files, including the metadata file, are left
     * out of listings and change tags.
     *
     * @param string $entry a bare directory entry name
     * @return bool whether the entry names a calendar object
     */
    public function isResourceName($entry)
    {
        if ($entry === "." || $entry === ".." || $entry[0] === ".") {
            return false;
        }
        $suffix = self::RESOURCE_SUFFIX;
        return substr($entry, -strlen($suffix)) === $suffix;
    }

    /**
     * Reads the display name out of a MKCALENDAR request body.
     * Only the fixed CalDAV vocabulary is looked for, so this
     * reads the one displayname element directly rather than
     * parsing the whole document. Returns an empty string when the
     * body names none.
     *
     * @param string $body the MKCALENDAR request body
     * @return string the display name, or an empty string
     */
    public function parseDisplayName($body)
    {
        $pattern = "/<(?:[\\w.-]+:)?displayname[^>]*>" .
            "(.*?)<\\/(?:[\\w.-]+:)?displayname>/si";
        if (preg_match($pattern, $body, $matches)) {
            return trim(html_entity_decode($matches[1]));
        }
        return "";
    }

    /**
     * Reads the accepted component types out of a MKCALENDAR
     * request body by collecting the name of each comp element.
     * Returns the defaults when the body lists none.
     *
     * @param string $body the MKCALENDAR request body
     * @return array the accepted component type names
     */
    public function parseComponentSet($body)
    {
        $pattern = "/<(?:[\\w.-]+:)?comp\\s+[^>]*name=" .
            "\"([^\"]+)\"/i";
        if (preg_match_all($pattern, $body, $matches) &&
            !empty($matches[1])) {
            return array_values(array_unique($matches[1]));
        }
        return $this->default_components;
    }

    /**
     * Answers OPTIONS: tells the client this is a WebDAV server
     * that also speaks calendar-access, and lists the verbs the
     * calendar routes answer, so a calendar client knows what it
     * may send.
     */
    public function handleOptions()
    {
        if (!$this->authenticate()) {
            return;
        }
        $this->status(200, "OK");
        $this->site->header("DAV: 1, calendar-access");
        $this->site->header("Allow: OPTIONS, PROPFIND, MKCALENDAR, GET, " .
            "PUT, DELETE");
        $this->site->header("Content-Length: 0");
    }

    /**
     * Answers MKCALENDAR: makes a new calendar folder and writes
     * its metadata (display name and accepted component types) from
     * the request body. A fresh calendar answers 201; a name that
     * is taken or a missing parent answers 409.
     */
    public function handleMkcalendar()
    {
        if (!$this->authenticate()) {
            return;
        }
        $disk_path = $this->containedPath($this->resourceForUri());
        if ($disk_path === false || file_exists($disk_path) ||
            !is_dir(dirname($disk_path))) {
            $this->status(409, "Conflict");
            return;
        }
        if (!mkdir($disk_path)) {
            $this->status(409, "Conflict");
            return;
        }
        $body = $_SERVER['CONTENT'] ?? "";
        $display = $this->parseDisplayName($body);
        if ($display === "") {
            $display = basename($disk_path);
        }
        $meta = ["displayname" => $display,
            "components" => $this->parseComponentSet($body)];
        $this->site->filePutContents($disk_path . "/" . self::META_FILE,
            json_encode($meta));
        $this->status(201, "Created");
    }

    /**
     * Answers PROPFIND: returns a 207 multi-status describing the
     * target and, at Depth 1 on a folder, its immediate children.
     * A calendar folder reports itself as a calendar with its
     * change tag and accepted components; an event reports its
     * entity tag, size, and type.
     */
    public function handlePropfind()
    {
        if (!$this->authenticate()) {
            return;
        }
        $resource = $this->resourceForUri();
        $disk_path = $this->containedPath($resource);
        if ($disk_path === false || !file_exists($disk_path)) {
            $this->status(404, "Not Found");
            return;
        }
        $depth = $_SERVER['HTTP_DEPTH'] ?? "1";
        $href = $this->hrefFor($resource, is_dir($disk_path));
        $body = '<?xml version="1.0" encoding="utf-8"?>' .
            '<D:multistatus xmlns:D="' . self::NS_DAV . '" xmlns:C="' .
            self::NS_CALDAV . '" xmlns:CS="' . self::NS_CALSERVER . '">';
        $body .= $this->responseFor($disk_path, $href);
        if (is_dir($disk_path) && $depth !== "0") {
            foreach (scandir($disk_path) as $entry) {
                if ($entry === "." || $entry === ".." ||
                    $entry === self::META_FILE) {
                    continue;
                }
                $child = $disk_path . "/" . $entry;
                $child_rel = ltrim($resource . "/" . $entry, "/");
                $child_href = $this->hrefFor($child_rel, is_dir($child));
                $body .= $this->responseFor($child, $child_href);
            }
        }
        $body .= "</D:multistatus>";
        $this->status(207, "Multi-Status");
        $this->site->header("Content-Type: application/xml; charset=utf-8");
        echo $body;
    }

    /**
     * Builds the href a PROPFIND reply reports for one target,
     * prefixing the route and giving a folder a trailing slash the
     * way calendar clients expect.
     *
     * @param string $relative the calendar-relative path
     * @param bool $is_dir whether the target is a folder
     * @return string the href to report
     */
    protected function hrefFor($relative, $is_dir)
    {
        $href = $this->route_prefix . "/" . ltrim($relative, "/");
        if ($relative === "") {
            $href = $this->route_prefix . "/";
        }
        if ($is_dir && substr($href, -1) !== "/") {
            $href .= "/";
        }
        return $href;
    }

    /**
     * Builds one response element for a PROPFIND reply, choosing
     * the calendar, plain-folder, or event shape by what the disk
     * path is.
     *
     * @param string $disk_path the target on disk
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function responseFor($disk_path, $href)
    {
        if ($this->isCalendar($disk_path)) {
            return $this->calendarResponse($disk_path, $href);
        }
        if (is_dir($disk_path)) {
            return $this->collectionResponse($href);
        }
        return $this->resourceResponse($disk_path, $href);
    }

    /**
     * Builds the response element for a calendar folder: it is a
     * collection and a calendar, and it carries a display name,
     * its accepted component types, and its change tag.
     *
     * @param string $disk_path the calendar folder on disk
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function calendarResponse($disk_path, $href)
    {
        $components = "";
        foreach ($this->componentsFor($disk_path) as $component) {
            $components .= '<C:comp name="' .
                htmlspecialchars($component) . '"/>';
        }
        $prop = "<D:resourcetype><D:collection/><C:calendar/>" .
            "</D:resourcetype>" .
            "<D:displayname>" .
            htmlspecialchars($this->displayNameFor($disk_path)) .
            "</D:displayname>" .
            "<C:supported-calendar-component-set>" . $components .
            "</C:supported-calendar-component-set>" .
            "<CS:getctag>" . $this->computeCTag($disk_path) .
            "</CS:getctag>";
        return $this->wrapResponse($href, $prop);
    }

    /**
     * Builds the response element for a plain folder, such as the
     * folder that holds the calendars: it is a collection and
     * nothing more.
     *
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function collectionResponse($href)
    {
        $prop = "<D:resourcetype><D:collection/></D:resourcetype>";
        return $this->wrapResponse($href, $prop);
    }

    /**
     * Builds the response element for a single event: its entity
     * tag, its type, its size, and when it last changed.
     *
     * @param string $disk_path the event file on disk
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function resourceResponse($disk_path, $href)
    {
        $bytes = $this->site->fileGetContents($disk_path);
        $modified = gmdate("D, d M Y H:i:s \\G\\M\\T",
            (int)@filemtime($disk_path));
        $prop = "<D:resourcetype/>" .
            "<D:getetag>" . $this->computeETag($bytes) . "</D:getetag>" .
            "<D:getcontenttype>" . self::CALENDAR_TYPE .
            "</D:getcontenttype>" .
            "<D:getcontentlength>" . strlen($bytes) .
            "</D:getcontentlength>" .
            "<D:getlastmodified>" . $modified . "</D:getlastmodified>";
        return $this->wrapResponse($href, $prop);
    }

    /**
     * Wraps a set of properties in the response and propstat
     * elements a PROPFIND reply uses, marking them all found.
     *
     * @param string $href the href the properties belong to
     * @param string $prop the property elements
     * @return string the response element
     */
    protected function wrapResponse($href, $prop)
    {
        return "<D:response><D:href>" . htmlspecialchars($href) .
            "</D:href><D:propstat><D:prop>" . $prop .
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status>" .
            "</D:propstat></D:response>";
    }

    /**
     * Answers GET: serves an event's bytes as calendar text, with
     * its entity tag, so a client can store and later re-check it.
     * A GET of a folder is not meaningful here and answers 404.
     */
    public function handleGet()
    {
        if (!$this->authenticate()) {
            return;
        }
        $disk_path = $this->containedPath($this->resourceForUri());
        if ($disk_path === false || !is_file($disk_path)) {
            $this->status(404, "Not Found");
            return;
        }
        $bytes = $this->site->fileGetContents($disk_path);
        $this->status(200, "OK");
        $this->site->header("Content-Type: " . self::CALENDAR_TYPE);
        $this->site->header("ETag: " . $this->computeETag($bytes));
        echo $bytes;
    }

    /**
     * Answers PUT: stores an event's bytes. If-None-Match "*" asks
     * to create only, so an existing event answers 412; If-Match
     * asks to overwrite a specific version, so a tag that no longer
     * matches answers 412. A new event answers 201, an overwrite
     * 204, and the reply carries the stored event's new tag.
     */
    public function handlePut()
    {
        if (!$this->authenticate()) {
            return;
        }
        $disk_path = $this->containedPath($this->resourceForUri());
        if ($disk_path === false || is_dir($disk_path) ||
            !is_dir(dirname($disk_path))) {
            $this->status(409, "Conflict");
            return;
        }
        $existed = is_file($disk_path);
        if (!$this->matchesPreconditions($disk_path, $existed)) {
            $this->status(412, "Precondition Failed");
            return;
        }
        $bytes = $_SERVER['CONTENT'] ?? "";
        if ($this->site->filePutContents($disk_path, $bytes) === false) {
            $this->status(409, "Conflict");
            return;
        }
        if ($existed) {
            $this->status(204, "No Content");
        } else {
            $this->status(201, "Created");
        }
        $this->site->header("ETag: " . $this->computeETag($bytes));
    }

    /**
     * Checks a write's If-Match and If-None-Match conditions
     * against what is on disk. If-None-Match "*" requires the
     * target be absent; If-Match requires the target's current tag
     * be among those listed. Returns whether the write may go
     * ahead.
     *
     * @param string $disk_path the target event on disk
     * @param bool $existed whether the target already exists
     * @return bool whether the write's preconditions hold
     */
    protected function matchesPreconditions($disk_path, $existed)
    {
        $if_none_match = $_SERVER['HTTP_IF_NONE_MATCH'] ?? "";
        if (trim($if_none_match) === "*" && $existed) {
            return false;
        }
        $if_match = $_SERVER['HTTP_IF_MATCH'] ?? "";
        if ($if_match === "") {
            return true;
        }
        if (!$existed) {
            return false;
        }
        $current = $this->computeETag(
            $this->site->fileGetContents($disk_path));
        foreach (explode(",", $if_match) as $candidate) {
            if (trim($candidate) === $current || trim($candidate) === "*") {
                return true;
            }
        }
        return false;
    }

    /**
     * Answers DELETE: removes an event, or a calendar and
     * everything in it. A missing target answers 404, a removal
     * 204.
     */
    public function handleDelete()
    {
        if (!$this->authenticate()) {
            return;
        }
        $disk_path = $this->containedPath($this->resourceForUri());
        if ($disk_path === false || !file_exists($disk_path)) {
            $this->status(404, "Not Found");
            return;
        }
        $this->removePath($disk_path);
        $this->status(204, "No Content");
    }

    /**
     * Removes a file, or a folder and everything under it.
     *
     * @param string $path the disk path to remove
     */
    protected function removePath($path)
    {
        if (is_dir($path)) {
            foreach (scandir($path) as $entry) {
                if ($entry !== "." && $entry !== "..") {
                    $this->removePath($path . "/" . $entry);
                }
            }
            rmdir($path);
            return;
        }
        unlink($path);
    }
}
