<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * A small, reusable CardDAV address-book endpoint that plugs into
 * an atto WebSite. CardDAV (RFC 6352) is contact management
 * layered on top of WebDAV, the address-book sibling of CalDAV: an
 * address book is a folder, and each contact is a small file in
 * the vCard text format (RFC 6350) inside it. This class takes a
 * running WebSite, a folder on disk to keep address books in, and
 * an optional log-in check, and registers the routes on the site
 * so the ordinary WebDAV verbs plus the CardDAV ones create, list,
 * read, change, and delete address books and their contacts.
 *
 * It is written by composition rather than by extending WebSite
 * so a project that already runs its own WebSite (for instance
 * Yioop, with its own subclass and its own log-in) can attach an
 * address book to that site without changing which server class it
 * runs. Every step is a method with a docblock so a reuser can
 * override storage, discovery, or a single verb in a subclass and
 * leave the rest in place.
 *
 * This file is self-contained in atto's style: it names no
 * framework or configuration, reads no outside constants, and
 * loads no other atto file. The caller loads whichever WebSite it
 * wants first, then this class attaches to that instance.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * Registers and answers CardDAV address-book routes on a WebSite.
 * An address book is a folder holding a hidden metadata file and
 * any number of .vcf contact files; the class turns the CardDAV
 * verbs into ordinary atto route handlers over that folder.
 */
class CardDav
{
    /**
     * Name of the hidden per-address-book metadata file. Its
     * presence in a folder is what marks that folder as an address
     * book (rather than a plain folder); it holds the book's
     * display name as a small JSON object.
     * @var string
     */
    const META_FILE = ".addressbook.json";
    /**
     * Filename suffix of a single contact stored as vCard text,
     * per RFC 6350.
     * @var string
     */
    const RESOURCE_SUFFIX = ".vcf";
    /**
     * Content type served for and expected from contacts.
     * @var string
     */
    const VCARD_TYPE = "text/vcard; charset=utf-8";
    /**
     * The DAV XML namespace, used for the WebDAV property elements.
     * @var string
     */
    const NS_DAV = "DAV:";
    /**
     * The CardDAV XML namespace (RFC 6352), used for the
     * address-book property and report elements.
     * @var string
     */
    const NS_CARDDAV = "urn:ietf:params:xml:ns:carddav";
    /**
     * The calendar-server namespace, used for the getctag change
     * tag that clients poll to learn whether a book changed. The
     * name is historical; the tag is not calendar-specific.
     * @var string
     */
    const NS_CALSERVER = "http://calendarserver.org/ns/";

    /**
     * The WebSite (or subclass) this address book attaches to.
     * Route handlers call back into it for headers and cached file
     * I/O.
     * @var WebSite
     */
    protected $site;
    /**
     * Absolute, resolved path of the folder that holds address
     * books.
     * @var string
     */
    protected $contact_root;
    /**
     * URL path the address books are served under, without a
     * trailing slash, for example "/addressbooks".
     * @var string
     */
    protected $route_prefix;
    /**
     * Log-in check run before every verb, or null to leave the
     * address books open. When set, it returns true to let the
     * request proceed, or sends its own 401 and returns false to
     * stop it.
     * @var callable|null
     */
    protected $authenticator;

    /**
     * Attaches an address-book endpoint to a running WebSite.
     * Creates the address-book folder if it is missing and
     * remembers where it is, what URL path to serve it under, and
     * how to check log-in.
     *
     * @param WebSite $site the site to register routes on
     * @param string $contact_root folder on disk to keep the
     *      address books in; created if it does not yet exist
     * @param string $route_prefix URL path to serve address books
     *      under; a trailing slash is trimmed
     * @param callable $authenticator optional log-in check run
     *      before each verb, or null to leave the books open
     */
    public function __construct($site, $contact_root,
        $route_prefix = "/addressbooks", $authenticator = null)
    {
        $this->site = $site;
        if (!is_dir($contact_root)) {
            mkdir($contact_root, 0777, true);
        }
        $this->contact_root = realpath($contact_root);
        $prefix = rtrim($route_prefix, "/");
        if ($prefix === "") {
            $prefix = "/addressbooks";
        }
        $this->route_prefix = $prefix;
        $this->authenticator = $authenticator;
    }

    /**
     * Adds every address-book route to the site. Both the bare
     * prefix (the list of books) and any path beneath it are
     * routed, so a handler can address a book or a contact any
     * number of folders deep. Call this once after construction.
     */
    public function register()
    {
        $prefix = $this->route_prefix;
        $verbs = [
            "OPTIONS" => "handleOptions",
            "PROPFIND" => "handlePropfind",
            "MKCOL" => "handleMkcol",
            "GET" => "handleGet",
            "PUT" => "handlePut",
            "DELETE" => "handleDelete",
            "REPORT" => "handleReport",
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
     * Pulls the book-relative path out of the request URI by
     * stripping the route prefix and any query string. The bare
     * prefix resolves to the empty path, meaning the whole set of
     * address books.
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
     * Resolves the disk path for a book-relative path and confirms
     * it stays inside the address-book folder. Returns the real
     * path, which need not exist yet (for a create), or false when
     * the target would escape the folder. For a target that does
     * not exist yet, its parent is what gets checked.
     *
     * @param string $relative book-relative path to resolve
     * @return string|false the contained disk path, or false when
     *      it would escape the address-book folder
     */
    public function containedPath($relative)
    {
        $relative = str_replace("\\", "/", urldecode($relative));
        $base = $this->contact_root;
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
     * Computes the entity tag for a contact from its bytes. The tag
     * changes exactly when the bytes change, so a client can tell a
     * stale copy from a current one and a conflicting write from a
     * safe one. It is a validator, not a secret, but it is derived
     * from client-supplied content, so a collision-resistant
     * SHA-256 is used rather than a hash with known collisions.
     * Returned already quoted, as the getetag property and the ETag
     * header want it.
     *
     * @param string $bytes the contact's contents
     * @return string the quoted entity tag
     */
    public function computeETag($bytes)
    {
        return '"' . hash("sha256", $bytes) . '"';
    }

    /**
     * Computes an address book's change tag (CTag) from a summary
     * of what it holds. The tag changes when any contact is added,
     * changed, or removed, so a client can poll this one value to
     * learn whether it needs to re-list the book at all.
     *
     * @param string $disk_path the address-book folder on disk
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
     * Reads an address book's display name from its metadata file,
     * falling back to the folder name when none was stored.
     *
     * @param string $disk_path the address-book folder on disk
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
     * Reads and decodes an address book's metadata file, or an
     * empty array when it is missing or unreadable.
     *
     * @param string $disk_path the address-book folder on disk
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
     * True when a directory is an address book, that is, when it
     * holds the metadata file a MKCOL wrote.
     *
     * @param string $disk_path the folder to test
     * @return bool whether the folder is an address book
     */
    public function isAddressbook($disk_path)
    {
        return is_dir($disk_path) &&
            is_file($disk_path . "/" . self::META_FILE);
    }

    /**
     * True when a directory entry is a stored contact, that is, a
     * visible file whose name ends in the resource suffix. Hidden
     * files, including the metadata file, are left out of listings
     * and change tags.
     *
     * @param string $entry a bare directory entry name
     * @return bool whether the entry names a contact
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
     * Reads the display name out of a request body. Only the fixed
     * CardDAV vocabulary is looked for, so this reads the one
     * displayname element directly rather than parsing the whole
     * document. Returns an empty string when the body names none.
     *
     * @param string $body the request body
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
     * True when a MKCOL body asks for an address book, that is,
     * when its resource type names the addressbook element. A
     * MKCOL without one makes a plain folder.
     *
     * @param string $body the MKCOL request body
     * @return bool whether the body asks for an address book
     */
    public function bodyMakesAddressbook($body)
    {
        return preg_match('/<(?:[\\w.-]+:)?addressbook\\b/i', $body) === 1;
    }

    /**
     * Answers OPTIONS: tells the client this is a WebDAV server
     * that also speaks addressbook-access and accepts an extended
     * MKCOL, and lists the verbs the routes answer, so a contacts
     * client knows what it may send.
     */
    public function handleOptions()
    {
        if (!$this->authenticate()) {
            return;
        }
        $this->status(200, "OK");
        $this->site->header("DAV: 1, addressbook-access, extended-mkcol");
        $this->site->header("Allow: OPTIONS, PROPFIND, MKCOL, GET, " .
            "PUT, DELETE, REPORT");
        $this->site->header("Content-Length: 0");
    }

    /**
     * Answers MKCOL: makes a new folder. When the request body asks
     * for an address book, the folder is marked as one by writing
     * its metadata (the display name from the body); otherwise a
     * plain folder is made. A fresh folder answers 201; a target
     * that already exists answers 405, and a missing parent 409.
     */
    public function handleMkcol()
    {
        if (!$this->authenticate()) {
            return;
        }
        $disk_path = $this->containedPath($this->resourceForUri());
        if ($disk_path === false || !is_dir(dirname($disk_path))) {
            $this->status(409, "Conflict");
            return;
        }
        if (file_exists($disk_path)) {
            $this->status(405, "Method Not Allowed");
            return;
        }
        if (!mkdir($disk_path)) {
            $this->status(409, "Conflict");
            return;
        }
        $body = $_SERVER['CONTENT'] ?? "";
        if ($this->bodyMakesAddressbook($body)) {
            $display = $this->parseDisplayName($body);
            if ($display === "") {
                $display = basename($disk_path);
            }
            $meta = ["displayname" => $display];
            $this->site->filePutContents($disk_path . "/" . self::META_FILE,
                json_encode($meta));
        }
        $this->status(201, "Created");
    }

    /**
     * Answers PROPFIND: returns a 207 multi-status describing the
     * target and, at Depth 1 on a folder, its immediate children.
     * An address-book folder reports itself as an address book with
     * its change tag and the vCard media type; a contact reports
     * its entity tag, size, and type.
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
            '<D:multistatus xmlns:D="' . self::NS_DAV . '" xmlns:CARD="' .
            self::NS_CARDDAV . '" xmlns:CS="' . self::NS_CALSERVER . '">';
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
     * way contacts clients expect.
     *
     * @param string $relative the book-relative path
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
     * the address-book, plain-folder, or contact shape by what the
     * disk path is.
     *
     * @param string $disk_path the target on disk
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function responseFor($disk_path, $href)
    {
        if ($this->isAddressbook($disk_path)) {
            return $this->addressbookResponse($disk_path, $href);
        }
        if (is_dir($disk_path)) {
            return $this->collectionResponse($href);
        }
        return $this->resourceResponse($disk_path, $href);
    }

    /**
     * Builds the response element for an address-book folder: it is
     * a collection and an address book, and it carries a display
     * name, the vCard media types it holds, and its change tag.
     *
     * @param string $disk_path the address-book folder on disk
     * @param string $href the href to report for it
     * @return string the response element
     */
    protected function addressbookResponse($disk_path, $href)
    {
        $prop = "<D:resourcetype><D:collection/><CARD:addressbook/>" .
            "</D:resourcetype>" .
            "<D:displayname>" .
            htmlspecialchars($this->displayNameFor($disk_path)) .
            "</D:displayname>" .
            "<CARD:supported-address-data>" .
            '<CARD:address-data-type content-type="text/vcard" ' .
            'version="3.0"/>' .
            '<CARD:address-data-type content-type="text/vcard" ' .
            'version="4.0"/>' .
            "</CARD:supported-address-data>" .
            "<CS:getctag>" . $this->computeCTag($disk_path) .
            "</CS:getctag>";
        return $this->wrapResponse($href, $prop);
    }

    /**
     * Builds the response element for a plain folder, such as the
     * folder that holds the address books: it is a collection and
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
     * Builds the response element for a single contact: its entity
     * tag, its type, its size, and when it last changed.
     *
     * @param string $disk_path the contact file on disk
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
            "<D:getcontenttype>" . self::VCARD_TYPE .
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
     * Answers GET: serves a contact's bytes as vCard text, with its
     * entity tag, so a client can store and later re-check it. A
     * GET of a folder is not meaningful here and answers 404.
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
        $this->site->header("Content-Type: " . self::VCARD_TYPE);
        $this->site->header("ETag: " . $this->computeETag($bytes));
        echo $bytes;
    }

    /**
     * Answers PUT: stores a contact's bytes. If-None-Match "*" asks
     * to create only, so an existing contact answers 412; If-Match
     * asks to overwrite a specific version, so a tag that no longer
     * matches answers 412. A new contact answers 201, an overwrite
     * 204, and the reply carries the stored contact's new tag.
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
     * @param string $disk_path the target contact on disk
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
     * Answers DELETE: removes a contact, or an address book and
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

    /**
     * Answers REPORT: runs one of the two address-book reports a
     * client uses to read contacts. addressbook-multiget returns a
     * named set of contacts; addressbook-query returns the contacts
     * matching a property filter. Both answer a 207 multi-status. An
     * unrecognized report answers 400.
     */
    public function handleReport()
    {
        if (!$this->authenticate()) {
            return;
        }
        $body = $_SERVER['CONTENT'] ?? "";
        if (stripos($body, "addressbook-multiget") !== false) {
            $this->reportMultiget($body);
            return;
        }
        if (stripos($body, "addressbook-query") !== false) {
            $this->reportQuery($body);
            return;
        }
        $this->status(400, "Bad Request");
    }

    /**
     * Runs an addressbook-multiget report: the body lists contact
     * hrefs, and the reply returns each named contact's ETag and
     * vCard data, or a not-found entry for one that is missing, so a
     * client fetches many contacts in a single round trip.
     *
     * @param string $body the REPORT request body
     */
    protected function reportMultiget($body)
    {
        $responses = "";
        foreach ($this->parseHrefs($body) as $href) {
            $disk_path = $this->containedPath($this->resourceForUri($href));
            if ($disk_path === false || !is_file($disk_path)) {
                $responses .= $this->notFoundResponse($href);
                continue;
            }
            $bytes = $this->site->fileGetContents($disk_path);
            $responses .= $this->addressDataResponse($href, $bytes);
        }
        $this->emitMultistatus($responses);
    }

    /**
     * Runs an addressbook-query report: the body filters by vCard
     * properties, and the reply returns each stored contact that
     * matches. Each contact is read only far enough to decide
     * whether it belongs; the returned bytes are the stored bytes.
     *
     * @param string $body the REPORT request body
     */
    protected function reportQuery($body)
    {
        $resource = $this->resourceForUri();
        $disk_path = $this->containedPath($resource);
        if ($disk_path === false || !is_dir($disk_path)) {
            $this->status(404, "Not Found");
            return;
        }
        list($test, $filters) = $this->parseQuery($body);
        $responses = "";
        foreach (scandir($disk_path) as $entry) {
            if (!$this->isResourceName($entry)) {
                continue;
            }
            $bytes = $this->site->fileGetContents($disk_path . "/" . $entry);
            if (!$this->contactMatches($bytes, $filters, $test)) {
                continue;
            }
            $child_rel = ltrim($resource . "/" . $entry, "/");
            $href = $this->hrefFor($child_rel, false);
            $responses .= $this->addressDataResponse($href, $bytes);
        }
        $this->emitMultistatus($responses);
    }

    /**
     * Wraps a set of response elements in a 207 multi-status
     * document with the DAV, CardDAV, and calendar-server
     * namespaces, and sends it.
     *
     * @param string $responses the response elements to wrap
     */
    protected function emitMultistatus($responses)
    {
        $body = '<?xml version="1.0" encoding="utf-8"?>' .
            '<D:multistatus xmlns:D="' . self::NS_DAV . '" xmlns:CARD="' .
            self::NS_CARDDAV . '" xmlns:CS="' . self::NS_CALSERVER . '">' .
            $responses . "</D:multistatus>";
        $this->status(207, "Multi-Status");
        $this->site->header("Content-Type: application/xml; charset=utf-8");
        echo $body;
    }

    /**
     * Builds a response element carrying a contact's ETag and its
     * vCard data, as the two address-book reports return for a
     * matched contact. The contact's bytes are XML-escaped so they
     * nest safely inside the reply.
     *
     * @param string $href the contact's href
     * @param string $bytes the contact's stored bytes
     * @return string the response element
     */
    protected function addressDataResponse($href, $bytes)
    {
        $prop = "<D:getetag>" . $this->computeETag($bytes) .
            "</D:getetag><CARD:address-data>" . htmlspecialchars($bytes) .
            "</CARD:address-data>";
        return $this->wrapResponse($href, $prop);
    }

    /**
     * Builds a response element marking an href not found, as an
     * addressbook-multiget reply does for a contact the client
     * named that is not there. The status here is response-document
     * content the client reads, not the transport status line.
     *
     * @param string $href the href that was not found
     * @return string the response element
     */
    protected function notFoundResponse($href)
    {
        return "<D:response><D:href>" . htmlspecialchars($href) .
            "</D:href><D:status>HTTP/1.1 404 Not Found</D:status>" .
            "</D:response>";
    }

    /**
     * Reads the href list out of an addressbook-multiget body. Only
     * the fixed vocabulary is looked for, so each href element's
     * text is taken directly.
     *
     * @param string $body the REPORT request body
     * @return array the hrefs the body named
     */
    public function parseHrefs($body)
    {
        $pattern = "/<(?:[\\w.-]+:)?href[^>]*>(.*?)" .
            "<\\/(?:[\\w.-]+:)?href>/si";
        $hrefs = [];
        if (preg_match_all($pattern, $body, $matches)) {
            foreach ($matches[1] as $href) {
                $hrefs[] = trim(html_entity_decode($href));
            }
        }
        return $hrefs;
    }

    /**
     * Reads an addressbook-query filter into the test that joins
     * its parts and a list of property filters. The filter's test
     * attribute is anyof or allof (anyof when absent, per
     * RFC 6352). Each prop-filter carries the property it names and
     * how to judge it: a text-match with a match type, or a bare
     * present/absent test (is-not-defined asks for absent, and a
     * prop-filter with neither asks the property be present).
     *
     * @param string $body the REPORT request body
     * @return array a pair of the test name and the filter list,
     *      each filter an array of name, mode, match type, and text
     */
    public function parseQuery($body)
    {
        $test = "anyof";
        if (preg_match('/<(?:[\\w.-]+:)?filter\\b[^>]*\\btest=' .
            '"([^"]+)"/i', $body, $found)) {
            $test = strtolower($found[1]);
        }
        $filters = [];
        $pattern = '/<(?:[\\w.-]+:)?prop-filter\\b[^>]*\\bname=' .
            '"([^"]+)"[^>]*>(.*?)<\\/(?:[\\w.-]+:)?prop-filter>/si';
        if (preg_match_all($pattern, $body, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $filters[] = $this->readPropFilter($match[1], $match[2]);
            }
        }
        return [$test, $filters];
    }

    /**
     * Reads one prop-filter's inner content into a filter record.
     * An is-not-defined asks the property be absent; a text-match
     * asks its value match, with the match type read from the
     * element (contains when absent); neither asks it be present.
     *
     * @param string $name the property the filter names
     * @param string $inner the prop-filter's inner XML
     * @return array the filter record: name, mode, match type, text
     */
    protected function readPropFilter($name, $inner)
    {
        if (preg_match('/<(?:[\\w.-]+:)?is-not-defined\\b/i', $inner)) {
            return ["name" => $name, "mode" => "absent",
                "match" => "", "text" => ""];
        }
        $pattern = '/<(?:[\\w.-]+:)?text-match\\b([^>]*)>(.*?)' .
            '<\\/(?:[\\w.-]+:)?text-match>/si';
        if (preg_match($pattern, $inner, $found)) {
            $match_type = "contains";
            if (preg_match('/\\bmatch-type="([^"]+)"/i', $found[1],
                $type_found)) {
                $match_type = strtolower($type_found[1]);
            }
            return ["name" => $name, "mode" => "text",
                "match" => $match_type,
                "text" => trim(html_entity_decode($found[2]))];
        }
        return ["name" => $name, "mode" => "present",
            "match" => "", "text" => ""];
    }

    /**
     * Judges a contact against the parsed filters. With no filters
     * every contact matches; otherwise each filter is judged and
     * the results joined by the test, allof requiring all to hold
     * and anyof requiring one.
     *
     * @param string $vcard the contact's vCard bytes
     * @param array $filters the parsed prop-filter records
     * @param string $test the joining test, anyof or allof
     * @return bool whether the contact matches
     */
    public function contactMatches($vcard, $filters, $test)
    {
        if (empty($filters)) {
            return true;
        }
        foreach ($filters as $filter) {
            $held = $this->filterMatches($vcard, $filter);
            if ($test === "allof" && !$held) {
                return false;
            }
            if ($test !== "allof" && $held) {
                return true;
            }
        }
        return $test === "allof";
    }

    /**
     * Judges one filter against a contact: an absent filter holds
     * when the named property is missing, a present filter when it
     * is there, and a text filter when any of the property's values
     * satisfies the text match.
     *
     * @param string $vcard the contact's vCard bytes
     * @param array $filter one parsed prop-filter record
     * @return bool whether the filter holds for the contact
     */
    protected function filterMatches($vcard, $filter)
    {
        $values = $this->vcardProperty($vcard, $filter["name"]);
        if ($filter["mode"] === "absent") {
            return empty($values);
        }
        if ($filter["mode"] === "present") {
            return !empty($values);
        }
        foreach ($values as $value) {
            if ($this->textMatches($value, $filter["match"],
                $filter["text"])) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests one property value against a match text under a match
     * type, case-insensitively: equals compares the whole value,
     * starts-with and ends-with anchor at an end, and contains (the
     * default) looks anywhere. An empty match text matches any
     * value.
     *
     * @param string $value the property value to test
     * @param string $match_type equals, starts-with, ends-with, or
     *      contains
     * @param string $text the match text
     * @return bool whether the value matches
     */
    public function textMatches($value, $match_type, $text)
    {
        if ($text === "") {
            return true;
        }
        $value = strtolower($value);
        $text = strtolower($text);
        $text_len = strlen($text);
        if ($match_type === "equals") {
            return $value === $text;
        }
        if ($match_type === "starts-with") {
            return strncmp($value, $text, $text_len) === 0;
        }
        if ($match_type === "ends-with") {
            return $text_len <= strlen($value) &&
                substr($value, -$text_len) === $text;
        }
        return strpos($value, $text) !== false;
    }

    /**
     * Collects the values of a named vCard property from a contact.
     * A line is read as the property name up to the first ";" or
     * ":", so parameters after a ";" are skipped, and the value is
     * what follows the first ":". A property may appear more than
     * once (several EMAIL lines, say), so a list is returned. This
     * reads the common unfolded form; folded continuation lines are
     * out of scope for this first cut.
     *
     * @param string $vcard the contact's vCard bytes
     * @param string $name the property name to collect
     * @return array the property's values, in file order
     */
    public function vcardProperty($vcard, $name)
    {
        $wanted = strtoupper($name);
        $values = [];
        foreach (preg_split('/\\r\\n|\\r|\\n/', $vcard) as $line) {
            $colon = strpos($line, ":");
            if ($colon === false) {
                continue;
            }
            $left = substr($line, 0, $colon);
            $semi = strpos($left, ";");
            $property = $semi === false ? $left : substr($left, 0, $semi);
            if (strtoupper(trim($property)) === $wanted) {
                $values[] = trim(substr($line, $colon + 1));
            }
        }
        return $values;
    }
}
