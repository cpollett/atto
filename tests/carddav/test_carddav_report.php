<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the CardDav REPORT verb and the vCard reading it
 * needs. The first group checks the pure filter parts in memory:
 * pulling a named property's values out of a contact, the
 * text-match under each match type, reading a query into its test
 * and prop-filters, and judging a contact against them. The second
 * group drives the report handler over a scratch address book:
 * addressbook-multiget returns named contacts and a not-found for a
 * missing one, and addressbook-query returns the contacts a filter
 * selects. Those checks touch disk on purpose, since reading the
 * stored contacts is what they are about.
 *
 * Run from the repo root:
 *     php tests/carddav/test_carddav_report.php
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
require __DIR__ . '/../../src/CardDav.php';

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
 * A WebSite stand-in for driving CardDav handlers without a live
 * server. It records the headers a handler sends so a test can read
 * the status, and reads and writes files plainly so there is no
 * cache state to reason about between steps.
 */
class CardDavReportProbe extends WebSite
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
     * Reports the numeric status of the last status line sent.
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
 * Sets the current request as the report handler reads it.
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

/**
 * Builds an addressbook-query body around a filter fragment.
 *
 * @param string $filter the filter element's XML
 * @return string the full report body
 */
function query($filter)
{
    return '<C:addressbook-query xmlns:D="DAV:" ' .
        'xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop>' .
        '<C:address-data/></D:prop>' . $filter .
        '</C:addressbook-query>';
}

$prefix = "/addressbooks";
$alice = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:alice\r\n" .
    "FN:Alice Example\r\nEMAIL;TYPE=home:alice@example.com\r\n" .
    "END:VCARD\r\n";
$bob = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:bob\r\n" .
    "FN:Bob Jones\r\nEMAIL:bob@example.com\r\nORG:Acme\r\n" .
    "END:VCARD\r\n";

$site = new CardDavReportProbe(".");
$scratch = sys_get_temp_dir() . "/atto_cardrep_" . getmypid();
$dav = new CardDav($site, $scratch, $prefix);

/*
    -----------------------------------------------------------
    Pure filter parts, no report driven
    -----------------------------------------------------------
 */

/* Test 1: a named property's values are pulled, params skipped. */
ok("a named property's values are read, parameters skipped",
    $dav->vcardProperty($alice, "FN") === ["Alice Example"] &&
    $dav->vcardProperty($alice, "email") === ["alice@example.com"] &&
    $dav->vcardProperty($alice, "ORG") === []);

/* Test 2: the text match under each match type. */
ok("text match honors equals, starts-with, ends-with, contains",
    $dav->textMatches("Alice", "equals", "alice") === true &&
    $dav->textMatches("Alice", "equals", "ali") === false &&
    $dav->textMatches("Alice", "starts-with", "ali") === true &&
    $dav->textMatches("alice@x.com", "ends-with", ".com") === true &&
    $dav->textMatches("Alice", "contains", "lic") === true &&
    $dav->textMatches("Alice", "contains", "zzz") === false);

/* Test 3: a query is read into its test and prop-filters. */
list($test, $filters) = $dav->parseQuery(query(
    '<C:filter test="allof">' .
    '<C:prop-filter name="FN"><C:text-match match-type="starts-with">' .
    'Al</C:text-match></C:prop-filter>' .
    '<C:prop-filter name="ORG"><C:is-not-defined/></C:prop-filter>' .
    '</C:filter>'));
ok("a query is read into its test and prop-filters",
    $test === "allof" && count($filters) === 2 &&
    $filters[0]["name"] === "FN" && $filters[0]["mode"] === "text" &&
    $filters[0]["match"] === "starts-with" &&
    $filters[0]["text"] === "Al" &&
    $filters[1]["name"] === "ORG" && $filters[1]["mode"] === "absent");

/* Test 4: the test defaults to anyof when the body omits it. */
list($test_default) = $dav->parseQuery(query(
    '<C:filter><C:prop-filter name="FN"><C:text-match>a' .
    '</C:text-match></C:prop-filter></C:filter>'));
ok("the filter test defaults to anyof", $test_default === "anyof");

/* Test 5: judging a contact under allof and anyof. */
$fn_ali = ["name" => "FN", "mode" => "text", "match" => "contains",
    "text" => "ali"];
$email_x = ["name" => "EMAIL", "mode" => "text", "match" => "contains",
    "text" => "example"];
$fn_zzz = ["name" => "FN", "mode" => "text", "match" => "contains",
    "text" => "zzz"];
ok("allof needs all filters, anyof needs one",
    $dav->contactMatches($alice, [$fn_ali, $email_x], "allof") === true &&
    $dav->contactMatches($alice, [$fn_zzz, $email_x], "allof") === false &&
    $dav->contactMatches($alice, [$fn_zzz, $email_x], "anyof") === true &&
    $dav->contactMatches($alice, [$fn_zzz], "anyof") === false);

/* Test 6: present and absent filters. */
$org_present = ["name" => "ORG", "mode" => "present", "match" => "",
    "text" => ""];
$org_absent = ["name" => "ORG", "mode" => "absent", "match" => "",
    "text" => ""];
ok("present and absent filters read the property's presence",
    $dav->contactMatches($bob, [$org_present], "anyof") === true &&
    $dav->contactMatches($alice, [$org_present], "anyof") === false &&
    $dav->contactMatches($alice, [$org_absent], "anyof") === true);

/*
    -----------------------------------------------------------
    Reports driven over a scratch address book
    -----------------------------------------------------------
 */
$real_root = realpath($scratch);
$dav = new CardDav($site, $real_root, $prefix);
$book = $real_root . "/book";
mkdir($book);
file_put_contents($book . "/" . CardDav::META_FILE,
    json_encode(["displayname" => "Book"]));
file_put_contents($book . "/alice.vcf", $alice);
file_put_contents($book . "/bob.vcf", $bob);

/* Test 7: multiget returns named contacts and a not-found. */
$site->reset();
request("$prefix/book", '<C:addressbook-multiget xmlns:D="DAV:" ' .
    'xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop>' .
    '<C:address-data/></D:prop>' .
    "<D:href>$prefix/book/alice.vcf</D:href>" .
    "<D:href>$prefix/book/ghost.vcf</D:href></C:addressbook-multiget>");
$multi = capture([$dav, "handleReport"]);
ok("multiget returns the named contact and a not-found for a gap",
    $site->status() === 207 &&
    strpos($multi, "$prefix/book/alice.vcf") !== false &&
    strpos($multi, "Alice Example") !== false &&
    strpos($multi, "404 Not Found") !== false);

/* Test 8: a FN contains query selects only the matching contact. */
$site->reset();
request("$prefix/book", query('<C:filter><C:prop-filter name="FN">' .
    '<C:text-match match-type="contains">ali</C:text-match>' .
    '</C:prop-filter></C:filter>'));
$fn_query = capture([$dav, "handleReport"]);
ok("a FN-contains query selects only the matching contact",
    strpos($fn_query, "alice.vcf") !== false &&
    strpos($fn_query, "bob.vcf") === false);

/* Test 9: an EMAIL equals query selects the exact contact. */
$site->reset();
request("$prefix/book", query('<C:filter><C:prop-filter name="EMAIL">' .
    '<C:text-match match-type="equals">bob@example.com</C:text-match>' .
    '</C:prop-filter></C:filter>'));
$email_query = capture([$dav, "handleReport"]);
ok("an EMAIL-equals query selects the exact contact",
    strpos($email_query, "bob.vcf") !== false &&
    strpos($email_query, "alice.vcf") === false);

/* Test 10: an allof query needs every prop-filter to hold. */
$site->reset();
request("$prefix/book", query('<C:filter test="allof">' .
    '<C:prop-filter name="FN"><C:text-match>ali</C:text-match>' .
    '</C:prop-filter><C:prop-filter name="EMAIL">' .
    '<C:text-match>example</C:text-match></C:prop-filter></C:filter>'));
$allof_query = capture([$dav, "handleReport"]);
ok("an allof query needs every prop-filter to hold",
    strpos($allof_query, "alice.vcf") !== false &&
    strpos($allof_query, "bob.vcf") === false);

/* Test 11: an is-not-defined query selects contacts lacking it. */
$site->reset();
request("$prefix/book", query('<C:filter><C:prop-filter name="ORG">' .
    '<C:is-not-defined/></C:prop-filter></C:filter>'));
$absent_query = capture([$dav, "handleReport"]);
ok("an is-not-defined query selects contacts lacking the property",
    strpos($absent_query, "alice.vcf") !== false &&
    strpos($absent_query, "bob.vcf") === false);

/* Test 12: a query on a missing book answers 404. */
$site->reset();
request("$prefix/ghostbook", query('<C:filter><C:prop-filter name="FN">' .
    '<C:text-match>x</C:text-match></C:prop-filter></C:filter>'));
capture([$dav, "handleReport"]);
ok("a query on a missing book answers 404", $site->status() === 404);

/* Test 13: an unrecognized report answers 400. */
$site->reset();
request("$prefix/book", '<C:silly xmlns:C="x"/>');
capture([$dav, "handleReport"]);
ok("an unrecognized report answers 400", $site->status() === 400);

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
    if (is_file($path)) {
        unlink($path);
    }
}
removeTree($scratch);

echo "\nTests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
