<?php
/**
 * seekquarry\atto\DnsSite -- a single-file authoritative DNS server
 *
 * Copyright (C) 2017-2026  Chris Pollett chris@pollett.org
 *
 * LICENSE:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * END LICENSE
 *
 * @author Chris Pollett chris@pollett.org
 * @license http://www.gnu.org/licenses/ GPL-3.0-or-later
 * @link http://www.seekquarry.com/
 * @copyright 2017-2026
 * @filesource
 */
namespace seekquarry\atto;

/**
 * One DNS resource record. The RDATA field is stored in its
 * type-specific decoded form (A: dotted IPv4, AAAA: colon-
 * separated IPv6, MX: [preference, exchange], SOA: assoc
 * array of seven fields, TXT: array of strings, CNAME/NS/PTR:
 * target name as a dotted string). Wire-format conversion
 * lives in DnsMessage::packRdata / DnsMessage::unpackRdata.
 *
 * Names are stored without the trailing dot in this class but
 * the wire format always emits one (the root label is the
 * empty string after the last dot). Comparisons are case-
 * insensitive per RFC 1035 sec 2.3.3 even though we preserve
 * the original case for echoing.
 */
class DnsRecord
{
    /**
     * @var string fully-qualified owner name without trailing
     * dot, e.g. "www.example.test"
     */
    public $name;
    /**
     * @var int RR type: TYPE_A, TYPE_AAAA, ...
     */
    public $type;
    /**
     * @var int class: usually CLASS_IN (1)
     */
    public $class;
    /**
     * @var int time-to-live in seconds
     */
    public $ttl;
    /**
     * @var mixed type-specific RDATA, decoded form
     */
    public $rdata;
    public function __construct($name, $type, $class, $ttl,
        $rdata)
    {
        $this->name = (string) $name;
        $this->type = (int) $type;
        $this->class = (int) $class;
        $this->ttl = (int) $ttl;
        $this->rdata = $rdata;
    }
}
/**
 * Abstract zone backend. A concrete authority answers two
 * questions: "which of my origins is the closest enclosing
 * ancestor of this name?" and "what records exist for this
 * (name, type, class) triple?". Returning the empty array
 * for a known name means NODATA (the name exists but not at
 * the requested type); returning false means the name is
 * outside any zone we serve and the dispatcher should reply
 * REFUSED instead of NXDOMAIN.
 *
 * Storage of authoritative zones is split out so the framework
 * can host a flat-file authority, a database-backed one, or an
 * in-memory testing one without changing DnsSite itself.
 */
abstract class DnsAuthority
{
    /**
     * Returns the closest origin (zone apex) that encloses
     * $name, or false if no zone served covers it.
     *
     * @param string $name fully-qualified name without
     *      trailing dot
     * @return string|false origin name, or false
     */
    abstract public function originFor($name);
    /**
     * Returns DnsRecord objects matching ($name, $type,
     * $class). $type may be TYPE_ANY to mean "every type".
     * Returns false when $name is outside any served zone,
     * and the empty array when the name exists but no records
     * match the requested type (NODATA).
     *
     * @param string $name fully-qualified, no trailing dot
     * @param int $type RR type or TYPE_ANY
     * @param int $class always CLASS_IN in practice
     * @return array|false
     */
    abstract public function findRecords($name, $type, $class);
    /**
     * Returns the SOA DnsRecord for an origin, used to fill
     * the authority section of NXDOMAIN / NODATA responses
     * (RFC 2308). Returns false if the origin is not served
     * or has no SOA configured.
     *
     * @param string $origin
     * @return DnsRecord|false
     */
    abstract public function soaFor($origin);
    /**
     * Returns the list of origins this authority serves.
     * Order is unspecified but typically the order they were
     * loaded.
     *
     * @return array list of origin names
     */
    abstract public function origins();
}
/**
 * RFC 1035 master-file backed DnsAuthority. Each ".zone" file
 * under the configured directory becomes one zone; the file's
 * basename without the extension is the origin (e.g. a file
 * named "example.test.zone" implicitly defines the
 * "example.test" zone). The file's first SOA record is taken
 * as authoritative for that origin and used to populate the
 * authority section of NXDOMAIN responses.
 *
 * Parsing supports the master-file features that real-world
 * zone files actually use:
 *   - $ORIGIN <name>          change the origin within a file
 *   - $TTL    <seconds>       default TTL for records that
 *                              omit one
 *   - @                       shorthand for the current origin
 *   - relative names get the current origin appended
 *   - parentheses span multiple lines, used by SOA
 *   - ;-to-end-of-line comments
 *
 * Names without a trailing dot are made absolute relative to
 * the current $ORIGIN. Names with a trailing dot are taken
 * literally. We strip trailing dots before storing so internal
 * comparisons can use plain strcasecmp.
 */
class FileDnsAuthority extends DnsAuthority
{
    /**
     * @var string directory under which .zone files live.
     */
    protected $zone_dir;
    /**
     * @var array origin (lowercased) => list of DnsRecord
     */
    protected $zones = [];
    /**
     * @var array origin (lowercased) => the SOA DnsRecord
     */
    protected $soas = [];
    /**
     * @var array origin (lowercased) => origin (original case)
     */
    protected $origins = [];
    /**
     * @var int signature of the zone directory (sum of file
     *      mtimes + sizes) at last load. Used by
     *      reloadIfChanged to detect on-disk edits.
     */
    protected $signature = 0;
    /**
     * @param string $zone_dir directory holding .zone files
     */
    public function __construct($zone_dir)
    {
        $this->zone_dir = rtrim($zone_dir, "/\\");
        $this->reload();
    }
    /**
     * Re-reads every .zone file from the configured directory.
     * Existing in-memory zones are discarded; callers can
     * invoke this after editing a zone file on disk.
     */
    public function reload()
    {
        $this->zones = [];
        $this->soas = [];
        $this->origins = [];
        $this->signature = $this->directorySignature();
        if (!is_dir($this->zone_dir)) {
            return;
        }
        $files = glob($this->zone_dir . DIRECTORY_SEPARATOR .
            "*.zone");
        if ($files === false) {
            return;
        }
        sort($files);
        foreach ($files as $file) {
            $base = basename($file, ".zone");
            $this->loadZoneFile($base, $file);
        }
    }
    /**
     * Cheap on-the-fly reload: compares the current
     * directory signature against the one captured at the
     * last load and re-reads if anything changed. Called
     * before every public lookup so the demo's zone-editor
     * UI gets immediate effect without an explicit signal.
     */
    protected function reloadIfChanged()
    {
        $current = $this->directorySignature();
        if ($current !== $this->signature) {
            $this->reload();
        }
    }
    /**
     * Returns a value that changes whenever any .zone file
     * is added, removed, or modified. We sum filename hashes
     * with mtimes and sizes; collisions are not a concern
     * because we only compare against the value we computed
     * ourselves on the last load.
     */
    protected function directorySignature()
    {
        if (!is_dir($this->zone_dir)) {
            return 0;
        }
        $files = glob($this->zone_dir . DIRECTORY_SEPARATOR .
            "*.zone");
        if ($files === false) {
            return 0;
        }
        $sig = 0;
        foreach ($files as $file) {
            $sig = ($sig * 31 + crc32(basename($file))) &
                0xFFFFFFFF;
            $sig = ($sig * 31 + (int) @filemtime($file)) &
                0xFFFFFFFF;
            $sig = ($sig * 31 + (int) @filesize($file)) &
                0xFFFFFFFF;
        }
        return $sig;
    }
    /**
     * @inheritdoc
     */
    public function originFor($name)
    {
        $this->reloadIfChanged();
        $name = strtolower($name);
        $best = false;
        foreach ($this->origins as $lower => $original) {
            if (strcasecmp($name, $lower) === 0 ||
                $this->isSubdomainOf($name, $lower)) {
                if ($best === false ||
                    strlen($lower) > strlen($best)) {
                    $best = $lower;
                }
            }
        }
        if ($best === false) {
            return false;
        }
        return $this->origins[$best];
    }
    /**
     * @inheritdoc
     */
    public function findRecords($name, $type, $class)
    {
        $origin_lower = $this->originFor($name);
        if ($origin_lower === false) {
            return false;
        }
        $origin_lower = strtolower($origin_lower);
        if (!isset($this->zones[$origin_lower])) {
            return [];
        }
        $matches = [];
        $name_exists = false;
        foreach ($this->zones[$origin_lower] as $record) {
            if (strcasecmp($record->name, $name) !== 0) {
                continue;
            }
            $name_exists = true;
            if ($class !== DnsSite::CLASS_ANY &&
                $record->class !== $class) {
                continue;
            }
            if ($type !== DnsSite::TYPE_ANY &&
                $record->type !== $type) {
                continue;
            }
            $matches[] = $record;
        }
        if (!empty($matches)) {
            return $matches;
        }
        if ($name_exists) {
            /*
                NODATA: the name exists at some other type.
                Caller emits a NOERROR response with empty
                answer and an SOA in authority.
             */
            return [];
        }
        /*
            Look for a wildcard at *.<parent>. A wildcard
            answers any name that has no exact match and is
            not itself empty-non-terminal (RFC 4592).
         */
        $wild_matches = $this->wildcardMatches($name,
            $origin_lower, $type, $class);
        if ($wild_matches !== null) {
            return $wild_matches;
        }
        /*
            Name does not exist in this zone at all.
            Caller emits NXDOMAIN.
         */
        return false;
    }
    /**
     * @inheritdoc
     */
    public function soaFor($origin)
    {
        $key = strtolower($origin);
        if (!isset($this->soas[$key])) {
            return false;
        }
        return $this->soas[$key];
    }
    /**
     * @inheritdoc
     */
    public function origins()
    {
        return array_values($this->origins);
    }
    /**
     * Loads one zone file. Origin defaults to the basename;
     * $ORIGIN directives inside the file can change it for
     * subsequent records.
     */
    protected function loadZoneFile($default_origin, $path)
    {
        $bytes = @file_get_contents($path);
        if ($bytes === false) {
            return;
        }
        $tokens = $this->tokenizeMasterFile($bytes);
        $origin = rtrim($default_origin, ".");
        $ttl = 3600;
        $owner = null;
        $records = [];
        $first_soa = null;
        foreach ($tokens as $line_tokens) {
            if (empty($line_tokens)) {
                continue;
            }
            $first = $line_tokens[0];
            if (strcasecmp($first, '$ORIGIN') === 0) {
                $origin = rtrim($line_tokens[1] ?? $origin, ".");
                continue;
            }
            if (strcasecmp($first, '$TTL') === 0) {
                $ttl = (int) ($line_tokens[1] ?? $ttl);
                continue;
            }
            $record = $this->buildRecord($line_tokens, $origin,
                $ttl, $owner);
            if ($record === null) {
                continue;
            }
            $owner = $record->name;
            $records[] = $record;
            if ($record->type === DnsSite::TYPE_SOA &&
                $first_soa === null) {
                $first_soa = $record;
            }
        }
        if ($first_soa === null) {
            /*
                A zone without an SOA cannot answer NXDOMAIN
                authoritatively (RFC 2308 sec 3); skip the
                file rather than serving partial answers that
                would confuse downstream caches.
             */
            return;
        }
        $key = strtolower($first_soa->name);
        $this->origins[$key] = $first_soa->name;
        $this->zones[$key] = $records;
        $this->soas[$key] = $first_soa;
    }
    /**
     * Tokenizes a master-file bytestream into a list of
     * lines, each line being a list of string tokens with
     * comments and parenthesized line continuations
     * resolved. Parentheses span lines; everything from "(",
     * to its matching ")" is one logical record. Quoted
     * strings preserve embedded whitespace; ;-to-EOL is a
     * comment.
     */
    protected function tokenizeMasterFile($bytes)
    {
        $tokens = [];
        $current = [];
        $i = 0;
        $n = strlen($bytes);
        $paren_depth = 0;
        $line_has_leading_ws = false;
        while ($i < $n) {
            $c = $bytes[$i];
            if ($c === "\r") {
                $i++;
                continue;
            }
            if ($c === "\n") {
                if ($paren_depth === 0) {
                    if ($line_has_leading_ws &&
                        !empty($current)) {
                        /*
                            Owner-name reuse: a leading-
                            whitespace line means "use the
                            same owner as the previous
                            record". Mark with a sentinel so
                            buildRecord knows.
                         */
                        array_unshift($current, "@@SAME@@");
                    }
                    $tokens[] = $current;
                    $current = [];
                    $line_has_leading_ws = false;
                }
                $i++;
                continue;
            }
            if ($c === ";") {
                while ($i < $n && $bytes[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($c === " " || $c === "\t") {
                if (empty($current)) {
                    $line_has_leading_ws = true;
                }
                $i++;
                continue;
            }
            if ($c === "(") {
                $paren_depth++;
                $i++;
                continue;
            }
            if ($c === ")") {
                if ($paren_depth > 0) {
                    $paren_depth--;
                }
                $i++;
                continue;
            }
            if ($c === '"') {
                $i++;
                $value = "";
                while ($i < $n && $bytes[$i] !== '"') {
                    if ($bytes[$i] === '\\' && $i + 1 < $n) {
                        $value .= $bytes[$i + 1];
                        $i += 2;
                        continue;
                    }
                    $value .= $bytes[$i];
                    $i++;
                }
                if ($i < $n) {
                    $i++;
                }
                $current[] = $value;
                continue;
            }
            $j = $i;
            while ($j < $n) {
                $cc = $bytes[$j];
                if ($cc === " " || $cc === "\t" ||
                    $cc === "\n" || $cc === "\r" ||
                    $cc === ";" || $cc === "(" ||
                    $cc === ")") {
                    break;
                }
                $j++;
            }
            $current[] = substr($bytes, $i, $j - $i);
            $i = $j;
        }
        if (!empty($current)) {
            $tokens[] = $current;
        }
        return $tokens;
    }
    /**
     * Builds one DnsRecord from a tokenized line. Handles
     * the optional TTL and CLASS fields whose order is
     * either [TTL CLASS TYPE] or [CLASS TTL TYPE]. Returns
     * null on a malformed line.
     */
    protected function buildRecord($tokens, $origin, $ttl,
        $previous_owner)
    {
        if ($tokens[0] === "@@SAME@@") {
            array_shift($tokens);
            $owner_token = "";
            $explicit_owner = false;
        } else {
            $owner_token = array_shift($tokens);
            $explicit_owner = true;
        }
        if ($explicit_owner) {
            $owner = $this->absoluteName($owner_token, $origin);
        } else if ($previous_owner !== null) {
            $owner = $previous_owner;
        } else {
            $owner = $origin;
        }
        $record_ttl = $ttl;
        $record_class = DnsSite::CLASS_IN;
        $type = null;
        while (!empty($tokens) && $type === null) {
            $next = $tokens[0];
            if (ctype_digit($next)) {
                $record_ttl = (int) array_shift($tokens);
                continue;
            }
            $upper = strtoupper($next);
            if ($upper === "IN" || $upper === "CH" ||
                $upper === "HS") {
                array_shift($tokens);
                $record_class = ($upper === "IN") ?
                    DnsSite::CLASS_IN : 0;
                continue;
            }
            $type_code = DnsSite::typeFromName($upper);
            if ($type_code === false) {
                return null;
            }
            $type = $type_code;
            array_shift($tokens);
        }
        if ($type === null) {
            return null;
        }
        $rdata = $this->parseRdata($type, $tokens, $origin);
        if ($rdata === null) {
            return null;
        }
        return new DnsRecord($owner, $type, $record_class,
            $record_ttl, $rdata);
    }
    /**
     * Parses the RDATA portion of a master-file line into
     * the per-type structured form DnsRecord stores. Returns
     * null on malformed input.
     */
    protected function parseRdata($type, $tokens, $origin)
    {
        switch ($type) {
            case DnsSite::TYPE_A:
                if (empty($tokens) ||
                    filter_var($tokens[0],
                        FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ===
                    false) {
                    return null;
                }
                return $tokens[0];
            case DnsSite::TYPE_AAAA:
                if (empty($tokens) ||
                    filter_var($tokens[0],
                        FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ===
                    false) {
                    return null;
                }
                return $tokens[0];
            case DnsSite::TYPE_CNAME:
            case DnsSite::TYPE_NS:
            case DnsSite::TYPE_PTR:
                if (empty($tokens)) {
                    return null;
                }
                return $this->absoluteName($tokens[0], $origin);
            case DnsSite::TYPE_MX:
                if (count($tokens) < 2) {
                    return null;
                }
                return [
                    'preference' => (int) $tokens[0],
                    'exchange' =>
                        $this->absoluteName($tokens[1], $origin),
                ];
            case DnsSite::TYPE_TXT:
                if (empty($tokens)) {
                    return null;
                }
                return $tokens;
            case DnsSite::TYPE_SOA:
                if (count($tokens) < 7) {
                    return null;
                }
                return [
                    'mname' =>
                        $this->absoluteName($tokens[0], $origin),
                    'rname' =>
                        $this->absoluteName($tokens[1], $origin),
                    'serial' => (int) $tokens[2],
                    'refresh' => (int) $tokens[3],
                    'retry' => (int) $tokens[4],
                    'expire' => (int) $tokens[5],
                    'minimum' => (int) $tokens[6],
                ];
        }
        return null;
    }
    /**
     * Resolves a name from a master file (which may be
     * relative, absolute, or "@") to an absolute name without
     * trailing dot.
     */
    protected function absoluteName($token, $origin)
    {
        if ($token === "@") {
            return $origin;
        }
        if (substr($token, -1) === ".") {
            return rtrim($token, ".");
        }
        if ($origin === "") {
            return $token;
        }
        return $token . "." . $origin;
    }
    /**
     * Returns true if $name is strictly under $parent in the
     * DNS hierarchy. "www.example.test" is a subdomain of
     * "example.test" but not of "ample.test".
     */
    protected function isSubdomainOf($name, $parent)
    {
        $suffix = "." . $parent;
        $len = strlen($suffix);
        if (strlen($name) <= $len) {
            return false;
        }
        return strcasecmp(substr($name, -$len), $suffix) === 0;
    }
    /**
     * Looks for a wildcard match at "*.<closest_ancestor>"
     * within the zone, walking up labels until we reach the
     * origin. Returns null if no wildcard applies. Per RFC
     * 4592 the wildcard owner is rewritten in the response to
     * the queried name.
     */
    protected function wildcardMatches($name, $origin_lower,
        $type, $class)
    {
        if (!isset($this->zones[$origin_lower])) {
            return null;
        }
        $labels = explode(".", $name);
        while (count($labels) > 0) {
            array_shift($labels);
            $candidate = "*." . implode(".", $labels);
            if (strcasecmp($candidate,
                "*." . $origin_lower) !== 0 &&
                !$this->isSubdomainOf($candidate,
                    $origin_lower) &&
                strcasecmp($candidate, $origin_lower) !== 0) {
                continue;
            }
            $hits = [];
            foreach ($this->zones[$origin_lower] as $r) {
                if (strcasecmp($r->name, $candidate) !== 0) {
                    continue;
                }
                if ($class !== DnsSite::CLASS_ANY &&
                    $r->class !== $class) {
                    continue;
                }
                if ($type !== DnsSite::TYPE_ANY &&
                    $r->type !== $type) {
                    continue;
                }
                $cloned = new DnsRecord($name, $r->type,
                    $r->class, $r->ttl, $r->rdata);
                $hits[] = $cloned;
            }
            if (!empty($hits)) {
                return $hits;
            }
        }
        return null;
    }
}
/**
 * DNS wire-format codec. A DnsMessage holds the parsed shape
 * of a query or response; static helpers pack a logical
 * message into bytes and unpack bytes into a logical message.
 *
 * The 12-byte fixed header carries flags, four section
 * counts, and the transaction ID. Each section is a list of
 * resource records (or, in the question section, just
 * (name, type, class) triples). Resource-record names use
 * the length-prefixed label scheme with a back-reference
 * compression pointer: a label byte with its top two bits set
 * is followed by a 14-bit offset back into the same packet.
 *
 * The unpack path defends against compression-loop attacks
 * with a hard hop cap; the pack path emits compression
 * pointers when a name suffix has already been written, which
 * keeps real responses compact without affecting correctness.
 */
class DnsMessage
{
    /**
     * @var int 16-bit transaction ID, echoed in responses.
     */
    public $id = 0;
    /**
     * @var bool QR bit: false = query, true = response.
     */
    public $qr = false;
    /**
     * @var int OPCODE, 0 = standard query (RFC 1035 sec 4.1.1).
     */
    public $opcode = 0;
    /**
     * @var bool AA bit: authoritative answer.
     */
    public $aa = false;
    /**
     * @var bool TC bit: truncated; client should retry over TCP.
     */
    public $tc = false;
    /**
     * @var bool RD bit: recursion desired (set by clients).
     */
    public $rd = false;
    /**
     * @var bool RA bit: recursion available (set by servers
     * that recurse; we never set it).
     */
    public $ra = false;
    /**
     * @var int RCODE: 0 NOERROR, 1 FORMERR, 2 SERVFAIL,
     *          3 NXDOMAIN, 4 NOTIMP, 5 REFUSED.
     */
    public $rcode = 0;
    /**
     * @var array list of [name, type, class] question triples.
     */
    public $questions = [];
    /**
     * @var array list of DnsRecord answers.
     */
    public $answers = [];
    /**
     * @var array list of DnsRecord authority-section records.
     */
    public $authority = [];
    /**
     * @var array list of DnsRecord additional-section records.
     */
    public $additional = [];
    /**
     * Packs a logical message into wire bytes.
     */
    public static function pack($message)
    {
        $body = "";
        $names_seen = [];
        $flags = ($message->qr ? 0x8000 : 0) |
            (($message->opcode & 0xF) << 11) |
            ($message->aa ? 0x0400 : 0) |
            ($message->tc ? 0x0200 : 0) |
            ($message->rd ? 0x0100 : 0) |
            ($message->ra ? 0x0080 : 0) |
            ($message->rcode & 0xF);
        $header = pack("nnnnnn",
            $message->id & 0xFFFF, $flags,
            count($message->questions),
            count($message->answers),
            count($message->authority),
            count($message->additional));
        $body = "";
        foreach ($message->questions as $q) {
            $body .= self::packName($q[0],
                strlen($header) + strlen($body), $names_seen);
            $body .= pack("nn", $q[1], $q[2]);
        }
        foreach ([$message->answers, $message->authority,
            $message->additional] as $section) {
            foreach ($section as $rr) {
                $body .= self::packName($rr->name,
                    strlen($header) + strlen($body),
                    $names_seen);
                $rdata_bytes = self::packRdata($rr->type,
                    $rr->rdata,
                    strlen($header) + strlen($body) + 10,
                    $names_seen);
                $body .= pack("nnNn", $rr->type, $rr->class,
                    $rr->ttl, strlen($rdata_bytes));
                $body .= $rdata_bytes;
            }
        }
        return $header . $body;
    }
    /**
     * Unpacks wire bytes into a DnsMessage. Returns false on
     * malformed input. Successful unpack does not validate
     * semantic constraints (e.g. multiple questions); callers
     * apply policy.
     */
    public static function unpack($bytes)
    {
        if (strlen($bytes) < 12) {
            return false;
        }
        $header = unpack("nid/nflags/nqd/nan/nns/nar",
            substr($bytes, 0, 12));
        $message = new DnsMessage();
        $message->id = $header['id'];
        $flags = $header['flags'];
        $message->qr = (bool) ($flags & 0x8000);
        $message->opcode = ($flags >> 11) & 0xF;
        $message->aa = (bool) ($flags & 0x0400);
        $message->tc = (bool) ($flags & 0x0200);
        $message->rd = (bool) ($flags & 0x0100);
        $message->ra = (bool) ($flags & 0x0080);
        $message->rcode = $flags & 0xF;
        $offset = 12;
        for ($i = 0; $i < $header['qd']; $i++) {
            $name = self::unpackName($bytes, $offset);
            if ($name === false) {
                return false;
            }
            if ($offset + 4 > strlen($bytes)) {
                return false;
            }
            $tc = unpack("ntype/nclass",
                substr($bytes, $offset, 4));
            $offset += 4;
            $message->questions[] = [$name, $tc['type'],
                $tc['class']];
        }
        $remaining = $header['an'] + $header['ns'] +
            $header['ar'];
        for ($i = 0; $i < $remaining; $i++) {
            $rr = self::unpackResourceRecord($bytes, $offset);
            if ($rr === false) {
                return false;
            }
            if ($i < $header['an']) {
                $message->answers[] = $rr;
            } else if ($i < $header['an'] + $header['ns']) {
                $message->authority[] = $rr;
            } else {
                $message->additional[] = $rr;
            }
        }
        return $message;
    }
    /**
     * Packs a name as a sequence of length-prefixed labels
     * terminated by a zero byte. Reuses a previously-emitted
     * suffix as a 14-bit back-reference pointer when possible
     * (the high two bits of a label byte distinguish a length
     * from a pointer).
     */
    protected static function packName($name, $current_offset,
        &$names_seen)
    {
        $name = rtrim($name, ".");
        if ($name === "") {
            return "\x00";
        }
        $key = strtolower($name);
        if (isset($names_seen[$key])) {
            return pack("n", 0xC000 | $names_seen[$key]);
        }
        $labels = explode(".", $name);
        $first_label = array_shift($labels);
        if (strlen($first_label) > 63) {
            $first_label = substr($first_label, 0, 63);
        }
        $bytes = chr(strlen($first_label)) . $first_label;
        $tail_offset = $current_offset + strlen($bytes);
        if (empty($labels)) {
            $names_seen[$key] = $current_offset;
            return $bytes . "\x00";
        }
        $tail = implode(".", $labels);
        $tail_bytes = self::packName($tail, $tail_offset,
            $names_seen);
        $names_seen[$key] = $current_offset;
        return $bytes . $tail_bytes;
    }
    /**
     * Reads one name from the packet, following compression
     * pointers. Bounds the recursion at 8 hops to defend
     * against compression-loop DoS.
     */
    protected static function unpackName($bytes, &$offset,
        $hops = 0)
    {
        if ($hops > 8) {
            return false;
        }
        $labels = [];
        $original_offset = $offset;
        $jumped = false;
        $n = strlen($bytes);
        while (true) {
            if ($offset >= $n) {
                return false;
            }
            $length = ord($bytes[$offset]);
            if ($length === 0) {
                $offset++;
                if (!$jumped) {
                    $original_offset = $offset;
                }
                break;
            }
            if (($length & 0xC0) === 0xC0) {
                if ($offset + 1 >= $n) {
                    return false;
                }
                $pointer = (($length & 0x3F) << 8) |
                    ord($bytes[$offset + 1]);
                if (!$jumped) {
                    $original_offset = $offset + 2;
                }
                $offset = $pointer;
                $jumped = true;
                $hops++;
                if ($hops > 8) {
                    return false;
                }
                continue;
            }
            if (($length & 0xC0) !== 0) {
                return false;
            }
            if ($offset + 1 + $length > $n) {
                return false;
            }
            $labels[] = substr($bytes, $offset + 1, $length);
            $offset += 1 + $length;
        }
        $offset = $original_offset;
        return implode(".", $labels);
    }
    /**
     * Reads one resource record from the packet, returning a
     * DnsRecord with the RDATA decoded into its type-specific
     * structured form, or false on malformed input.
     */
    protected static function unpackResourceRecord($bytes,
        &$offset)
    {
        $name = self::unpackName($bytes, $offset);
        if ($name === false) {
            return false;
        }
        if ($offset + 10 > strlen($bytes)) {
            return false;
        }
        $head = unpack("ntype/nclass/Nttl/nrdlength",
            substr($bytes, $offset, 10));
        $offset += 10;
        if ($offset + $head['rdlength'] > strlen($bytes)) {
            return false;
        }
        $rdata = self::unpackRdata($head['type'], $bytes,
            $offset, $head['rdlength']);
        $offset += $head['rdlength'];
        return new DnsRecord($name, $head['type'],
            $head['class'], $head['ttl'], $rdata);
    }
    /**
     * Encodes the per-type RDATA payload. Names inside RDATA
     * (CNAME/NS/PTR target, MX exchange, SOA mname/rname)
     * participate in name compression, so we pass through the
     * names-seen table.
     */
    protected static function packRdata($type, $rdata,
        $rdata_offset, &$names_seen)
    {
        switch ($type) {
            case DnsSite::TYPE_A:
                return inet_pton($rdata) ?: "\0\0\0\0";
            case DnsSite::TYPE_AAAA:
                $packed = inet_pton($rdata);
                return ($packed !== false &&
                    strlen($packed) === 16)
                    ? $packed : str_repeat("\0", 16);
            case DnsSite::TYPE_CNAME:
            case DnsSite::TYPE_NS:
            case DnsSite::TYPE_PTR:
                return self::packName($rdata, $rdata_offset,
                    $names_seen);
            case DnsSite::TYPE_MX:
                $pref = pack("n", $rdata['preference']);
                return $pref . self::packName(
                    $rdata['exchange'],
                    $rdata_offset + 2, $names_seen);
            case DnsSite::TYPE_TXT:
                $bytes = "";
                $strings = is_array($rdata) ? $rdata :
                    [(string) $rdata];
                foreach ($strings as $s) {
                    $s = (string) $s;
                    if (strlen($s) > 255) {
                        $s = substr($s, 0, 255);
                    }
                    $bytes .= chr(strlen($s)) . $s;
                }
                return $bytes;
            case DnsSite::TYPE_SOA:
                $mname = self::packName($rdata['mname'],
                    $rdata_offset, $names_seen);
                $rname = self::packName($rdata['rname'],
                    $rdata_offset + strlen($mname),
                    $names_seen);
                return $mname . $rname . pack("NNNNN",
                    $rdata['serial'], $rdata['refresh'],
                    $rdata['retry'], $rdata['expire'],
                    $rdata['minimum']);
        }
        return is_string($rdata) ? $rdata : "";
    }
    /**
     * Decodes per-type RDATA into the structured form
     * DnsRecord stores.
     */
    protected static function unpackRdata($type, $bytes,
        $offset, $length)
    {
        $payload = substr($bytes, $offset, $length);
        switch ($type) {
            case DnsSite::TYPE_A:
                if ($length !== 4) {
                    return $payload;
                }
                return inet_ntop($payload);
            case DnsSite::TYPE_AAAA:
                if ($length !== 16) {
                    return $payload;
                }
                return inet_ntop($payload);
            case DnsSite::TYPE_CNAME:
            case DnsSite::TYPE_NS:
            case DnsSite::TYPE_PTR:
                $cursor = $offset;
                $name = self::unpackName($bytes, $cursor);
                return $name === false ? "" : $name;
            case DnsSite::TYPE_MX:
                if ($length < 3) {
                    return ['preference' => 0,
                        'exchange' => ""];
                }
                $pref = unpack("n",
                    substr($payload, 0, 2))[1];
                $cursor = $offset + 2;
                $exchange = self::unpackName($bytes, $cursor);
                return [
                    'preference' => $pref,
                    'exchange' =>
                        $exchange === false ? "" : $exchange,
                ];
            case DnsSite::TYPE_TXT:
                $strings = [];
                $i = 0;
                while ($i < $length) {
                    $len = ord($payload[$i]);
                    $i++;
                    if ($i + $len > $length) {
                        break;
                    }
                    $strings[] = substr($payload, $i, $len);
                    $i += $len;
                }
                return $strings;
            case DnsSite::TYPE_SOA:
                $cursor = $offset;
                $mname = self::unpackName($bytes, $cursor);
                $rname = self::unpackName($bytes, $cursor);
                if ($cursor + 20 > $offset + $length) {
                    return ['mname' => $mname,
                        'rname' => $rname];
                }
                $tail = unpack(
                    "Nserial/Nrefresh/Nretry/Nexpire/Nminimum",
                    substr($bytes, $cursor, 20));
                return [
                    'mname' => $mname,
                    'rname' => $rname,
                    'serial' => $tail['serial'],
                    'refresh' => $tail['refresh'],
                    'retry' => $tail['retry'],
                    'expire' => $tail['expire'],
                    'minimum' => $tail['minimum'],
                ];
        }
        return $payload;
    }
}
/**
 * Authoritative DNS server. Binds three sockets (UDP plain,
 * TCP plain, TCP+TLS for DNS-over-TLS per RFC 7858) and runs
 * a select-loop that dispatches queries to the configured
 * DnsAuthority. Responses are built per RFC 1035 with EDNS0
 * (RFC 6891) when the client included an OPT pseudo-record.
 *
 * Configuration keys recognized by listen():
 *   BIND          interface to bind, default 0.0.0.0
 *   DNS_UDP_PORT  default 15353 (low ports require root)
 *   DNS_TCP_PORT  default 15353
 *   DNS_TLS_PORT  default 18853 (DoT)
 *   SERVER_NAME   string for trace headers
 *   MAX_TCP_LEN   maximum bytes per TCP-framed message
 *                 (default 65535, the on-wire max)
 *   SERVER_CONTEXT stream context options for the TLS socket
 *                 (mirrors MailSite); when empty DoT is
 *                 silently skipped.
 *
 * A typical setup:
 *
 *      $authority = new FileDnsAuthority(__DIR__ . "/zones");
 *      $dns = new DnsSite($authority);
 *      $dns->listen([
 *          'DNS_UDP_PORT' => 15353,
 *          'DNS_TCP_PORT' => 15353,
 *          'DNS_TLS_PORT' => 18853,
 *          'SERVER_CONTEXT' => ['ssl' => [
 *              'local_cert' => 'cert.pem',
 *              'local_pk' => 'key.pem',
 *          ]],
 *      ]);
 */
class DnsSite
{
    /* Class values (RFC 1035 sec 3.2.4) */
    const CLASS_IN  = 1;
    const CLASS_ANY = 255;
    /* Type values (RFC 1035 sec 3.2.2 and successors) */
    const TYPE_A     = 1;
    const TYPE_NS    = 2;
    const TYPE_CNAME = 5;
    const TYPE_SOA   = 6;
    const TYPE_PTR   = 12;
    const TYPE_MX    = 15;
    const TYPE_TXT   = 16;
    const TYPE_AAAA  = 28;
    const TYPE_OPT   = 41;
    const TYPE_ANY   = 255;
    /* RCODE values (RFC 1035 sec 4.1.1, RFC 6895 registry) */
    const RCODE_NOERROR  = 0;
    const RCODE_FORMERR  = 1;
    const RCODE_SERVFAIL = 2;
    const RCODE_NXDOMAIN = 3;
    const RCODE_NOTIMP   = 4;
    const RCODE_REFUSED  = 5;
    /**
     * @var DnsAuthority zone backend.
     */
    protected $authority;
    /**
     * @var array runtime config from listen($config).
     */
    protected $config = [];
    /**
     * @var array ssl options (the contents of
     *      SERVER_CONTEXT['ssl']) saved from listen() so the
     *      DoT accept path can apply them per-connection.
     */
    protected $ssl_options = [];
    /**
     * Maps RR type names ("A", "AAAA", ...) to their integer
     * codes. Used by master-file parsing and by callers that
     * accept user-typed types.
     */
    public static function typeFromName($name)
    {
        $map = [
            'A' => self::TYPE_A,
            'NS' => self::TYPE_NS,
            'CNAME' => self::TYPE_CNAME,
            'SOA' => self::TYPE_SOA,
            'PTR' => self::TYPE_PTR,
            'MX' => self::TYPE_MX,
            'TXT' => self::TYPE_TXT,
            'AAAA' => self::TYPE_AAAA,
            'OPT' => self::TYPE_OPT,
            'ANY' => self::TYPE_ANY,
        ];
        $upper = strtoupper((string) $name);
        return isset($map[$upper]) ? $map[$upper] : false;
    }
    /**
     * Inverse of typeFromName: returns "A", "AAAA", ... for a
     * given integer, or "TYPE<n>" for unknown codes (the
     * RFC 3597 unknown-type representation).
     */
    public static function nameFromType($type)
    {
        $map = [
            self::TYPE_A => 'A',
            self::TYPE_NS => 'NS',
            self::TYPE_CNAME => 'CNAME',
            self::TYPE_SOA => 'SOA',
            self::TYPE_PTR => 'PTR',
            self::TYPE_MX => 'MX',
            self::TYPE_TXT => 'TXT',
            self::TYPE_AAAA => 'AAAA',
            self::TYPE_OPT => 'OPT',
            self::TYPE_ANY => 'ANY',
        ];
        return isset($map[$type]) ? $map[$type] :
            "TYPE" . $type;
    }
    /**
     * @param DnsAuthority $authority zone backend
     */
    public function __construct($authority)
    {
        $this->authority = $authority;
    }
    /**
     * Returns the authority backend (the demo's webui uses
     * this to render the zone editor).
     */
    public function authority()
    {
        return $this->authority;
    }
    /**
     * Binds the configured sockets and runs the event loop
     * until the process is killed. Mirrors MailSite::listen
     * in style: required listeners (UDP+TCP) are fatal on
     * bind failure, the optional DoT listener prints a
     * warning and continues if its bind fails.
     */
    public function listen($config = [])
    {
        $defaults = [
            'BIND' => '0.0.0.0',
            'DNS_UDP_PORT' => 15353,
            'DNS_TCP_PORT' => 15353,
            'DNS_TLS_PORT' => 18853,
            'SERVER_NAME' => 'atto-dns',
            'MAX_TCP_LEN' => 65535,
        ];
        $context_array = [];
        if (isset($config['SERVER_CONTEXT'])) {
            $context_array = $config['SERVER_CONTEXT'];
            unset($config['SERVER_CONTEXT']);
        }
        $this->config = array_merge($defaults, $config);
        $tls_available = !empty($context_array['ssl']);
        if ($tls_available) {
            $this->ssl_options = $context_array['ssl'];
        }
        $bind = $this->config['BIND'];
        $udp_addr = "udp://$bind:" .
            $this->config['DNS_UDP_PORT'];
        $tcp_addr = "tcp://$bind:" .
            $this->config['DNS_TCP_PORT'];
        $udp = @stream_socket_server($udp_addr,
            $errno, $errstr,
            STREAM_SERVER_BIND);
        if (!$udp) {
            echo "Failed to bind UDP $udp_addr: $errstr\n";
            return false;
        }
        stream_set_blocking($udp, 0);
        $tcp = @stream_socket_server($tcp_addr,
            $errno, $errstr,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$tcp) {
            echo "Failed to bind TCP $tcp_addr: $errstr\n";
            fclose($udp);
            return false;
        }
        stream_set_blocking($tcp, 0);
        echo "atto-dns listening: UDP at $udp_addr\n";
        echo "atto-dns listening: TCP at $tcp_addr\n";
        $tls = false;
        if ($tls_available) {
            $tls_addr = "tcp://$bind:" .
                $this->config['DNS_TLS_PORT'];
            $tls_context = stream_context_create(
                ['ssl' => $context_array['ssl']]);
            $tls = @stream_socket_server($tls_addr,
                $errno, $errstr,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
                $tls_context);
            if ($tls) {
                stream_set_blocking($tls, 0);
                echo "atto-dns listening: DoT at $tls_addr" .
                    " (implicit TLS)\n";
            } else {
                echo "Warning: failed to bind DoT $tls_addr:" .
                    " $errstr\n";
                $tls = false;
            }
        }
        $tcp_clients = [];
        while (true) {
            $reads = [$udp, $tcp];
            if ($tls !== false) {
                $reads[] = $tls;
            }
            foreach ($tcp_clients as $client) {
                $reads[] = $client['stream'];
            }
            $writes = null;
            $excepts = null;
            $n = @stream_select($reads, $writes, $excepts, 5);
            if ($n === false || $n === 0) {
                continue;
            }
            foreach ($reads as $stream) {
                if ($stream === $udp) {
                    $this->serviceUdp($udp);
                    continue;
                }
                if ($stream === $tcp) {
                    $this->acceptTcp($tcp, $tcp_clients,
                        false);
                    continue;
                }
                if ($tls !== false && $stream === $tls) {
                    $this->acceptTcp($tls, $tcp_clients,
                        true);
                    continue;
                }
                $this->serviceTcpClient($stream,
                    $tcp_clients);
            }
            $this->reapIdleTcpClients($tcp_clients);
        }
    }
    /**
     * Reads one UDP datagram, builds a response, and writes
     * it back to the same peer. UDP responses are capped at
     * 512 bytes (RFC 1035) unless the client sent EDNS0 with
     * a larger advertised buffer.
     */
    protected function serviceUdp($udp)
    {
        $peer = "";
        $bytes = @stream_socket_recvfrom($udp, 65535, 0, $peer);
        if ($bytes === false || $bytes === "") {
            return;
        }
        $request = DnsMessage::unpack($bytes);
        $max_size = 512;
        if ($request !== false) {
            $max_size = max($max_size,
                $this->ednsBufferSize($request));
        }
        $response_bytes =
            $this->buildResponseBytes($bytes, $request,
                $max_size);
        @stream_socket_sendto($udp, $response_bytes, 0, $peer);
    }
    /**
     * Accepts one TCP connection (plain or already-handshaken
     * TLS) and adds it to the client table for select-driven
     * service. For DoT listeners we perform the TLS server
     * handshake here before adding the client; the underlying
     * stream_socket_server with a TLS context only stages the
     * cert, it does not negotiate.
     */
    protected function acceptTcp($listener, &$tcp_clients,
        $is_tls)
    {
        $client = @stream_socket_accept($listener, 0);
        if (!$client) {
            return;
        }
        if ($is_tls && !$this->upgradeToTls($client)) {
            @fclose($client);
            return;
        }
        stream_set_blocking($client, 0);
        $tcp_clients[(int) $client] = [
            'stream' => $client,
            'buffer' => '',
            'is_tls' => $is_tls,
            'opened' => time(),
        ];
    }
    /**
     * Performs the server-side TLS handshake on an accepted
     * DoT client socket. Mirrors MailSite::upgradeToTls: the
     * stream_socket_enable_crypto call is bracketed by a
     * scoped error handler so a handshake failure can be
     * attributed to this exact call (error_get_last is
     * process-wide and easily polluted).
     */
    protected function upgradeToTls($connection)
    {
        if (empty($this->ssl_options)) {
            return false;
        }
        foreach ($this->ssl_options as $option_name =>
            $option_value) {
            stream_context_set_option($connection, 'ssl',
                $option_name, $option_value);
        }
        $error = null;
        set_error_handler(
            function ($errno, $errstr) use (&$error) {
                $error = $errstr;
                return true;
            });
        stream_set_blocking($connection, 1);
        $method = STREAM_CRYPTO_METHOD_TLS_SERVER;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
        }
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            $method |= STREAM_CRYPTO_METHOD_TLSv1_3_SERVER;
        }
        $ok = @stream_socket_enable_crypto($connection, true,
            $method);
        stream_set_blocking($connection, 0);
        restore_error_handler();
        if ($ok === true) {
            return true;
        }
        if ($error !== null) {
            echo "DoT handshake failed: $error\n";
        }
        return false;
    }
    /**
     * Drains pending bytes from one TCP/DoT client and emits
     * a response for each fully-received message. TCP frames
     * each message with a 2-byte length prefix per RFC 1035
     * sec 4.2.2.
     */
    protected function serviceTcpClient($stream, &$tcp_clients)
    {
        $key = (int) $stream;
        if (!isset($tcp_clients[$key])) {
            return;
        }
        $chunk = @fread($stream, 8192);
        if ($chunk === false || $chunk === "") {
            $meta = stream_get_meta_data($stream);
            if (!empty($meta['eof'])) {
                @fclose($stream);
                unset($tcp_clients[$key]);
            }
            return;
        }
        $tcp_clients[$key]['buffer'] .= $chunk;
        if (strlen($tcp_clients[$key]['buffer']) >
            $this->config['MAX_TCP_LEN'] + 4096) {
            @fclose($stream);
            unset($tcp_clients[$key]);
            return;
        }
        while (strlen($tcp_clients[$key]['buffer']) >= 2) {
            $length = unpack("n",
                substr($tcp_clients[$key]['buffer'], 0, 2))[1];
            if ($length > $this->config['MAX_TCP_LEN']) {
                @fclose($stream);
                unset($tcp_clients[$key]);
                return;
            }
            if (strlen($tcp_clients[$key]['buffer']) <
                2 + $length) {
                break;
            }
            $request_bytes = substr(
                $tcp_clients[$key]['buffer'], 2, $length);
            $tcp_clients[$key]['buffer'] = substr(
                $tcp_clients[$key]['buffer'], 2 + $length);
            $request = DnsMessage::unpack($request_bytes);
            $response_bytes = $this->buildResponseBytes(
                $request_bytes, $request,
                $this->config['MAX_TCP_LEN']);
            @fwrite($stream,
                pack("n", strlen($response_bytes)) .
                $response_bytes);
        }
    }
    /**
     * Closes TCP/DoT clients that have been open more than
     * 30 seconds without producing a complete message; the
     * idle-connection cap is a DoS hedge.
     */
    protected function reapIdleTcpClients(&$tcp_clients)
    {
        $now = time();
        foreach ($tcp_clients as $key => $client) {
            if ($now - $client['opened'] > 30 &&
                $client['buffer'] === '') {
                @fclose($client['stream']);
                unset($tcp_clients[$key]);
            }
        }
    }
    /**
     * Returns the EDNS0 advertised UDP buffer size from a
     * request (RFC 6891 sec 6.1.2: the OPT pseudo-record's
     * CLASS field carries the requestor's UDP payload size).
     * Returns 0 if the request did not include OPT.
     */
    protected function ednsBufferSize($request)
    {
        foreach ($request->additional as $rr) {
            if ($rr->type === self::TYPE_OPT) {
                return $rr->class;
            }
        }
        return 0;
    }
    /**
     * Builds the full response to one query. Returns the
     * already-packed bytes; the caller writes them to the
     * appropriate transport. If the response would exceed
     * $max_size, the TC bit is set and the answer/authority/
     * additional sections are stripped (RFC 1035 sec 4.2.1).
     */
    public function buildResponseBytes($request_bytes, $request,
        $max_size)
    {
        $response = $this->buildResponse($request_bytes,
            $request);
        $bytes = DnsMessage::pack($response);
        if (strlen($bytes) <= $max_size) {
            return $bytes;
        }
        $response->tc = true;
        $response->answers = [];
        $response->authority = [];
        $response->additional = [];
        return DnsMessage::pack($response);
    }
    /**
     * Constructs the logical response for one parsed query.
     * Public so the demo's "raw query" path can build a
     * response without writing it to a socket.
     */
    public function buildResponse($request_bytes, $request)
    {
        $response = new DnsMessage();
        if ($request === false) {
            $response->qr = true;
            $response->rcode = self::RCODE_FORMERR;
            return $response;
        }
        $response->id = $request->id;
        $response->qr = true;
        $response->opcode = $request->opcode;
        $response->rd = $request->rd;
        $response->questions = $request->questions;
        if ($request->opcode !== 0) {
            $response->rcode = self::RCODE_NOTIMP;
            return $response;
        }
        if (count($request->questions) === 0) {
            $response->rcode = self::RCODE_FORMERR;
            return $response;
        }
        $question = $request->questions[0];
        list($qname, $qtype, $qclass) = $question;
        if ($qclass !== self::CLASS_IN &&
            $qclass !== self::CLASS_ANY) {
            $response->rcode = self::RCODE_REFUSED;
            return $response;
        }
        $origin = $this->authority->originFor($qname);
        if ($origin === false) {
            $response->rcode = self::RCODE_REFUSED;
            return $response;
        }
        $response->aa = true;
        $this->resolveQuery($qname, $qtype, $qclass, $origin,
            $response);
        return $response;
    }
    /**
     * Walks the lookup logic for one question, populating
     * answer / authority / additional sections on the
     * response. CNAME targets are followed up to a small
     * chase limit so a query for an A record at a CNAME owner
     * returns both the CNAME and the resolved address.
     */
    protected function resolveQuery($qname, $qtype, $qclass,
        $origin, $response)
    {
        $current = $qname;
        $hops = 0;
        while ($hops < 8) {
            $records = $this->authority->findRecords($current,
                $qtype, $qclass);
            if ($records === false) {
                $response->rcode = self::RCODE_NXDOMAIN;
                $soa = $this->authority->soaFor($origin);
                if ($soa !== false) {
                    $response->authority[] = $soa;
                }
                return;
            }
            if (!empty($records)) {
                foreach ($records as $r) {
                    $response->answers[] = $r;
                }
                $this->addGlue($response);
                return;
            }
            if ($qtype !== self::TYPE_CNAME) {
                $cnames = $this->authority->findRecords(
                    $current, self::TYPE_CNAME, $qclass);
                if (is_array($cnames) && !empty($cnames)) {
                    foreach ($cnames as $r) {
                        $response->answers[] = $r;
                    }
                    $current = $cnames[0]->rdata;
                    $hops++;
                    $next_origin = $this->authority->originFor(
                        $current);
                    if ($next_origin === false) {
                        return;
                    }
                    $origin = $next_origin;
                    continue;
                }
            }
            $soa = $this->authority->soaFor($origin);
            if ($soa !== false) {
                $response->authority[] = $soa;
            }
            return;
        }
    }
    /**
     * Adds glue records (A/AAAA for names referenced from MX
     * or NS targets) into the additional section when they
     * are available locally. RFC 1034 sec 4.3.4 allows but
     * does not require this; clients use it to skip a follow-
     * up lookup.
     */
    protected function addGlue($response)
    {
        $targets = [];
        foreach ($response->answers as $rr) {
            if ($rr->type === self::TYPE_MX) {
                $targets[] = $rr->rdata['exchange'];
            } else if ($rr->type === self::TYPE_NS) {
                $targets[] = $rr->rdata;
            }
        }
        $seen = [];
        foreach ($targets as $name) {
            $name_key = strtolower($name);
            if (isset($seen[$name_key])) {
                continue;
            }
            $seen[$name_key] = true;
            $a4 = $this->authority->findRecords($name,
                self::TYPE_A, self::CLASS_IN);
            if (is_array($a4)) {
                foreach ($a4 as $r) {
                    $response->additional[] = $r;
                }
            }
            $a6 = $this->authority->findRecords($name,
                self::TYPE_AAAA, self::CLASS_IN);
            if (is_array($a6)) {
                foreach ($a6 as $r) {
                    $response->additional[] = $r;
                }
            }
        }
    }
}
