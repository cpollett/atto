<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9000 sec 10.3 stateless reset
 * packet builder. The listener uses this to nudge a peer to
 * give up on a connection it still has CIDs for but the
 * server no longer recognizes (e.g. after a server restart
 * or after the peer's CID was unknown to begin with).
 *
 * Run from the repo root:
 *     php tests/http3/test_stateless_reset.php
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

class Connection {}
class Listener
{
    public function __construct(...$a) {}
    public function close() {}
}
abstract class Transport
{
    public function __construct($s) {}
}

require __DIR__ . '/../../src/H3Listener.php';

$tests = 0;
$pass = 0;
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

$secret = str_repeat("\x42", 32);
$dcid = "\x01\x02\x03\x04\x05\x06\x07\x08";

/*
    Test 1: standard 1200-byte trigger -> reset capped at
    1199 bytes (one shorter), with valid first-byte form
    bits (top bit 0, second bit 1) and a 16-byte trailing
    token.
 */
$reset = H3Listener::buildStatelessReset($dcid, $secret, 1200);
ok("trigger=1200: reset is 1199 bytes",
    strlen($reset) === 1199);
ok("trigger=1200: first byte top 2 bits = 0b01",
    (ord($reset[0]) >> 6) === 0x1);
ok("trigger=1200: trailing 16 bytes are deterministic",
    substr($reset, -16) === substr(hash_hmac('sha256',
        $dcid, $secret, true), 0, 16));

/*
    Test 2: medium-sized trigger; reset should be one byte
    shorter, never larger than 1200 bytes regardless.
 */
$reset = H3Listener::buildStatelessReset($dcid, $secret, 500);
ok("trigger=500: reset is 499 bytes",
    strlen($reset) === 499);
ok("trigger=500: shorter than trigger",
    strlen($reset) < 500);

/*
    Test 3: minimum-viable trigger -> 21-byte reset, since
    the min reset packet is 1+4+16 = 21 bytes (RFC 9000 fig
    16). Trigger of exactly 22 bytes leaves room for a
    21-byte reset.
 */
$reset = H3Listener::buildStatelessReset($dcid, $secret, 22);
ok("trigger=22: reset is 21 bytes (minimum)",
    strlen($reset) === 21);

/*
    Test 4: trigger too small for a valid reset (< 22
    bytes) -> empty string returned, no packet emitted.
 */
$reset = H3Listener::buildStatelessReset($dcid, $secret, 21);
ok("trigger=21: too small, returns empty",
    $reset === '');
$reset = H3Listener::buildStatelessReset($dcid, $secret, 1);
ok("trigger=1: way too small, returns empty",
    $reset === '');

/*
    Test 5: trigger > 1201 bytes is capped at 1200-byte
    reset (don't outgrow QUIC's max datagram size we ever
    produce).
 */
$reset = H3Listener::buildStatelessReset($dcid, $secret, 9999);
ok("trigger=9999: reset capped at 1200 bytes",
    strlen($reset) === 1200);

/*
    Test 6: token derivation is deterministic per CID and
    secret. Two resets for the same DCID under the same
    secret yield the same trailing 16 bytes (the leading
    random padding differs).
 */
$reset_a = H3Listener::buildStatelessReset($dcid, $secret, 200);
$reset_b = H3Listener::buildStatelessReset($dcid, $secret, 200);
ok("token: deterministic across calls",
    substr($reset_a, -16) === substr($reset_b, -16));
ok("padding: random across calls (different leading bytes)",
    substr($reset_a, 0, -16) !== substr($reset_b, 0, -16));

/*
    Test 7: token is distinct for distinct DCIDs.
 */
$dcid_other = str_repeat("\x99", 8);
$reset_other = H3Listener::buildStatelessReset($dcid_other,
    $secret, 200);
ok("token: distinct for distinct DCIDs",
    substr($reset_a, -16) !== substr($reset_other, -16));

/*
    Test 8: token is distinct for distinct secrets.
 */
$other_secret = str_repeat("\x77", 32);
$reset_other_secret = H3Listener::buildStatelessReset($dcid,
    $other_secret, 200);
ok("token: distinct for distinct secrets",
    substr($reset_a, -16)
    !== substr($reset_other_secret, -16));

/*
    Test 9: empty secret -> no reset (listener never
    initialized the secret).
 */
$reset = H3Listener::buildStatelessReset($dcid, '', 1200);
ok("empty secret: returns empty",
    $reset === '');

/*
    Test 10: empty DCID -> no reset (peeked nothing
    routable).
 */
$reset = H3Listener::buildStatelessReset('', $secret, 1200);
ok("empty DCID: returns empty",
    $reset === '');

/*
    Test 11: first-byte randomness exercises the bottom 6
    bits. Generate many resets and confirm the first byte
    spans more than just the fixed bits.
 */
$first_bytes = [];
for ($i = 0; $i < 64; $i++) {
    $r = H3Listener::buildStatelessReset($dcid, $secret, 200);
    $first_bytes[ord($r[0])] = true;
}
ok("first byte: bottom 6 bits are random (sees > 4 distinct)",
    count($first_bytes) > 4);
foreach (array_keys($first_bytes) as $b) {
    if (($b >> 6) !== 0x1) {
        ok("first byte: every observed byte has form bits 0b01",
            false);
        break;
    }
}
if (count($first_bytes) > 0) {
    /*
        If the loop above didn't trip a fail, all observed
        first-byte values had the right form bits.
     */
    $all_ok = true;
    foreach (array_keys($first_bytes) as $b) {
        if (($b >> 6) !== 0x1) {
            $all_ok = false;
            break;
        }
    }
    ok("first byte: every observed byte has form bits 0b01",
        $all_ok);
}

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
