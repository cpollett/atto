<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Unit tests for the RFC 9000 sec 8.2 + sec 9 path-
 * validation and client-migration state machine. Covers
 * the inbound PATH_CHALLENGE -> PATH_RESPONSE echo, the
 * pending_path bookkeeping that QuicConnection exposes
 * for the H3Listener to drive, and the
 * buildPathChallengePacket helper that encodes a single
 * 1-RTT challenge for an alternative path.
 *
 * Run from the repo root:
 *     php tests/http3/test_path_validation.php
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

/*
    Build a QuicConnection in ST_ESTABLISHED with real
    1-RTT keys so we can exercise the encode/decode round-
    trip and the path-validation state without running a
    full handshake. peer_cid is set to a recognizable
    value so emitted packets carry the right DCID.
 */
function makeConn()
{
    $rc = new \ReflectionClass('seekquarry\\atto\\QuicConnection');
    $conn = $rc->newInstanceWithoutConstructor();
    $conn->state = QuicConnection::ST_ESTABLISHED;
    $conn->local_cid = "\x01\x02\x03\x04\x05\x06\x07\x08";
    $conn->peer_cid = "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
    $conn->next_pn = [
        QuicConnection::LEVEL_INITIAL => 0,
        QuicConnection::LEVEL_HANDSHAKE => 0,
        QuicConnection::LEVEL_APPLICATION => 0,
    ];
    $conn->largest_pn = [
        QuicConnection::LEVEL_INITIAL => -1,
        QuicConnection::LEVEL_HANDSHAKE => -1,
        QuicConnection::LEVEL_APPLICATION => -1,
    ];
    $conn->received_pns = [
        QuicConnection::LEVEL_INITIAL => [],
        QuicConnection::LEVEL_HANDSHAKE => [],
        QuicConnection::LEVEL_APPLICATION => [],
    ];
    $conn->ack_pending = [
        QuicConnection::LEVEL_INITIAL => false,
        QuicConnection::LEVEL_HANDSHAKE => false,
        QuicConnection::LEVEL_APPLICATION => false,
    ];
    $conn->sent_packets = [
        QuicConnection::LEVEL_INITIAL => [],
        QuicConnection::LEVEL_HANDSHAKE => [],
        QuicConnection::LEVEL_APPLICATION => [],
    ];
    $conn->loss_time = [
        QuicConnection::LEVEL_INITIAL => null,
        QuicConnection::LEVEL_HANDSHAKE => null,
        QuicConnection::LEVEL_APPLICATION => null,
    ];
    $conn->largest_acked_pn = [
        QuicConnection::LEVEL_INITIAL => -1,
        QuicConnection::LEVEL_HANDSHAKE => -1,
        QuicConnection::LEVEL_APPLICATION => -1,
    ];
    $conn->latest_rtt = null;
    $conn->smoothed_rtt = null;
    $conn->rttvar = null;
    $conn->min_rtt = null;
    $conn->pto_count = 0;
    $conn->loss_detection_timer = null;
    $conn->bytes_in_flight = 0;
    $conn->congestion_window =
        QuicConnection::CC_INITIAL_WINDOW_BYTES;
    $conn->ssthresh = PHP_INT_MAX;
    $conn->recovery_start_time = 0.0;
    $conn->stats_bytes_received = 100000;
    $conn->stats_bytes_sent = 0;
    $conn->stats_packets_received = 0;
    $conn->stats_packets_sent = 0;
    $conn->send_queue = [];
    $conn->handshake_done_sent = true;
    $conn->pending_path = [];
    $conn->path_responses_pending = [];
    $conn->streams = [];
    $secret = str_repeat("\x42", 32);
    $tx = QuicPacketKeys::fromTrafficSecret($secret,
        Tls13Engine::CIPHER_AES_128_GCM_SHA256);
    $rx = QuicPacketKeys::fromTrafficSecret($secret,
        Tls13Engine::CIPHER_AES_128_GCM_SHA256);
    $conn->keys = [
        QuicConnection::LEVEL_APPLICATION => [
            'tx' => $tx,
            'rx' => $rx,
        ],
    ];
    return $conn;
}

/*
    Test 1: buildPathChallengePacket returns a non-empty
    encrypted 1-RTT packet for an established connection.
 */
$conn = makeConn();
$challenge = "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8";
$packet = H3Listener::buildPathChallengePacket($conn,
    $challenge);
ok("buildPathChallengePacket: non-empty",
    $packet !== '');
ok("buildPathChallengePacket: looks like short header",
    strlen($packet) > 0
    && (ord($packet[0]) & 0x80) === 0);

/*
    Test 2: round-trip the encoded packet through
    QuicPacket::decodeShort and verify the inner frame is a
    PATH_CHALLENGE carrying the original 8 bytes.
 */
$rx = $conn->keys[QuicConnection::LEVEL_APPLICATION]['rx'];
$decoded = QuicPacket::decodeShort($packet, 0, $rx,
    strlen($conn->local_cid), -1);
$pkt = $decoded[0];
ok("path-challenge packet: decodes",
    $pkt !== false);
list($frames, $err) = QuicFrame::decodeAll($pkt->payload);
ok("path-challenge packet: payload decodes to one frame",
    $err === '' && count($frames) === 1);
ok("path-challenge packet: frame is PATH_CHALLENGE",
    $frames[0]['type'] === QuicFrame::F_PATH_CHALLENGE);
ok("path-challenge packet: data matches original",
    $frames[0]['data'] === $challenge);

/*
    Test 3: buildPathChallengePacket returns '' when 1-RTT
    keys aren't available (pre-handshake scenario).
 */
$conn = makeConn();
unset($conn->keys[QuicConnection::LEVEL_APPLICATION]);
$packet = H3Listener::buildPathChallengePacket($conn,
    $challenge);
ok("buildPathChallengePacket: empty without 1-RTT keys",
    $packet === '');

/*
    Helper: drives processPacketFrames by building a minimal
    QuicPacket carrying the encoded frames as its payload,
    then invoking the protected method via reflection.
 */
function feedFrames($conn, $frames)
{
    $payload = '';
    foreach ($frames as $f) {
        $payload .= QuicFrame::encode($f);
    }
    $pkt = new QuicPacket();
    $pkt->payload = $payload;
    $rm = new \ReflectionMethod(
        'seekquarry\\atto\\QuicConnection',
        'processPacketFrames');
    $rm->invokeArgs($conn, [
        QuicConnection::LEVEL_APPLICATION,
        $pkt,
    ]);
}

/*
    Test 4: inbound PATH_CHALLENGE queues a PATH_RESPONSE
    on path_responses_pending. The connection's frame
    dispatcher should populate it without any side effects
    on connection state.
 */
$conn = makeConn();
$challenge_in = "\x10\x20\x30\x40\x50\x60\x70\x80";
feedFrames($conn, [
    ['type' => QuicFrame::F_PATH_CHALLENGE,
     'data' => $challenge_in],
]);
ok("inbound PATH_CHALLENGE: queues one response",
    count($conn->path_responses_pending) === 1);
ok("inbound PATH_CHALLENGE: response carries the right data",
    $conn->path_responses_pending[0] === $challenge_in);

/*
    Test 5: inbound PATH_RESPONSE matching the pending
    challenge sets response_received true.
 */
$conn = makeConn();
$conn->pending_path = [
    'address' => '10.0.0.1:9999',
    'challenge' => "\xab\xcd\xef\x01\x23\x45\x67\x89",
    'first_seen' => microtime(true),
    'response_received' => false,
];
feedFrames($conn, [
    ['type' => QuicFrame::F_PATH_RESPONSE,
     'data' => "\xab\xcd\xef\x01\x23\x45\x67\x89"],
]);
ok("matching PATH_RESPONSE: response_received true",
    $conn->pending_path['response_received'] === true);

/*
    Test 6: inbound PATH_RESPONSE that does NOT match the
    pending challenge leaves response_received false.
    Defends against a rogue echo of stale challenge data.
 */
$conn = makeConn();
$conn->pending_path = [
    'address' => '10.0.0.1:9999',
    'challenge' => "\xab\xcd\xef\x01\x23\x45\x67\x89",
    'first_seen' => microtime(true),
    'response_received' => false,
];
feedFrames($conn, [
    ['type' => QuicFrame::F_PATH_RESPONSE,
     'data' => "\x00\x00\x00\x00\x00\x00\x00\x00"],
]);
ok("mismatched PATH_RESPONSE: response_received still false",
    $conn->pending_path['response_received'] === false);

/*
    Test 7: PATH_RESPONSE arriving with no pending validation
    is a silent no-op (no crash, no state change). The peer
    can send unsolicited PATH_RESPONSE in response to its own
    earlier challenge that we may have echoed; we just don't
    care.
 */
$conn = makeConn();
$conn->pending_path = [];
feedFrames($conn, [
    ['type' => QuicFrame::F_PATH_RESPONSE,
     'data' => "\x55\x55\x55\x55\x55\x55\x55\x55"],
]);
ok("PATH_RESPONSE without pending: pending_path stays empty",
    $conn->pending_path === []);

/*
    Test 8: emit() drains path_responses_pending into an
    encoded PATH_RESPONSE on the 1-RTT send queue. End-to-
    end round-trip via decodeShort confirms the wire bytes.
 */
$conn = makeConn();
$conn->path_responses_pending = ["\xfe\xed\xfa\xce\xde\xad\xbe\xef"];
$out = $conn->emit();
ok("emit: drains responses_pending",
    count($conn->path_responses_pending) === 0);
ok("emit: produces at least one datagram",
    count($out) >= 1);
$got_path_response = false;
foreach ($out as $datagram) {
    $rx = $conn->keys[QuicConnection::LEVEL_APPLICATION]['rx'];
    $decoded = QuicPacket::decodeShort($datagram, 0, $rx,
        strlen($conn->local_cid), -1);
    if ($decoded[0] === false) continue;
    list($frames, $derr) =
        QuicFrame::decodeAll($decoded[0]->payload);
    if ($derr !== '') continue;
    foreach ($frames as $fr) {
        if ($fr['type'] === QuicFrame::F_PATH_RESPONSE
            && $fr['data']
                === "\xfe\xed\xfa\xce\xde\xad\xbe\xef") {
            $got_path_response = true;
        }
    }
}
ok("emit: encoded PATH_RESPONSE round-trips",
    $got_path_response);

echo "\n";
echo "Tests run:    $tests\n";
echo "Tests passed: $pass\n";
exit($tests === $pass ? 0 : 1);
