<?php
/**
 * SeekQuarry/Atto Web Site Project
 *
 * Reusable call-counting instrumentation for the H3 listener
 * hotpath classes. Each class here extends one of the real QUIC
 * classes and overrides the methods the benchmarks time so that a
 * driver can learn how many times each one runs while handling a
 * request, without adding any counter to the shipping
 * src/H3Listener.php. The trick is that the real code reaches these
 * methods through the object it holds -- a connection calls
 * $this->emit(), a packet calls $keys->seal(), a flush loop calls
 * $stream->takeForFrame() -- so when a driver builds the connection,
 * keys, and streams from these subclasses instead, every one of
 * those calls, including the ones the real code makes to itself,
 * lands on an override that adds one to a shared tally and then runs
 * the real method through parent.
 *
 * Only methods reached through an object can be counted this way;
 * the few benchmarked methods that are called statically (for
 * instance QuicFrame::encode) cannot be, and a driver derives those
 * counts from the ones counted here. What this helper does cover:
 * seal, open, and headerProtectionMask on the packet keys;
 * takeForFrame and consume on a stream; and emit, flushStreams,
 * processAck, setLossDetectionTimer, and detectAndRemoveLostPackets
 * on the connection.
 *
 * These are instrumentation for the timed benchmarks, not the
 * pass/fail tests: they belong to the bench_ family and the test
 * runner does not pick them up. They are written to be shared, so a
 * later test or benchmark that needs a call tally can require this
 * file rather than re-deriving the subclasses.
 *
 * Require order: load src/H3Listener.php (which needs its stub
 * parent classes defined first, the way the benchmarks set them up)
 * before this file, since the classes here extend the QUIC classes
 * that file defines.
 *
 * @author Chris Pollett chris@pollett.org
 * @license https://www.gnu.org/licenses/ GPL3
 * @link https://www.seekquarry.com/
 * @copyright 2018 - 2026
 * @package seekquarry\atto
 */
namespace seekquarry\atto;

/**
 * A shared tally of how many times each instrumented method has run.
 * A driver resets it before a run and reads it after. Keeping the
 * count in one static place, rather than on each object, lets a run
 * span several connections, keys, and streams and still add up to a
 * single per-method total.
 */
class CallCounts
{
    /**
     * @var array method label => number of calls since the last
     *      reset
     */
    public static $counts = [];

    /**
     * Clears the tally so the next run starts from zero.
     */
    public static function reset()
    {
        self::$counts = [];
    }

    /**
     * Adds one to the tally for a method.
     *
     * @param string $label the method's label, such as
     *      "QuicPacketKeys::seal"
     */
    public static function bump($label)
    {
        if (!isset(self::$counts[$label])) {
            self::$counts[$label] = 0;
        }
        self::$counts[$label]++;
    }

    /**
     * Returns the whole tally as a label => count map.
     *
     * @return array the counts gathered since the last reset
     */
    public static function all()
    {
        return self::$counts;
    }
}

/**
 * Packet keys that count their seal, open, and header-protection
 * calls. The real encode and decode paths call these on whichever
 * keys object the connection holds, so a connection built with these
 * keys counts one seal per packet sealed, one open per packet
 * opened, and one header-protection mask per packet in either
 * direction.
 */
class CountingQuicPacketKeys extends QuicPacketKeys
{
    /**
     * Counts and forwards a seal (encrypt-and-tag of one packet).
     *
     * @param int $packet_number the packet's number
     * @param string $aad the header bytes authenticated but not
     *      hidden
     * @param string $plaintext the payload to protect
     * @return string the sealed payload
     */
    public function seal($packet_number, $aad, $plaintext)
    {
        CallCounts::bump("QuicPacketKeys::seal");
        return parent::seal($packet_number, $aad, $plaintext);
    }

    /**
     * Counts and forwards an open (verify-and-decrypt of one
     * packet).
     *
     * @param int $packet_number the packet's number
     * @param string $aad the header bytes authenticated but not
     *      hidden
     * @param string $ciphertext the protected payload
     * @return string the recovered payload, or false on failure
     */
    public function open($packet_number, $aad, $ciphertext)
    {
        CallCounts::bump("QuicPacketKeys::open");
        return parent::open($packet_number, $aad, $ciphertext);
    }

    /**
     * Counts and forwards a header-protection mask, run once per
     * packet in each direction.
     *
     * @param string $sample the ciphertext sample the mask derives
     *      from
     * @return string the mask bytes
     */
    public function headerProtectionMask($sample)
    {
        CallCounts::bump("QuicPacketKeys::headerProtectionMask");
        return parent::headerProtectionMask($sample);
    }
}

/**
 * A stream that counts the two send-side calls the flush loop makes
 * on it: takeForFrame, which hands out the next chunk to frame, and
 * consume, which delivers received in-order bytes.
 */
class CountingQuicStream extends QuicStream
{
    /**
     * Counts and forwards a takeForFrame (the next outgoing chunk).
     *
     * @param int $max_bytes the most bytes to take
     * @return array the [offset, data, fin] chunk, or null if
     *      nothing is queued
     */
    public function takeForFrame($max_bytes)
    {
        CallCounts::bump("QuicStream::takeForFrame");
        return parent::takeForFrame($max_bytes);
    }

    /**
     * Counts and forwards a consume (in-order received bytes).
     *
     * @return string the in-order bytes now available
     */
    public function consume()
    {
        CallCounts::bump("QuicStream::consume");
        return parent::consume();
    }
}

/**
 * A connection that counts the five whole-connection methods the
 * benchmarks time. Because the real code makes these calls through
 * $this, a connection built from this class counts not only the
 * emit and flushStreams a driver calls directly but also the
 * processAck, setLossDetectionTimer, and detectAndRemoveLostPackets
 * the connection calls on itself while handling acknowledgements.
 * The two methods the parent declares protected are widened to
 * public here so a driver can also drive them directly when it wants
 * to feed acknowledgements without a full receive path.
 */
class CountingQuicConnection extends QuicConnection
{
    /**
     * Counts and forwards an emit (seal the queued packets).
     *
     * @return array the datagrams to send
     */
    public function emit()
    {
        CallCounts::bump("QuicConnection::emit");
        return parent::emit();
    }

    /**
     * Counts and forwards a flushStreams (cut queued stream bytes
     * into frames).
     *
     * @param int $budget the most stream bytes to emit this call
     * @return bool true if data still remains to send
     */
    public function flushStreams($budget = self::DEFAULT_FLUSH_BUDGET)
    {
        CallCounts::bump("QuicConnection::flushStreams");
        return parent::flushStreams($budget);
    }

    /**
     * Counts and forwards a processAck (retire acknowledged
     * packets). Widened to public so a driver can feed an ACK frame
     * directly.
     *
     * @param int $level the encryption stage of the ACK
     * @param array $frame the decoded ACK frame
     */
    public function processAck($level, $frame)
    {
        CallCounts::bump("QuicConnection::processAck");
        parent::processAck($level, $frame);
    }

    /**
     * Counts and forwards a setLossDetectionTimer (arm the loss
     * timer).
     */
    public function setLossDetectionTimer()
    {
        CallCounts::bump("setLossDetectionTimer");
        parent::setLossDetectionTimer();
    }

    /**
     * Counts and forwards a detectAndRemoveLostPackets (declare and
     * drop lost packets). Widened to public for the same reason as
     * processAck.
     *
     * @param int $level the encryption stage to check
     * @return int how many packets were declared lost
     */
    public function detectAndRemoveLostPackets($level)
    {
        CallCounts::bump("detectAndRemoveLostPackets");
        return parent::detectAndRemoveLostPackets($level);
    }
}

/**
 * Builds a counting copy of a real packet-keys object by copying
 * every property across, so the copy protects packets with the same
 * keys while counting its calls. Used because the real key material
 * comes from QuicPacketKeys::fromInitialDcid, which returns plain
 * QuicPacketKeys objects.
 *
 * @param QuicPacketKeys $real the key object to copy
 * @return CountingQuicPacketKeys a counting copy with the same keys
 */
function countingKeysFrom($real)
{
    $source = new \ReflectionObject($real);
    $target_class = new \ReflectionClass(
        CountingQuicPacketKeys::class);
    $copy = $target_class->newInstanceWithoutConstructor();
    foreach ($source->getProperties() as $property) {
        $value = $property->getValue($real);
        $target_property = new \ReflectionProperty($copy,
            $property->getName());
        $target_property->setValue($copy, $value);
    }
    return $copy;
}
