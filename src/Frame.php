<?php

namespace seekquarry\atto;

use Exception;
use Amp\Http\HPack;

require __DIR__ . "/../vendor/autoload.php";

class Frame {

    // Properties
    protected $defined_flags = [];
    protected $type = null;
    protected $stream_association = null;
    public $stream_id;
    public $flags;
    public $body_len = 0;

    // Constants
    const STREAM_ASSOC_HAS_STREAM = "has-stream";
    const STREAM_ASSOC_NO_STREAM = "no-stream";
    const STREAM_ASSOC_EITHER = "either";

    const FRAME_MAX_LEN = (2 ** 14); //initial
    const FRAME_MAX_ALLOWED_LEN = (2 ** 24) - 1; //max-allowed

    // Constructor
    public function __construct($stream_id, $flags = [])
    {
        $this->stream_id = $stream_id;
        $this->flags = new Flags($this->defined_flags);

        foreach ($flags as $flag) {
            $this->flags->add($flag);
        }

        if (!$this->stream_id && $this->stream_association == self::STREAM_ASSOC_HAS_STREAM) {
            throw new Exception("Stream ID must be non-zero for " . get_class($this));
        }
        if ($this->stream_id && $this->stream_association == self::STREAM_ASSOC_NO_STREAM) {
            throw new Exception("Stream ID must be zero for " . get_class($this) . " with stream_id=" . $this->stream_id);
        }
    }

    // toString equivalent
    public function __toString()
    {
        return get_class($this) . "(stream_id=" . $this->stream_id . ", flags=" . $this->flags . "): " . $this->body_repr();
    }

    // Method to serialize the body (not implemented in base class)
    public function serialize_body()
    {
        throw new Exception("Not implemented");
    }

    // Method to serialize the frame
    public function serialize()
    {
        $body = $this->serialize_body();
        $this->body_len = strlen($body);

        // Build the common frame header
        $flags = 0;
        foreach ($this->defined_flags as $flag => $flag_bit) {
            if ($this->flags->contains($flag)) {
                $flags |= $flag_bit;
            }
        }

        $header = pack("nCCCN", 
            ($this->body_len >> 8) & 0xFFFF, 
            $this->body_len & 0xFF, 
            $this->type, 
            $flags,
            $this->stream_id & 0x7FFFFFFF
        );

        return ($header . $body);
    }

    // Method to parse frame header
    public static function parseFrameHeader($header)
    {
        if (strlen($header) != 9) {
            echo "Invalid frame header: length should be 9, received " . strlen($header);
            return;
        }

        $header = bin2hex($header);

        $fields['length'] = $length = hexdec(substr($header, 0, 6));
        $fields['type'] = $type = hexdec(substr($header, 6, 2));
        $fields['flags'] = $flags = substr($header, 8, 2);
        $fields['stream_id'] = $stream_id = hexdec(substr($header, 10, 8));

        if (!isset(FrameFactory::$frames[$type])) {
            throw new Exception("Unknown frame type: " . $type);
            return;
        } else {
            $frame = new FrameFactory::$frames[$type]($stream_id);
        }

        $frame->parse_flags($flags);
        return [$frame, $length];
    }

    // Method to parse flags
    public function parse_flags($flag_byte)
    {
        foreach ($this->defined_flags as $flag => $flag_bit) {
            if ($flag_byte & $flag_bit) {
                $this->flags->add($flag);
            }
        }
        return $this->flags;
    }

    // Method to parse the body (not implemented in base class)
    public function parse_body($data)
    {
        throw new Exception("Not implemented");
    }

    // Helper method for body representation (for debugging)
    public function body_repr()
    {
        // Fallback shows the serialized (and truncated) body content.
        return $this->raw_data_repr($this->serialize_body());
    }

    // Helper method for raw data representation (for debugging)
    private function raw_data_repr($data)
    {
        if (!$data) {
            return "None";
        }
        $r = bin2hex($data);
        if (strlen($r) > 20) {
            $r = substr($r, 0, 20) . "...";
        }
        return "<hex:" . $r . ">";
    }
}

/* Mapping of frame types to classes
 * usage:
 *  $frameType = 0x0; // Suppose this is the type of frame you want to create
 *  $frameClass = FrameFactory::$frames[$frameType]; // Look up the class name
 *  $frameObject = new $frameClass(); // Create a new instance of the class
 */
class FrameFactory {
    public static $frames = [
        0x0 => DataFrame::class,
        0x1 => HeaderFrame::class,
        0x2 => PriorityFrame::class,
        0x3 => RstStreamFrame::class,
        0x4 => SettingsFrame::class,
        0x5 => PushPromiseFrame::class,
        0x6 => PingFrame::class,
        0x7 => GoAwayFrame::class,
        0x8 => WindowUpdateFrame::class,
        0x9 => ContinuationFrame::class,
    ];
}

/*
Settings frame class implementation 
 */
class SettingsFrame extends Frame {

    protected $defined_flags = [
        'ACK' => 0x01
    ];
    protected $type = 0x04;
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';

    const PAYLOAD_SETTINGS = [
        0x01 => 'HEADER_TABLE_SIZE',
        0x02 => 'ENABLE_PUSH',
        0x03 => 'MAX_CONCURRENT_STREAMS',
        0x04 => 'INITIAL_WINDOW_SIZE',
        0x05 => 'MAX_FRAME_SIZE',
        0x06 => 'MAX_HEADER_LIST_SIZE',
        0x08 => 'ENABLE_CONNECT_PROTOCOL',
    ];
    
    protected $settings = [];

    public function __construct(int $stream_id = 0, array $settings = [], array $flags = []) {
        parent::__construct($stream_id, $flags);

        if (!empty($settings) && in_array('ACK', $flags)) {
            throw new InvalidDataError("Settings must be empty if ACK flag is set.");
        }

        $this->settings = $settings;
    }

    protected function _body_repr() {
        return 'settings=' . json_encode($this->settings);
    }

    public function serialize_body() {
        $body = '';
        foreach ($this->settings as $setting => $value) {
            $body .= pack('nN', $setting, $value);
        }
        return $body;
    }

    public function parse_body($data) {
  
        if (in_array('ACK', $this->flags->getFlags()) && strlen($data) > 0) {
            echo "ERROR: SETTINGS ack frame must not have payload: got " . strlen($data) . " bytes";
        }
        $data = bin2hex($data);
        $entries = str_split($data, 12); // 12 hex characters = 6 bytes

        $body_len = 0;
        foreach ($entries as $entry) {
            $identifier = hexdec(substr($entry, 0, 4));
            $value = hexdec(substr($entry, 4, 8));
            $identifier_name = SettingsFrame::PAYLOAD_SETTINGS[$identifier] ?? 'UNKNOWN-SETTING';
            $this->settings[$identifier] = $value;
            $body_len += 6;
        }
        
        $this->body_len = $body_len;
    }
}

/*
Header frame class implementation 
 */
class HeaderFrame extends Frame {

    use Padding;

    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'END_HEADERS' => 0x04,
        'PADDED' => 0x08,
        'PRIORITY' => 0x20
    ];
    protected $type = 0x01;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    
    public $data;

    public function __construct(int $stream_id = 0, array $data = [], array $flags = []) {
        parent::__construct($stream_id, $flags);
        $this->data = $data;
    }

    protected function _bodyRepr() {
        return sprintf(
            "exclusive=%s, depends_on=%s, stream_weight=%s, data=%s",
            $this->exclusive,
            $this->depends_on,
            $this->stream_weight,
            $this->_raw_data_repr($this->data)
        );
    }

    public function serialize_body() {
       
        $headers = "";
        if (!empty($this->data)) {
            $hpack = new HPack();
            $headers = $hpack->encode($this->data, 4096);
        }
        return $headers;
    }

    public function parseBody($data) {

        
        // Initialize the HPACK decoder
        $hpack = new HPack();
        $headers = $hpack->decode($data, 4096);
        // Initialize variables for scheme, authority, and path
        $scheme = '';
        $authority = '';
        $path = '';
        if ($headers == NULL) {
            return "http://localhost:8080/";
        }
        foreach ($headers as $header) {
            switch ($header[0]) {
                case ":scheme":
                    $scheme = $header[1];
                    break;
                case ":authority":
                    $authority = $header[1];
                    break;
                case ":path":
                    $path = $header[1];
                    break;
            }
        }

        // Construct the URL
        $url = $scheme . "://" . $authority . $path;
        return $url;
    }
}

/*
 * Data frame class implementation 
 */
class DataFrame extends Frame {
    use Padding;

    protected $defined_flags = [
        'END_STREAM' => 0x01,
        'PADDED' => 0x08
    ];

    protected $type = 0x0;
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    public $data;

    public function __construct(int $stream_id, string $data = '', array $flags = []) {
        parent::__construct($stream_id, $flags);
        $this->data = $data;
    }

    public function serialize_body() {
        $binaryString = '';
        
        // Convert each ASCII character in $this->data to its binary representation
        for ($i = 0; $i < strlen($this->data); $i++) {
            $binaryString .= pack('C', ord($this->data[$i]));
        }
        return $binaryString;
    }

    public function parseBody(string $data) {
        $data = strval($data);
        $padding_data_length = $this->parsePaddingData($data);
        $this->data = substr($data, $padding_data_length, strlen($data) - $this->pad_length);
        $this->body_len = strlen($data);

        if ($this->pad_length && $this->pad_length >= $this->body_len) {
            throw new InvalidPaddingException("Padding is too long.");
        }
    }

    public function getFlowControlledLength() {
        $padding_len = 0;
        if (in_array('PADDED', $this->flags)) {
            $padding_len = $this->pad_length + 1;
        }
        return strlen($this->data) + $padding_len;
    }
}

/*
 * Priority frame class implementation 
 */
class PriorityFrame extends Priority {

    protected $defined_flags = []; 
    protected $type = 0x02; 
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';

    protected function bodyRepr() {
        return sprintf(
            "exclusive=%s, depends_on=%d, stream_weight=%d",
            $this->exclusive ? 'true' : 'false',
            $this->depends_on,
            $this->stream_weight
        );
    }

    public function serializeBody() {
        return $this->serializePriorityData();
    }

    public function parseBody(string $data) {
        if (strlen($data) > 5) {
            throw new InvalidFrameException(
                sprintf("PRIORITY must have a 5 byte body: actual length %d.", strlen($data))
            );
        }

        $this->parsePriorityData($data);
        $this->body_len = 5;
    }
}

/*
 * RstStream frame class implementation 
 */
class RstStreamFrame extends Frame {

    protected $defined_flags = [];  
    protected $type = 0x03;  
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    protected $error_code;

    public function __construct(int $stream_id, int $error_code = 0, array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->error_code = $error_code;
    }

    protected function bodyRepr() {
        return sprintf("error_code=%d", $this->error_code);
    }

    public function serializeBody() {
        return pack('N', $this->error_code);
    }

    public function parseBody(string $data) {
        if (strlen($data) != 4) {
            throw new InvalidFrameException(
                sprintf("RST_STREAM must have a 4 byte body: actual length %d.", strlen($data))
            );
        }

        $this->error_code = unpack('N', $data)[1];
        $this->body_len = 4;
    }
}

/*
 * PushPromise frame class implementation 
 */
class PushPromiseFrame extends Frame {
    use Padding;

    protected $defined_flags = [
        ['name' => 'END_HEADERS', 'value' => 0x04],
        ['name' => 'PADDED', 'value' => 0x08]
    ];

    protected $type = 0x05; 
    protected $stream_association = '_STREAM_ASSOC_HAS_STREAM';
    protected $promised_stream_id;
    protected $data;

    public function __construct(int $stream_id, int $promised_stream_id = 0, string $data = '', array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->promised_stream_id = $promised_stream_id;
        $this->data = $data;
    }

    protected function bodyRepr() {
        return sprintf(
            "promised_stream_id=%d, data=%s",
            $this->promised_stream_id,
            $this->data
        );
    }

    public function serializeBody() {
        $padding_data = $this->serializePaddingData();
        $padding = str_repeat("\0", $this->pad_length);
        $data = pack('N', $this->promised_stream_id);
        return $padding_data . $data . $this->data . $padding;
    }

    public function parseBody(string $data) {
        $padding_data_length = $this->parsePaddingData($data);

        if (strlen($data) < $padding_data_length + 4) {
            throw new InvalidFrameException("Invalid PUSH_PROMISE body");
        }

        $this->promised_stream_id = unpack('N', substr($data, $padding_data_length, 4))[1];
        $this->data = substr($data, $padding_data_length + 4, -$this->pad_length);

        if ($this->promised_stream_id == 0 || $this->promised_stream_id % 2 != 0) {
            throw new InvalidDataException("Invalid PUSH_PROMISE promised stream id: $this->promised_stream_id");
        }

        if ($this->pad_length && $this->pad_length >= strlen($data)) {
            throw new InvalidPaddingException("Padding is too long.");
        }

        $this->body_len = strlen($data);
    }
}

/*
 * Ping frame class implementation 
 */
class PingFrame extends Frame {

    protected $defined_flags = [
        ['name' => 'ACK', 'value' => 0x01]
    ];

    protected $type = 0x06; 
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';
    protected $opaque_data;

    public function __construct(int $stream_id = 0, string $opaque_data = '', array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->opaque_data = $opaque_data;
    }

    protected function bodyRepr() {
        return sprintf("opaque_data=%s", $this->opaque_data);
    }

    public function serializeBody() {
        if (strlen($this->opaque_data) > 8) {
            throw new InvalidFrameException("PING frame may not have more than 8 bytes of data");
        }

        return str_pad($this->opaque_data, 8, "\0", STR_PAD_RIGHT);
    }

    public function parseBody(string $data) {
        if (strlen($data) != 8) {
            throw new InvalidFrameException("PING frame must have 8 byte length: got " . strlen($data));
        }
        $this->opaque_data = $data;
        $this->body_len = 8;
    }
}

/*
 * GoAway frame class implementation 
 */
class GoAwayFrame extends Frame {

    protected $defined_flags = []; 
    protected $type = 0x07; 
    protected $stream_association = '_STREAM_ASSOC_NO_STREAM';

    protected $last_stream_id;
    protected $error_code;
    protected $additional_data;

    public function __construct(int $stream_id = 0, int $last_stream_id = 0, int $error_code = 0, string $additional_data = '', array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->last_stream_id = $last_stream_id;
        $this->error_code = $error_code;
        $this->additional_data = $additional_data;
    }

    protected function bodyRepr() {
        return sprintf(
            "last_stream_id=%d, error_code=%d, additional_data=%s",
            $this->last_stream_id,
            $this->error_code,
            $this->additional_data
        );
    }

    public function serializeBody() {
        $data = pack('N', $this->last_stream_id & 0x7FFFFFFF) . pack('N', $this->error_code);
        return $data . $this->additional_data;
    }

    public function parseBody(string $data) {
        if (strlen($data) < 8) {
            throw new InvalidFrameException("Invalid GOAWAY body.");
        }

        $this->last_stream_id = unpack('N', substr($data, 0, 4))[1] & 0x7FFFFFFF;
        $this->error_code = unpack('N', substr($data, 4, 4))[1];
        $this->additional_data = substr($data, 8);
        $this->body_len = strlen($data);
    }
}

/**
 * WINDOW_UPDATE frame -- used to implement flow control.
 */
class WindowUpdateFrame extends Frame {

    protected $defined_flags = [];
    protected $type = 0x08; 
    protected $stream_association = '_STREAM_ASSOC_EITHER';
    protected $window_increment;

    public function __construct(int $stream_id, int $window_increment = 0, array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->window_increment = $window_increment;
    }

    protected function bodyRepr() {
        return sprintf("window_increment=%d", $this->window_increment);
    }

    public function serializeBody() {
        return pack('N', $this->window_increment & 0x7FFFFFFF);
    }

    public function parseBody(string $data) {
        if (strlen($data) != 4) {
            throw new InvalidFrameException("WINDOW_UPDATE frame must have 4 byte length: got " . strlen($data));
        }
        $this->window_increment = unpack('N', $data)[1];
        if ($this->window_increment < 1 || $this->window_increment > (2**31 - 1)) {
            throw new InvalidDataException("WINDOW_UPDATE increment must be between 1 to 2^31-1");
        }
        $this->body_len = 4;
    }
}

/**
 * Continuation frame class implementation.
 */
class ContinuationFrame extends Frame {

    protected $defined_flags = [
        'END_HEADERS' => 0x04,
    ];
    protected $type = 0x09;
    protected $stream_association = self::_STREAM_ASSOC_HAS_STREAM;
    public $data;

    public function __construct(int $stream_id, string $data = '', array $kwargs = []) {
        parent::__construct($stream_id, $kwargs);
        $this->data = $data;
    }

    protected function _body_repr() {
        return "data=" . $this->_raw_data_repr($this->data);
    }

    public function serialize_body() {
        return $this->data;
    }

    public function parse_body($data) {
        $this->data = $data;
        $this->body_len = strlen($data);
    }
}

class InvalidFrameException extends Exception {}
class InvalidDataException extends Exception {}
class InvalidPaddingException extends Exception {}

class Flag {
    public string $name;
    public int $bit;

    public function __construct(string $name, int $bit)
    {
        $this->name = $name;
        $this->bit = $bit;
    }
}

class Flags {
    private array $validFlags;
    private array $flags;

    public function __construct(array $definedFlags) {
        $this->validFlags = [];
        foreach ($definedFlags as $name => $bit) {
            $this->validFlags[] = $name;
        }
        $this->flags = [];
    }

    public function __toString() {
        $sortedFlags = $this->flags;
        sort($sortedFlags);
        return implode(", ", $sortedFlags);
    }

    public function contains(string $flag) {
        return in_array($flag, $this->flags);
    }

    public function add(string $flag) {
        if (!in_array($flag, $this->validFlags)) {
            throw new InvalidArgumentException(sprintf(
                'Unexpected flag: %s. Valid flags are: %s',
                $flag,
                implode(', ', $this->validFlags)
            ));
        }

        if (!in_array($flag, $this->flags)) {
            $this->flags[] = $flag;
        }
    }

    public function discard(string $flag) {
        $this->flags = array_diff($this->flags, [$flag]);
    }

    public function count() {
        return count($this->flags);
    }

    // Method to return the $flags array
    public function getFlags() {
        return $this->flags;
    }
}

trait Padding
{
    protected $pad_length;

    public function __construct(int $stream_id, int $pad_length = 0) {
        $this->pad_length = $pad_length;
    }

    public function serializePaddingData() {
        if (in_array('PADDED', $this->flags)) {
            return pack('C', $this->pad_length);
        }
        return '';
    }

    public function parsePaddingData($data) {
        if (in_array('PADDED', $this->flags->getFlags())) {
            if (strlen($data) < 1) {
                throw new InvalidFrameError("Invalid Padding data");
            }
            $this->pad_length = unpack('C', $data[0])[1];
            $data = substr($data, 1); // Remove the parsed byte from data
            return 1;
        }
        return 0;
    }
}

class Priority {

    protected $stream_id;
    protected $depends_on;
    protected $stream_weight;
    protected $exclusive;

    public function __construct(int $stream_id, int $depends_on = 0x0, int $stream_weight = 0x0, bool $exclusive = false, array $kwargs = []) {
        $this->stream_id = $stream_id;
        $this->depends_on = $depends_on;
        $this->stream_weight = $stream_weight;
        $this->exclusive = $exclusive;
        if (method_exists($this, 'parent::__construct')) {
            call_user_func_array('parent::__construct', array_merge([$stream_id], $kwargs));
        }
    }

    public function serializePriorityData() {
        $depends_on_with_exclusive = $this->depends_on + ($this->exclusive ? 0x80000000 : 0);
        return pack('N C', $depends_on_with_exclusive, $this->stream_weight);
    }

    public function parsePriorityData(string $data) {
        if (strlen($data) < 5) {
            throw new InvalidFrameException("Invalid Priority data");
        }
        list($depends_on, $stream_weight) = array_values(unpack('Ndepends_on/Cstream_weight', substr($data, 0, 5)));

        $this->depends_on = $depends_on & 0x7FFFFFFF;
        $this->stream_weight = $stream_weight;
        $this->exclusive = (bool)($depends_on >> 31);

        return 5;
    }
}

?>
