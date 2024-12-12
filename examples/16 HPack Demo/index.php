<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;
use seekquarry\atto\HPack;

$test = new WebSite();
$hpack = new HPack();

$test->get('/', function() use ($hpack) {
    echo renderHPackDemoPage();
});

$test->post('/', function() use ($hpack) {
    $headersInput = [];
    $result = [];

    $result['output'] = '';
    $result['debug'] = '';
    
    if (isset($_POST['encode']) && !empty(trim($_POST['headers_encode']))) {
        $headersInput = explode("\n", trim($_POST['headers_encode']));
        $headersArray = [];

        try {
            foreach ($headersInput as $header) {
                if (!preg_match("/^\['(.+)',\s*'(.+)'\]$/", 
                    trim($header), $matches)) {
                    throw new Exception(
                        'Invalid header format. 
                         Use "[\'Header-Name\', \'Header-Value\']".');
                }
                $name = $matches[1];
                $value = $matches[2];
                $headersArray[] = [trim($name), trim($value)];
            }
            $encodedHeaders = $hpack->encode($headersArray);
            $result = [
                'action' => 'encode',
                'input' => $headersInput,
                'output' => bin2hex($encodedHeaders),
                'debug' => $hpack->getDebugOutput() 
            ];
        } catch (Exception $e) {
            $result = ['error' => $e->getMessage()];
        }
    }
    elseif (isset($_POST['decode']) && 
        !empty(trim($_POST['headers_decode']))) {
        $hexInput = trim($_POST['headers_decode']);
        try {
            $decodedHeaders = $hpack->decodeHeaderBlockFragment($hexInput);
            $result = [
                'action' => 'decode',
                'input' => [$hexInput],
                'output' => json_encode($decodedHeaders, JSON_PRETTY_PRINT),
                'debug' => $hpack->getDebugOutput() 
            ];
        } catch (Exception $e) {
            $result = ['error' => $e->getMessage()];
        }
    } else {
        $result = ['error' => 'Please provide headers to encode or decode.'];
    }
    echo renderHPackDemoPage($result);
});

function renderHPackDemoPage($result = null) {
    $outputHTML = '';

    if ($result) {
        if (isset($result['error'])) {
            $outputHTML .= '<div class="error">' . 
                htmlspecialchars($result['error']) . '</div>';
        } else {
            $outputHTML .= '<h3>Result of ' . 
                ucfirst($result['action']) . '</h3>';
            $outputHTML .= '<pre><strong>Input:</strong><br>' . 
                htmlspecialchars(implode("\n", $result['input'])) . '</pre>';
            $outputHTML .= '<pre><strong>Output:</strong><br>' . 
                htmlspecialchars($result['output']) . '</pre>';
            if (isset($result['debug'])) {
                $outputHTML .= '<pre><strong>Debug Info:</strong><br>' . 
                    htmlspecialchars($result['debug']) . '</pre>';
            }
        }
    }
    $encodeInput = "[':authority', 'localhost:8080']\n[':method', 'GET']\n[':path', '/']\n[':scheme', 'https']\n['accept', 'text/html']";
    $decodeInput = "8286418aa0e41d139d09b8f01e07847a8825b650c3cbbab87f53032a2f2a";
    return '
    <!DOCTYPE html>
    <html>
    <head>
        <title>HPack Encoder/Decoder Demo</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 20px;
            }
            h1 {
                text-align: center;
                color: #333;
            }
            .container {
                display: flex;
                justify-content: space-between;
                gap: 20px;
            }
            .box {
                width: 48%;
                padding: 20px;
                background-color: #fff;
                border: 1px solid #ddd;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                border-radius: 8px;
            }
            textarea {
                width: 100%;
                height: 150px;
                padding: 10px;
                border-radius: 5px;
                border: 1px solid #ccc;
                margin-bottom: 15px;
                font-family: monospace;
                font-size: 14px;
                background-color: #f0f0f0; /* grey background */
            }
            input[type="submit"] {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 14px;
                cursor: pointer;
                border-radius: 5px;
                transition: background-color 0.3s;
            }
            input[type="submit"]:hover {
                background-color: #45a049;
            }
            .result-box {
                margin-top: 20px;
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                padding: 10px;
                border-radius: 5px;
            }
            .error {
                color: red;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>HPack Encoder/Decoder Demo</h1>
        <form method="post">
            <div class="container">
                <!-- Encode Section -->
                <div class="box">
                    <h2>Encode</h2>
                    <label for="headers_encode">Enter Headers (Format: "Header-Name: Header-Value" per line):</label>
                    <textarea id="headers_encode" name="headers_encode">' . htmlspecialchars($encodeInput) . '</textarea>
                    <input type="submit" name="encode" value="Encode">
                </div>

                <!-- Decode Section -->
                <div class="box">
                    <h2>Decode</h2>
                    <label for="headers_decode">Enter Encoded Headers (Hex format):</label>
                    <textarea id="headers_decode" name="headers_decode">' . htmlspecialchars($decodeInput) . '</textarea>
                    <input type="submit" name="decode" value="Decode">
                </div>
            </div>
        </form>

        ' . $outputHTML . '
    </body>
    </html>';
}

if($test->isCli()) {
    $test->listen(8000);
} else {
    $test->process();
}
