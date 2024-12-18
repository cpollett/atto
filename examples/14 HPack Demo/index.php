<?php
require '../../src/WebSite.php';

use seekquarry\atto\WebSite;
use seekquarry\atto\HPack;

if (!defined("seekquarry\\atto\\RUN")) {
    exit();
}

$test = new WebSite();
$hpack = new HPack();

$test->get('/', function () use ($hpack) {
    renderDemoPage();
});

$test->post('/', function () use ($hpack) {
    $result = null;
    if (isset($_POST['encode']) && !empty(trim($_POST['headers_encode']))) {
        $headers_input = explode("\n", trim($_POST['headers_encode']));
        $headers_array = [];
        try {
            foreach ($headers_input as $header) {
                if (!preg_match("/^\['(.+)',\s*'(.+)'\]$/", trim($header), 
                    $matches)) {
                    throw new Exception
                    ('Invalid header format. 
                    Use "[\'Header-Name\', \'Header-Value\']".');
                }
                $headers_array[] = [trim($matches[1]), trim($matches[2])];
            }
            $encoded_headers = $hpack->encode($headers_array);
            $result = [
                'action' => 'encode',
                'input' => $headers_input,
                'output' => bin2hex($encoded_headers),
                'debug' => $hpack->getDebugOutput()
            ];
        } catch (Exception $e) {
            $result = ['error' => $e->getMessage()];
        }
    } elseif (isset($_POST['decode']) 
        && !empty(trim($_POST['headers_decode']))) {
        $hex_input = trim($_POST['headers_decode']);
        try {
            $decoded_headers = $hpack->decodeHeaderBlockFragment($hex_input);
            $result = [
                'action' => 'decode',
                'input' => [$hex_input],
                'output' => json_encode($decoded_headers, JSON_PRETTY_PRINT),
                'debug' => $hpack->getDebugOutput()
            ];
        } catch (Exception $e) {
            $result = ['error' => $e->getMessage()];
        }
    } else {
        $result = ['error' => 'Please provide headers to encode or decode.'];
    }
    renderDemoPage($result);
});

function renderDemoPage($result = null)
{
    $encode_input = "[':authority', 'localhost:8080']\n"
                  . "[':method', 'GET']\n"
                  . "[':path', '/']\n"
                  . "[':scheme', 'https']\n"
                  . "['accept', 'text/html']";
    $decode_input = 
        "8286418aa0e41d139d09b8f01e07847a8825b650c3cbbab87f53032a2f2a";
    ?>
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
                background-color: #f0f0f0;
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
                <div class="box">
                    <h2>Encode</h2>
                    <label for="headers_encode">
                        Enter Headers per line
                        (Format: "Header-Name: Header-Value"):
                    </label>
                    <textarea id="headers_encode" 
                    name="headers_encode"><?php echo 
                        htmlspecialchars($encode_input); ?></textarea>
                    <input type="submit" name="encode" value="Encode">
                </div>
                <div class="box">
                    <h2>Decode</h2>
                    <label for="headers_decode">
                        Enter Encoded Headers (Hex format):
                    </label>
                    <textarea id="headers_decode" 
                    name="headers_decode"><?php echo 
                        htmlspecialchars($decode_input); ?></textarea>
                    <input type="submit" name="decode" value="Decode">
                </div>
            </div>
        </form>
        <?php if ($result): ?>
            <div class="result-box">
                <?php if (isset($result['error'])): ?>
                    <div class="error">
                        <?php echo htmlspecialchars($result['error']); ?>
                    </div>
                <?php else: ?>
                    <h3>Result of<?php echo ucfirst($result['action']); ?></h3>
                    <pre><strong>Input:</strong><br><?php echo 
                        htmlspecialchars(implode("\n", $result['input'])); 
                    ?></pre>
                    <pre><strong>Output:</strong><br><?php 
                        echo htmlspecialchars($result['output']); 
                    ?></pre>
                    <?php if (isset($result['debug'])): ?>
                        <pre><strong>Debug Info:</strong><br><?php echo 
                            htmlspecialchars($result['debug']); 
                        ?></pre>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </body>
    </html>
    <?php
}

if ($test->isCli()) {
    $test->listen(8080);
} else {
    $test->process();
}
