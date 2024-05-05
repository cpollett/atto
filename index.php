<?php
namespace seekquarry\atto;

if (php_sapi_name() != 'cli') {
    exit();
} else if (empty($argv[1])) {
    echo "Usage:\n";
    echo "  php index.php example_number_you_would_like_to_run\n";
    echo "For example,\n";
    echo "  php index.php 01\n";
    echo "would run the first example in the examples folder\n";
    exit();
}
$examples = glob("examples/[0-9][0-9]*",GLOB_ONLYDIR);
foreach ($examples as $example) {
    if (str_contains($example, $argv[1])) {
        define("seekquarry\\atto\\RUN", true);
        chdir($example);
        require("index.php");
        exit();
    }
}
