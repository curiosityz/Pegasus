<?php
/**
 * Parses bck logs to get balance briefs
 */

/**
 * Returns value identified by $val_name by searching $data for ValName="value"
 *
 * @param string $data
 * @param string $val_name
 * @return string
 */
function getVal($data, $val_name)
{
    $pattern = '/'.$val_name.'="([^"]*)"/';
    preg_match($pattern, $data, $matches);
    return $matches[1] ?? '';
}

/**
 * Formats the value to millions with 2 decimal places
 *
 * @param int $val
 * @return string
 */
function formatValue($val)
{
    return round($val / 100 / 1000 / 1000, 2) . 'M';
}

/**
 * Parses file contents specified by file pointer
 *
 * @param string $data
 * @param array $context
 */
function parseFileContents($data, &$context)
{
    // Check for interested patterns
    if (strpos($data, '<ED211') !== false) {
        $stamp = getVal($data, 'LastMovetDate') . " " . getVal($data, 'EndTime');
        echo $stamp . " " . formatValue(getVal($data, 'EnterBal')) . " -> " . formatValue(getVal($data, 'OutBal')) . "<br>";

        if (!isset($context[getVal($data, 'LastMovetDate')]['min'])) {
            $context[getVal($data, 'LastMovetDate')]['min'] = getVal($data, 'EnterBal');
        }
        if (!isset($context[getVal($data, 'LastMovetDate')]['max'])) {
            $context[getVal($data, 'LastMovetDate')]['max'] = getVal($data, 'EnterBal');
        }

        $context[getVal($data, 'LastMovetDate')]['min'] = min(
            $context[getVal($data, 'LastMovetDate')]['min'],
            getVal($data, 'EnterBal'),
            getVal($data, 'OutBal')
        );
        $context[getVal($data, 'LastMovetDate')]['max'] = max(
            $context[getVal($data, 'LastMovetDate')]['max'],
            getVal($data, 'EnterBal'),
            getVal($data, 'OutBal')
        );
    }
}

/**
 * Parses a single zip file - extracts files and send it to other parsers
 *
 * @param string $fname
 * @param array $context
 */
function parseZip($fname, &$context)
{
    $zip = new ZipArchive;

    // Open the archive
    if ($zip->open($fname) === true) {
        // Iterate the archive files array and display the filename of each one
        for ($i = 0; $i < $zip->numFiles; $i++) {
            // Read file contents into memory
            $data = $zip->getFromIndex($i);

            // Parse contents
            if ($data !== false) {
                parseFileContents($data, $context);
            }
        }
    } else {
        echo "Failed to open {$fname}";
    }

    $zip->close();
}

set_time_limit(600);

// Results array context
$context = [];

foreach (glob("./bck_logs/*/*.zip") as $fname) {
    parseZip($fname, $context);
}

echo "<br><hr>";
foreach ($context as $key => $val) {
    echo $key . " -> " . formatValue($val['min']) . " - " . formatValue($val['max']) . "<br>";
}
