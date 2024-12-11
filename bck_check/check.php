<?php
/*
    Parses bck logs to get balance briefs
*/

/**
 * Returns value identified by $val_name by searching $data for ValName="value"
 *
 * @param string $data
 * @param string $val_name
 * @return string
 */
function GetVal($data, $val_name)
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
function fmt($val)
{
    return round($val / 100 / 1000 / 1000, 2).'M';
}

/**
 * Parses file contents, specified by file pointer
 *
 * @param resource $fp
 * @param array $context
 */
function ParseFileContentsByFP($fp, &$context)
{
    // read all file's contents into var
    $data = stream_get_contents($fp);

    // check for interested patterns
    if (strpos($data, '<ED211') !== FALSE) {
        $stamp = GetVal($data, 'LastMovetDate')." ".GetVal($data, 'EndTime');
        echo $stamp." ".fmt(GetVal($data, 'EnterBal'))." -> ".fmt(GetVal($data, 'OutBal'))."<br>";

        if ($context[GetVal($data, 'LastMovetDate')]['min'] == 0) {
            $context[GetVal($data, 'LastMovetDate')]['min'] = GetVal($data, 'EnterBal');
        }
        if ($context[GetVal($data, 'LastMovetDate')]['max'] == 0) {
            $context[GetVal($data, 'LastMovetDate')]['max'] = GetVal($data, 'EnterBal');
        }

        $context[GetVal($data, 'LastMovetDate')]['min'] = min($context[GetVal($data, 'LastMovetDate')]['min'], GetVal($data, 'EnterBal'), GetVal($data, 'OutBal'));
        $context[GetVal($data, 'LastMovetDate')]['max'] = max($context[GetVal($data, 'LastMovetDate')]['max'], GetVal($data, 'EnterBal'), GetVal($data, 'OutBal'));
    }
}

/**
 * Parses a single zip file - extracts files and send it to other parsers
 *
 * @param string $fname
 * @param array $context
 */
function ParseZip($fname, &$context)
{
    // enum all files in that zip
    $zip = new ZipArchive;
    // open the archive
    if ($zip->open($fname) === TRUE) {
        // iterate the archive files array and display the filename or each one
        for ($i = 0; $i < $zip->numFiles; $i++) {
            // read file contents into memory
            $fp = $zip->getStream($zip->getNameIndex($i));
            // parse contents by file pointer
            if ($fp) {
                ParseFileContentsByFP($fp, $context);
                fclose($fp);
            }
        }
    } else {
        echo "Failed to open {$fname}";
    }
    $zip->close();
}

set_time_limit(600);

// results array context
$context = array();

foreach (glob("./bck_logs/*/*.zip") as $fname) {
    ParseZip($fname, $context);
}

echo "<br><hr>";
foreach ($context as $key => $val) {
    echo $key." -> ".fmt($val['min'])." - ".fmt($val['max'])."<br>";
}
?>
