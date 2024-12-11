<?php

/*
    gen.php

*/

// Load settings from configuration file
$configFile = './config/settings.json';
if (!file_exists($configFile)) {
    die("Configuration file not found.");
}

$configContent = file_get_contents($configFile);
$g_Settings = json_decode($configContent, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error parsing configuration file.");
}

function chk_account($s)
{
    $SM = "71371371371371371371371";

    $l = 0;
    for ($i = 0; $i <= 23; $i++) {
        $l = $l + intval(substr(strval(intval($s[$i]) * intval($SM[$i])), -1));
    }

    return substr($l, -1) == "0";
}

// account key check routines
function chk_corr($corr, $bic)
{
    return chk_account("0" . substr($bic, 4, 2) . $corr);
}

function chk_rs($rs, $bic)
{
    return chk_account(substr($bic, -3) . $rs);
}

/*
    Check entries for a single acc and adds it to accs array

    [0] => 044030858     bic
    [1] => 30101810800000000858 corr
    [2] => 40817810450020276802 acc
    [3] => 000000000000          bank inn
    [4] => ������� ���� ����������     name
    [5] => 200                          min_k
    [6] => 450                          max_k
    [7] => 803                          total_max_k
*/
function ParseAddAcc($acc, &$arr, &$arr_dist, $fname)
{
    // Normalize chars case for 4
    $name = mb_convert_case($acc[4], MB_CASE_TITLE, "CP-1251");
    if ($name != $acc[4]) {
        $acc[4] = $name;
    }

    // Check bic & corr last 3 digits
    if (substr($acc[0], -3) != substr($acc[1], -3)) {
        echo "<b><font color='red'>ERR: bic-corr mismatch\r\n</font></b>";
        print_r($acc);
        echo "\r\n";
        return;
    }

    // Check for 810 acc
    if (substr($acc[2], 5, 3) != '810') {
        echo "<b><font color='red'>ERR: NOT a RUR account\r\n</font></b>";
        print_r($acc);
        echo "\r\n";
        return;
    }

    // Account key check
    if (chk_corr($acc[1], $acc[0]) !== TRUE) {
        echo "<b><font color='red'>ERR: CORR {$acc[1]} account key check failed\r\n</font></b>";
        print_r($acc);
        echo "\r\n";
        return;
    }
    if (chk_rs($acc[2], $acc[0]) !== TRUE) {
        echo "<b><font color='red'>ERR: ACC {$acc[2]} account key check failed\r\n</font></b>";
        print_r($acc);
        echo "\r\n";
        return;
    }

    // Check name for forbidden chars
    for ($i = 0; $i < strlen($acc[4]); $i++) {
        if (ord($acc[4][$i]) == 160) {
            $acc[4][$i] = ' ';
        }
    }
    for ($i = 0; $i < strlen($acc[4]); $i++) {
        if ((ord($acc[4][$i]) < 32) || (ord($acc[4][$i]) == 160)) {
            echo "<b><font color='red'>ERR: rec contains bogus char at name at pos {$i}\r\n</font></b>";
            print_r($acc);
            echo "\r\n";
            return;
        }
    }

    // Convert K to cents
    $acc[5] = $acc[5] * 100000;
    $acc[6] = $acc[6] * 100000;
    $acc[7] = $acc[7] * 100000;

    // Calc hash for unique check
    $hash = md5($acc[2] . $acc[4]);

    // Add to resulting array
    if (!isset($arr[$hash])) {
        $arr[$hash] = $acc;

        // Save fname-related stats
        $arr_dist[basename($fname)] += $acc[7] / 100000;
    }
}

/*
    Scans .\t_accs for all files and parse it as t-accs
    ���/��������/����/���/����������/����������� ����� � �������/������������ �����/������������ ������
*/
function EnumTAccs(&$arr, &$arr_dist)
{
    foreach (glob("./t_accs/*.*") as $fname) {
        echo "Processing {$fname} ";

        $fdata = file_get_contents($fname);
        echo "flen " . strval(strlen($fdata)) . "\r\n";

        $lines = explode("\n", $fdata);
        foreach ($lines as $line) {
            $s = trim($line);
            if (strlen($s) > 5) {
                $acc = explode('/', $s);
                if (count($acc) == 8) {
                    ParseAddAcc($acc, $arr, $arr_dist, $fname);
                }
            }
        }
    }
}

/*
    Checks tag name to be one of EdNo counter contains:
    EDnnn & Packetxxx
*/
function IsEdnoTag($tagname)
{
    $res = FALSE;

    do {
        $ed = substr($tagname, 0, 2);
        $packet = substr($tagname, 0, 6);

        if (($ed != 'ED') && ($packet != 'PACKET')) {
            return FALSE;
        }

        if ($ed == 'ED') {
            // Check to be a number
            $ed_n = substr($tagname, 2);
            if ($ed_n != strval(intval($ed_n))) {
                return FALSE;
            }
        }

        // No exit -> ok
        $res = TRUE;
    } while (FALSE);

    return $res;
}

/*
    Enum files in curday_inp dir for EdNos and AccDocNos
    to exclude it in generation
*/
function EnumCurday(&$edno, &$accdocno)
{
    foreach (glob("./curday_inp/*.*") as $fname) {
        echo "Processing curday {$fname} ";

        $fdata = file_get_contents($fname);
        echo "flen " . strval(strlen($fdata)) . "\r\n";

        $p = xml_parser_create();
        xml_parse_into_struct($p, $fdata, $vals, $index);
        xml_parser_free($p);

        foreach ($vals as $key => $value) {
            // Edno numbers      EDnnn & Packetxxx
            if (isset($value['attributes']['EDNO'])) {
                // Check tag name to match correct patterns
                if (IsEdnoTag($value['tag'])) {
                    $edno[] = $value['attributes']['EDNO'];
                }
            }

            // Accdoc numbers
            if (($value['tag'] == 'ACCDOC') && (isset($value['attributes']['ACCDOCNO']))) {
                $accdocno[] = $value['attributes']['ACCDOCNO'];
            }
        }
    }

    // Post-process numbers
    echo "EdNo: min=" . strval(min($edno)) . " max=" . strval(max($edno)) . " count_raw=" . strval(count($edno)) . " count_uniq=" . strval(count(array_unique($edno))) . "\r\n";
    echo "AccDocNo: min=" . strval(min($accdocno)) . " max=" . strval(max($accdocno)) . " count_raw=" . strval(count($accdocno)) . " count_uniq=" . strval(count(array_unique($accdocno))) . "\r\n";
}

/*
    Enums src_accs dir for ED101 packet epd plain files
    and extract unique payer's information to be used later

    [0] => 044030858     bic    (ALL THE SAME FOR ALL)
    [1] => 30101810800000000858 corr  (ALL THE SAME FOR ALL)
    [2] => 40817810450020276802 acc
    [3] => 000000000000          bank inn
    [4] => ������� ���� ����������     name

    [10] => KPP
*/
function EnumPayers(&$pyr, &$accdoc_numbers, &$edno_numbers)
{
    foreach (glob("./src_accs/*.*") as $fname) {
        $fdata = file_get_contents($fname);

        $p = xml_parser_create();
        xml_parse_into_struct($p, $fdata, $vals, $index);
        xml_parser_free($p);

        foreach ($vals as $key => $value) {
            // Edno numbers
            if (($value['tag'] == 'ED101') && (isset($value['attributes']['EDNO']))) {
                $edno_numbers[] = $value['attributes']['EDNO'];
            }

            // Accdoc numbers
            if (($value['tag'] == 'ACCDOC') && (isset($value['attributes']['ACCDOCNO']))) {
                $accdoc_numbers[] = $value['attributes']['ACCDOCNO'];
            }

            // Payers
            if (($value['tag'] == 'PAYER') && (isset($value['attributes']['PERSONALACC']))) {
                do {
                    // Calc array key to maintain unique
                    $hash_key = md5($value['attributes']['PERSONALACC'] . $value['attributes']['INN'] . $vals[$key + 1]['value']);

                    // Prepare name for parsing
                    $pname = mb_convert_encoding($vals[$key + 1]['value'], 'CP-1251', 'UTF-8');

                    $pname = str_replace('&', '&amp;', $pname);
                    $pname = str_replace('"', '&quot;', $pname);
                    $pname = str_replace("'", '&quot;', $pname);
                    $pname = str_replace('<', '&lt;', $pname);
                    $pname = str_replace('>', '&gt;', $pname);

                    if (strpos($pname, '���') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '����') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '��') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '����') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '���') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '��') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '������') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '+') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '!') !== FALSE) {
                        break;
                    }
                    if (strpos($pname, '�������') !== FALSE) {
                        break;
                    }

                    $pyr[$hash_key] = array(
                        2 => $value['attributes']['PERSONALACC'],
                        3 => $value['attributes']['INN'],
                        4 => $pname,
                        10 => $value['attributes']['KPP']
                    );
                } while (FALSE);
            }
        }
    }
}

/*
    Get a single tacc record according to its limits
    Updates tacc's internal state, do its removal from array if no more limits left for it
*/
function GetTAccDetails(&$tacc_arr, &$tacc)
{
    // Get a random value from array
    $key = array_rand($tacc_arr);

    // Gen target sum according to settings
    if ($tacc_arr[$key][7] <= $tacc_arr[$key][6]) {
        // Left is less than max limit, use all left value
        $t_sum = $tacc_arr[$key][7];
    } else {
        // Else gen rnd value in limits
        $t_sum = rand($tacc_arr[$key][5], $tacc_arr[$key][6]);
    }

    // Store result
    $tacc = $tacc_arr[$key];
    $tacc['tsum'] = $t_sum;

    // Modify limits value
    $tacc_arr[$key][7] = bcsub($tacc_arr[$key][7], $t_sum);

    // Check if limits done -> remove tacc
    if ($tacc_arr[$key][7] <= 2000) {
        unset($tacc_arr[$key]);
    }
}

/*
    Generates some date in near past, at workdays
    Returns text buffer
    DD.MM.YYYY format
*/
function GenDate()
{
    while (TRUE) {
        // Make now
        $date = new DateTime();

        // Sub rnd
        date_sub($date, new DateInterval('P' . strval(rand(60, 1000)) . 'D'));

        // Check weekdate (w): 0 (for Sunday) through 6 (for Saturday)
        $wd = $date->format('w');

        if (($wd != '0') && ($wd != '6')) {
            break;
        }
    }

    return $date->format('d.m.Y');
}

/*
    Calculates 18% sales tax, returns RRRRR.CC formatted value
*/
function CalcSalesTax($tsum)
{
    $tax_val = ($tsum - ($tsum / 1.18)) / 100;

    $formats = array('%u-%02u', '%u.%02u');
    $format = $formats[array_rand($formats)];

    return sprintf($format, $tax_val, ($tax_val - (int)$tax_val) * 100);
}

/*
    Generates payment's purpose using template algo. Calculates sales tax.
*/
function GenPurpose($tsum)
{
    global $g_Settings;

    $res = '������ �� ';
    $arr = array(
        '������ �����', '��������', '�������', '������ ��� �����',
        '������', '�������', '�������� �����', '�����', '������', '�������',
        '��������� ���������', '������', '����', '������', '���������� ���������',
        '��������', '������', '�������� ��������', '����������� �������', '������� �������',
        '������� �������-��������', '������', '�������� ��������������', '������� � ����������� ���������',
        '���������', '������������',
        '������ �������', '��������� ���������',
        '��������������', '������ ��������������', '�������������� ������',
        '������� ���������������� ����������', '������������ �������',
        '����- � ��������������', '���������� ��������', '������������ ����������', '������������������ �����������',
        '������� �����������', '������� ������� ������������', '�����',
        '�������', '�������',
        '���������������� � ������ �������', '�������'
    );
    $res .= $arr[array_rand($arr)];

    $res .= " �� ";

    $arr = array('����', '���������', '��������', '���������', '��������', '�������', '�����������', '��������');
    $res .= $arr[array_rand($arr)];

    $res .= " " . strval(rand(1, 999)) . "/" . strval(rand(1, 999));

    $res .= " �� " . GenDate();

    // Check calc_sales_tax
    if ($g_Settings['calc_sales_tax'] === TRUE) {
        // For jur - use sales tax
        $arr = array(' � �.�. ��� 18% - ', ' ���(18%) ');
        $res .= $arr[array_rand($arr)];

        $res .= CalcSalesTax($tsum);
    } else {
        // For fiz - no sales tax
        $arr = array(' ��� �� ����������', '��� ������ (���)', ', ��� ������ (���).', ' ��� �� ����������.');
        $res .= $arr[array_rand($arr)];
    }

    return $res;
}

function GetEdNo()
{
    global $g_Settings;

    // Check if $g_Settings['cur_edno'] inited
    if (!isset($g_Settings['cur_edno'])) {
        $g_Settings['cur_edno'] = $g_Settings['starting_edno'];
    }

    while (in_array($g_Settings['cur_edno'], $g_Settings['curday_edno']) === TRUE) {
        $g_Settings['cur_edno'] += 1;
    }

    $g_Settings['cur_edno'] += 1;

    return $g_Settings['cur_edno'] - 1;
}

function GetAccDocNo()
{
    global $g_Settings;

    // Check if inited
    if (!isset($g_Settings['cur_accdocno'])) {
        $g_Settings['cur_accdocno'] = $g_Settings['starting_accdoc'];
    }

    while (in_array($g_Settings['cur_accdocno'], $g_Settings['curday_accdoc']) === TRUE) {
        $g_Settings['cur_accdocno'] += 1;
    }

    $g_Settings['cur_accdocno'] += 1;

    return $g_Settings['cur_accdocno'] - 1;
}

/*
    Selects random values from src & target accs, fills ed101 details,
    updates taccs internal state

    $g_Settings['cur_edno'] contains current (last used EdNo number)
    $g_Settings['curday_edno'], $g_Settings['curday_accdoc'] contains inited values used for no generation
*/
function GenPayments(&$tacc_arr, $payer_arr, &$gen_count, &$gen_sum)
{
    global $g_Settings;

    // Resulting string
    $s = '';

    while ((count($tacc_arr) > 0) && ($gen_sum < $g_Settings['target_sum'] * 100000)) {
        $ed_no = GetEdNo();
        $accdoc_no = GetAccDocNo();

        // Get tacc
        $tacc = array();
        GetTAccDetails($tacc_arr, $tacc);

        // Get src-acc
        $payer = $payer_arr[array_rand($payer_arr)];

        // Set payer's KPP, if set
        $payer_kpp = " KPP=\"0\"";
        if ((isset($payer[10])) && ($payer[10] != '') && ($payer[10] != '0')) {
            $payer_kpp = " KPP=\"{$payer[10]}\"";
        }

        // Absent payer's INN
        if ($payer[3] == '') {
            $payer[3] = "0";
        }

        // Append payment
        $s .= "<ED101 ChargeOffDate=\"{$g_Settings['date']}\" EDAuthor=\"{$g_Settings['edauthor']}\" EDDate=\"{$g_Settings['date']}\" EDNo=\"{$ed_no}\" Priority=\"5\" ReceiptDate=\"{$g_Settings['date']}\" Sum=\"" . strval($tacc['tsum']) . "\" TransKind=\"01\" xmlns=\"urn:cbr-ru:ed:v2.0\">" .
            "<AccDoc AccDocDate=\"{$g_Settings['date']}\" AccDocNo=\"{$accdoc_no}\"/>" .
            "<Payer PersonalAcc=\"{$payer[2]}\" INN=\"{$payer[3]}\"{$payer_kpp}>" .
            "<Name>{$payer[4]}</Name>" .
            "<Bank BIC=\"{$g_Settings['source_bik']}\" CorrespAcc=\"{$g_Settings['source_corr']}\"/>" .
            "</Payer>" .
            "<Payee PersonalAcc=\"{$tacc[2]}\" INN=\"{$tacc[3]}\">" .
            "<Name>{$tacc[4]}</Name>" .
            "<Bank BIC=\"{$tacc[0]}\" CorrespAcc=\"{$tacc[1]}\"/>" .
            "</Payee>" .
            "<Purpose>" . GenPurpose($tacc['tsum']) . "</Purpose>" .
            "<DepartmentalInfo/>" .
            "</ED101>";

        // Modify results
        $gen_count++;
        $gen_sum = bcadd($gen_sum, $tacc['tsum']);
    }

    // Some checks
    if ($gen_sum < $g_Settings['target_sum'] * 100000) {
        echo "WARN: generated sum only " . strval(round($gen_sum / 100000, 0)) . "K of {$g_Settings['target_sum']}K requested, out of t-accs\r\n";
    }

    if (count($tacc_arr) > 0) {
        $l_sum = 0;
        foreach ($tacc_arr as $ta) {
            $l_sum += $ta[7];
        }
        echo "NOTE: left " . strval(count($tacc_arr)) . " taccs for " . strval(round($l_sum / 100000, 0)) . "K\r\n";
    }

    return $s;
}

/*
    Generates output filename based on the first edno
*/
function GetOutFilename($first_edno)
{
    return "res.xml";
}

echo "<pre>Gen\r\n";

bcscale(0);

// Read contexts of t-acc files
$tacc_arr = array();
$arr_dist = array();
EnumTAccs($tacc_arr, $arr_dist);

$acc_count = count($tacc_arr);

// Calc max sum
$acc_maxsum_total = 0;
foreach ($tacc_arr as $acc) {
    $acc_maxsum_total += $acc[7];
}

echo "<b>Total {$acc_count} accs for " . strval(round($acc_maxsum_total / 100000, 0)) . "K</b>\r\n\r\n";

foreach ($arr_dist as $key => $val) {
    echo "{$key} -> {$val}\r\n";
}

// Prepare payer info
$payer_arr = array();
$accdoc_numbers = array();
$edno_numbers = array();
EnumPayers($payer_arr, $accdoc_numbers, $edno_numbers);

echo "<b>Unique payers amount " . strval(count($payer_arr)) . "</b>\r\n\r\n";

$min_accdoc = min($accdoc_numbers);
$max_accdoc = max($accdoc_numbers);
echo "AccDocNo range found [{$min_accdoc}-{$max_accdoc}]\r\n\r\n";
if ($max_accdoc >= $g_Settings['starting_accdoc']) {
    echo "<font color='red'><b>WARN: found max accdocno is greater than starting_accdoc, numbers will be OVERLAPPED!</b></font>\r\n";
}

$min_edno = min($edno_numbers);
$max_edno = max($edno_numbers);
echo "EdNo range found [{$min_edno}-{$max_edno}]\r\n\r\n";
if ($max_edno >= $g_Settings['starting_edno']) {
    echo "<font color='red'><b>WARN: found max edno is greater than starting_edno, numbers will be OVERLAPPED!</b></font>\r\n";
}

// Process curday input files to prevent number overlapping for edno & accdocno
$g_Settings['curday_edno'] = array();
$g_Settings['curday_accdoc'] = array();
EnumCurday($g_Settings['curday_edno'], $g_Settings['curday_accdoc']);

// Do gen internal payment strings
$gen_count = 0;
$gen_sum = 0;
$first_edno = GetEdNo();
$payments = GenPayments($tacc_arr, $payer_arr, $gen_count, $gen_sum);

echo "Generated {$gen_count} payments for sum " . strval(round($gen_sum / 100000, 0)) . "K\r\n";

// Prepare packet headers
$packet = "<?xml version=\"1.0\" encoding=\"WINDOWS-1251\"?>
<PacketEPD EDAuthor=\"{$g_Settings['edauthor']}\" EDDate=\"{$g_Settings['date']}\" EDNo=\"{$first_edno}\" EDQuantity=\"{$gen_count}\" Sum=\"" . strval($gen_sum) . "\" SystemCode=\"{$g_Settings['systemcode']}\" xmlns=\"urn:cbr-ru:ed:v2.0\">
" . $payments . "
</PacketEPD>
";

// Store result
file_put_contents(GetOutFilename($first_edno), $packet);

echo "Resulting file " . GetOutFilename($first_edno) . " sha1 " . sha1($packet) . " len " . strval(strlen($packet)) . " b\r\n";

?>
