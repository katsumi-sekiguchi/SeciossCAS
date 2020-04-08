<?php
$path = ini_get('include_path');
$path =  __DIR__ . PATH_SEPARATOR . $path;
ini_set('include_path', $path);

require_once("Log.php");
require_once("PEAR.php");
require_once("HTTP/Request.php");
require_once("Mail.php");

function getDevice()
{
    if (isset($_SERVER['HTTP_X_SECIOSS_UA']) && $_SERVER['HTTP_X_SECIOSS_UA']) {
        return $_SERVER['HTTP_X_SECIOSS_UA'];
    }
    $agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $device = 'computer';
    if (preg_match('/(DoCoMo|FOMA)/', $agent)) {
        $device = 'mobile_docomo';
    } else if (preg_match('/UP\.Browser\//', $agent)) {
        $device = 'mobile_au';
    } else if (preg_match('/(J-PHONE|Vodafone|SoftBank)/', $agent)) {
        $device = 'mobile_softbank';
    } else if (preg_match('/iPhone/', $agent)) {
        $device = 'smartphone_iphone';
    } else if (preg_match('/iPad/', $agent)) {
        $device = 'tablet_ipad';
    } else if (preg_match('/Android/', $agent) && preg_match('/Mobile/', $agent)) {
        $device = 'smartphone_android';
    } else if (preg_match('/Android/', $agent)) {
        $device = 'tablet_android';
    } else if (preg_match('/Chrome/i', $agent)) {
        $device = 'computer_chrome';
    } else if (preg_match('/Firefox\//i', $agent)) {
        $device = 'computer_firefox';
    } else if (preg_match('/Opera/i', $agent) || preg_match('/OPR/i', $agent)) {
        $device = 'computer_opera';
    } else if (preg_match('/MSIE/i', $agent) || preg_match('/Trident\/7\.0/i', $agent)) {
        $device = 'computer_ie';
    } else if (preg_match('/Edge/i', $agent)) {
        $device = 'computer_edge';
    }

    return $device;
}

function getMemcache($conf)
{
    $memcache = new Memcache;
    if (isset($conf) && isset($conf['memcache_host'])) {
        $hosts = explode(' ', $conf['memcache_host']);
        foreach ($hosts as $host) {
            if (strpos($host, ':') !== false) {
                list($host, $port) = explode(':', $host);
            } else {
                $port = 11211;
            }
            $memcache->addServer($host, $port);
        }
    } else {
        $memcache->addServer('localhost', 11211);
    }

    return $memcache;
}

function sam_auth($url, $username, $password)
{
    $req = new HTTP_Request($url.(strpos($url, '?') === false ? '?' : '&')."userid=$username&ip=".$_SERVER['REMOTE_ADDR'].'&device='.preg_replace('/_.+$/', '', getDevice()));
    $req->setMethod(HTTP_REQUEST_METHOD_POST);
    $req->addPostData('password', $password);
    $res = $req->sendRequest();
    if (PEAR::isError($res) || $req->getResponseCode() != 200) {
        return PEAR::raiseError("Authentication server returns error response".(PEAR::isError($res) ? ": ".$res->getMessage() : ''), -1);
    }

    $xml = simplexml_load_string($req->getResponseBody());
    $rc = intval($xml->code);
    $tokens = null;
    $ticket = null;
    if ($rc < 0) {
        return PEAR::raiseError(strval($xml->message), -1);
    } else if ($rc == 0) {
        $tokens = strval($xml->tokens);
        $ticket = strval($xml->ticket);
    }

    return array($rc, $tokens, $ticket);
}

function logformat($message, $user = '-')
{
    $conf = parse_ini_file(__DIR__ . '/../conf/config.ini', true);
    if (isset($conf['remote_ip']) && isset($_SERVER[$conf['remote_ip']])) {
        $ipaddr = $_SERVER[$conf['remote_ip']];
        if (preg_match('/, *([^, ]+)$/', $ipaddr, $matches)) {
            $ipaddr = $matches[1];
        }
    } else {
        $ipaddr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    }
    if (isset($_SERVER['REMOTE_USER'])) {
        $user = $_SERVER['REMOTE_USER'];
    } else if (isset($_SESSION['username'])) {
        $user = $_SESSION['username'];
    }
    $tenant = preg_match('/@(.+)$/', $user, $matches) ? $matches[1] : '-';
    $agent = preg_replace('/_.+$/', '', getDevice());

    return "$ipaddr; $tenant; $user; $agent; $message";
}

function sendMail($mail, $from, $template, $message)
{
    $conf = parse_ini_file(__DIR__ . '/../conf/config.ini', true);

    if (!$mail || !isset($conf['mail_smtp']) || !preg_match('/^([^:]+):?([0-9]*)$/', $conf['mail_smtp'], $matches) || !file_exists($template)) {
        return 0;
    }

    $charcode = 'ISO-2022-JP-MS';
    $option = array(
        'host' => $matches[1],
        'port' => $matches[2] ? $matches[2] : 25
    );

    mb_internal_encoding('UTF-8');
    $smtp = Mail::factory('smtp', $option);

    $content = file_get_contents($template);
    if (preg_match("/^Subject: *(.*)\n/i", $content, $matches)) {
        $subject = $matches[1];
        $body = preg_replace("/^Subject:.*\n/i", '', $content);
    } else {
        return 0;
    }
    $body = str_replace('%{msg}', $message, $body);

    $headers = array(
        'Content-Type' => 'text/plain; charset="'.$charcode.'"',
        'Content-Transfer-Encoding' => '7bit',
        'To' => $mail,
        'From' => $from ? $from : $mail,
        'Subject' => mb_encode_mimeheader($subject, $charcode)
    );

    return $smtp->send($mail, $headers, $body);
}

?>
