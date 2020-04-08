<?php
$basedir = dirname(dirname(__FILE__));
$path = ini_get('include_path');
$path =  "$basedir/lib" . PATH_SEPARATOR . $path;
ini_set('include_path', $path);

include "$basedir/vendor/autoload.php";

require_once("Secioss/Crypt.php");
require_once("util.php");
require_once("Akita/JOSE/JWS.php");

use Secioss\DLP;
use Secioss\Crypt;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter;
use League\Flysystem\Util\MimeType;
use League\Flysystem\AwsS3v3\AwsS3Adapter;
use GuzzleHttp\Client as GuzzleClient;
use Spatie\FlysystemDropbox\DropboxAdapter;
use Hypweb\Flysystem\GoogleDrive\GoogleDriveAdapter;
use Microsoft\Graph\Graph;
use NicolasBeauvais\FlysystemOneDrive\OneDriveAdapter;
use FlysystemBox\BoxAdapter;

require_once("$basedir/conf/oauth_services.php");

define('CONVCMD', '/usr/bin/unoconv');
define('PDFCMD', '/bin/pdftotext');
define('ALERTTMPL', "$basedir/conf/dlp_alert.mail");

$log = Log::singleton('syslog', LOG_LOCAL5, 'DlpCheck');

function getToken($oauth)
{
    $req = new HTTP_Request($oauth['tokenurl']);
    $req->setMethod(HTTP_REQUEST_METHOD_POST);
    $req->addPostData('client_id', $oauth['clientid']);
    $req->addPostData('client_secret', $oauth['clientsecret']);
    if (isset($oauth['resource'])) {
        $req->addPostData('resource', $oauth['resource']);
    }
    if (isset($oauth['jwt'])) {
        $req->addPostData('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
        $req->addPostData('assertion', $oauth['jwt']);
    } else {
        $req->addPostData('grant_type', 'client_credentials');
    }

    $res = $req->sendRequest();
    if (PEAR::isError($res)) {
        return array(null, "send token request failure: ".$res->getMessage());
    } elseif ($req->getResponseCode() >= 300) {
        return array(null, "bad response code from ".$oauth['tokenurl'].": ".$req->getResponseBody());
    } else {
        $body = $req->getResponseBody();
        $data = json_decode($body, true);
        if (isset($data['access_token'])) {
            $token = $data['access_token'];
        } elseif (isset($data['error'])) {
            return array(null, isset($data['error_description']) ? $data['error_description'] : $data['error']);
        }
    }
    if (!$token) {
        return array(null, "No token");
    } else {
        return array($token, null);
    }
}

function getStorageClient(&$storage)
{
    global $conf;
    global $oauth_services;
    global $log;

    $sclient = null;
    $service_id = $storage['config']['host'][0];
    $service = preg_replace('/0[0-9]+$/', '', $service_id);
    $option = isset($storage['config']['description']) ? $storage['config']['description'][0] : '';
    switch ($service) {
        case 'aws':
            if (!isset($storage['config']['seciossencryptedpassword'])) {
                break;
            }
            preg_match('/region=([^#]+)/', $option, $matches);
            $region = $matches[1];
            $sclient = Aws\S3\S3Client::factory([
                'credentials' => [
                    'key' => $storage['config']['uid'][0],
                    'secret' => Crypt::decrypt($storage['config']['seciossencryptedpassword'][0], Crypt::getSecretKey($conf['keyfile'])),
                ],
                'region' => $region,
                'version' => 'latest'
            ]);
            break;
        case 'box':
            if (!isset($storage['config']['seciossencryptedpassword;x-secret'])) {
                break;
            }
            if (preg_match('/publickeyid=([^#]+)/', $option, $matches)) {
                $publickeyid = $matches[1];
            } else {
                break;
            }
            if (preg_match('/enterpriseid=([^#]+)/', $option, $matches)) {
                $enterpriseid = $matches[1];
            } else {
                break;
            }
            if (preg_match('/passphrase=([^#]+)/', $option, $matches)) {
                $passphrase = $matches[1];
            } else {
                break;
            }
            $data = array(
                'iss' => $storage['config']['uid'][0],
                'sub' => $enterpriseid,
                'box_sub_type' => 'enterprise',
                'aud' => $oauth_services[$service]['tokenurl'],
                'jti' => hash('sha256', $enterpriseid.time()),
                'exp' => time() + 60
            );
            $jws = new Akita_JOSE_JWS('RS256');
            $jws->setPayload($data);
            $jws->setHeaderItem('kid', $publickeyid);
            $privatekey = openssl_pkey_get_private(str_replace("\\n", "\n", $storage['config']['seciosscertificate'][0]), $passphrase);
            $jws->sign($privatekey);
            $oauth_services[$service]['jwt'] = $jws->getTokenString();
            $oauth_services[$service]['clientid'] = $storage['config']['uid'][0];
            $oauth_services[$service]['clientsecret'] = $storage['config']['seciossencryptedpassword;x-secret'][0];
            list($token, $error) = getToken($oauth_services[$service]);
            if (!$token) {
                $log->err("$error($service_id)");
                break;
            }
            $sclient = new GuzzleClient([
                    'headers' => [
                        'Authorization' => "Bearer $token"
                    ],
                ]);
            break;
        case 'dropbox':
            if (!isset($storage['config']['seciossencryptedpassword'])) {
                break;
            }
            $token = Crypt::decrypt($storage['config']['seciossencryptedpassword'][0], Crypt::getSecretKey($conf['keyfile']));
            $sclient = new Spatie\Dropbox\Client($token);
            $storage['recursive'] = true;
            break;
        case 'googleapps':
            if (!isset($storage['config']['seciosscertificate'])) {
                break;
            }
            $sclient = new Google_Client();
            $sclient->setAuthConfig([
                'type' => 'service_account',
                'client_id' => $storage['config']['uid'][0],
                'client_email' => $storage['config']['mail'][0],
                'private_key' => str_replace("\\n", "\n", $storage['config']['seciosscertificate'][0])
            ]);
            $sclient->setScopes([$oauth_services[$service]['scope']]);
            break;
        case 'office365':
            if (!isset($storage['config']['seciossencryptedpassword;x-secret'])) {
                break;
            }
            $oauth_services[$service]['clientid'] = $storage['config']['uid'][0];
            $oauth_services[$service]['clientsecret'] = $storage['config']['seciossencryptedpassword;x-secret'][0];
            $oauth_services[$service]['resource'] = 'https://graph.microsoft.com/';
            if (preg_match('/%{([^}]+)}/', $oauth_services[$service]['tokenurl'], $matches) && isset($storage['config'][$matches[1]])) {
                $oauth_services[$service]['tokenurl'] = str_replace('%{'.$matches[1].'}', $storage['config'][$matches[1]][0], $oauth_services[$service]['tokenurl']);
            }
            list($token, $error) = getToken($oauth_services[$service]);
            if (!$token) {
                $log->err("$error($service_id)");
                break;
            }
            $sclient = new Graph();
            $sclient->setAccessToken($token);
            $storage['recursive'] = true;
            break;
    }

    return $sclient;
}

function getAdapter($storage, $sclient, $target)
{
    global $conf;
    global $oauth_services;
    global $log;

    $adapter = null;
    $service_id = $storage['config']['host'][0];
    $service = preg_replace('/0[0-9]+$/', '', $service_id);
    $option = isset($storage['config']['description']) ? $storage['config']['description'][0] : '';
    switch ($service) {
        case 'aws':
            $adapter = new AwsS3Adapter($sclient, $target, null);
            break;
        case 'box':
            $res = $sclient->request('GET', 'https://api.box.com/2.0/users?filter_term='.urlencode($target));
            $users = json_decode($res->getBody());
            preg_match('/publickeyid=([^#]+)/', $option, $matches);
            $publickeyid = $matches[1];
            preg_match('/enterpriseid=([^#]+)/', $option, $matches);
            $enterpriseid = $matches[1];
            preg_match('/passphrase=([^#]+)/', $option, $matches);
            $passphrase = $matches[1];
            $data = array(
                'iss' => $storage['config']['uid'][0],
                'sub' => $users->entries[0]->id,
                'box_sub_type' => 'user',
                'aud' => $oauth_services[$service]['tokenurl'],
                'jti' => hash('sha256', $enterpriseid.time()),
                'exp' => time() + 60
            );
            $jws = new Akita_JOSE_JWS('RS256');
            $jws->setPayload($data);
            $jws->setHeaderItem('kid', $publickeyid);
            $privatekey = openssl_pkey_get_private(str_replace("\\n", "\n", $storage['config']['seciosscertificate'][0]), $passphrase);
            $jws->sign($privatekey);
            $oauth_services[$service]['jwt'] = $jws->getTokenString();
            $oauth_services[$service]['clientid'] = $storage['config']['uid'][0];
            $oauth_services[$service]['clientsecret'] = $storage['config']['seciossencryptedpassword;x-secret'][0];
            list($token, $error) = getToken($oauth_services[$service]);
            if (!$token) {
                $log->err($error);
                break;
            }
            $bclient = new LaravelBox\LaravelBox($token);
            $adapter = new BoxAdapter($bclient);
            break;
        case 'dropbox':
            $token = Crypt::decrypt($storage['config']['seciossencryptedpassword'][0], Crypt::getSecretKey($conf['keyfile']));
            $members = $sclient->rpcEndpointRequest('team/members/get_info', array('members' => array(array('.tag' => 'email', 'email' => $target))));
            if (!is_array($members) || !count($members) || !isset($members[0]['profile'])) {
                continue;
            }

            $http_client = new GuzzleClient([
                    'headers' => [
                        'Authorization' => "Bearer $token",
                        'Dropbox-API-Select-User' => $members[0]['profile']['team_member_id']
                    ],
                ]);
            $sclient = new Spatie\Dropbox\Client($token, $http_client);
            $adapter = new DropboxAdapter($sclient);
            break;
        case 'googleapps':
            $sclient->setSubject($target);
            $storage_service = new Google_Service_Drive($sclient);
            $adapter = new GoogleDriveAdapter($storage_service, 'root');
            break;
        case 'office365':
            $adapter = new OneDriveAdapter($sclient, 'root', true, $target);
            break;
    }

    return $adapter;
}

$conf = parse_ini_file("$basedir/conf/config.ini", true);
if (empty($conf)) {
    $log->crit("Can't read config.ini");
    exit(1);
}

if (!isset($conf['dlp'])) {
    $log->crit(logformat("Set dlp configuration"));
    exit(1);
}

$datadir = "$basedir/data";
$checked = null;
if (file_exists("$datadir/checked")) {
    $checked = unserialize(file_get_contents("$datadir/checked"));
}
if (!$checked) {
    $checked = array();
}

$tenants = array();
$ldap = @ldap_connect($conf['uri']);
@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
if (!@ldap_bind($ldap, $conf['binddn'], $conf['bindpw'])) {
    $log->err("Can't bind LDAP server(".ldap_error($ldap).")");
    exit(1);
} else {
    $res = @ldap_list($ldap, $conf['basedn'], "(&(objectClass=organization)(seciossAllowedFunction=dlp))", array('o', 'seciossconfigserializeddata', 'mail;x-type-admin', 'mail'));
    if ($res == false) {
        $log->err("Failed to search tenants(".ldap_error($ldap).")");
        exit(1);
    } else {
        $entries = ldap_get_entries($ldap, $res);
        for ($i = 0; $i < $entries['count']; $i++) {
            $data = unserialize($entries[$i]['seciossconfigserializeddata'][0]);
            $tenants[$entries[$i]['o'][0]] = array('encrption' => isset($data['dlp']) ? $data['dlp']['encryption']['services'] : array(), 'detection' => isset($data['dlp']) ? $data['dlp']['detection']['services'] : array(), 'mail' => isset($entries[$i]['mail;x-type-admin']) ? $entries[$i]['mail;x-type-admin'][0] : '', 'from' => isset($entries[$i]['mail']) ? $entries[$i]['mail'][0] : '');
        }
    }
}

$db = null;
if (isset($conf['db_host'])) {
    $db = mysqli_connect($conf['db_host'], $conf['db_user'], $conf['db_password']);
    if (!$db) {
        $log->err("Can't connect db server ".$conf['db_host']);
        exit(1);
    }

    mysqli_select_db($db, $conf['db_name']);
    mysqli_query($db, "SET NAMES utf8");
}

require_once('Secioss/DLP/'.$conf['dlp']['class'].'.php');
$dlp_class = 'Secioss\\DLP\\'.$conf['dlp']['class'];
$dlp = new $dlp_class($conf['dlp']);

$encrypt = null;
if (isset($conf['encrypt'])) {
    require_once('Secioss/Encrypt/'.$conf['encrypt']['class'].'.php');
    $encrypt_class = 'Encrypt_'.$conf['encrypt']['class'];
    $encrypt = new $encrypt_class($conf['encrypt']);
}

foreach ($tenants as $tenant => $tenant_info) {
    $storages = array();
    $res = @ldap_search($ldap, 'ou=Storages,'.($tenant != 'System' ? "o=$tenant," : '').$conf['basedn'], "(&(objectClass=account)(seciossAccountStatus=active))");
    if ($res == false) {
        $log->err("Failed to search storages".($tenant != 'System' ? " of $tenant": '')."(".ldap_error($ldap).")");
        continue;
    } else {
        $entries = ldap_get_entries($ldap, $res);
        for ($i = 0; $i < $entries['count']; $i++) {
            $service_id = $entries[$i]['host'][0];
            $service = preg_replace('/0[0-9]+$/', '', $service_id);
            if (!in_array($service, $tenant_info['detection'])) {
                continue;
            }

            $rootdir = null;
            $encryption = 0;
            $option = isset($entries[$i]['description']) ? $entries[$i]['description'][0] : '';
            if (preg_match('/rootdir=([^#]+)/', $option, $matches)) {
                $rootdir = null;
            }
            if (isset($oauth_services[$service]) && preg_match('/%{([^}]+)}/', $oauth_services[$service]['tokenurl'], $matches) && isset($entries[0][$matches[1]])) {
                $oauth_services[$service]['tokenurl'] = str_replace('%{'.$matches[1].'}', $entries[0][$matches[1]][0], $oauth_services[$service]['tokenurl']);
            }
            if (isset($tenant_info['encryption']) && in_array($service, $tenant_info['encryption'])) {
                $encryption = 1;
            }
            $storages[$service_id] = array('service' => $service, 'config' => $entries[$i], 'rootdir' => $rootdir, 'encryption' => $encryption, 'recursive' => false);
        }
    }

    $alerts = array();
    if (!isset($checked[$tenant])) {
        $checked[$tenant] = array();
    }
    foreach ($storages as $service_id => $storage) {
        $service = $storage['service'];
        $current_time = time();
        $checked_time = isset($checked[$tenant][$service_id]) ? $checked[$tenant][$service_id] : 0;
        $sclient = getStorageClient($storage);
        if (!$sclient) {
            continue;
        }

        $targets = array();
        if ($service == 'aws') {
            preg_match('/bucket=([^#]+)/', $storage['config']['description'][0], $matches);
            $targets = preg_split('/, */', $matches[1]);
        } else {
            $attr = 'mail';
            if ($service == 'googleapps' || $service == 'office365') {
                $pdomain = null;
                switch ($service_id) {
                  case 'googleapps':
                    $host = 'google.com';
                    break;
                  case 'office365':
                    $host = 'onlinemicrosoft.com';
                    break;
                  default:
                    $host = $service_id;
                }
                $res = @ldap_search($ldap, 'ou=Administrators,'.($tenant != 'System' ? "o=$tenant," : '').$conf['basedn'], "(host=$host)", array('o', 'description', 'description;x-attrmap-user'));
                $entries = ldap_get_entries($ldap, $res);
                if ($service == 'googleapps') {
                    if ($entries['count'] && preg_match('/mail=(.+)/', $entries[0]['description'][0], $matches)) {
                        $attr = $matches[1];
                    }
                } elseif ($service == 'office365') {
                    if ($entries['count'] && preg_match('/userattr=uid/', $entries[0]['description'][0])) {
                        $pdomain = $entries[0]['o'][0];
                    }
                }
            }

            $res = @ldap_search($ldap, 'ou=People,'.($tenant != 'System' ? "o=$tenant," : '').$conf['basedn'], "(&(seciossAllowedService=$service_id)(seciossAccountStatus=active))", array('uid', $attr));
            if ($res == false) {
                $log->err("Failed to search users(".ldap_error($ldap).")");
                exit(1);
            } else {
                $entries = ldap_get_entries($ldap, $res);
                for ($i = 0; $i < $entries['count']; $i++) {
                    switch ($service) {
                        case 'office365':
                            if ($pdomain) {
                                if ($tenant != 'System') {
                                    $targets[] = preg_replace("/$tenant$/i", $pdomain, $entries[$i]['uid'][0]);
                                } else {
                                    $targets[] = $entries[$i]['uid'][0]."@$pdomain";
                                }
                            } else {
                                $targets[] = $entries[$i][$attr][0];
                            }
                            break;
                        default:
                            $targets[] = $entries[$i][$attr][0];
                    }
                }
            }
        }

        $error = false;
        foreach ($targets as $target) {
            $adapter = getAdapter($storage, $sclient, $target);
            if (!$adapter) {
                $error = true;
                break;
            }

            $path_list = array();
            $fs = new Filesystem($adapter);
            try {
                $contents = $fs->listContents($storage['rootdir'], $storage['recursive']);
            } catch (Exception $e) {
                $log->err("Failed to get $service_id files of $target".($tenant != 'System' ? " $tenant" : '').": ".$e->getMessage());
                $error = true;
                break;
            }
            foreach ($contents as $content) {
                if ($service == 'googleapps' && isset($content['path'])) {
                    $path_list[$content['path']] = $content['name'];
                }
                try {
                    $alert = checkFiles($fs, $dlp, $encryption && $encrypt ? $encrypt : null, $content, $checked_time, $storage['recursive']);
                } catch (Exception $e) {
                    $log->err("Failed to check $service_id files of $target".($tenant != 'System' ? " $tenant" : '').": ".$e->getMessage());
                    continue;
                }
                if ($alert) {
                    $alerts[] = $alert;
                }
            }
            if ($error) {
                break;
            }
        }
        if (!$error) {
            $checked[$tenant][$service_id] = $current_time;
        }
    }
    if (count($alerts) && $tenant_info['mail'] && preg_match('/^[^@]+@.+$/', $tenant_info['mail']) && file_exists(ALERTTMPL)) {
        if (!sendMail($tenant_info['mail'], $tenant_info['from'], ALERTTMPL, join("\n\n", $alerts))) {
            $log->err("Failed to send $tenant alert mail to ".$tenant_info['mail']);
        }
    }
    file_put_contents("$datadir/checked", serialize($checked));
}

function id2name($path, $list) {
    $name = '';

    while ($path) {
        $name = $list[$path].($name ? '/' : '').$name;
        $path = preg_replace('/\/?[^\/]*$/', '', $path);
    }

    return $name;
}

function checkFiles($fs, $dlp, $encrypt, $file, $checked_time, $recursive = false) {
    global $datadir;
    global $tenant;
    global $service_id;
    global $service;
    global $target;
    global $path_list;
    global $db;
    global $log;

    $likelihoods = ['Unknown', 'Very unlikely', 'Unlikely', 'Possible', 'Likely', 'Very likely'];

    $alerts = array();
    if ($file['type'] == 'dir') {
        if (!$recursive) {
            $contents = $fs->listContents($file['path'], false);
            foreach ($contents as $content) {
                if ($service == 'googleapps') {
                    $path_list[$content['path']] = $content['name'];
                }
                try {
                    $alert = checkFiles($fs, $dlp, $encrypt, $content, $checked_time);
                } catch (Exception $e) {
                    $log->err("Failed to check $service_id files of $target".($tenant != 'system' ? " $tenant" : '').": ".$e->getMessage());
                    continue;
                }
                if ($alert) {
                    $alerts[] = $alert;
                }
            }
        }
    } else {
        if ($file['timestamp'] < $checked_time || (isset($file['mimetype']) && preg_match('/\.google-apps\./', $file['mimetype']))) {
            return;
        }

        $data = $fs->read($file['path']);
        if ($data && $encrypt) {
            $data = $encrypt->decrypt($data);
        }

        $mimetype = MimeType::detectByContent($data);
        if (preg_match('/^image/', $mimetype)) {
            return;
        } elseif (preg_match('/^text/', $mimetype)) {
            $encoding = mb_detect_encoding($data, 'UTF-8,CP932,SJIS,EUC-JP,ASCII');
            if ($encoding != 'UTF-8' && $encoding != 'ASCI') {
                $data = mb_convert_encoding($data, 'UTF-8', $encoding);
            }
        } elseif (preg_match('/^application\/(.+)/', $mimetype, $matches)) {
            $tmpfile = "$datadir/".sha1($file['basename']);
            file_put_contents($tmpfile, $data);
            switch ($matches[1]) {
                case 'pdf':
                    $cmd = PDFCMD." $tmpfile -";
                    break;
                case 'msword':
                case 'mspowerpoint':
                case 'powerpoint':
                case 'vnd.ms-powerpoint':
                case 'x-mspowerpoint':
                case 'rtf':
                case 'x-rtf':
                case 'richtext':
                    $cmd = CONVCMD." -f txt --stdout $tmpfile";
                    break;
                case 'excel':
                case 'vnd.ms-excel':
                case 'x-excel':
                case 'x-msexcel':
                    $cmd = CONVCMD." -f csv --stdout $tmpfile";
                default:
                    return;
            }
            exec($cmd, $output);
            $data = join('', $output);
            unlink($tmpfile);
        }

        $messages = $dlp->inspect($data);
        if (count($messages)) {
            $path = $file['path'];
            if ($service == 'googleapps') {
                $path = id2name($path, $path_list);
            }
            $write_db = false;
            if ($db) {
                if (mysqli_query($db, "INSERT INTO dlp_alert(datetime, tenant, uid, service, file, msg) VALUES('".date("Y-m-d H:i:s")."', '$tenant', '$target', '$service_id', '".$path."', '".implode("\n", $messages)."')")) {
                    $write_db = true;
                }
            }
            if (!$write_db) {
                foreach ($messages as $message) {
                    $log->notice("$tenant; $service_id; $target; ".$path."; ".$message);
                }
            }
            $alerts[] = "Service: $service_id\nFIle:".$path."\n".join("\n", $messages);
        }
    }

    return join("\n\n", $alerts);
}

?>
