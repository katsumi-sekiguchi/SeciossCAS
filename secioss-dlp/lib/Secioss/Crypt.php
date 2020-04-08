<?php
/**
 *  Crypt.php
 *
 *  PHP version 5.4+
 *
 *  @package    Crypt
 *  @author     SECIOSS <info@secioss.co.jp>
 *  @copyright  2019 SECIOSS, INC.
 *  @version    $Id$
 */

namespace Secioss;

define('DEC_KEY_FILE', '/etc/httpd/conf.d/auth_tkt.conf');
define('DEC_SECRETKEY_DIRECTIVE', 'TKTAuthSecret');

/**
 *  Crypt
 *
 *  @package    Crypt
 *  @author     SECIOSS <info@secioss.co.jp>
 *  @copyright  2019 SECIOSS, INC.
 *  @version    $Id$
 */
class Crypt
{
    /**
     * 文字列の暗号化を行う。
     *
     * @access public
     * @param  string   被暗号化文字列
     * @return string   暗号化文字列
    */
    public function encrypt($data, $key = null)
    {
        if (is_null($key)) {
            $key = Crypt::getSecretKey(DEC_KEY_FILE);
            if (is_null($key)) {
                return false;
            }
        }

        $hashed = hash('sha256', $key, true);
        $checksum = substr($hashed, 0, 16);
        
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt(
                        $checksum.$data,
                        'aes-256-cbc',
                        $hashed,
                        OPENSSL_RAW_DATA,
                        $iv
                    );
    
        $base64 = base64_encode($iv.$encrypted);
    
        return $base64;
    }
    
    /**
     * 3DESで文字列の暗号化を行う。
     * 下位互換用。新規には使用しないこと
     *
     * @access public
     * @param  string   被暗号化文字列
     * @return string   暗号化文字列
    */
    public function encrypt3des($data, $key)
    {
        $hashed = md5($key);
        $checksum = $hashed;
        
        $iv = openssl_random_pseudo_bytes(8);

        $cipher = mcrypt_module_open('tripledes', '', 'cfb', '');
        $hashed = substr($hashed, 0, mcrypt_enc_get_key_size($cipher));

        mcrypt_generic_init($cipher, $hashed, $iv);

        $encrypted = mcrypt_generic($cipher, $checksum.$data);
        $base64 = base64_encode($iv.$encrypted);

        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);

        return $base64;
    }

    /**
     * 文字列の複合化を行う。
     *
     * @access public
     * @param  string   暗号化文字列
     * @return string   複合化した文字列
    */
    public function decrypt($data, $key = null)
    {
        if ($data === null || $data === '') {
            return false;
        }

        if (is_null($key)) {
            $key = Crypt::getSecretKey(DEC_KEY_FILE);
            if (is_null($key)) {
                return false;
            }
        }

        $hashed = hash('sha256', $key, true);
        $checksum = substr($hashed, 0, 16);
        $bytesdata = base64_decode($data);

        $iv = substr($bytesdata, 0, 16);
        $encrypted = substr($bytesdata, 16);

        $decrypted = openssl_decrypt(
                        $encrypted,
                        'aes-256-cbc',
                        $hashed,
                        OPENSSL_RAW_DATA,
                        $iv
                    );
        if ($decrypted && substr($decrypted, 0, 16) === $checksum) {
            $decrypted = substr($decrypted, 16);
        } else {
            $decrypted = false;
        }
        if (!$decrypted) {
            $decrypted = Crypt::decrypt3des($data, $key);
        }

        return $decrypted;
    }
    
    /**
     * 3DESで文字列の複合化を行う。
     * 下位互換用。新規には使用しないこと
     *
     * @access public
     * @param  string   暗号化文字列
     * @return string   複合化した文字列
    */
    public function decrypt3des($data, $key)
    {
        $hashed = md5($key);
        $checksum = $hashed;
        $bytesdata = base64_decode($data);

        $cipher = mcrypt_module_open('tripledes', '', 'cfb', '');
        $hashed = substr($hashed, 0, mcrypt_enc_get_key_size($cipher));
        $iv = substr($bytesdata, 0, 8);
        $encrypted = substr($bytesdata, 8);
        if (!$encrypted) {
            return null;
        }

        mcrypt_generic_init($cipher, $hashed, $iv);
        $decrypted = mdecrypt_generic($cipher, $encrypted);
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);
        if ($decrypted && substr($decrypted, 0, 32) === $checksum) {
            $decrypted = substr($decrypted, 32);
        } else {
            $decrypted = false;
        }

        return $decrypted;
    }
    
    /**
     * 暗号化用のキーをファイルから取得する
     *
     * @access public
     * @param  string   ファイル
     * @return string   キー
    */
    public function getSecretKey($file)
    {
        $matches = array();
        $secretKey = "";

        $content = file_get_contents($file);
        if ($content === false) {
            // Cannot read key file
            return null;
        }

        if (preg_match("/^\s*".DEC_SECRETKEY_DIRECTIVE."\s+[\"']*([^\"']*)[\"']*/mi", $content, $matches)) {
            $secretKey = $matches[1];
        }

        return $secretKey;
    }
}
