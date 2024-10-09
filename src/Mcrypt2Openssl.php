<?php

namespace Pephpit\Crypto;

class Mcrypt2Openssl
{
    /**
     * Return OpenSSL cipher name for a Mcrypt cipher name and mode name
     * Return null if no corresponding cipher
     * @param string $cipher Mcrypt Cipher name
     * @param string $mode Mcrypt Mode name
     * @param int $keylength Key length
     * @return string OpenSSL Cipher
     * @see https://github.com/tom--/mcrypt2openssl/blob/master/mapping.md
     */
    public static function get($cipher, $mode, $keylength)
    {
        if ($cipher == 'blowfish' || $cipher == 'blowfish-compat') {
            if ($mode == 'cbc') {
                return 'bf-cbc';
            } else if ($mode == 'ecb') {
                return 'bf-ecb';
            } else if ($mode == 'ncfb' || $mode == 'cfb') {
                return 'bf-cfb';
            } else if ($mode == 'nofb' || $mode == 'ofb') {
                return 'bf-ofb';
            }
        } else if ($cipher == 'cast-128') {
            if ($mode == 'cbc') {
                return 'cast5-cbc';
            } else if ($mode == 'ecb') {
                return 'cast5-ecb';
            } else if ($mode == 'ncfb') {
                return 'cast5-cfb';
            } else if ($mode == 'nofb') {
                return 'cast5-ofb';
            }
        } else if ($cipher == 'des') {
            if ($mode == 'cbc') {
                return 'des-cbc';
            } else if ($mode == 'cfb') {
                return 'des-cfb8';
            } else if ($mode == 'ecb') {
                return 'des-ecb';
            } else if ($mode == 'ncfb') {
                return 'des-cfb';
            } else if ($mode == 'nofb') {
                return 'des-ofb';
            }
        } else if ($cipher == 'rijndael-128' && $keylength == 16) {
            if ($mode == 'cbc') {
                return 'aes-128-cbc';
            } else if ($mode == 'cfb') {
                return 'aes-128-cfb8';
            } else if ($mode == 'ecb') {
                return 'aes-128-ecb';
            } else if ($mode == 'ncfb') {
                return 'aes-128-cfb';
            } else if ($mode == 'nofb') {
                return 'aes-128-ofb';
            }
        } else if ($cipher == 'rijndael-128' && $keylength == 24) {
            if ($mode == 'cbc') {
                return 'aes-192-cbc';
            } else if ($mode == 'cfb') {
                return 'aes-192-cfb8';
            } else if ($mode == 'ecb') {
                return 'aes-192-ecb';
            } else if ($mode == 'ncfb') {
                return 'aes-192-cfb';
            } else if ($mode == 'nofb') {
                return 'aes-192-ofb';
            }
        } else if ($cipher == 'rijndael-128' && $keylength == 32) {
            if ($mode == 'cbc') {
                return 'aes-256-cbc';
            } else if ($mode == 'cfb') {
                return 'aes-256-cfb8';
            } else if ($mode == 'ecb') {
                return 'aes-256-ecb';
            } else if ($mode == 'ncfb') {
                return 'aes-256-cfb';
            } else if ($mode == 'nofb') {
                return 'aes-256-ofb';
            }
        } else if ($cipher == 'tripledes' && $keylength == 8) {
            if ($mode == 'cbc') {
                return 'des-cbc';
            } else if ($mode == 'cfb') {
                return 'des-cfb8';
            } else if ($mode == 'ecb') {
                return 'des-ecb';
            } else if ($mode == 'ncfb') {
                return 'des-cfb';
            } else if ($mode == 'nofb') {
                return 'des-ofb';
            }
        } else if ($cipher == 'tripledes' && $keylength == 16) {
            if ($mode == 'cbc') {
                return 'des-ede-cbc';
            } else if ($mode == 'ecb') {
                return 'des-ede';
            } else if ($mode == 'ncfb') {
                return 'des-ede-cfb';
            } else if ($mode == 'nofb') {
                return 'des-ede-ofb';
            }
        } else if ($cipher == 'tripledes' && $keylength == 24) {
            if ($mode == 'cbc') {
                return 'des-ede3-cbc';
            } else if ($mode == 'cfb') {
                return 'des-ede3-cfb8';
            } else if ($mode == 'ecb') {
                return 'des-ede3';
            } else if ($mode == 'ncfb') {
                return 'des-ede3-cfb';
            } else if ($mode == 'nofb') {
                return 'des-ede3-ofb';
            }
        } else if ($cipher == 'arcfour') {
            if ($mode == 'stream') {
                return 'rc4-40';
            }
        }

        return null;
    }

    public static function getKeySize($openssl_cipher)
    {

        if (preg_match('/^bf-/i', $openssl_cipher)) {
            return 56;
        } else if (preg_match('/^cast5/i', $openssl_cipher)) {
            return 16;
        } else if (preg_match('/^des-ede3/i', $openssl_cipher)) {
            return 24;
        } else if (preg_match('/^des-ede/i', $openssl_cipher)) {
            return 16;
        } else if (preg_match('/^des-/i', $openssl_cipher)) {
            return 8;
        } else if (preg_match('/^aes-128-/i', $openssl_cipher)) {
            return 16;
        } else if (preg_match('/^aes-192-/i', $openssl_cipher)) {
            return 24;
        } else if (preg_match('/^aes-256-/i', $openssl_cipher)) {
            return 32;
        } else if (preg_match('/^rc4-/i', $openssl_cipher)) {
            return 256;
        } else {
            return 16;
        }
    }

    public static function defineMcryptConstants()
    {
        if (defined('MCRYPT_ENCRYPT') === true) {
            return;
        }

        define('MCRYPT_ENCRYPT', 0);
        define('MCRYPT_DECRYPT', 1);
        define('MCRYPT_DEV_RANDOM', 0);
        define('MCRYPT_DEV_URANDOM', 1);
        define('MCRYPT_RAND', 2);
        define('MCRYPT_3DES', "tripledes");
        define('MCRYPT_ARCFOUR_IV', "arcfour-iv");
        define('MCRYPT_ARCFOUR', "arcfour");
        define('MCRYPT_BLOWFISH', "blowfish");
        define('MCRYPT_BLOWFISH_COMPAT', "blowfish-compat");
        define('MCRYPT_CAST_128', "cast-128");
        define('MCRYPT_CAST_256', "cast-256");
        define('MCRYPT_CRYPT', "crypt");
        define('MCRYPT_DES', "des");
        define('MCRYPT_ENIGNA', "crypt");
        define('MCRYPT_GOST', "gost");
        define('MCRYPT_LOKI97', "loki97");
        define('MCRYPT_PANAMA', "panama");
        define('MCRYPT_RC2', "rc2");
        define('MCRYPT_RIJNDAEL_128', "rijndael-128");
        define('MCRYPT_RIJNDAEL_192', "rijndael-192");
        define('MCRYPT_RIJNDAEL_256', "rijndael-256");
        define('MCRYPT_SAFER64', "safer-sk64");
        define('MCRYPT_SAFER128', "safer-sk128");
        define('MCRYPT_SAFERPLUS', "saferplus");
        define('MCRYPT_SERPENT', "serpent");
        define('MCRYPT_THREEWAY', "threeway");
        define('MCRYPT_TRIPLEDES', "tripledes");
        define('MCRYPT_TWOFISH', "twofish");
        define('MCRYPT_WAKE', "wake");
        define('MCRYPT_XTEA', "xtea");
        define('MCRYPT_IDEA', "idea");
        define('MCRYPT_MARS', "mars");
        define('MCRYPT_RC6', "rc6");
        define('MCRYPT_SKIPJACK', "skipjack");
        define('MCRYPT_MODE_CBC', "cbc");
        define('MCRYPT_MODE_CFB', "cfb");
        define('MCRYPT_MODE_ECB', "ecb");
        define('MCRYPT_MODE_NOFB', "nofb");
        define('MCRYPT_MODE_OFB', "ofb");
        define('MCRYPT_MODE_STREAM', "stream");
    }
}
