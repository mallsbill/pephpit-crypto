<?php

namespace Pephpit\Crypto;

class Symetric
{
    /**
     * @var string Algorithm
     */
    private $cipher;
    /**
     * @var string Key
     */
    private $key;
    /**
     * @var string Initialization vector
     */
    private $iv;
    private $encoding = 'base64';

    /**
     * Constructeur
     * @param string $cipher Algorithm
     * @param string $mode Mode
     * @param string $key Key
     */
    public function __construct($cipher, $mode, $key)
    {
        if (!in_array($cipher, $this->getCiphers())) {
            $cipher = Mcrypt2Openssl::get($cipher, $mode, strlen($key));

            if (empty($cipher) || !in_array($cipher, $this->getCiphers())) {
                throw new Exception('Cipher not available');
            }
        }

        $keysize = Mcrypt2Openssl::getKeySize($cipher);
        if (strlen($key) < $keysize) {
            $key = str_pad($key, $keysize, $key);
        } elseif (strlen($key) > $keysize) {
            $key = substr($key, 0, $keysize);
        }

        $this->cipher = $cipher;
        $this->key = $key;
    }

    public function getKey()
    {
        return $this->key;
    }

    /**
     * Create initialization vector
     */
    private function createIV()
    {
        $iv_size = openssl_cipher_iv_length($this->cipher);

        if ($iv_size === 0) {
            return;
        }

        if (!empty($this->iv) && strlen($this->iv) === $iv_size) {
            return;
        } else if (!empty($this->iv)) {
            trigger_error('Wrong size for the initialization vector, should be ' . $iv_size . ' long', E_USER_WARNING);
        }

        $this->iv = openssl_random_pseudo_bytes($iv_size);
    }

    public function getIV()
    {
        return $this->iv;
    }

    /**
     *  Define initialization vector
     *  @param string $iv Initialization vector
     */
    public function setIV(string $iv)
    {
        $this->iv = $iv;
    }

    /**
     * Define enconding with base64
     */
    public function setBase64Encoding()
    {
        $this->encoding = 'base64';
    }

    /**
     * Define enconding with bin2hex
     * Convert binary data into hexadecimal representation
     */
    public function setHexEncoding()
    {
        $this->encoding = 'bin2hex';
    }

    /**
     * Encrypt a string
     * @param string $string String to encrypt
     * @return string $crypt Encrypted and base64 encoded string
     */
    public function encrypt($string)
    {
        $this->createIV();

        $crypt = openssl_encrypt($string, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);

        return $this->encode($this->iv . $crypt);
    }

    /**
     * Decrypt crypted string
     * @param string $crypt_encode Crypted and base64 encoded string
     * @return string|false $string Decrypted string
     */
    public function decrypt($crypt_encode)
    {

        $crypt_decode = $this->decode($crypt_encode);

        if ($crypt_decode === false) {
            throw new Exception('Unable to decode the crypt');
        }

        $iv_size = openssl_cipher_iv_length($this->cipher);

        $this->iv = substr($crypt_decode, 0, $iv_size);
        $crypt = substr($crypt_decode, $iv_size);

        if ($crypt != '') {
            $string = openssl_decrypt($crypt, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);

            if ($string === false) {
                throw new Exception(openssl_error_string());
            }

            return $string;
        } else {
            return false;
        }
    }

    private function encode($string)
    {
        if ($this->encoding == 'bin2hex') {
            return bin2hex($string);
        } else {
            return base64_encode($string);
        }
    }

    private function decode($string_encoded)
    {
        if ($this->encoding == 'bin2hex') {
            return hex2bin($string_encoded);
        } else {
            return base64_decode($string_encoded);
        }
    }

    /**
     * Gets an array of all supported modes
     * @return array Returns an array with all the supported modes
     */
    public function getModes()
    {
        return array();
    }

    /**
     * Gets an array of all supported ciphers
     * @return array Returns an array with all the supported algorithms
     */
    public function getCiphers()
    {
        return openssl_get_cipher_methods();
    }
}
