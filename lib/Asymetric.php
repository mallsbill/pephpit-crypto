<?php
namespace Flex\Crypto;

class Asymetric
{

    private $padding = OPENSSL_PKCS1_PADDING;
    private $public_key;
    private $private_key;
    private $private_key_pass;

    /**
     * Define padding
     * @param int $padding OPENSSL padding value
     * @return \Flex\Crypto\Asymetric
     * @throws \InvalidArgumentException
     */
    public function setPadding($padding)
    {
        if (!in_array($padding, array(OPENSSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING))) {
            throw new \InvalidArgumentException('Invalid padding value');
        }

        $this->padding = $padding;
        return $this;
    }

    /**
     * Define public key
     * @param string $public_key
     * @return \Flex\Crypto\Asymetric
     */
    public function setPublicKey($public_key)
    {
        $this->public_key = $public_key;
        return $this;
    }

    /**
     * Define private key
     * @param string $private_key
     * @param string $pass
     * @return \Flex\Crypto\Asymetric
     */
    public function setPrivateKey($private_key, $pass = null)
    {
        $this->private_key = $private_key;
        $this->private_key_pass = $pass;
        return $this;
    }

    /**
     * Define public key from a file
     * @param string $public_key_filename
     * @return \Flex\Crypto\Asymetric
     * @throws \InvalidArgumentException
     */
    public function setPublicKeyFile($public_key_filename)
    {
        if (!is_file($public_key_filename)) {
            throw new \InvalidArgumentException($public_key_filename . ' is not a valid file');
        }
        $fp = fopen($public_key_filename, 'r');
        $this->public_key = fread($fp, 8192);
        fclose($fp);
        return $this;
    }

    /**
     * Define private key from a file
     * @param string $private_key_filename
     * @param string $pass
     * @return \Flex\Crypto\Asymetric
     * @throws \InvalidArgumentException
     */
    public function setPrivateKeyFile($private_key_filename, $pass = null)
    {
        if (!is_file($private_key_filename)) {
            throw new \InvalidArgumentException($private_key_filename . ' is not a valid file');
        }
        $fp = fopen($private_key_filename, 'r');
        $this->private_key = fread($fp, 8192);
        fclose($fp);

        $this->private_key_pass = $pass;
        return $this;
    }

    /**
     * Encrypt a string with public key
     * Can be decrypt with private key
     * @param string $string string to encrypt
     * @return string String encrypted
     * @throws \LogicException
     * @throws Exception
     */
    public function publicEncrypt($string)
    {
        if (empty($this->public_key)) {
            throw new \LogicException('public key not defined');
        }

        $key = openssl_pkey_get_public($this->public_key);

        if ($key === false) {
            throw new Exception(openssl_error_string());
        }

        $crypt = '';

        if (openssl_public_encrypt($string, $crypt, $key, $this->padding) === false) {
            throw new Exception(openssl_error_string());
        }

        return base64_encode($crypt);
    }

    /**
     * Encrypt a string with private key
     * Can be decrypt with public key
     * @param string $string String to encrypt
     * @return string Encrypted and base64 encoded string
     * @throws \LogicException
     * @throws Exception
     */
    public function privateEncrypt($string)
    {
        if (empty($this->private_key)) {
            throw new \LogicException('private key not defined');
        }

        $key = openssl_pkey_get_private($this->private_key, $this->private_key_pass);

        if ($key === false) {
            throw new Exception(openssl_error_string());
        }

        $crypt = '';

        if (openssl_private_encrypt($string, $crypt, $key, $this->padding) === false) {
            throw new Exception(openssl_error_string());
        }

        return base64_encode($crypt);
    }

    /**
     * Decrypt with public key a string encrypted with private key
     * @param string $crypt_encode Crypted and base64 encoded string
     * @return string Decrypted string
     * @throws \LogicException
     * @throws Exception
     */
    public function publicDecrypt($crypt_encode)
    {
        if (empty($this->public_key)) {
            throw new \LogicException('public key not defined');
        }

        $key = openssl_pkey_get_public($this->public_key);

        if ($key === false) {
            throw new Exception(openssl_error_string());
        }

        $crypt = base64_decode($crypt_encode, true);

        if ($crypt === false) {
            throw new Exception('Unable to decode the crypt');
        }

        $decrypt = '';

        if (openssl_public_decrypt($crypt, $decrypt, $key, $this->padding) == false) {
            throw new Exception(openssl_error_string());
        }

        return $decrypt;
    }

    /**
     * Decrypt with private key a string encrypted with public key
     * @param string $crypt_encode Crypted and base64 encoded string
     * @return string Decrypted string
     * @throws \LogicException
     * @throws Exception
     */
    public function privateDecrypt($crypt_encode)
    {
        if (empty($this->private_key)) {
            throw new \LogicException('private key not defined');
        }

        $key = openssl_pkey_get_private($this->private_key, $this->private_key_pass);

        if ($key === false) {
            throw new Exception(openssl_error_string());
        }

        $crypt = base64_decode($crypt_encode, true);

        if ($crypt === false) {
            throw new Exception('Unable to decode the crypt');
        }

        $decrypt = '';

        if (openssl_private_decrypt($crypt, $decrypt, $key, $this->padding) == false) {
            throw new Exception(openssl_error_string());
        }

        return $decrypt;
    }

}
