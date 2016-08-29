Flex \ Crypto
=============

Librairies de cryptage ou d'ofuscation


Installation
------------

Ajouter à votre composer.json, le dépot suivant

	"repositories": [
        {
            "type": "composer",
            "url": "http://packagist.flex-multimedia.dev/"
        }
    ]

 et ajouter au require

	"flex/crypto": "0.*"


Exemple d'utilisation cryptage Symetric
---------------------------------------

Encrypt

	$symetric = new \Flex\Crypto\Symetric(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, 'mykey');
	$my_string_crypted = $symetric->encrypt('my string');

Decrypt

	$symetric = new \Flex\Crypto\Symetric(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, 'mykey');
	$my_string_decrypted = $symetric->decrypt($my_string_crypted);


