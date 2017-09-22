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

Exemple d'utilisation cryptage Asymetric
---------------------------------------

Génération des clés privé et public

	openssl genrsa -out private.key 4096
	openssl req -new -key private.key -out cert.tpm
	openssl x509 -req -in cert.tpm -signkey private.key -out public.crt

Encrypt

	$asymetric = new TestedClass();
	$asymetric->setPublicKeyFile('public.crt');
	$my_string_crypted = $asymetric->publicEncrypt('my string');

Decrypt

	$asymetric = new TestedClass();
	$asymetric->setPrivateKeyFile('private.key');
	$my_string_decrypted = $asymetric->privateDecrypt($my_string_crypted);


