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
----------------------------------------

Génération des clés privé et public

	openssl genrsa -out private.key 4096
	openssl req -new -key private.key -out cert.tpm
	openssl x509 -req -in cert.tpm -signkey private.key -out public.crt

Encrypt

	$asymetric = new \Flex\Crypto\Asymetric();
	$asymetric->setPublicKeyFile('public.crt');
	$my_string_crypted = $asymetric->publicEncrypt('my string');

Decrypt

	$asymetric = new \Flex\Crypto\Asymetric();
	$asymetric->setPrivateKeyFile('private.key');
	$my_string_decrypted = $asymetric->privateDecrypt($my_string_crypted);

Exemple d'utilisation cryptage par Substitution
-----------------------------------------------

Génération des pbox

	$substitution = new \Flex\Crypto\Substitution('', array());
	$pbox = $substitution->generatePBox();
	echo json_encode($pbox);

ce qui donne par exemple

	[[21,19,1,18,22,5,10,11,12,6,17,13,2,20,3,26,9,29,27,14,15,24,25,7,16,8,4,0,28,23],[25,24,22,19,2,18,26,7,16,20,27,29,12,14,1,23,21,28,6,15,17,13,0,11,8,9,4,3,10,5],[20,2,0,1,19,8,3,17,6,24,7,28,12,22,5,13,15,10,4,11,25,26,27,18,23,16,9,21,14,29]]

Encrypt

	$pbox = [
		[21,19,1,18,22,5,10,11,12,6,17,13,2,20,3,26,9,29,27,14,15,24,25,7,16,8,4,0,28,23],
		[25,24,22,19,2,18,26,7,16,20,27,29,12,14,1,23,21,28,6,15,17,13,0,11,8,9,4,3,10,5],
		[20,2,0,1,19,8,3,17,6,24,7,28,12,22,5,13,15,10,4,11,25,26,27,18,23,16,9,21,14,29]
	];
	
	$substitution = new \Flex\Crypto\Substitution('mykey', $pbox);
	$my_string_crypted = $asymetric->encrypt('my string');

Decrypt

	$pbox = [
		[21,19,1,18,22,5,10,11,12,6,17,13,2,20,3,26,9,29,27,14,15,24,25,7,16,8,4,0,28,23],
		[25,24,22,19,2,18,26,7,16,20,27,29,12,14,1,23,21,28,6,15,17,13,0,11,8,9,4,3,10,5],
		[20,2,0,1,19,8,3,17,6,24,7,28,12,22,5,13,15,10,4,11,25,26,27,18,23,16,9,21,14,29]
	];
	
	$substitution = new \Flex\Crypto\Substitution('mykey', $pbox);
	$my_string_decrypted = $asymetric->decrypt($my_string_crypted);


