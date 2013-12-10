# Simple OAuth 2.0 Client Library

Simple PHP Library to do the OAuth2 authetification process using curl.

## Usage

```php
<?php

require_once 'Authentificator.php';

$provider = new naev\oauth2\Authentificator(array(
		// 'proxy' => '123.123.221.121:81',
		'clientId' => 'PUT_CLIENT_ID_HERE',
		'clientSecret' => 'PUT_CLIENT_SECRET',
		'redirectUri' => 'http://mydomain/oauth/',
		'scopeSeperator' => ' ', // Google needs seperator other than default ','
		'urlAuthorize' => 'https://accounts.google.com/o/oauth2/auth',
		'urlAccessToken' => 'https://accounts.google.com/o/oauth2/token',
		'scopes' => array('https://www.google.com/m8/feeds/')
	)
);

if (!isset($_GET['code'])) {
	// If we don't have an authorization code then get one
	$provider->authorize();
} else {
	try {
		// Try to get an access token (using the authorization code grant)
		$token = $provider->getToken($_GET['code']);
		var_dump($token);

		// Get new Access Token with the refresh token
 		$token2 = $provider->updateAccessToken($token, true);
 		var_dump($token2);
	} catch (Exception $e) {
		echo "Exception: " . $e->getMessage();
	}
}
```

## License

Based on OAuth 2.0 Client Library by Alex Bilbie
Adapted by Nick Russler

The MIT License (MIT). Please see [License File](https://github.com/php-loep/:package_name/blob/master/LICENSE) for more information.
