<?php
/* Based on OAuth 2.0 Client Library by Alex Bilbie
 * Adapted by Nick Russler
 * 
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Alex Bilbie <hello@alexbilbie.com>
 * Copyright (c) 2013 Nick Russler <nick.russler@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace naev\oauth2;

class Authentificator {
    public $clientId = '';

    public $clientSecret = '';

    public $redirectUri = '';

    public $name;

    public $uidKey = 'uid';

    public $scopes = array();

    public $method = 'post';

    public $scopeSeperator = ',';

    public $responseType = 'json';
    
    public $urlAuthorize = '';
    
    public $urlAccessToken = '';
    
    public $proxy = '';

    public function __construct($options = array()) {
        foreach ($options as $option => $value) {
            if (isset($this->{$option})) {
                $this->{$option} = $value;
            }
        }
    }

    private $curlParams = array (
    		CURLOPT_RETURNTRANSFER => true,
    		CURLOPT_FOLLOWLOCATION => 0,
    		CURLOPT_FAILONERROR => false,
    		// CURLOPT_SSL_VERIFYPEER => false, // This is not very safe, but sometimes needed..
    		CURLOPT_HEADER => false,
    		CURLOPT_VERBOSE => false,
    );
    
    private function getBody($url, $params = null) {   	
    	// Get cURL resource
    	$ch = curl_init();
    	
    	curl_setopt_array($ch, $this->curlParams);
    	curl_setopt($ch, CURLOPT_URL, $url);
    	
    	if ($this->proxy !== '') {	
	    	curl_setopt($ch, CURLOPT_PROXY, $this->proxy);
    	}
    	
    	if ($params) {
    		curl_setopt($ch, CURLOPT_POST, true);    		   		
    		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params)); 
    	}
    	
    	$resp = curl_exec($ch);
    	curl_close($ch);
    
    	return $resp;
    }

    public function authorize($options = array()) {
    	$state = md5(uniqid(rand(), true));
    	setcookie($this->name.'_authorize_state', $state);
    	
    	$params = array(
    			'client_id' => $this->clientId,
    			'redirect_uri' => $this->redirectUri,
    			'state' => $state,
    			'scope' => is_array($this->scopes) ? implode($this->scopeSeperator, $this->scopes) : $this->scopes,
    			'response_type' => isset($options['response_type']) ? $options['response_type'] : 'code',
    			'approval_prompt' => 'force', // - google force-recheck,
    			'access_type' => 'offline'
    	);
    	
    	$authorization_url = $this->urlAuthorize.'?'.http_build_query($params);
    	
        header('Location: ' . $authorization_url);
        exit;
    }

    private function oauth2_query($grant, $params = array()) {
        $defaultParams = array(
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type'    => $grant,
        );

        $requestParams = array_merge($defaultParams, $params);
		
        switch ($this->method) {
        	case 'get':
        		$response = $this->getBody($this->urlAccessToken. '?' . http_build_query($requestParams));
        		break;
        	case 'post':
        		$response = $this->getBody($this->urlAccessToken, $requestParams);
        		break;
        }
            
        switch ($this->responseType) {
            case 'json':
                $result = json_decode($response, true);
                break;
            case 'string':
                parse_str($response, $result);
                break;
        }

        if (isset($result['error']) && ! empty($result['error'])) {
        	throw new \Exception('naev\oauth2\Authentificator#getAccessToken: Invalid Response (Body: '.$response.').');
        }

        return $result;
    }
    
    public function getToken($code) {
    	$params = array('redirect_uri' => $this->redirectUri, 'code' => $code);
    	$token = $this->oauth2_query('authorization_code', $params);
    	
    	$token['expires_in'] = time() + (int)$token['expires_in'];
    	
    	return $token;
    }
    
    public function updateAccessToken($token, $force = false) {
		if (!$force && isset($token['expires_in']) && (time() <= (int)$token['expires_in'])) {
			return $token;
		}
		   	
    	$token_tmp = $this->oauth2_query('refresh_token', array('refresh_token' => $token["refresh_token"]));
    	$token_tmp['expires_in'] = time() + (int)$token_tmp['expires_in'];
    	
    	return array_merge($token, $token_tmp);	
    }
}