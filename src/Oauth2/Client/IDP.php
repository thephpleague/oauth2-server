<?php

namespace OAuth2\Client;

use Guzzle\Service\Client;

class IDPException extends \Exception {}

class IDP {

	public $clientId = '';

	public $clientSecret = '';

	public $redirectUri = '';

	public $name;

	public $uidKey = 'uid';

	public $scopes = array();

	public $method = 'post';

	public $scopeSeperator = ',';

	public $responseType = 'json';

	public function __construct()
	{
		//$this->redirectUri = $_SERVER[]
	}

	public function __get($key)
	{
		return $this->$key;
	}

	abstract public function urlAuthorize();

	abstract public function urlAccessToken();

	abstract public function urlUserInfo();

	public function authorize($options = array())
	{
		$state = md5(uniqid(rand(), TRUE));
		setcookie($this->name.'_authorize_state', $state);

		$params = array(
			'client_id' 		=> $this->clientId,
			'redirect_uri' 		=> $this->redirectUri,
			'state' 			=> $state,
			'scope'				=> is_array($this->scope) ? implode($this->scopeSeperator, $this->scope) : $this->scope,
			'response_type' 	=> isset($options['response_type']) ? $options['response_type'] : 'code',
			'approval_prompt'   => 'force' // - google force-recheck
		);

		header('Location: ' . $this->urlAuthorize().'?'.http_build_query($params));
		exit;
	}

	public function getAccessToken()
	{
		$params = array(
			'client_id' 	=> $this->clientId,
			'client_secret' => $this->clientSecret,
			'grant_type' 	=> isset($options['grant_type']) ? $options['grant_type'] : 'authorization_code',
		);

		switch ($params['grant_type']) {

			case 'authorization_code':
				$params['code'] = $code;
				$params['redirect_uri'] = isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirect_uri;
			break;

			case 'refresh_token':
				$params['refresh_token'] = $code;
			break;

		}

		switch ($this->method) {

			case 'get':
				$client = new Client($this->urlAccessToken() .= '?'.http_build_query($params));
				$response = $client->get();
				break;

			default:
				$client = new Client($this->urlAccessToken());
				$response = $client->{$this->method}(null, null, $params);
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

			throw new Oauth2\Client\IDPException($result);

		}

		switch ($params['grant_type']) {

			case 'authorization_code':
				return Oauth2\Client\Token::factory('access', $result);
			break;

			case 'refresh_token':
				return Oauth2\Client\Token::factory('refresh', $result);
			break;

		}
	}

}