<?php

use Oauth2\Resource\Database;

class ResourceDB implements Database
{
	private $accessTokens = array(
		'test12345' => array(
			'id'	=>	1,
			'owner_type'	=>	'user',
			'owner_id'	=>	123
		)
	);

	private $sessionScopes = array(
		1	=>	array(
			'foo',
			'bar'
		)
	);

	public function validateAccessToken($accessToken)
	{
		return (isset($this->accessTokens[$accessToken])) ? $this->accessTokens[$accessToken] : false;
	}

	public function sessionScopes($sessionId)
	{
		return (isset($this->sessionScopes[$sessionId])) ? $this->sessionScopes[$sessionId] : array();
	}
}