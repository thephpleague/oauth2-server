<?php

use Oauth2\Authentication\Database;

class OAuthdb implements Database
{
	private $sessions = array();
	private $sessions_client_type_id = array();
	private $sessions_code = array();
	private $session_scopes = array();

	private $clients = array(0 => array(
		'client_id'	=>	'test',
		'client_secret'	=>	'test',
		'redirect_uri'	=>	'http://example.com/test',
		'name'	=>	'Test Client'
	));

	private $scopes = array('test' => array(
		'id'	=>	1,
		'scope'	=>	'test',
		'name'	=>	'test',
		'description'	=>	'test'
	));

	public function validateClient($clientId, $clientSecret = null, $redirectUri = null)
	{
		if ($clientId !== $this->clients[0]['client_id'])
		{
			return false;
		}

		if ($clientSecret !== null && $clientSecret !== $this->clients[0]['client_secret'])
		{
			return false;
		}

		if ($redirectUri !== null && $redirectUri !== $this->clients[0]['redirect_uri'])
		{
			return false;
		}

		return $this->clients[0];
	}

	public function newSession($clientId, $redirectUri, $type = 'user', $typeId = null, $authCode = null, $accessToken = null, $accessTokenExpire = null, $stage = 'requested')
	{
		$id = count($this->sessions);

		$this->sessions[$id] = array(
			'id'	=>	$id,
			'client_id'	=>	$clientId,
			'redirect_uri'	=>	$redirectUri,
			'owner_type'	=>	$type,
			'owner_id'	=>	$typeId,
			'auth_code'	=>	$authCode,
			'access_token'	=>	$accessToken,
			'access_token_expire'	=>	$accessTokenExpire,
			'stage'	=>	$stage
		);

		$this->sessions_client_type_id[$clientId . ':' . $type . ':' . $typeId] = $id;
		$this->sessions_code[$clientId . ':' . $redirectUri . ':' . $authCode] = $id;

		return $id;
	}

	public function updateSession($sessionId, $authCode = null, $accessToken = null, $accessTokenExpire = null, $stage = 'requested')
	{
		$this->sessions[$sessionId]['auth_code'] = $authCode;
		$this->sessions[$sessionId]['access_token'] = $accessToken;
		$this->sessions[$sessionId]['access_token_expire'] = $accessTokenExpire;
		$this->sessions[$sessionId]['stage'] = $stage;

		return true;
	}

	public function deleteSession($clientId, $type, $typeId)
	{
		$key = $clientId . ':' . $type . ':' . $typeId;
		if (isset($this->sessions_client_type_id[$key]))
		{
			unset($this->sessions[$this->sessions_client_type_id[$key]]);
		}
		return true;
	}

	public function validateAuthCode($clientId, $redirectUri, $authCode)
	{
		$key = $clientId . ':' . $redirectUri . ':' . $authCode;

		if (isset($this->sessions_code[$key]))
		{
			return $this->sessions[$this->sessions_code[$key]];
		}

		return false;
	}

	public function hasSession($type, $typeId, $clientId)
	{
		die('not implemented hasSession');
	}

	public function getAccessToken($sessionId)
	{
		die('not implemented getAccessToken');
	}

	public function removeAuthCode($sessionId)
	{
		die('not implemented removeAuthCode');
	}

	public function setAccessToken(
		$sessionId,
		$accessToken
	)
	{
		die('not implemented setAccessToken');
	}

	public function addSessionScope($sessionId, $scope)
	{
		if ( ! isset($this->session_scopes[$sessionId]))
		{
			$this->session_scopes[$sessionId] = array();
		}

		$this->session_scopes[$sessionId][] = $scope;

		return true;
	}

	public function getScope($scope)
	{
		if ( ! isset($this->scopes[$scope]))
		{
			return false;
		}

		return $this->scopes[$scope];
	}

	public function updateSessionScopeAccessToken($sessionId, $accessToken)
	{
		return true;
	}

	public function accessTokenScopes($accessToken)
	{
		die('not implemented accessTokenScopes');
	}
}