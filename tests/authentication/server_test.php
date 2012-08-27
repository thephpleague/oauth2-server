<?php

class Authentication_Server_test extends PHPUnit_Framework_TestCase {

	function setUp()
	{
		$this->oauth = new Oauth2\Authentication\Server();

		require_once('database_mock.php');
		$this->oauthdb = new OAuthdb();
		$this->assertInstanceOf('Oauth2\Authentication\Database', $this->oauthdb);
		$this->oauth->registerDbAbstractor($this->oauthdb);
	}

	function test_generateCode()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('generateCode');
		$method->setAccessible(true);

		$result = $method->invoke($this->oauth);
		$result2 = $method->invoke($this->oauth);

		$this->assertEquals(40, strlen($result));
		$this->assertNotEquals($result, $result2);
	}

	function test_redirectUri()
	{
		$result1 = $this->oauth->redirectUri('http://example.com/foo');
		$result2 = $this->oauth->redirectUri('http://example.com/foo', array('foo' => 'bar'));
		$result3 = $this->oauth->redirectUri('http://example.com/foo', array('foo' => 'bar'), '#');

		$this->assertEquals('http://example.com/foo?', $result1);
		$this->assertEquals('http://example.com/foo?foo=bar', $result2);
		$this->assertEquals('http://example.com/foo#foo=bar', $result3);
	}

	function test_checkClientAuthoriseParams_GET()
	{
		$_GET['client_id'] = 'test';
		$_GET['redirect_uri'] = 'http://example.com/test';
		$_GET['response_type'] = 'code';
		$_GET['scope'] = 'test';
		
		$expect = array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'response_type'	=>	'code',
			'scopes'	=>	array(
					0 => array(
					'id'	=>	1,
					'scope'	=>	'test',
					'name'	=>	'test',
					'description'	=>	'test'
				)
			)
		);

		$result = $this->oauth->checkClientAuthoriseParams();

		$this->assertEquals($expect, $result);
	}

	function test_checkClientAuthoriseParams_PassedParams()
	{
		unset($_GET['client_id']);
		unset($_GET['redirect_uri']);
		unset($_GET['response_type']);
		unset($_GET['scope']);

		$params = array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'response_type'	=>	'code',
			'scope'	=>	'test'
		);

		$this->assertEquals(array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'response_type'	=>	'code',
			'scopes'	=>	array(0 => array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		), $this->oauth->checkClientAuthoriseParams($params));
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_checkClientAuthoriseParams_missingClientId()
	{
		$this->oauth->checkClientAuthoriseParams();
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_checkClientAuthoriseParams_missingRedirectUri()
	{
		$_GET['client_id'] = 'test';

		$this->oauth->checkClientAuthoriseParams();
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_checkClientAuthoriseParams_missingResponseType()
	{
		$_GET['client_id'] = 'test';
		$_GET['redirect_uri'] = 'http://example.com/test';

		$this->oauth->checkClientAuthoriseParams();
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_checkClientAuthoriseParams_missingScopes()
	{
		$_GET['client_id'] = 'test';
		$_GET['redirect_uri'] = 'http://example.com/test';
		$_GET['response_type'] = 'code';
		$_GET['scope'] = ' ';

		$this->oauth->checkClientAuthoriseParams();
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    4
	 */
	function test_checkClientAuthoriseParams_invalidScopes()
	{
		$_GET['client_id'] = 'test';
		$_GET['redirect_uri'] = 'http://example.com/test';
		$_GET['response_type'] = 'code';
		$_GET['scope'] = 'blah';

		$this->oauth->checkClientAuthoriseParams();
	}

	function test_newAuthoriseRequest()
	{
		$result = $this->oauth->newAuthoriseRequest('user', '123', array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'scopes'	=>	array(array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		));

		$this->assertEquals(40, strlen($result));
	}

	function test_newAuthoriseRequest_isUnique()
	{
		$result1 = $this->oauth->newAuthoriseRequest('user', '123', array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'scopes'	=>	array(array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		));

		$result2 = $this->oauth->newAuthoriseRequest('user', '123', array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'scopes'	=>	array(array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		));

		$this->assertNotEquals($result1, $result2);
	}

	function test_issueAccessToken_POST()
	{
		$auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'scopes'	=>	array(array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		));

		$_POST['client_id'] = 'test';
		$_POST['client_secret'] = 'test';
		$_POST['redirect_uri'] = 'http://example.com/test';
		$_POST['grant_type'] = 'authorization_code';
		$_POST['code'] = $auth_code;

		$result = $this->oauth->issueAccessToken();

		$this->assertCount(3, $result);
		$this->assertArrayHasKey('access_token', $result);
		$this->assertArrayHasKey('token_type', $result);
		$this->assertArrayHasKey('expires_in', $result);
	}

	function test_issueAccessToken_PassedParams()
	{
		$auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
			'client_id'	=>	'test',
			'redirect_uri'	=>	'http://example.com/test',
			'scopes'	=>	array(array(
				'id'	=>	1,
				'scope'	=>	'test',
				'name'	=>	'test',
				'description'	=>	'test'
			))
		));

		$params['client_id'] = 'test';
		$params['client_secret'] = 'test';
		$params['redirect_uri'] = 'http://example.com/test';
		$params['grant_type'] = 'authorization_code';
		$params['code'] = $auth_code;

		$result = $this->oauth->issueAccessToken($params);

		$this->assertCount(3, $result);
		$this->assertArrayHasKey('access_token', $result);
		$this->assertArrayHasKey('token_type', $result);
		$this->assertArrayHasKey('expires_in', $result);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_issueAccessToken_missingGrantType()
	{
		$this->oauth->issueAccessToken();
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    7
	 */
	function test_issueAccessToken_unsupportedGrantType()
	{
		$params['grant_type'] = 'blah';

		$this->oauth->issueAccessToken($params);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_completeAuthCodeGrant_missingClientId()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$method->invoke($this->oauth);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_completeAuthCodeGrant_missingClientSecret()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$authParams['client_id'] = 'test';

		$method->invoke($this->oauth, $authParams);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_completeAuthCodeGrant_missingRedirectUri()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$authParams['client_id'] = 'test';
		$authParams['client_secret'] = 'test';

		$method->invoke($this->oauth, $authParams);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    8
	 */
	function test_completeAuthCodeGrant_invalidClient()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$authParams['client_id'] = 'test';
		$authParams['client_secret'] = 'test123';
		$authParams['redirect_uri'] = 'http://example.com/test';

		$method->invoke($this->oauth, $authParams);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    0
	 */
	function test_completeAuthCodeGrant_missingCode()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$authParams['client_id'] = 'test';
		$authParams['client_secret'] = 'test';
		$authParams['redirect_uri'] = 'http://example.com/test';

		$method->invoke($this->oauth, $authParams);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerClientException
	 * @expectedExceptionCode    9
	 */
	function test_completeAuthCodeGrant_invalidCode()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('completeAuthCodeGrant');
		$method->setAccessible(true);

		$authParams['client_id'] = 'test';
		$authParams['client_secret'] = 'test';
		$authParams['redirect_uri'] = 'http://example.com/test';
		$authParams['code'] = 'blah';

		$method->invoke($this->oauth, $authParams);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerException
	 * @expectedExceptionMessage No registered database abstractor
	 */
	function test_noRegisteredDatabaseAbstractor()
	{
		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('dbcall');
		$method->setAccessible(true);

		$dbAbstractor = $reflector->getProperty('db');
		$dbAbstractor->setAccessible(true);
		$dbAbstractor->setValue($this->oauth, null);

		$result = $method->invoke($this->oauth);
	}

	/**
	 * @expectedException        Oauth2\Authentication\OAuthServerException
	 * @expectedExceptionMessage Registered database abstractor is not an instance of Oauth2\Authentication\Database
	 */
	function test_invalidRegisteredDatabaseAbstractor()
	{
		$fake = new stdClass;
		$this->oauth->registerDbAbstractor($fake);

		$reflector = new ReflectionClass($this->oauth);
		$method = $reflector->getMethod('dbcall');
		$method->setAccessible(true);

		$result = $method->invoke($this->oauth);
	}

}