<?php

class Server_test extends PHPUnit_Framework_TestCase {

	function setUp()
	{
		$this->oauth = new Oauth2\Authentication\Server();
		
		require_once('database_mock.php');
		$this->oauthdb = new OAuthdb();
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

}