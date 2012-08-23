<?php

class Server_test extends PHPUnit_Framework_TestCase {

	function setUp()
	{
		require_once('database_mock.php');
		$this->server = new Oauth2\Resource\Server();
		$this->db = new ResourceDB();

		$this->server->registerDbAbstractor($this->db);
	}

	function test_init_POST()
	{
		$_POST['oauth_token'] = 'test12345';

		$this->server->init();

		$this->assertEquals($this->server->_accessToken, $_POST['oauth_token']);
		$this->assertEquals($this->server->_type, 'user');
		$this->assertEquals($this->server->_typeId, 123);
		$this->assertEquals($this->server->_scopes, array('foo', 'bar'));
	}

	function test_init_GET()
	{
		$_GET['oauth_token'] = 'test12345';

		$this->server->init();

		$this->assertEquals($this->server->_accessToken, $_GET['oauth_token']);
		$this->assertEquals($this->server->_type, 'user');
		$this->assertEquals($this->server->_typeId, 123);
		$this->assertEquals($this->server->_scopes, array('foo', 'bar'));
	}

	function test_init_header()
	{
		// Test with authorisation header
	}

	/**
	 * @exception OAuthResourceServerException
	 */
	function test_init_wrongToken()
	{
		$_POST['access_token'] = 'test12345';

		$this->server->init();
	}

	function test_hasScope()
	{
		$_POST['oauth_token'] = 'test12345';

		$this->server->init();

		$this->assertEquals(true, $this->server->hasScope('foo'));
		$this->assertEquals(true, $this->server->hasScope('bar'));
		$this->assertEquals(true, $this->server->hasScope(array('foo', 'bar')));

		$this->assertEquals(false, $this->server->hasScope('foobar'));
		$this->assertEquals(false, $this->server->hasScope(array('foobar')));
	}

	function test___call()
	{
		$_POST['oauth_token'] = 'test12345';

		$this->server->init();

		$this->assertEquals(123, $this->server->isUser());
		$this->assertEquals(false, $this->server->isMachine());
	}

}