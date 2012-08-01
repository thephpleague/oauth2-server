<?php

class Server_test extends PHPUnit_Framework_TestCase {

	function __construct()
	{
		$this->oauth = new Oauth2\Authentication\Server();
		
		//$this->oauth->registerDbAbstractor($this->oauthdb);
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


}