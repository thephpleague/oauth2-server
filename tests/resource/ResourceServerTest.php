<?php

use \Mockery as m;

class Resource_Server_test extends PHPUnit_Framework_TestCase
{
	private $session;

	public function setUp()
	{
        $this->session = M::mock('OAuth2\Storage\SessionInterface');
	}

	private function returnDefault()
	{
		return new OAuth2\ResourceServer($this->session);
	}

	public function test_setRequest()
    {
        $s = $this->returnDefault();
        $request = new OAuth2\Util\Request();
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);
        $requestProperty = $reflector->getProperty('request');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($s);

        $this->assertTrue($v instanceof OAuth2\Util\RequestInterface);
    }

    public function test_getRequest()
    {
        $s = $this->returnDefault();
        $request = new OAuth2\Util\Request();
        $s->setRequest($request);
        $v = $s->getRequest();

        $this->assertTrue($v instanceof OAuth2\Util\RequestInterface);
    }

    public function test_getTokenKey()
    {
        $s = $this->returnDefault();
        $this->assertEquals('access_token', $s->getTokenKey());
    }

    public function test_setTokenKey()
    {
        $s = $this->returnDefault();
       	$s->setTokenKey('oauth_token');

        $reflector = new ReflectionClass($s);
        $requestProperty = $reflector->getProperty('tokenKey');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($s);

        $this->assertEquals('oauth_token', $v);
    }

    /**
     * @expectedException OAuth2\Exception\InvalidAccessTokenException
     */
    public function test_determineAccessToken_missingToken()
    {
    	$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer';
   		$request = new OAuth2\Util\Request(array(), array(), array(), array(), $_SERVER);

    	$s = $this->returnDefault();
    	$s->setRequest($request);

    	$reflector = new ReflectionClass($s);
	    $method = $reflector->getMethod('determineAccessToken');
	    $method->setAccessible(true);

	    $result = $method->invoke($s);
    }

    public function test_determineAccessToken_fromHeader()
    {
        $request = new OAuth2\Util\Request();

        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer YWJjZGVm'
        ));
        $s = $this->returnDefault();
        $s->setRequest($request);

    	$reflector = new ReflectionClass($s);

	    $method = $reflector->getMethod('determineAccessToken');
	    $method->setAccessible(true);

	    $result = $method->invoke($s);

	    $this->assertEquals('abcdef', $result);
    }

    public function test_determineAccessToken_fromMethod()
    {
    	$s = $this->returnDefault();

    	$_GET[$s->getTokenKey()] = 'abcdef';
    	$_SERVER['REQUEST_METHOD'] = 'get';

   		$request = new OAuth2\Util\Request($_GET, array(), array(), array(), $_SERVER);
    	$s->setRequest($request);

    	$reflector = new ReflectionClass($s);
	    $method = $reflector->getMethod('determineAccessToken');
	    $method->setAccessible(true);

	    $result = $method->invoke($s);

	    $this->assertEquals('abcdef', $result);
    }

    /**
     * @expectedException OAuth2\Exception\InvalidAccessTokenException
     */
    public function test_isValid_notValid()
    {
    	$this->session->shouldReceive('validateAccessToken')->andReturn(false);

    	$request = new OAuth2\Util\Request();
        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer YWJjZGVm'
        ));
        $s = $this->returnDefault();
        $s->setRequest($request);

        $s->isValid();
    }

    public function test_isValid_valid()
    {
    	$this->session->shouldReceive('validateAccessToken')->andReturn(array(
    		'id'	=>	1,
    		'owner_type'	=>	'user',
    		'owner_id'	=>	123
    	));
    	$this->session->shouldReceive('getScopes')->andReturn(array('foo', 'bar'));

   		$request = new OAuth2\Util\Request();
        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer YWJjZGVm'
        ));
        $s = $this->returnDefault();
        $s->setRequest($request);

    	$this->assertTrue($s->isValid());
    	$this->assertEquals(123, $s->getOwnerId());
    	$this->assertEquals('user', $s->getOwnerType());
    	$this->assertEquals('abcdef', $s->getAccessToken());
    	$this->assertTrue($s->hasScope('foo'));
    	$this->assertTrue($s->hasScope('bar'));
    	$this->assertTrue($s->hasScope(array('foo', 'bar')));
    	$this->assertFalse($s->hasScope(array('foobar')));
    	$this->assertFalse($s->hasScope('foobar'));
    	$this->assertFalse($s->hasScope(new StdClass));
    }
}