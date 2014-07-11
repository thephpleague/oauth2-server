<?php

use \Mockery as m;

class Resource_Server_test extends PHPUnit_Framework_TestCase
{
    private $session;

    public function setUp()
    {
        $this->session = M::mock('League\OAuth2\Server\Storage\SessionInterface');
    }

    private function returnDefault()
    {
        return new League\OAuth2\Server\Resource($this->session);
    }

    public function test_getExceptionMessage()
    {
        $m = League\OAuth2\Server\Resource::getExceptionMessage('invalid_request');

        $reflector = new ReflectionClass($this->returnDefault());
        $exceptionMessages = $reflector->getProperty('exceptionMessages');
        $exceptionMessages->setAccessible(true);
        $v = $exceptionMessages->getValue();

        $this->assertEquals($v['invalid_request'], $m);
    }

    public function test_getExceptionCode()
    {
        $this->assertEquals('invalid_request', League\OAuth2\Server\Resource::getExceptionType(0));
        $this->assertEquals('invalid_token', League\OAuth2\Server\Resource::getExceptionType(1));
        $this->assertEquals('insufficient_scope', League\OAuth2\Server\Resource::getExceptionType(2));
    }

    public function test_getExceptionHttpHeaders()
    {
        $this->assertEquals(array('HTTP/1.1 400 Bad Request'), League\OAuth2\Server\Resource::getExceptionHttpHeaders('invalid_request'));
        $this->assertEquals(array('HTTP/1.1 401 Unauthorized'), League\OAuth2\Server\Resource::getExceptionHttpHeaders('invalid_token'));
        $this->assertContains('HTTP/1.1 403 Forbidden', League\OAuth2\Server\Resource::getExceptionHttpHeaders('insufficient_scope'));
    }

    public function test_setRequest()
    {
        $s = $this->returnDefault();
        $request = new League\OAuth2\Server\Util\Request();
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);
        $requestProperty = $reflector->getProperty('request');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($s);

        $this->assertTrue($v instanceof League\OAuth2\Server\Util\RequestInterface);
    }

    public function test_getRequest()
    {
        $s = $this->returnDefault();
        $request = new League\OAuth2\Server\Util\Request();
        $s->setRequest($request);
        $v = $s->getRequest();

        $this->assertTrue($v instanceof League\OAuth2\Server\Util\RequestInterface);
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

    public function test_getScopes()
    {
        $s = $this->returnDefault();
        $this->assertEquals(array(), $s->getScopes());
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\MissingAccessTokenException
     */
    public function test_determineAccessToken_missingToken()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer';
           $request = new League\OAuth2\Server\Util\Request(array(), array(), array(), array(), $_SERVER);

        $s = $this->returnDefault();
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);
        $method = $reflector->getMethod('determineAccessToken');
        $method->setAccessible(true);

        $method->invoke($s);
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\MissingAccessTokenException
     */
    public function test_determineAccessToken_brokenCurlRequest()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer, Bearer abcdef';
        $request = new League\OAuth2\Server\Util\Request(array(), array(), array(), array(), $_SERVER);

        $s = $this->returnDefault();
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);
        $method = $reflector->getMethod('determineAccessToken');
        $method->setAccessible(true);

        $method->invoke($s);
    }

    public function test_determineAccessToken_fromHeader()
    {
        $request = new League\OAuth2\Server\Util\Request();

        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer abcdef'
        ));
        $s = $this->returnDefault();
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);

        $method = $reflector->getMethod('determineAccessToken');
        $method->setAccessible(true);

        $result = $method->invoke($s);

        $this->assertEquals('abcdef', $result);
    }

    public function test_determineAccessToken_fromBrokenCurlHeader()
    {
        $request = new League\OAuth2\Server\Util\Request();

        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer abcdef, Bearer abcdef'
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

           $request = new League\OAuth2\Server\Util\Request($_GET, array(), array(), array(), $_SERVER);
        $s->setRequest($request);

        $reflector = new ReflectionClass($s);
        $method = $reflector->getMethod('determineAccessToken');
        $method->setAccessible(true);

        $result = $method->invoke($s);

        $this->assertEquals('abcdef', $result);
    }

    public function test_hasScope_isRequired()
    {
        $s = $this->returnDefault();

        $reflector = new ReflectionClass($s);
        $param = $reflector->getProperty('sessionScopes');
        $param->setAccessible(true);
        $param->setValue($s, array(
            'a', 'b', 'c'
        ));

        $result = $s->hasScope(array('a', 'b'), true);

        $this->assertEquals(true, $result);
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\InsufficientScopeException
     */
    public function test_hasScope_isRequiredFailure()
    {
        $s = $this->returnDefault();

        $reflector = new ReflectionClass($s);
        $param = $reflector->getProperty('sessionScopes');
        $param->setAccessible(true);
        $param->setValue($s, array(
            'a', 'b', 'c'
        ));

        $s->hasScope('d', true);
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\InvalidAccessTokenException
     */
    public function test_isValid_notValid()
    {
        $this->session->shouldReceive('validateAccessToken')->andReturn(false);

        $request = new League\OAuth2\Server\Util\Request();
        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer abcdef'
        ));
        $s = $this->returnDefault();
        $s->setRequest($request);

        $s->isValid();
    }

    public function test_isValid_valid()
    {
        $this->session->shouldReceive('validateAccessToken')->andReturn(array(
            'session_id'  =>    1,
            'owner_type'  =>    'user',
            'owner_id'    =>    123,
            'client_id' =>  'testapp'
        ));

        $this->session->shouldReceive('getScopes')->andReturn(array(
            array('scope' =>  'foo'),
            array('scope' =>  'bar')
        ));

           $request = new League\OAuth2\Server\Util\Request();
        $requestReflector = new ReflectionClass($request);
        $param = $requestReflector->getProperty('headers');
        $param->setAccessible(true);
        $param->setValue($request, array(
            'Authorization' =>  'Bearer abcdef'
        ));

        $s = $this->returnDefault();
        $s->setRequest($request);

        $this->assertTrue($s->isValid());
        $this->assertEquals(123, $s->getOwnerId());
        $this->assertEquals('user', $s->getOwnerType());
        $this->assertEquals('abcdef', $s->getAccessToken());
        $this->assertEquals('testapp', $s->getClientId());
    	$this->assertTrue($s->hasScope('foo'));
    	$this->assertTrue($s->hasScope('bar'));
    	$this->assertTrue($s->hasScope(array('foo', 'bar')));
    	$this->assertFalse($s->hasScope(array('foobar')));
    	$this->assertFalse($s->hasScope('foobar'));
    }
}
