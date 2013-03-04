<?php

use \Mockery as m;

class Authorization_Server_test extends PHPUnit_Framework_TestCase
{
    private $client;
    private $session;
    private $scope;

    public function setUp()
    {
        $this->client = M::mock('OAuth2\Storage\ClientInterface');
        $this->session = M::mock('OAuth2\Storage\SessionInterface');
        $this->scope = M::mock('OAuth2\Storage\ScopeInterface');
    }

    private function returnDefault()
    {
        return new OAuth2\AuthServer($this->client, $this->session, $this->scope);
    }

    /**
     * @expectedException PHPUnit_Framework_Error
     */
    public function test__construct_NoStorage()
    {
        $a = new OAuth2\AuthServer;
    }

    public function test__contruct_WithStorage()
    {
        $a = $this->returnDefault();
    }

    public function test_getExceptionMessage()
    {
        $m = OAuth2\AuthServer::getExceptionMessage('access_denied');

        $reflector = new ReflectionClass($this->returnDefault());
        $exceptionMessages = $reflector->getProperty('exceptionMessages');
        $exceptionMessages->setAccessible(true);
        $v = $exceptionMessages->getValue();

        $this->assertEquals($v['access_denied'], $m);
    }

    public function test_getExceptionCode()
    {
        $this->assertEquals('access_denied', OAuth2\AuthServer::getExceptionType(2));
    }

    public function test_hasGrantType()
    {
        $this->assertFalse(OAuth2\AuthServer::hasGrantType('test'));
    }

    public function test_addGrantType()
    {
        $a = $this->returnDefault();
        $grant = M::mock('OAuth2\Grant\GrantTypeInterface');
        $grant->shouldReceive('getResponseType')->andReturn('test');
        $a->addGrantType($grant, 'test');

        $this->assertTrue(OAuth2\AuthServer::hasGrantType('test'));
    }

    public function test_addGrantType_noIdentifier()
    {
        $a = $this->returnDefault();
        $grant = M::mock('OAuth2\Grant\GrantTypeInterface');
        $grant->shouldReceive('getIdentifier')->andReturn('test');
        $grant->shouldReceive('getResponseType')->andReturn('test');
        $a->addGrantType($grant);

        $this->assertTrue(OAuth2\AuthServer::hasGrantType('test'));
    }

    public function test_getScopeDelimeter()
    {
        $a = $this->returnDefault();
        $this->assertEquals(',', $a->getScopeDelimeter());
    }

    public function test_setScopeDelimeter()
    {
        $a = $this->returnDefault();
        $a->setScopeDelimeter(';');
        $this->assertEquals(';', $a->getScopeDelimeter());
    }

    public function test_requireScopeParam()
    {
        $a = $this->returnDefault();
        $a->requireScopeParam(false);

        $reflector = new ReflectionClass($a);
        $requestProperty = $reflector->getProperty('requireScopeParam');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($a);

        $this->assertFalse($v);
    }

    public function test_requireStateParam()
    {
        $a = $this->returnDefault();
        $a->requireStateParam(true);

        $reflector = new ReflectionClass($a);
        $requestProperty = $reflector->getProperty('requireStateParam');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($a);

        $this->assertTrue($v);
    }

    public function test_getExpiresIn()
    {
        $a = $this->returnDefault();
        $a->setExpiresIn(7200);
        $this->assertEquals(7200, $a::getExpiresIn());
    }

    public function test_setExpiresIn()
    {
        $a = $this->returnDefault();
        $a->setScopeDelimeter(';');
        $this->assertEquals(';', $a->getScopeDelimeter());
    }

    public function test_setRequest()
    {
        $a = $this->returnDefault();
        $request = new OAuth2\Util\Request();
        $a->setRequest($request);

        $reflector = new ReflectionClass($a);
        $requestProperty = $reflector->getProperty('request');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue();

        $this->assertTrue($v instanceof OAuth2\Util\RequestInterface);
    }

    public function test_getRequest()
    {
        $a = $this->returnDefault();
        $request = new OAuth2\Util\Request();
        $a->setRequest($request);
        $v = $a::getRequest();

        $this->assertTrue($v instanceof OAuth2\Util\RequestInterface);
    }

    public function test_getStorage()
    {
        $a = $this->returnDefault();
        $this->assertTrue($a->getStorage('session') instanceof OAuth2\Storage\SessionInterface);
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noClientId()
    {
        $a = $this->returnDefault();
        $a->checkAuthoriseParams();
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noRedirectUri()
    {
        $a = $this->returnDefault();
        $a->checkAuthoriseParams(array(
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_checkAuthoriseParams_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_missingResponseType()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $a = $this->returnDefault();
        $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    3
     */
    public function test_checkAuthoriseParams_badResponseType()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $a = $this->returnDefault();
        $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'foo'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_missingScopes()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope' =>  ''
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    4
     */
    public function test_checkAuthoriseParams_badScopes()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->scope->shouldReceive('getScope')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope' =>  'foo'
        ));
    }

    public function test_checkAuthoriseParams_passedInput()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'scope' =>  'foo',
            'name'  =>  'Foo Name',
            'description'   =>  'Foo Name Description'
        ));

        $v = $a->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope' =>  'foo',
            'state' =>  'xyz'
        ));

        $this->assertEquals(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'client_details' => array(
                'client_id' => 1234,
                'client_secret' => 5678,
                'redirect_uri' => 'http://foo/redirect',
                'name' => 'Example Client'
            ),
            'response_type' =>  'code',
            'scopes'    =>  array(
                array(
                    'id'    =>  1,
                    'scope' =>  'foo',
                    'name'  =>  'Foo Name',
                    'description'   =>  'Foo Name Description'
                )
            ),
            'scope' =>  'foo',
            'state' =>  'xyz'
        ), $v);
    }

    public function test_checkAuthoriseParams()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'scope' =>  'foo',
            'name'  =>  'Foo Name',
            'description'   =>  'Foo Name Description'
        ));

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $_GET['client_id'] = 1234;
        $_GET['redirect_uri'] = 'http://foo/redirect';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'foo';
        $_GET['state'] = 'xyz';

        $request = new OAuth2\Util\Request($_GET);
        $a->setRequest($request);

        $v = $a->checkAuthoriseParams();

        $this->assertEquals(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'client_details' => array(
                'client_id' => 1234,
                'client_secret' => 5678,
                'redirect_uri' => 'http://foo/redirect',
                'name' => 'Example Client'
            ),
            'response_type' =>  'code',
            'scopes'    =>  array(
                array(
                    'id'    =>  1,
                    'scope' =>  'foo',
                    'name'  =>  'Foo Name',
                    'description'   =>  'Foo Name Description'
                )
            ),
            'scope' =>  'foo',
            'state' =>  'xyz'
        ), $v);
    }

    function test_newAuthoriseRequest()
    {
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('associateScope')->andReturn(null);

        $a = $this->returnDefault();

        $params = array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'client_details' => array(
                'client_id' => 1234,
                'client_secret' => 5678,
                'redirect_uri' => 'http://foo/redirect',
                'name' => 'Example Client'
            ),
            'response_type' =>  'code',
            'scopes'    =>  array(
                array(
                    'id'    =>  1,
                    'scope' =>  'foo',
                    'name'  =>  'Foo Name',
                    'description'   =>  'Foo Name Description'
                )
            )
        );

        $v = $a->newAuthoriseRequest('user', 123, $params);

        $this->assertEquals(40, strlen($v));
    }

    public function test_getGrantType()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $reflector = new ReflectionClass($a);
        $method = $reflector->getMethod('getGrantType');
        $method->setAccessible(true);

        $result = $method->invoke($a, 'authorization_code');

        $this->assertTrue($result instanceof OAuth2\Grant\GrantTypeInterface);
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingGrantType()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken();
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    7
     */
    public function test_issueAccessToken_badGrantType()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array('grant_type' => 'foo'));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingClientSecret()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingRedirectUri()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingCode()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    9
     */
    public function test_issueAccessToken_badCode()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());
        $this->session->shouldReceive('validateAuthCode')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'code'  =>  'foobar'
        ));
    }

    public function test_issueAccessToken_passedInput()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'authorization_code',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'code'  =>  'foobar'
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }

    public function test_issueAccessToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());

        $_POST['grant_type'] = 'authorization_code';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['redirect_uri'] = 'http://foo/redirect';
        $_POST['code'] = 'foobar';

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }

    public function tearDown() {
        M::close();
    }
}