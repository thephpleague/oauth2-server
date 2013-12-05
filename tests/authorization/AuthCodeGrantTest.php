<?php

use \Mockery as m;

class Auth_Code_Grant_Test extends PHPUnit_Framework_TestCase
{
    private $client;
    private $session;
    private $scope;

    public function setUp()
    {
        $this->client = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $this->session = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $this->scope = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
    }

    private function returnDefault()
    {
        return new League\OAuth2\Server\Authorization($this->client, $this->session, $this->scope);
    }

    /**
    * @expectedException PHPUnit_Framework_Error
    */
    public function test__construct()
    {
        $a = $this->returnDefault();
        $grant = new League\OAuth2\Server\Grant\AuthCode($a);
    }

    public function test_setIdentifier()
    {
        $grant = new League\OAuth2\Server\Grant\AuthCode();
        $grant->setIdentifier('foobar');
        $this->assertEquals($grant->getIdentifier(), 'foobar');
    }

    public function test_setAuthTokenTTL()
    {
        $a = $this->returnDefault();
        $grant = new League\OAuth2\Server\Grant\AuthCode();
        $grant->setAuthTokenTTL(30);

        $reflector = new ReflectionClass($grant);
        $requestProperty = $reflector->getProperty('authTokenTTL');
        $requestProperty->setAccessible(true);
        $v = $requestProperty->getValue($grant);

        $this->assertEquals(30, $v);
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noClientId()
    {
        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $g->checkAuthoriseParams();
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noRedirectUri()
    {
        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noRequiredState()
    {
        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->requireStateParam(true);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }


    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_checkAuthoriseParams_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'foo'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());
        $a->requireScopeParam(true);

        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope' =>  ''
        ));
    }

    public function test_checkAuthoriseParams_defaultScope()
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());
        $a->setDefaultScope('test.scope');
        $a->requireScopeParam(false);

        $params = $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope'    =>  ''
        ));

        $this->assertArrayHasKey('scopes', $params);
        $this->assertEquals(1, count($params['scopes']));
    }

    public function test_checkAuthoriseParams_defaultScopeArray()
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());
        $a->setDefaultScope(array('test.scope', 'test.scope2'));
        $a->requireScopeParam(false);

        $params = $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope'    =>  ''
        ));

        $this->assertArrayHasKey('scopes', $params);
        $this->assertEquals(2, count($params['scopes']));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());

        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope' =>  'foo'
        ));
    }

    public function test_checkAuthoriseParams_passedInput()
    {
        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());

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

        $v = $g->checkAuthoriseParams(array(
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
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode());

        $_GET['client_id'] = 1234;
        $_GET['redirect_uri'] = 'http://foo/redirect';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'foo';
        $_GET['state'] = 'xyz';

        $request = new League\OAuth2\Server\Util\Request($_GET);
        $a->setRequest($request);

        $v = $g->checkAuthoriseParams();

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
        $this->session->shouldReceive('associateRedirectUri')->andReturn(null);
        $this->session->shouldReceive('associateAuthCode')->andReturn(1);
        $this->session->shouldReceive('associateAuthCodeScope')->andReturn(null);

        $a = $this->returnDefault();
        $g = new League\OAuth2\Server\Grant\AuthCode();
        $a->addGrantType($g);

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

        $v = $g->newAuthoriseRequest('user', 123, $params);

        $this->assertEquals(40, strlen($v));
    }


}