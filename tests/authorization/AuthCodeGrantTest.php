<?php

use \Mockery as m;

class Auth_Code_Grant_Test extends PHPUnit_Framework_TestCase
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
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noClientId()
    {
        $a = $this->returnDefault();
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $g->checkAuthoriseParams();
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noRedirectUri()
    {
        $a = $this->returnDefault();
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkAuthoriseParams_noRequiredState()
    {
        $a = $this->returnDefault();
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->requireStateParam(true);
        $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect'
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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $g->checkAuthoriseParams(array(
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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->addGrantType(new OAuth2\Grant\AuthCode($a));

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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->addGrantType(new OAuth2\Grant\AuthCode($a));
        $a->setDefaultScope('test.scope');
        $a->requireScopeParam(false);

        $params = $g->checkAuthoriseParams(array(
            'client_id' =>  1234,
            'redirect_uri'  =>  'http://foo/redirect',
            'response_type' =>  'code',
            'scope'    =>  ''
        ));

        $this->assertArrayHasKey('scopes', $params);
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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->addGrantType(new OAuth2\Grant\AuthCode($a));

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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->addGrantType(new OAuth2\Grant\AuthCode($a));

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
        $g = new OAuth2\Grant\AuthCode($a);
        $a->addGrantType($g);
        $a->addGrantType(new OAuth2\Grant\AuthCode($a));

        $_GET['client_id'] = 1234;
        $_GET['redirect_uri'] = 'http://foo/redirect';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'foo';
        $_GET['state'] = 'xyz';

        $request = new OAuth2\Util\Request($_GET);
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

        $a = $this->returnDefault();
        $g = new OAuth2\Grant\AuthCode($a);
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