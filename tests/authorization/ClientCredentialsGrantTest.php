<?php

use \Mockery as m;

class Client_Credentials_Grant_Test extends PHPUnit_Framework_TestCase
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
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_clientCredentialsGrant_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_clientCredentialsGrant_missingClientPassword()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_clientCredentialsGrant_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_clientCredentialsGrant_missingScopes()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));
        $a->requireScopeParam(true);

        $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    public function test_issueAccessToken_clientCredentialsGrant_defaultScope()
    {
        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'key' =>  'foo',
            'name'  =>  'Foo Name',
            'description'   =>  'Foo Name Description'
        ));

        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateScope')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));
        $a->requireScopeParam(false);
        $a->setDefaultScope('foobar');

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'scope' =>  ''
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    4
     */
    public function test_issueAccessToken_clientCredentialsGrant_badScope()
    {
        $this->scope->shouldReceive('getScope')->andReturn(false);

        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateScope')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));

        $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'scope' =>  'blah'
        ));
    }

    public function test_issueAccessToken_clientCredentialsGrant_goodScope()
    {
        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'key' =>  'foo',
            'name'  =>  'Foo Name',
            'description'   =>  'Foo Name Description'
        ));

        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateScope')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'scope' =>  'blah'
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
    }

    function test_issueAccessToken_clientCredentialsGrant_passedInput()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));
        $a->requireScopeParam(false);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'client_credentials',
            'client_id' =>  1234,
            'client_secret' =>  5678,
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

    function test_issueAccessToken_clientCredentialsGrant()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

    function test_issueAccessToken_clientCredentialsGrant_customExpiresIn()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $grant = new League\OAuth2\Server\Grant\ClientCredentials($a);
        $grant->setAccessTokenTTL(30);
        $a->addGrantType($grant);
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertNotEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertNotEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
        $this->assertEquals(30, $v['expires_in']);
        $this->assertEquals(time()+30, $v['expires']);
    }

    function test_issueAccessToken_clientCredentialsGrant_withRefreshToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('createSession')->andReturn(1);
        $this->session->shouldReceive('deleteSession')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\ClientCredentials($a));
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

}