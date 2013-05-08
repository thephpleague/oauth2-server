<?php

use \Mockery as m;

class Refresh_Token_test extends PHPUnit_Framework_TestCase
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

    public function test_setRefreshTokenTTL()
    {
        $a = $this->returnDefault();
        $rt = new League\OAuth2\Server\Grant\RefreshToken($a);
        $rt->setRefreshTokenTTL(30);
        $this->assertEquals(30, $rt->getRefreshTokenTTL());
    }

    public function test_issueAccessToken_with_refresh_token()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('removeAuthCode')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);
        $this->session->shouldReceive('associateRefreshToken')->andReturn(1);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\AuthCode($a));
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $_POST['grant_type'] = 'authorization_code';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['redirect_uri'] = 'http://foo/redirect';
        $_POST['code'] = 'foobar';

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingClientSecret()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_refreshTokenGrant_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingRefreshToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_badRefreshToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());
        $this->session->shouldReceive('validateRefreshToken')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'refresh_token' =>  'abcdef'
        ));
    }

    public function test_issueAccessToken_refreshTokenGrant_passedInput()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);
        $this->session->shouldReceive('associateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('getAccessToken')->andReturn(null);
        $this->session->shouldReceive('getScopes')->andReturn(array());

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $_POST['grant_type'] = 'refresh_token';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['refresh_token'] = 'abcdef';

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

    public function test_issueAccessToken_refreshTokenGrant()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);
        $this->session->shouldReceive('getAccessToken')->andReturn(null);
        $this->session->shouldReceive('getScopes')->andReturn(array('id'    =>  1));
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);
        $this->session->shouldReceive('associateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('associateScope')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'refresh_token'  =>  'abcdef',
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
    }

    public function test_issueAccessToken_refreshTokenGrant_customExpiresIn()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->session->shouldReceive('validateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);
        $this->session->shouldReceive('getAccessToken')->andReturn(null);
        $this->session->shouldReceive('getScopes')->andReturn(array('id'    =>  1));
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);
        $this->session->shouldReceive('associateRefreshToken')->andReturn(1);
        $this->session->shouldReceive('associateScope')->andReturn(null);

        $a = $this->returnDefault();
        $grant = new League\OAuth2\Server\Grant\RefreshToken($a);
        $grant->setAccessTokenTTL(30);
        $a->addGrantType($grant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'refresh_token'  =>  'abcdef',
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertNotEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertNotEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
        $this->assertEquals(30, $v['expires_in']);
        $this->assertEquals(time()+30, $v['expires']);
    }
}