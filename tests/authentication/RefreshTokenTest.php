<?php

use \Mockery as m;

class Refresh_Token_test extends PHPUnit_Framework_TestCase
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

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\AuthCode());
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

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
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingClientSecret()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_refreshTokenGrant_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_missingRefreshToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'refresh_token',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            //'refresh_token' =>
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refreshTokenGrant_badRefreshToken()
    {
        $this->client->shouldReceive('getClient')->andReturn(array());
        $this->client->shouldReceive('validateRefreshToken')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
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

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $_POST['grant_type'] = 'refresh_token';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['refresh_token'] = 'abcdef';

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken();

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);
        $this->assertArrayHasKey('refresh_token', $v);

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }

    public function test_issueAccessToken_refreshTokenGrant()
    {
        $this->client->shouldReceive('getClient')->andReturn(array(
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'redirect_uri'  =>  'http://foo/redirect',
            'name'  =>  'Example Client'
        ));

        $this->client->shouldReceive('validateRefreshToken')->andReturn(1);

        $this->session->shouldReceive('validateAuthCode')->andReturn(1);
        $this->session->shouldReceive('updateSession')->andReturn(null);
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

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

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }
}