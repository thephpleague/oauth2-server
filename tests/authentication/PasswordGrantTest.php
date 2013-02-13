<?php

use \Mockery as m;

class Password_Grant_Test extends PHPUnit_Framework_TestCase
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
    public function test_issueAccessToken_passwordGrant_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\Password());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_passwordGrant_missingClientPassword()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\Password());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_passwordGrant_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new OAuth2\Grant\Password());

        $request = new OAuth2\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\InvalidGrantTypeException
     */
    function test_issueAccessToken_passwordGrant_invalidCallback()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = null;

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  => 'foo',
            'password'  => 'bar'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    function test_issueAccessToken_passwordGrant_missingUsername()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return false; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    function test_issueAccessToken_passwordGrant_missingPassword()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return false; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  =>  'foo'
        ));
    }

    /**
     * @expectedException        OAuth2\Exception\ClientException
     * @expectedExceptionCode    0
     */
    function test_issueAccessToken_passwordGrant_badCredentials()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return false; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  => 'foo',
            'password'  => 'bar'
        ));
    }

    function test_issueAccessToken_passwordGrant_passedInput()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  => 'foo',
            'password'  => 'bar'
        ));

        $this->assertArrayHasKey('access_token', $v);
        $this->assertArrayHasKey('token_type', $v);
        $this->assertArrayHasKey('expires', $v);
        $this->assertArrayHasKey('expires_in', $v);

        $this->assertEquals($a::getExpiresIn(), $v['expires_in']);
        $this->assertEquals(time()+$a::getExpiresIn(), $v['expires']);
    }

    function test_issueAccessToken_passwordGrant()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $_POST['grant_type'] = 'password';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['username'] = 'foo';
        $_POST['password'] = 'bar';

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

    function test_issueAccessToken_passwordGrant_withRefreshToken()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new OAuth2\Grant\Password();
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->addGrantType(new OAuth2\Grant\RefreshToken());

        $_POST['grant_type'] = 'password';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['username'] = 'foo';
        $_POST['password'] = 'bar';

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

}