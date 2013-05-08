<?php

use \Mockery as m;

class Password_Grant_Test extends PHPUnit_Framework_TestCase
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
    public function test_issueAccessToken_passwordGrant_missingClientId()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\Password($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_passwordGrant_missingClientPassword()
    {
        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\Password($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    8
     */
    public function test_issueAccessToken_passwordGrant_badClient()
    {
        $this->client->shouldReceive('getClient')->andReturn(false);

        $a = $this->returnDefault();
        $a->addGrantType(new League\OAuth2\Server\Grant\Password($a));

        $request = new League\OAuth2\Server\Util\Request(array(), $_POST);
        $a->setRequest($request);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\InvalidGrantTypeException
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
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
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
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
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
     * @expectedException        League\OAuth2\Server\Exception\ClientException
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
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
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
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    4
     */
    public function test_issueAccessToken_passwordGrant_badScopes()
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  =>  'foo',
            'password'  =>  'bar',
            'scope' =>  'blah'
        ));
    }

    /**
     * @expectedException        League\OAuth2\Server\Exception\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_passwordGrant_missingScopes()
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
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->requireScopeParam(true);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  =>  'foo',
            'password'  =>  'bar'
        ));
    }

    public function test_issueAccessToken_passwordGrant_defaultScope()
    {
        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'scope' =>  'foo',
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);
        $this->session->shouldReceive('associateScope')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->requireScopeParam(false);
        $a->setDefaultScope('foobar');

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  =>  'foo',
            'password'  =>  'bar',
            'scope' =>  ''
        ));
    }

    public function test_issueAccessToken_passwordGrant_goodScope()
    {
        $this->scope->shouldReceive('getScope')->andReturn(array(
            'id'    =>  1,
            'scope' =>  'foo',
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
        $this->session->shouldReceive('updateRefreshToken')->andReturn(null);
        $this->session->shouldReceive('associateScope')->andReturn(null);
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);

        $v = $a->issueAccessToken(array(
            'grant_type'    =>  'password',
            'client_id' =>  1234,
            'client_secret' =>  5678,
            'username'  =>  'foo',
            'password'  =>  'bar',
            'scope' =>  'blah'
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
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->requireScopeParam(false);

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

        $this->assertEquals($a->getAccessTokenTTL(), $v['expires_in']);
        $this->assertEquals(time()+$a->getAccessTokenTTL(), $v['expires']);
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
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'password';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['username'] = 'foo';
        $_POST['password'] = 'bar';

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

    function test_issueAccessToken_passwordGrant_customExpiresIn()
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
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $pgrant->setAccessTokenTTL(30);
        $a->addGrantType($pgrant);
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'password';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['username'] = 'foo';
        $_POST['password'] = 'bar';

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
        $this->session->shouldReceive('associateAccessToken')->andReturn(1);
        $this->session->shouldReceive('associateRefreshToken')->andReturn(null);

        $testCredentials = function($u, $p) { return 1; };

        $a = $this->returnDefault();
        $pgrant = new League\OAuth2\Server\Grant\Password($a);
        $pgrant->setVerifyCredentialsCallback($testCredentials);
        $a->addGrantType($pgrant);
        $a->addGrantType(new League\OAuth2\Server\Grant\RefreshToken($a));
        $a->requireScopeParam(false);

        $_POST['grant_type'] = 'password';
        $_POST['client_id'] = 1234;
        $_POST['client_secret'] = 5678;
        $_POST['username'] = 'foo';
        $_POST['password'] = 'bar';

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

}