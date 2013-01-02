<?php

require_once 'src/OAuth2/Authentication/Server.php';
require_once 'src/OAuth2/Authentication/Database.php';

class Authentication_Server_test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->oauth = new Oauth2\Authentication\Server();

        require_once 'database_mock.php';
        $this->oauthdb = new OAuthdb();
        $this->assertInstanceOf('Oauth2\Authentication\Database', $this->oauthdb);
        $this->oauth->registerDbAbstractor($this->oauthdb);
    }

    public function test_setupWithOptions()
    {
        $o = new Oauth2\Authentication\Server(array(
            'access_token_ttl'  =>  86400
        ));

        $reflector = new ReflectionClass($o);
        $param = $reflector->getProperty('_config');
        $param->setAccessible(true);
        $array = $param->getValue($o);

        $this->assertEquals(86400, $array['access_token_ttl']);
    }

    public function test_generateCode()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_generateCode');
        $method->setAccessible(true);

        $result = $method->invoke($this->oauth);
        $result2 = $method->invoke($this->oauth);

        $this->assertEquals(40, strlen($result));
        $this->assertNotEquals($result, $result2);
    }

    public function test_redirectUri()
    {
        $result1 = $this->oauth->redirectUri('http://example.com/foo');
        $result2 = $this->oauth->redirectUri('http://example.com/foo', array('foo' => 'bar'));
        $result3 = $this->oauth->redirectUri('http://example.com/foo', array('foo' => 'bar'), '#');

        $this->assertEquals('http://example.com/foo?', $result1);
        $this->assertEquals('http://example.com/foo?foo=bar', $result2);
        $this->assertEquals('http://example.com/foo#foo=bar', $result3);
    }

    public function test_checkClientAuthoriseParams_GET()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'test';

        $expect = array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'client_details'    =>  array(
                'client_id' =>  'test',
                'client_secret' =>  'test',
                'redirect_uri'  =>  'http://example.com/test',
                'name'  =>  'Test Client'
            ),
            'response_type' =>  'code',
            'scopes'    =>  array(
                    0 => array(
                    'id'    =>  1,
                    'scope' =>  'test',
                    'name'  =>  'test',
                    'description'   =>  'test'
                )
            )
        );

        $result = $this->oauth->checkClientAuthoriseParams();

        $this->assertEquals($expect, $result);
    }

    public function test_checkClientAuthoriseParams_PassedParams()
    {
        unset($_GET['client_id']);
        unset($_GET['redirect_uri']);
        unset($_GET['response_type']);
        unset($_GET['scope']);

        $params = array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'response_type' =>  'code',
            'scope' =>  'test'
        );

        $this->assertEquals(array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'client_details'    =>  array(
                'client_id' =>  'test',
                'client_secret' =>  'test',
                'redirect_uri'  =>  'http://example.com/test',
                'name'  =>  'Test Client'
            ),
            'response_type' =>  'code',
            'scopes'    =>  array(0 => array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ), $this->oauth->checkClientAuthoriseParams($params));
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkClientAuthoriseParams_missingClientId()
    {
        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkClientAuthoriseParams_missingRedirectUri()
    {
        $_GET['client_id'] = 'test';

        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkClientAuthoriseParams_missingResponseType()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test';

        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_checkClientAuthoriseParams_missingScopes()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = ' ';

        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    4
     */
    public function test_checkClientAuthoriseParams_invalidScopes()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'blah';

        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    8
     */
    public function test_checkClientAuthoriseParams_invalidClient()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test2';
        $_GET['response_type'] = 'code';
        $_GET['scope'] = 'blah';

        $this->oauth->checkClientAuthoriseParams();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    3
     */
    public function test_checkClientAuthoriseParams_invalidResponseType()
    {
        $_GET['client_id'] = 'test';
        $_GET['redirect_uri'] = 'http://example.com/test';
        $_GET['response_type'] = 'blah';
        $_GET['scope'] = 'blah';

        $this->oauth->checkClientAuthoriseParams();
    }

    public function test_newAuthoriseRequest()
    {
        $result = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $this->assertEquals(40, strlen($result));
    }

    public function test_newAuthoriseRequest_isUnique()
    {
        $result1 = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $result2 = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $this->assertNotEquals($result1, $result2);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    7
     */
    public function test_issueAccessTokenNoRegisteredGrant()
    {
        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'authorization_code';
        $_POST['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken();
    }

    public function test_issueAccessToken_POST_authorization_code()
    {
        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'authorization_code';
        $_POST['code'] = $auth_code;

        $this->oauth->enableGrantType('authorization_code');
        $result = $this->oauth->issueAccessToken();

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

    public function test_issueAccessToken_PassedParams_authorization_code()
    {
        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['redirect_uri'] = 'http://example.com/test';
        $params['grant_type'] = 'authorization_code';
        $params['code'] = $auth_code;

        $this->oauth->enableGrantType('authorization_code');
        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

    public function test_issueAccessToken_refresh_token()
    {
        $this->oauth->enableGrantType('authorization_code');
        $this->oauth->enableGrantType('refresh_token');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['redirect_uri'] = 'http://example.com/test';
        $params['grant_type'] = 'authorization_code';
        $params['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);

        // Wait for a few seconds for the access token to age
        sleep(1);

        // Refresh the token
        $params2['client_id'] = 'test';
        $params2['client_secret'] = 'test';
        $params2['redirect_uri'] = 'http://example.com/test';
        $params2['grant_type'] = 'refresh_token';
        $params2['refresh_token'] = $result['refresh_token'];

        $result2 = $this->oauth->issueAccessToken($params2);

        $this->assertCount(5, $result2);
        $this->assertArrayHasKey('access_token', $result2);
        $this->assertArrayHasKey('token_type', $result2);
        $this->assertArrayHasKey('expires_in', $result2);
        $this->assertArrayHasKey('expires', $result2);
        $this->assertArrayHasKey('refresh_token', $result2);

        $this->assertNotEquals($result['access_token'], $result2['access_token']);
        $this->assertNotEquals($result['refresh_token'], $result2['refresh_token']);
        $this->assertNotEquals($result['expires'], $result2['expires']);
        $this->assertEquals($result['expires_in'], $result2['expires_in']);
        $this->assertEquals($result['token_type'], $result2['token_type']);
    }

    public function test_issueAccessToken_client_credentials()
    {
        $this->oauth->enableGrantType('client_credentials');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['redirect_uri'] = 'http://example.com/test';
        $params['grant_type'] = 'client_credentials';
        $params['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

    public function test_issueAccessToken_client_credentialsPOST()
    {
        $this->oauth->enableGrantType('client_credentials');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'client_credentials';
        $_POST['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken();

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

    public function test_issueAccessToken_client_credentials_withRefreshToken()
    {
        $this->oauth->enableGrantType('client_credentials');
        $this->oauth->enableGrantType('refresh_token');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['redirect_uri'] = 'http://example.com/test';
        $params['grant_type'] = 'client_credentials';
        $params['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);
    }

    public function test_issueAccessToken_refresh_tokenPOST()
    {
        $this->oauth->enableGrantType('authorization_code');
        $this->oauth->enableGrantType('refresh_token');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'authorization_code';
        $_POST['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken();

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);

        // Wait for a few seconds for the access token to age
        sleep(1);

        // Refresh the token
        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'refresh_token';
        $_POST['refresh_token'] = $result['refresh_token'];

        $result2 = $this->oauth->issueAccessToken();

        $this->assertCount(5, $result2);
        $this->assertArrayHasKey('access_token', $result2);
        $this->assertArrayHasKey('token_type', $result2);
        $this->assertArrayHasKey('expires_in', $result2);
        $this->assertArrayHasKey('expires', $result2);
        $this->assertArrayHasKey('refresh_token', $result2);

        $this->assertNotEquals($result['access_token'], $result2['access_token']);
        $this->assertNotEquals($result['refresh_token'], $result2['refresh_token']);
        $this->assertNotEquals($result['expires'], $result2['expires']);
        $this->assertEquals($result['expires_in'], $result2['expires_in']);
        $this->assertEquals($result['token_type'], $result2['token_type']);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_refresh_tokenMissingToken()
    {
        $this->oauth->enableGrantType('authorization_code');
        $this->oauth->enableGrantType('refresh_token');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'authorization_code';
        $_POST['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken();

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);

        // Wait for a few seconds for the access token to age
        sleep(1);

        // Refresh the token
        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['redirect_uri'] = 'http://example.com/test';
        $_POST['grant_type'] = 'refresh_token';

        $result2 = $this->oauth->issueAccessToken();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_invalid_refresh_token()
    {
        $this->oauth->enableGrantType('authorization_code');
        $this->oauth->enableGrantType('refresh_token');

        $auth_code = $this->oauth->newAuthoriseRequest('user', '123', array(
            'client_id' =>  'test',
            'redirect_uri'  =>  'http://example.com/test',
            'scopes'    =>  array(array(
                'id'    =>  1,
                'scope' =>  'test',
                'name'  =>  'test',
                'description'   =>  'test'
            ))
        ));

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['redirect_uri'] = 'http://example.com/test';
        $params['grant_type'] = 'authorization_code';
        $params['code'] = $auth_code;

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);

        // Wait for a few seconds for the access token to age
        sleep(1);

        // Refresh the token
        $params2['client_id'] = 'test';
        $params2['client_secret'] = 'test';
        $params2['redirect_uri'] = 'http://example.com/test';
        $params2['grant_type'] = 'refresh_token';
        $params2['refresh_token'] = 'blah';

        $result2 = $this->oauth->issueAccessToken($params2);
    }

    /**
     * @expectedException        Oauth2\Authentication\ServerException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_password_grant_Missing_Callback()
    {
        $this->oauth->enableGrantType('password');
    }

    public function test_issueAccessToken_password_grant()
    {
        $this->oauth->enableGrantType('password', function(){
            return true;
        });

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['grant_type'] = 'password';
        $params['username'] = 'alexbilbie';
        $params['password'] = 'helloworld';

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

    public function test_issueAccessToken_password_grantPOST()
    {
        $this->oauth->enableGrantType('password', function(){
            return true;
        });

        $_POST['client_id'] = 'test';
        $_POST['client_secret'] = 'test';
        $_POST['grant_type'] = 'password';
        $_POST['username'] = 'alexbilbie';
        $_POST['password'] = 'helloworld';

        $result = $this->oauth->issueAccessToken();

        $this->assertCount(4, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
    }

     public function test_issueAccessToken_password_grant_withRefreshToken()
    {
        $this->oauth->enableGrantType('password', function(){
            return true;
        });

        $this->oauth->enableGrantType('refresh_token');

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['grant_type'] = 'password';
        $params['username'] = 'alexbilbie';
        $params['password'] = 'helloworld';

        $result = $this->oauth->issueAccessToken($params);

        $this->assertCount(5, $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);
        $this->assertArrayHasKey('expires_in', $result);
        $this->assertArrayHasKey('expires', $result);
        $this->assertArrayHasKey('refresh_token', $result);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_password_grant_wrongCreds()
    {
        $this->oauth->enableGrantType('password', function(){
            return false;
        });

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['grant_type'] = 'password';
        $params['username'] = 'alexbilbie';
        $params['password'] = 'helloworld';

        $result = $this->oauth->issueAccessToken($params);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_password_grant_missingUsername()
    {
        $this->oauth->enableGrantType('password', function(){
            return true;
        });

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['grant_type'] = 'password';

        $result = $this->oauth->issueAccessToken($params);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_password_grant_missingPassword()
    {
        $this->oauth->enableGrantType('password', function(){
            return true;
        });

        $params['client_id'] = 'test';
        $params['client_secret'] = 'test';
        $params['grant_type'] = 'password';
        $params['username'] = 'alexbilbie';

        $result = $this->oauth->issueAccessToken($params);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_issueAccessToken_missingGrantType()
    {
        $this->oauth->issueAccessToken();
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    7
     */
    public function test_issueAccessToken_unsupportedGrantType()
    {
        $params['grant_type'] = 'blah';

        $this->oauth->issueAccessToken($params);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_completeAuthCodeGrant_missingClientId()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $method->invoke($this->oauth);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_completeAuthCodeGrant_missingClientSecret()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $authParams['client_id'] = 'test';

        $method->invoke($this->oauth, $authParams);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_completeAuthCodeGrant_missingRedirectUri()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $authParams['client_id'] = 'test';
        $authParams['client_secret'] = 'test';

        $method->invoke($this->oauth, $authParams);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    8
     */
    public function test_completeAuthCodeGrant_invalidClient()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $authParams['client_id'] = 'test';
        $authParams['client_secret'] = 'test123';
        $authParams['redirect_uri'] = 'http://example.com/test';

        $method->invoke($this->oauth, $authParams);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    0
     */
    public function test_completeAuthCodeGrant_missingCode()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $authParams['client_id'] = 'test';
        $authParams['client_secret'] = 'test';
        $authParams['redirect_uri'] = 'http://example.com/test';

        $method->invoke($this->oauth, $authParams);
    }

    /**
     * @expectedException        Oauth2\Authentication\ClientException
     * @expectedExceptionCode    9
     */
    public function test_completeAuthCodeGrant_invalidCode()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_completeAuthCodeGrant');
        $method->setAccessible(true);

        $authParams['client_id'] = 'test';
        $authParams['client_secret'] = 'test';
        $authParams['redirect_uri'] = 'http://example.com/test';
        $authParams['code'] = 'blah';

        $method->invoke($this->oauth, $authParams);
    }

    /**
     * @expectedException        Oauth2\Authentication\ServerException
     * @expectedExceptionMessage No registered database abstractor
     */
    public function test_noRegisteredDatabaseAbstractor()
    {
        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_dbCall');
        $method->setAccessible(true);

        $dbAbstractor = $reflector->getProperty('_db');
        $dbAbstractor->setAccessible(true);
        $dbAbstractor->setValue($this->oauth, null);

        $result = $method->invoke($this->oauth);
    }

    /**
     * @expectedException        Oauth2\Authentication\ServerException
     * @expectedExceptionMessage Registered database abstractor is not an instance of Oauth2\Authentication\Database
     */
    public function test_invalidRegisteredDatabaseAbstractor()
    {
        $fake = new stdClass;
        $this->oauth->registerDbAbstractor($fake);

        $reflector = new ReflectionClass($this->oauth);
        $method = $reflector->getMethod('_dbCall');
        $method->setAccessible(true);

        $result = $method->invoke($this->oauth);
    }

}
