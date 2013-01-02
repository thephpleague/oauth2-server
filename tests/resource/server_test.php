<?php

class Resource_Server_test extends PHPUnit_Framework_TestCase {

    function setUp()
    {
        require_once('database_mock.php');
        $this->server = new Oauth2\Resource\Server();
        $this->db = new ResourceDB();

        $this->assertInstanceOf('Oauth2\Resource\Database', $this->db);
        $this->server->registerDbAbstractor($this->db);
    }

    function test_init_POST()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['oauth_token'] = 'test12345';

        $this->server->init();

        $reflector = new ReflectionClass($this->server);

        $_accessToken = $reflector->getProperty('_accessToken');
        $_accessToken->setAccessible(true);

        $_type = $reflector->getProperty('_type');
        $_type->setAccessible(true);

        $_typeId = $reflector->getProperty('_typeId');
        $_typeId->setAccessible(true);

        $_scopes = $reflector->getProperty('_scopes');
        $_scopes->setAccessible(true);

        $this->assertEquals($_accessToken->getValue($this->server), $_POST['oauth_token']);
        $this->assertEquals($_type->getValue($this->server), 'user');
        $this->assertEquals($_typeId->getValue($this->server), 123);
        $this->assertEquals($_scopes->getValue($this->server), array('foo', 'bar'));
    }

    function test_init_GET()
    {
        $_GET['oauth_token'] = 'test12345';

        $this->server->init();

        $reflector = new ReflectionClass($this->server);

        $_accessToken = $reflector->getProperty('_accessToken');
        $_accessToken->setAccessible(true);

        $_type = $reflector->getProperty('_type');
        $_type->setAccessible(true);

        $_typeId = $reflector->getProperty('_typeId');
        $_typeId->setAccessible(true);

        $_scopes = $reflector->getProperty('_scopes');
        $_scopes->setAccessible(true);

        $this->assertEquals($_accessToken->getValue($this->server), $_GET['oauth_token']);
        $this->assertEquals($_type->getValue($this->server), 'user');
        $this->assertEquals($_typeId->getValue($this->server), 123);
        $this->assertEquals($_scopes->getValue($this->server), array('foo', 'bar'));
    }

    function test_init_header()
    {
        // Test with authorisation header
        $this->markTestIncomplete('Authorisation header test has not been implemented yet.');
    }

    /**
     * @expectedException        \Oauth2\Resource\ClientException
     * @expectedExceptionMessage An access token was not presented with the request
     */
    function test_init_missingToken()
    {
        $this->server->init();
    }

    /**
     * @expectedException        \Oauth2\Resource\ClientException
     * @expectedExceptionMessage The access token is not registered with the resource server
     */
    function test_init_wrongToken()
    {
        $_POST['oauth_token'] = 'blah';
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->server->init();
    }

    function test_hasScope()
    {
        $_POST['oauth_token'] = 'test12345';
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->server->init();

        $this->assertEquals(true, $this->server->hasScope('foo'));
        $this->assertEquals(true, $this->server->hasScope('bar'));
        $this->assertEquals(true, $this->server->hasScope(array('foo', 'bar')));

        $this->assertEquals(false, $this->server->hasScope('foobar'));
        $this->assertEquals(false, $this->server->hasScope(array('foobar')));
    }

    function test___call()
    {
        $_POST['oauth_token'] = 'test12345';
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->server->init();

        $this->assertEquals(123, $this->server->isUser());
        $this->assertEquals(false, $this->server->isMachine());
    }

}