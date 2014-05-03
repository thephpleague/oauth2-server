<?php

namespace LeagueTests;

use LeagueTests\Stubs\StubAbstractServer;

class AbstractServerTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = new StubAbstractServer();
        $this->assertTrue($server->getRequest() instanceof \Symfony\Component\HttpFoundation\Request);

        $server2 = new StubAbstractServer();
        $server2->setRequest((new \Symfony\Component\HttpFoundation\Request));
        $this->assertTrue($server2->getRequest() instanceof \Symfony\Component\HttpFoundation\Request);
    }

    public function testGetStorageException()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ServerErrorException');
        $server = new StubAbstractServer();
        $server->getStorage('foobar');
    }
}
