<?php

namespace LeagueTests;

use LeagueTests\Stubs\StubAbstractServer;

class AbstractServerTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = new StubAbstractServer();
        $var = 0;
        $server->addEventListener('event.name', function() use ($var) {
            $var++;
            $this->assertSame(1, $var);
        });
        $server->getEventEmitter()->emit('event.name');
        $this->assertTrue($server->getRequest() instanceof \Symfony\Component\HttpFoundation\Request);
        $this->assertTrue($server->getEventEmitter() instanceof \League\Event\Emitter);


        $server2 = new StubAbstractServer();
        $server2->setRequest((new \Symfony\Component\HttpFoundation\Request));
        $server2->setEventEmitter(1);
        $this->assertTrue($server2->getRequest() instanceof \Symfony\Component\HttpFoundation\Request);

    }

    public function testGetStorageException()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ServerErrorException');
        $server = new StubAbstractServer();
        $server->getStorage('foobar');
    }
}
