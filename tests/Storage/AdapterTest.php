<?php

namespace LeagueTests\Storage;

use League\OAuth2\Server\Storage\Adapter;
use LeagueTests\Stubs\StubAbstractServer;
use \Mockery as M;

class AdapterTest extends \PHPUnit_Framework_TestCase
{
    function testSetGet()
    {
        $adapter = new Adapter;

        $reflector = new \ReflectionClass($adapter);
        $setMethod = $reflector->getMethod('setServer');
        $setMethod->setAccessible(true);
        $setMethod->invokeArgs($adapter, [new StubAbstractServer]);
        $getMethod = $reflector->getMethod('getServer');
        $getMethod->setAccessible(true);

        $this->assertTrue($getMethod->invoke($adapter) instanceof StubAbstractServer);
    }
}