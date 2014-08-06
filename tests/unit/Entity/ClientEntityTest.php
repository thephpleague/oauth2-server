<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ClientEntity;
use \Mockery as M;

class ClientTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $client = (new ClientEntity($server))->hydrate([
            'id' => 'foobar',
            'secret' => 'barfoo',
            'name' => 'Test Client',
            'redirectUri' => 'http://foo/bar'
        ]);

        $this->assertEquals('foobar', $client->getId());
        $this->assertEquals('barfoo', $client->getSecret());
        $this->assertEquals('Test Client', $client->getName());
        $this->assertEquals('http://foo/bar', $client->getRedirectUri());
    }
}
