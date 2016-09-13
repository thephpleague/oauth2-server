<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ScopeEntity;
use Mockery as M;

class ScopeEntityTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $scope = (new ScopeEntity($server))->hydrate([
            'id'          => 'foobar',
            'description' => 'barfoo',
        ]);

        $this->assertEquals('foobar', $scope->getId());
        $this->assertEquals('barfoo', $scope->getDescription());

        $this->assertTrue(is_array($scope->jsonSerialize()));
    }
}
