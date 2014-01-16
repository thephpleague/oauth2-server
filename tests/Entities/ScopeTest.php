<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\Scope;
use \Mockery as M;

class ScopeTests extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $scope = new Scope($server);
        $scope->setId('foobar');
        $scope->setDescription('barfoo');

        $this->assertEquals('foobar', $scope->getId());
        $this->assertEquals('barfoo', $scope->getDescription());
    }
}