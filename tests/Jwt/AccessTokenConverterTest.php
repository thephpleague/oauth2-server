<?php

namespace LeagueTests\Jwt;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\ScopeEntity;

class AccessTokenConverterTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateJwt()
    {
        $scope = new ScopeEntity();
        $scope->setIdentifier('scope1');

        $client = new ClientEntity();
        $client->setIdentifier(1);
        $client->setName('test');

        $token = new AccessTokenEntity();
        $token->setClient($client);
        $token->setIdentifier(2);
        $token->setExpiryDateTime(new \DateTime());
        $token->setUserIdentifier('test');
        $token->addScope($scope);

        $converter = new AccessTokenConverter(new Builder(), 'file://' . __DIR__ . '/../Stubs/private.key');
        $jwt = $converter->convert($token);
        $this->assertGreaterThan(0, strlen((string) $jwt));
    }
}
