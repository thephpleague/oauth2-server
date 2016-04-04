<?php

namespace LeagueTests\Jwt;

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

        $converter = new AccessTokenConverter('file://' . __DIR__ . '/../Stubs/private.key');
        $jwtBuilder = $converter->convert($token);

        $token = $jwtBuilder->getToken();
        $this->assertGreaterThan(0, strlen((string) $token));
        $this->assertEquals('test', $token->getClaim('sub'));
        $this->assertEquals('integer', gettype($token->getClaim('exp')));
        $this->assertEquals('integer', gettype($token->getClaim('nbf')));
        $this->assertEquals('integer', gettype($token->getClaim('iat')));
        $this->assertEquals(2, $token->getClaim('jti'));
        $this->assertEquals([$scope], $token->getClaim('scopes'));
    }
}
