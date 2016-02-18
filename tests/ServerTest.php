<?php

namespace LeagueTests;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Server;
use LeagueTests\Stubs\StubResponseType;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\Http\Message\ResponseInterface;

class ServerTest extends \PHPUnit_Framework_TestCase
{
    public function testRespondToRequestInvalidGrantType()
    {
        $server = new Server(
            $this->getMock(ClientRepositoryInterface::class),
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            '',
            new StubResponseType()
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new \DateInterval('PT1M'));

        $response = $server->respondToRequest();
        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertEquals(400, $response->getStatusCode());
    }

    public function testRespondToRequest()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn(new ClientEntity());

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            '',
            new StubResponseType()
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new \DateInterval('PT1M'));

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';
        $response = $server->respondToRequest();
        $this->assertEquals(200, $response->getStatusCode());
    }
}
