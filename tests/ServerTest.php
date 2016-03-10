<?php

namespace LeagueTests;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\Server;
use LeagueTests\Stubs\StubResponseType;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\ServerRequest;

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

    public function testRespondToRequestPsrResponse()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setIdentifier('http://bar.com');

        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn($client);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            '',
            new StubResponseType()
        );

        $server->enableGrantType(
            new AuthCodeGrant(
                $this->getMock(AuthCodeRepositoryInterface::class),
                $this->getMock(RefreshTokenRepositoryInterface::class),
                $this->getMock(UserRepositoryInterface::class),
                new \DateInterval('PT1H')
            ),
            new \DateInterval('PT1M')
        );

        $_SERVER['HTTP_HOST'] = 'http://auth.com';
        $_SERVER['REQUEST_URI'] = '/auth';
        $_GET['response_type'] = 'code';
        $_GET['client_id'] = $client->getIdentifier();
        $_GET['redirect_uri'] = $client->getRedirectUri();
        $response = $server->respondToRequest();
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue($response instanceof ResponseInterface);
    }

    public function testGetResponseType()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            ''
        );

        $abstractGrantReflection = new \ReflectionClass($server);
        $method = $abstractGrantReflection->getMethod('getResponseType');
        $method->setAccessible(true);

        $this->assertTrue($method->invoke($server) instanceof BearerTokenResponse);
    }

    public function testValidateRequest()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            ''
        );

        try {
            $server->validateRequest(new ServerRequest());
        } catch (OAuthServerException $e) {
            $this->assertEquals('Missing "Authorization" header', $e->getHint());
        }
    }
}
