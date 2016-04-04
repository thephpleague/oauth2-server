<?php

namespace LeagueTests;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use League\OAuth2\Server\Jwt\BearerTokenValidator;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseFactory;
use League\OAuth2\Server\Server;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\UserEntity;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class ServerTest extends \PHPUnit_Framework_TestCase
{
    public function testRespondToRequestInvalidGrantType()
    {
        $server = new Server(
            $this->getMock(ClientRepositoryInterface::class),
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            new ResponseFactory(
                new AccessTokenConverter('file://' . __DIR__ . '/Stubs/private.key'),
                $this->getMock(RendererInterface::class)
            ),
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/Stubs/public.key'
            )
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new \DateInterval('PT1M'));

        try {
            $server->respondToRequest(ServerRequestFactory::fromGlobals(), new Response);
        } catch (OAuthServerException $e) {
            $this->assertEquals('unsupported_grant_type', $e->getErrorType());
            $this->assertEquals(400, $e->getHttpStatusCode());
        }
    }

    public function testRespondToRequest()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn(new ClientEntity());

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $scopeRepositoryMock,
            new ResponseFactory(
                new AccessTokenConverter('file://' . __DIR__ . '/Stubs/private.key'),
                $this->getMock(RendererInterface::class)
            ),
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/Stubs/public.key'
            )
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new \DateInterval('PT1M'));

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';
        $response = $server->respondToRequest(ServerRequestFactory::fromGlobals(), new Response);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testRespondToRequestPsrResponse()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setIdentifier('http://bar.com');

        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $scopeRepositoryMock,
            new ResponseFactory(
                new AccessTokenConverter('file://' . __DIR__ . '/Stubs/private.key'),
                $this->getMock(RendererInterface::class)
            ),
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/Stubs/public.key'
            )
        );

        $userRepository = $this->getMock(UserRepositoryInterface::class);
        $userRepository->method('getUserEntityByUserCredentials')->willReturn(new UserEntity());

        $server->enableGrantType(
            new AuthCodeGrant(
                $this->getMock(AuthCodeRepositoryInterface::class),
                $this->getMock(RefreshTokenRepositoryInterface::class),
                $userRepository,
                new MessageEncryption(
                    'file://' . __DIR__ . '/Stubs/private.key',
                    'file://' . __DIR__ . '/Stubs/public.key'
                ),
                new \DateInterval('PT1H')
            ),
            new \DateInterval('PT1M')
        );

        $_SERVER['HTTP_HOST'] = 'http://auth.com';
        $_SERVER['REQUEST_URI'] = '/auth';
        $_GET['response_type'] = 'code';
        $_GET['client_id'] = $client->getIdentifier();
        $_GET['redirect_uri'] = $client->getRedirectUri();
        $_POST['action'] = 'approve';
        $_POST['username'] = 'user';
        $_POST['password'] = 'pass';
        $response = $server->respondToRequest(ServerRequestFactory::fromGlobals(), new Response);
        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertTrue(strstr($response->getHeaderLine('location'), 'code=') !== false);
    }

    public function testValidateRequest()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            new ResponseFactory(
                new AccessTokenConverter('file://' . __DIR__ . '/Stubs/private.key'),
                $this->getMock(RendererInterface::class)
            ),
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/Stubs/public.key'
            )
        );

        try {
            $server->validateAuthenticatedRequest(ServerRequestFactory::fromGlobals());
        } catch (OAuthServerException $e) {
            $this->assertEquals('Missing "Authorization" header', $e->getHint());
        }
    }
}
