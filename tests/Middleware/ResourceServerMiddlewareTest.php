<?php

namespace LeagueTests\Middleware;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class ResourceServerMiddlewareTest extends TestCase
{
    public function testValidResponse()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $token = $accessToken->convertToJWT(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                $this->assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testInvalidTimeResponse()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');

        $token = (new Builder())
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier(), true)
            ->issuedAt(time() + 100)
            ->canOnlyBeUsedAfter(time() + 100)
            ->expiresAt($accessToken->getExpiryDateTime()->getTimestamp())
            ->relatedTo($accessToken->getUserIdentifier())
            ->withClaim('scopes', $accessToken->getScopes())
            ->getToken(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                $this->assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testValidResponseDueToLeeway()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key',
            null,
            150
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');

        $token = (new Builder())
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier(), true)
            ->issuedAt(time() + 100)
            ->canOnlyBeUsedAfter(time() + 100)
            ->expiresAt($accessToken->getExpiryDateTime()->getTimestamp())
            ->relatedTo($accessToken->getUserIdentifier())
            ->withClaim('scopes', $accessToken->getScopes())
            ->getToken(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                $this->assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testValidResponseExpiredToken()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->sub(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $token = $accessToken->convertToJWT(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                $this->assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testErrorResponse()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', '');

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );

        $this->assertEquals(401, $response->getStatusCode());
    }
}
