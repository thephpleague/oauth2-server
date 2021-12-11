<?php

namespace LeagueTests;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Stream;
use Laminas\Diactoros\StreamFactory;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\IntrospectionServer;
use League\OAuth2\Server\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\Introspection\AbstractResponseType;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

class IntrospectionServerTest extends TestCase
{
    public function setUp(): void
    {
        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/public.key', 0600);
    }

    public function testIfGetRequestThrowsInvalidMethodException()
    {
        $this->expectException(OAuthServerException::class);

        $introspectionServer = new IntrospectionServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/public.key'),
            null,
            $this->getMockBuilder(AuthorizationValidatorInterface::class)->getMock()
        );

        // invalid request method
        $request = new ServerRequest([], [], '/', 'GET');

        try {
            $introspectionServer->respondToIntrospectionRequest($request, new Response);
        } catch (OAuthServerException $e) {
            $this->assertEquals('access_denied', $e->getErrorType());
            $this->assertEquals(401, $e->getHttpStatusCode());
            $this->assertStringContainsString('Invalid request method', $e->getHint());
            throw $e;
        }
    }

    public function testIfUnauthorizedRequestThrowsAuthorizationException()
    {
        $this->expectException(OAuthServerException::class);

        $introspectionServer = new IntrospectionServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/public.key'),
            null
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        // expired token
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->sub(new DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        $token = (string) $accessToken;

        $request = new ServerRequest(
            [],
            [],
            '/',
            'POST',
            'php://input',
            ['Authorization' => 'Bearer ' . $token]
        );

        try {
            $introspectionServer->respondToIntrospectionRequest($request, new Response);
        } catch (OAuthServerException $e) {
            $this->assertEquals('access_denied', $e->getErrorType());
            $this->assertEquals(401, $e->getHttpStatusCode());
            throw $e;
        }
    }

    public function testIfServerRespondsWhenTokenIsMissing()
    {
        $introspectionServer = new IntrospectionServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/public.key'),
            null,
            $this->getMockBuilder(AuthorizationValidatorInterface::class)->getMock()
        );

        $request = new ServerRequest([], [], '/', 'POST', 'php://input');

        $response = $introspectionServer->respondToIntrospectionRequest($request, new Response);
        $response->getBody()->rewind();

        $responseData = json_decode($response->getBody()->getContents(), true);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals([
            'active' => false
        ], $responseData);
    }

    public function testIfServerRespondsWhenTokenIsValid()
    {
        $introspectionValidator = $this->getMockBuilder(IntrospectionValidatorInterface::class)->getMock();
        $introspectionValidator->method('validateIntrospection')->willReturn(true);

        $introspectionServer = new IntrospectionServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/public.key'),
            $introspectionValidator,
            $this->getMockBuilder(AuthorizationValidatorInterface::class)->getMock()
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $jwtConfiguration = Configuration::forSymmetricSigner(new Sha256(), InMemory::file('file://' . __DIR__ . '/Stubs/private.key'));
        $token = $jwtConfiguration
            ->builder()
            ->permittedFor('clientName')
            ->identifiedBy('test')
            ->issuedAt((new DateTimeImmutable('2016-01-01')))
            ->canOnlyBeUsedAfter((new DateTimeImmutable('2016-01-01')))
            ->expiresAt((new DateTimeImmutable('2017-01-01')))
            ->relatedTo('123')
            ->withClaim('scopes', ['a', 'b', 'c'])
            ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
            ->toString();

        $requestMock->method('getMethod')->willReturn('POST');
        $requestMock->method('getParsedBody')->willReturn(['token' => $token]);

        $response = $introspectionServer->respondToIntrospectionRequest($requestMock, new Response);
        $response->getBody()->rewind();
        $responseData = json_decode($response->getBody()->getContents(), true);

        $this->assertEquals([
            'active' => true,
            'token_type' => 'access_token',
            'scope' => [
                'a', 'b', 'c'
            ],
            'client_id' => [
                'clientName'
            ],
            'exp' => [
                'date' => '2017-01-01 00:00:00.000000',
                'timezone_type' => 1,
                'timezone' => '+00:00'
            ],
            'iat' => [
                'date' => '2016-01-01 00:00:00.000000',
                'timezone_type' => 1,
                'timezone' => '+00:00'
            ],
            'sub' => '123',
            'jti' => 'test',
        ], $responseData);
    }
}
