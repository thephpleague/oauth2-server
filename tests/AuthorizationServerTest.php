<?php

declare(strict_types=1);

namespace LeagueTests;

use DateInterval;
use Defuse\Crypto\Key;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\ServerRequestFactory;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\GrantType;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;

use function base64_encode;
use function chmod;
use function get_class;
use function random_bytes;

class AuthorizationServerTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';
    private const REDIRECT_URI = 'https://foo/bar';

    public function setUp(): void
    {
        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/private.key', 0600);
        chmod(__DIR__ . '/Stubs/public.key', 0600);
        chmod(__DIR__ . '/Stubs/private.key.crlf', 0600);
    }

    public function testKeyPermissions(): void
    {
        $permission = PHP_OS_FAMILY === 'Windows' ? '666' : '600';

        self::assertSame($permission, decoct(fileperms(__DIR__ . '/Stubs/private.key') & 0777));
        self::assertSame($permission, decoct(fileperms(__DIR__ . '/Stubs/public.key') & 0777));
        self::assertSame($permission, decoct(fileperms(__DIR__ . '/Stubs/private.key.crlf') & 0777));
    }

    public function testGrantTypeGetsEnabled(): void
    {
        $server = new AuthorizationServer(
            $this->getMockBuilder(ClientRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            base64_encode(random_bytes(36)),
            new StubResponseType()
        );

        $server->enableGrantType(new GrantType(), new DateInterval('PT1M'));

        $authRequest = $server->validateAuthorizationRequest($this->createMock(ServerRequestInterface::class));
        self::assertSame(GrantType::class, $authRequest->getGrantTypeId());
    }

    public function testRespondToRequestInvalidGrantType(): void
    {
        $server = new AuthorizationServer(
            $this->getMockBuilder(ClientRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            base64_encode(random_bytes(36)),
            new StubResponseType()
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new DateInterval('PT1M'));

        try {
            $server->respondToAccessTokenRequest(ServerRequestFactory::fromGlobals(), new Response());
        } catch (OAuthServerException $e) {
            self::assertEquals('unsupported_grant_type', $e->getErrorType());
            self::assertEquals(400, $e->getHttpStatusCode());
        }
    }

    public function testRespondToRequest(): void
    {
        $client = new ClientEntity();

        $client->setConfidential();
        $client->setRedirectUri(self::REDIRECT_URI);

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($client);
        $clientRepository->method('validateClient')->willReturn(true);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepositoryMock,
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/Stubs/private.key',
            base64_encode(random_bytes(36)),
            new StubResponseType()
        );

        $server->setDefaultScope(self::DEFAULT_SCOPE);
        $server->enableGrantType(new ClientCredentialsGrant(), new DateInterval('PT1M'));

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';
        $response = $server->respondToAccessTokenRequest(ServerRequestFactory::fromGlobals(), new Response());
        self::assertEquals(200, $response->getStatusCode());
    }

    public function testGetResponseType(): void
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $abstractGrantReflection = new ReflectionClass($server);
        $method = $abstractGrantReflection->getMethod('getResponseType');
        $method->setAccessible(true);

        self::assertInstanceOf(BearerTokenResponse::class, $method->invoke($server));
    }

    public function testGetResponseTypeExtended(): void
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $privateKey = 'file://' . __DIR__ . '/Stubs/private.key';
        $encryptionKey = 'file://' . __DIR__ . '/Stubs/public.key';

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $abstractGrantReflection = new ReflectionClass($server);
        $method = $abstractGrantReflection->getMethod('getResponseType');
        $method->setAccessible(true);

        $responseType = $method->invoke($server);

        $responseTypeReflection = new ReflectionClass($responseType);

        $privateKeyProperty = $responseTypeReflection->getProperty('privateKey');
        $privateKeyProperty->setAccessible(true);

        $encryptionKeyProperty = $responseTypeReflection->getProperty('encryptionKey');
        $encryptionKeyProperty->setAccessible(true);

        // generated instances should have keys setup
        self::assertSame($privateKey, $privateKeyProperty->getValue($responseType)->getKeyPath());
        self::assertSame($encryptionKey, $encryptionKeyProperty->getValue($responseType));
    }

    public function testMultipleRequestsGetDifferentResponseTypeInstances(): void
    {
        $privateKey = 'file://' . __DIR__ . '/Stubs/private.key';
        $encryptionKey = 'file://' . __DIR__ . '/Stubs/public.key';

        $responseTypePrototype = new class () extends BearerTokenResponse {
            protected CryptKeyInterface $privateKey;
            protected Key|string|null $encryptionKey = null;

            public function getPrivateKey(): CryptKeyInterface
            {
                return $this->privateKey;
            }

            public function getEncryptionKey(): Key|string|null
            {
                return $this->encryptionKey;
            }
        };

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            $privateKey,
            $encryptionKey,
            $responseTypePrototype
        );

        $abstractGrantReflection = new ReflectionClass($server);
        $method = $abstractGrantReflection->getMethod('getResponseType');
        $method->setAccessible(true);

        $responseTypeA = $method->invoke($server);
        $responseTypeB = $method->invoke($server);

        // generated instances should have keys setup
        self::assertSame($privateKey, $responseTypeA->getPrivateKey()->getKeyPath());
        self::assertSame($encryptionKey, $responseTypeA->getEncryptionKey());

        // all instances should be different but based on the same prototype
        self::assertSame(get_class($responseTypePrototype), get_class($responseTypeA));
        self::assertSame(get_class($responseTypePrototype), get_class($responseTypeB));
        self::assertNotSame($responseTypePrototype, $responseTypeA);
        self::assertNotSame($responseTypePrototype, $responseTypeB);
        self::assertNotSame($responseTypeA, $responseTypeB);
    }

    public function testCompleteAuthorizationRequest(): void
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $server->enableGrantType($grant);

        $client = new ClientEntity();

        $client->setRedirectUri('http://foo/bar');
        $client->setIdentifier('clientId');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $response = $server->completeAuthorizationRequest($authRequest, new Response());

        $locationHeader = $response->getHeader('Location')[0];

        self::assertStringStartsWith('http://foo/bar', $locationHeader);
        self::assertStringContainsString('code=', $locationHeader);
    }

    public function testValidateAuthorizationRequest(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $server = new AuthorizationServer(
            $clientRepositoryMock,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $server->setDefaultScope(self::DEFAULT_SCOPE);
        $server->enableGrantType($grant);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ]
        );

        self::assertInstanceOf(AuthorizationRequest::class, $server->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestUnregistered(): void
    {
        $server = new AuthorizationServer(
            $this->getMockBuilder(ClientRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(2);

        $server->validateAuthorizationRequest($request);
    }
}
