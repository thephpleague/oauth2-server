<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LogicException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

use function base64_encode;

class AbstractGrantTest extends TestCase
{
    public function testHttpBasicWithPassword(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . base64_encode('Open:Sesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame(['Open', 'Sesame'], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNoPassword(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . base64_encode('Open:'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame(['Open', ''], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNotBasic(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Foo ' . base64_encode('Open:Sesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicCaseInsensitive(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'bAsIc ' . base64_encode('Open:Sesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame(['Open', 'Sesame'], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNotBase64(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ||');
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNoColon(): void
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . base64_encode('OpenSesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        self::assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testGetClientCredentialsClientSecretNotAString(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'client_id'     => 'client_id',
                'client_secret' => ['not', 'a', 'string'],
            ]
        );
        $getClientCredentialsMethod = $abstractGrantReflection->getMethod('getClientCredentials');
        $getClientCredentialsMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $getClientCredentialsMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientPublic(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $result = $validateClientMethod->invoke($grantMock, $serverRequest);
        self::assertEquals($client, $result);
    }

    public function testValidateClientConfidential(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'redirect_uri'  => 'http://foo/bar',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $result = $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
        self::assertEquals($client, $result);
    }

    public function testValidateClientMissingClientId(): void
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = new ServerRequest();
        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientMissingClientSecret(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidClientSecret(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidRedirectUri(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'    => 'foo',
            'redirect_uri' => 'http://bar/foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidRedirectUriArray(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'    => 'foo',
            'redirect_uri' => 'http://bar/foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientMalformedRedirectUri(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'    => 'foo',
            'redirect_uri' => ['not', 'a', 'string'],
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientBadClient(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true);
    }

    public function testCanRespondToRequest(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');
        $grantMock->setDefaultScope('defaultScope');

        $serverRequest = (new ServerRequest())->withParsedBody([
            'grant_type' => 'foobar',
        ]);

        self::assertTrue($grantMock->canRespondToAccessTokenRequest($serverRequest));
    }

    public function testIssueRefreshToken(): void
    {
        $refreshTokenRepoMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepoMock
            ->expects(self::once())
            ->method('getNewRefreshToken')
            ->willReturn(new RefreshTokenEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setRefreshTokenTTL(new DateInterval('PT1M'));
        $grantMock->setRefreshTokenRepository($refreshTokenRepoMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $issueRefreshTokenMethod = $abstractGrantReflection->getMethod('issueRefreshToken');
        $issueRefreshTokenMethod->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient(new ClientEntity());

        /** @var RefreshTokenEntityInterface $refreshToken */
        $refreshToken = $issueRefreshTokenMethod->invoke($grantMock, $accessToken);

        self::assertEquals($accessToken, $refreshToken->getAccessToken());
    }

    public function testIssueNullRefreshToken(): void
    {
        $refreshTokenRepoMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepoMock
            ->expects(self::once())
            ->method('getNewRefreshToken')
            ->willReturn(null);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setRefreshTokenTTL(new DateInterval('PT1M'));
        $grantMock->setRefreshTokenRepository($refreshTokenRepoMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $issueRefreshTokenMethod = $abstractGrantReflection->getMethod('issueRefreshToken');
        $issueRefreshTokenMethod->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        self::assertNull($issueRefreshTokenMethod->invoke($grantMock, $accessToken));
    }

    public function testIssueAccessToken(): void
    {
        $accessTokenRepoMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepoMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grantMock->setAccessTokenRepository($accessTokenRepoMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $issueAccessTokenMethod = $abstractGrantReflection->getMethod('issueAccessToken');
        $issueAccessTokenMethod->setAccessible(true);

        /** @var AccessTokenEntityInterface $accessToken */
        $accessToken = $issueAccessTokenMethod->invoke(
            $grantMock,
            new DateInterval('PT1H'),
            new ClientEntity(),
            123,
            [new ScopeEntity()]
        );

        self::assertNotEmpty($accessToken->getIdentifier());
    }

    public function testIssueAuthCode(): void
    {
        $authCodeRepoMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepoMock->expects(self::once())->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setAuthCodeRepository($authCodeRepoMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $issueAuthCodeMethod = $abstractGrantReflection->getMethod('issueAuthCode');
        $issueAuthCodeMethod->setAccessible(true);

        $scope = new ScopeEntity();
        $scope->setIdentifier('scopeId');

        self::assertInstanceOf(
            AuthCodeEntityInterface::class,
            $issueAuthCodeMethod->invoke(
                $grantMock,
                new DateInterval('PT1H'),
                new ClientEntity(),
                123,
                'http://foo/bar',
                [$scope]
            )
        );
    }

    public function testGetCookieParameter(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('getCookieParameter');
        $method->setAccessible(true);

        $serverRequest = (new ServerRequest())->withCookieParams([
            'foo' => 'bar',
        ]);

        self::assertEquals('bar', $method->invoke($grantMock, 'foo', $serverRequest));
        self::assertEquals('foo', $method->invoke($grantMock, 'bar', $serverRequest, 'foo'));
    }

    public function testGetQueryStringParameter(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('getQueryStringParameter');
        $method->setAccessible(true);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'foo' => 'bar',
        ]);

        self::assertEquals('bar', $method->invoke($grantMock, 'foo', $serverRequest));
        self::assertEquals('foo', $method->invoke($grantMock, 'bar', $serverRequest, 'foo'));
    }

    public function testValidateScopes(): void
    {
        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->expects(self::exactly(3))->method('getScopeEntityByIdentifier')->willReturn($scope);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setScopeRepository($scopeRepositoryMock);

        self::assertEquals([$scope, $scope, $scope], $grantMock->validateScopes('basic  test 0    '));
    }

    public function testValidateScopesBadScope(): void
    {
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(null);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setScopeRepository($scopeRepositoryMock);

        $this->expectException(OAuthServerException::class);

        $grantMock->validateScopes('basic   ');
    }

    public function testGenerateUniqueIdentifier(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $abstractGrantReflection = new ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('generateUniqueIdentifier');
        $method->setAccessible(true);

        self::assertIsString($method->invoke($grantMock));
    }

    public function testCanRespondToAuthorizationRequest(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        self::assertFalse($grantMock->canRespondToAuthorizationRequest(new ServerRequest()));
    }

    public function testValidateAuthorizationRequest(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $this->expectException(LogicException::class);

        $grantMock->validateAuthorizationRequest(new ServerRequest());
    }

    public function testCompleteAuthorizationRequest(): void
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $this->expectException(LogicException::class);

        $grantMock->completeAuthorizationRequest(new AuthorizationRequest());
    }
}
