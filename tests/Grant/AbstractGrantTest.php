<?php

namespace LeagueTests\Grant;

use DateInterval;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
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
use PHPUnit\Framework\TestCase;

class AbstractGrantTest extends TestCase
{
    public function testHttpBasicWithPassword()
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . \base64_encode('Open:Sesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        $this->assertSame(['Open', 'Sesame'], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNoPassword()
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . \base64_encode('Open:'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        $this->assertSame(['Open', ''], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNotBasic()
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Foo ' . \base64_encode('Open:Sesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        $this->assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNotBase64()
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ||');
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        $this->assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testHttpBasicNoColon()
    {
        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withHeader('Authorization', 'Basic ' . \base64_encode('OpenSesame'));
        $basicAuthMethod = $abstractGrantReflection->getMethod('getBasicAuthCredentials');
        $basicAuthMethod->setAccessible(true);

        $this->assertSame([null, null], $basicAuthMethod->invoke($grantMock, $serverRequest));
    }

    public function testGetClientCredentialsClientSecretNotAString()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

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
                'client_id' => 'client_id',
                'client_secret' => ['not', 'a', 'string'],
            ]
        );
        $getClientCredentialsMethod = $abstractGrantReflection->getMethod('getClientCredentials');
        $getClientCredentialsMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $getClientCredentialsMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientPublic()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $result = $validateClientMethod->invoke($grantMock, $serverRequest);
        $this->assertEquals($client, $result);
    }

    public function testValidateClientConfidential()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'bar',
            'redirect_uri' => 'http://foo/bar',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $result = $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
        $this->assertEquals($client, $result);
    }

    public function testValidateClientMissingClientId()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = new ServerRequest();
        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientMissingClientSecret()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidClientSecret()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidRedirectUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'redirect_uri' => 'http://bar/foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientInvalidRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'redirect_uri' => 'http://bar/foo',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientMalformedRedirectUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'redirect_uri' => ['not', 'a', 'string'],
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true, true);
    }

    public function testValidateClientBadClient()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'bar',
        ]);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $validateClientMethod->invoke($grantMock, $serverRequest, true);
    }

    public function testCanRespondToRequest()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');

        $serverRequest = (new ServerRequest())->withParsedBody([
            'grant_type' => 'foobar',
        ]);

        $this->assertTrue($grantMock->canRespondToAccessTokenRequest($serverRequest));
    }

    public function testIssueRefreshToken()
    {
        $refreshTokenRepoMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepoMock
            ->expects($this->once())
            ->method('getNewRefreshToken')
            ->willReturn(new RefreshTokenEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setRefreshTokenTTL(new DateInterval('PT1M'));
        $grantMock->setRefreshTokenRepository($refreshTokenRepoMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $issueRefreshTokenMethod = $abstractGrantReflection->getMethod('issueRefreshToken');
        $issueRefreshTokenMethod->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        /** @var RefreshTokenEntityInterface $refreshToken */
        $refreshToken = $issueRefreshTokenMethod->invoke($grantMock, $accessToken);
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $refreshToken);
        $this->assertEquals($accessToken, $refreshToken->getAccessToken());
    }

    public function testIssueNullRefreshToken()
    {
        $refreshTokenRepoMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepoMock
            ->expects($this->once())
            ->method('getNewRefreshToken')
            ->willReturn(null);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setRefreshTokenTTL(new \DateInterval('PT1M'));
        $grantMock->setRefreshTokenRepository($refreshTokenRepoMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $issueRefreshTokenMethod = $abstractGrantReflection->getMethod('issueRefreshToken');
        $issueRefreshTokenMethod->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $this->assertNull($issueRefreshTokenMethod->invoke($grantMock, $accessToken));
    }

    public function testIssueAccessToken()
    {
        $accessTokenRepoMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepoMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grantMock->setAccessTokenRepository($accessTokenRepoMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);
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
        $this->assertInstanceOf(AccessTokenEntityInterface::class, $accessToken);
    }

    public function testIssueAuthCode()
    {
        $authCodeRepoMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepoMock->expects($this->once())->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setAuthCodeRepository($authCodeRepoMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $issueAuthCodeMethod = $abstractGrantReflection->getMethod('issueAuthCode');
        $issueAuthCodeMethod->setAccessible(true);

        $this->assertInstanceOf(
            AuthCodeEntityInterface::class,
            $issueAuthCodeMethod->invoke(
                $grantMock,
                new DateInterval('PT1H'),
                new ClientEntity(),
                123,
                'http://foo/bar',
                [new ScopeEntity()]
            )
        );
    }

    public function testGetCookieParameter()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('getCookieParameter');
        $method->setAccessible(true);

        $serverRequest = (new ServerRequest())->withCookieParams([
            'foo' => 'bar',
        ]);

        $this->assertEquals('bar', $method->invoke($grantMock, 'foo', $serverRequest));
        $this->assertEquals('foo', $method->invoke($grantMock, 'bar', $serverRequest, 'foo'));
    }

    public function testGetQueryStringParameter()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->method('getIdentifier')->willReturn('foobar');

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('getQueryStringParameter');
        $method->setAccessible(true);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'foo' => 'bar',
        ]);

        $this->assertEquals('bar', $method->invoke($grantMock, 'foo', $serverRequest));
        $this->assertEquals('foo', $method->invoke($grantMock, 'bar', $serverRequest, 'foo'));
    }

    public function testValidateScopes()
    {
        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->expects($this->exactly(3))->method('getScopeEntityByIdentifier')->willReturn($scope);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setScopeRepository($scopeRepositoryMock);

        $this->assertEquals([$scope, $scope, $scope], $grantMock->validateScopes('basic  test 0    '));
    }

    public function testValidateScopesBadScope()
    {
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(null);

        /** @var AbstractGrant $grantMock */
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setScopeRepository($scopeRepositoryMock);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grantMock->validateScopes('basic   ');
    }

    public function testGenerateUniqueIdentifier()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $abstractGrantReflection = new \ReflectionClass($grantMock);
        $method = $abstractGrantReflection->getMethod('generateUniqueIdentifier');
        $method->setAccessible(true);

        $this->assertIsString($method->invoke($grantMock));
    }

    public function testCanRespondToAuthorizationRequest()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $this->assertFalse($grantMock->canRespondToAuthorizationRequest(new ServerRequest()));
    }

    public function testValidateAuthorizationRequest()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $this->expectException(\LogicException::class);

        $grantMock->validateAuthorizationRequest(new ServerRequest());
    }

    public function testCompleteAuthorizationRequest()
    {
        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);

        $this->expectException(\LogicException::class);

        $grantMock->completeAuthorizationRequest(new AuthorizationRequest());
    }
}
