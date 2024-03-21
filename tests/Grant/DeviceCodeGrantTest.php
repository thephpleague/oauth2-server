<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\DeviceCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\DeviceCodeEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function json_encode;
use function random_bytes;
use function time;
use function uniqid;

class DeviceCodeGrantTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';
    private const INTERVAL_RATE = 10;

    protected CryptTraitStub $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier(): void
    {
        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $this::assertEquals('urn:ietf:params:oauth:grant-type:device_code', $grant->getIdentifier());
    }

    public function testCanRespondToDeviceAuthorizationRequest(): void
    {
        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $this::assertTrue($grant->canRespondToDeviceAuthorizationRequest($request));
    }

    public function testRespondToDeviceAuthorizationRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getNewDeviceCode')->willReturn(new DeviceCodeEntity());

        $scope = new ScopeEntity();
        $scope->setIdentifier('basic');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $deviceCodeResponse = $grant->respondToDeviceAuthorizationRequest($request);

        $responseJson = json_decode($deviceCodeResponse->generateHttpResponse(new Response())->getBody()->__toString());

        self::assertObjectHasProperty('device_code', $responseJson);
        self::assertObjectHasProperty('user_code', $responseJson);
        self::assertObjectHasProperty('verification_uri', $responseJson);
        self::assertEquals('http://foo/bar', $responseJson->verification_uri);
    }

    public function testRespondToDeviceAuthorizationRequestWithVerificationUriComplete(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getNewDeviceCode')->willReturn(new DeviceCodeEntity());

        $scope = new ScopeEntity();
        $scope->setIdentifier('basic');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setIncludeVerificationUriComplete(true);

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $deviceCodeResponse = $grant->respondToDeviceAuthorizationRequest($request);

        $responseJson = json_decode($deviceCodeResponse->generateHttpResponse(new Response())->getBody()->__toString());

        self::assertObjectHasProperty('device_code', $responseJson);
        self::assertObjectHasProperty('user_code', $responseJson);
        self::assertObjectHasProperty('verification_uri', $responseJson);
        self::assertObjectHasProperty('verification_uri_complete', $responseJson);
        self::assertEquals('http://foo/bar', $responseJson->verification_uri);
        self::assertEquals('http://foo/bar?user_code=' . $responseJson->user_code, $responseJson->verification_uri_complete);
    }

    public function testValidateDeviceAuthorizationRequestMissingClient(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withParsedBody([
            'scope' => 'basic',
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testValidateDeviceAuthorizationRequestEmptyScope(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withParsedBody([
            'scope' => '',
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testValidateDeviceAuthorizationRequestClientMismatch(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'bar',
            'scope' => 'basic',
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testCompleteDeviceAuthorizationRequest(): void
    {
        $deviceCode = new DeviceCodeEntity();
        $deviceCode->setUserCode('foo');

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCode);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar',
        );

        $grant->setEncryptionKey($this->cryptStub->getKey());

        $grant->completeDeviceAuthorizationRequest($deviceCode->getUserCode(), 'userId', true);

        $this::assertEquals('userId', $deviceCode->getUserIdentifier());
    }

    public function testDeviceAuthorizationResponse(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setConfidential();
        $client->setRedirectUri('http://foo/bar');

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($client);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('basic');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getNewDeviceCode')->willReturn(new DeviceCodeEntity());

        $server = new AuthorizationServer(
            $clientRepository,
            $accessRepositoryMock,
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/../Stubs/private.key',
            base64_encode(random_bytes(36)),
            new StubResponseType()
        );

        $server->setDefaultScope(self::DEFAULT_SCOPE);

        $serverRequest = (new ServerRequest())->withParsedBody([
           'client_id'     => 'foo',
        ]);

        $deviceCodeGrant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $deviceCodeGrant->setEncryptionKey($this->cryptStub->getKey());

        $server->enableGrantType($deviceCodeGrant);

        $response = $server->respondToDeviceAuthorizationRequest($serverRequest, new Response());

        $responseObject = json_decode($response->getBody()->__toString());

        $this::assertObjectHasProperty('device_code', $responseObject);
        $this::assertObjectHasProperty('user_code', $responseObject);
        $this::assertObjectHasProperty('verification_uri', $responseObject);
        $this::assertObjectHasProperty('expires_in', $responseObject);
    }

    public function testRespondToAccessTokenRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();

        $deviceCodeEntity->setUserIdentifier('baz');
        $deviceCodeEntity->setIdentifier('deviceCodeEntityIdentifier');
        $deviceCodeEntity->setUserCode('123456');
        $deviceCodeEntity->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
        $deviceCodeEntity->setClient($client);

        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $grant->completeDeviceAuthorizationRequest($deviceCodeEntity->getUserCode(), '1', true);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code'   => $this->cryptStub->doEncrypt(
                json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ],
                    JSON_THROW_ON_ERROR
                )
            ),
            'client_id'     => 'foo',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        $this::assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    public function testRespondToRequestMissingClient(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'device_code' => $this->cryptStub->doEncrypt(
                json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ],
                    JSON_THROW_ON_ERROR
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestMissingDeviceCode(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setUserIdentifier('baz');
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testIssueSlowDownError(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setLastPolledAt(new DateTimeImmutable());
        $deviceCodeEntity->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
        $deviceCodeEntity->setClient($client);
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ],
                    JSON_THROW_ON_ERROR
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(13);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testIssueAuthorizationPendingError(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
        $deviceCodeEntity->setClient($client);
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ],
                    JSON_THROW_ON_ERROR
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(12);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testIssueExpiredTokenError(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setExpiryDateTime(new DateTimeImmutable('-1 hour'));
        $deviceCodeEntity->setClient($client);
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() - 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ],
                    JSON_THROW_ON_ERROR
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(11);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testSettingDeviceCodeIntervalRate(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $deviceCode = new DeviceCodeEntity();

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getNewDeviceCode')->willReturn($deviceCode);

        $scope = new ScopeEntity();
        $scope->setIdentifier('basic');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M'),
            'http://foo/bar',
            self::INTERVAL_RATE
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setIntervalVisibility(true);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $deviceCodeResponse = $grant
            ->respondToDeviceAuthorizationRequest($request)
            ->generateHttpResponse(new Response());

        $deviceCode = json_decode((string) $deviceCodeResponse->getBody());

        $this::assertObjectHasProperty('interval', $deviceCode);
        $this::assertEquals(self::INTERVAL_RATE, $deviceCode->interval);
    }
    public function testIssueAccessDeniedError(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();

        $deviceCode = new DeviceCodeEntity();

        $deviceCode->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
        $deviceCode->setClient($client);
        $deviceCode->setUserCode('12345678');
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCode);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            'http://foo/bar'
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $grant->completeDeviceAuthorizationRequest($deviceCode->getUserCode(), '1', false);

        $serverRequest = (new ServerRequest())->withParsedBody([
                'client_id'     => 'foo',
                'device_code'   => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                        ],
                        JSON_THROW_ON_ERROR
                    ),
                ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(9);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }
}
