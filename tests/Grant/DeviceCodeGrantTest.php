<?php

namespace LeagueTests\Grant;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Grant\DeviceCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\DeviceAuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\DeviceCodeEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

use function time;
use function uniqid;

class DeviceCodeGrantTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    /**
     * @var CryptTraitStub
     */
    protected $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier()
    {
        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M'),
            5
        );

        $this->assertEquals('urn:ietf:params:oauth:grant-type:device_code', $grant->getIdentifier());
    }

    public function testCanRespondToDeviceAuthorizationRequest()
    {
        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $this->assertTrue($grant->canRespondToDeviceAuthorizationRequest($request));
    }

    public function testValidateDeviceAuthorizationRequest()
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
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(), // TODO: Does this have a refersh token?
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setVerificationUri('http://foo/bar');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $this->assertInstanceOf(DeviceCodeResponse::class, $grant->respondToDeviceAuthorizationRequest($request));
    }

    public function testValidateDeviceAuthorizationRequestMissingClient()
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
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withParsedBody([
            'scope' => 'basic',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testValidateDeviceAuthorizationRequestEmptyScope()
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
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withParsedBody([
            'scope' => '',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testValidateDeviceAuthorizationRequestClientMismatch()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'bar',
            'scope' => 'basic',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToDeviceAuthorizationRequest($request);
    }

    public function testCompleteDeviceAuthorizationRequest()
    {
        $deviceCode = new DeviceCodeEntity();
        $deviceCode->setUserCode('foo');

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCode);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setVerificationUri('http://foo/bar');
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $grant->completeDeviceAuthorizationRequest($deviceCode->getUserCode(), 'userId');

        $this->assertEquals('userId', $deviceCode->getUserIdentifier());
    }

    public function testDeviceAuthorizationResponse()
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setConfidential();
        $client->setRedirectUri('http://foo/bar');

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($client);

        $scopeEntity = new ScopeEntity;
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
            \base64_encode(\random_bytes(36)),
            new StubResponseType()
        );

        $server->setDefaultScope(self::DEFAULT_SCOPE);

        $serverRequest = (new ServerRequest())->withParsedBody([
           'client_id'     => 'foo',
        ]);

         $deviceCodeGrant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $deviceCodeGrant->setEncryptionKey($this->cryptStub->getKey());
        $deviceCodeGrant->setVerificationUri('http://foo/bar');

        $server->enableGrantType($deviceCodeGrant);

        $response = $server->respondToDeviceAuthorizationRequest($serverRequest, new Response());

        $responseObject = json_decode($response->getBody()->__toString());

        $this->assertObjectHasAttribute('device_code', $responseObject);
        $this->assertObjectHasAttribute('user_code', $responseObject);
        $this->assertObjectHasAttribute('verification_uri', $responseObject);
        // TODO: $this->assertObjectHasAttribute('verification_uri_complete', $responseObject);
        $this->assertObjectHasAttribute('expires_in', $responseObject);
        // TODO: $this->assertObjectHasAttribute('interval', $responseObject);
    }

    public function testRespondToAccessTokenRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

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
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code'   => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
            'client_id'     => 'foo',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    public function testRespondToRequestMissingClient()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'device_code' => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestMissingDeviceCode()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

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
            new DateInterval('PT10M')
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

        // TODO: We need to be more specific with this exception
        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testIssueSlowDownError()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setLastPolledAt(new DateTimeImmutable());
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(13);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    function testIssueAuthorizationPendingError()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCode = new DeviceCodeEntity();
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCode);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(12);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    function testIssueExpiredTokenError()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $deviceCodeRepositoryMock = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCode = new DeviceCodeEntity();
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCode);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => uniqid(),
                        'expire_time' => time() - 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(11);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    // NEED TO ADD IN TESTS FOR:
    // access_denied - for this one, we need to add it to the completeDeviceAuthorizationRequest method
}
