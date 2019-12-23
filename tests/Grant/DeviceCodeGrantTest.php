<?php

namespace LeagueTests\Grant;

use DateInterval;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Grant\DeviceCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\DeviceAuthorizationRequestRepository;
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
use Zend\Diactoros\ServerRequest;

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
        $requestRepositoryMock = $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $requestRepositoryMock,
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
            $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock(),
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

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new DeviceCodeGrant(
            $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'scope' => 'basic',
        ]);

        $this->assertInstanceOf(DeviceAuthorizationRequest::class, $grant->validateDeviceAuthorizationRequest($request));
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
            $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock(),
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

        $grant->validateDeviceAuthorizationRequest($request);
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
            $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock(),
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

        $grant->validateDeviceAuthorizationRequest($request);
    }

    public function testCompleteDeviceAuthorizationRequest()
    {
        $deviceAuthRequest = new DeviceAuthorizationRequest();
        $deviceAuthRequest->setClient(new ClientEntity());
        $deviceAuthRequest->setGrantTypeId('device_code');

        $deviceCodeRepository = $this->getMockBuilder(DeviceCodeRepositoryInterface::class)->getMock();
        $deviceCodeRepository->method('getNewDeviceCode')->willReturn(new DeviceCodeEntity());

        $grant = new DeviceCodeGrant(
            $deviceCodeRepository,
            $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setEncryptionKey($this->cryptStub->getKey());

        $this->assertInstanceOf(DeviceCodeResponse::class, $grant->completeDeviceAuthorizationRequest($deviceAuthRequest));
    }

    public function testRespondToRequest()
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
        $requestRepositoryMock = $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock();
        $requestRepositoryMock->method('getLast')->willReturn(null);
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setUserIdentifier('baz');
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $requestRepositoryMock,
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
            'client_id'     => 'foo',
            'device_code'   => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => \uniqid(),
                        'expire_time' => \time() + 3600,
                        'client_id' => 'foo',
                        'user_code' => '12345678',
                        'scopes' => ['foo'],
                        'verification_uri' => 'http://foo/bar',
                    ]
                )
            ),
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
        $requestRepositoryMock = $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $requestRepositoryMock,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'device_code' => $this->cryptStub->doEncrypt(
                \json_encode(
                    [
                        'device_code_id' => \uniqid(),
                        'expire_time' => \time() + 3600,
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
        $requestRepositoryMock = $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock();
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setUserIdentifier('baz');
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $requestRepositoryMock,
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
        $requestRepositoryMock = $this->getMockBuilder(DeviceAuthorizationRequestRepository::class)->getMock();
        $requestRepositoryMock->method('getLast')->willReturn(new \DateTimeImmutable());
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setUserIdentifier('baz');
        $deviceCodeRepositoryMock->method('getDeviceCodeEntityByDeviceCode')->willReturn($deviceCodeEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new DeviceCodeGrant(
            $deviceCodeRepositoryMock,
            $requestRepositoryMock,
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
                        'device_code_id' => \uniqid(),
                        'expire_time' => \time() + 3600,
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
}
