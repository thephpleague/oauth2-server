<?php

namespace LeagueTests\Grant;

use DateInterval;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

class RefreshTokenGrantTest extends TestCase
{
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
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $this->assertEquals('refresh_token', $grant->getIdentifier());
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequest($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects($this->once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->expects($this->once())->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestNullRefreshToken($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects($this->once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);
        $refreshTokenRepositoryMock->expects($this->never())->method('persistNewRefreshToken');

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new \DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertNull($responseType->getRefreshToken());
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToReducedScopes($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope = new ScopeEntity();
        $scope->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
            'scope'         => 'foo',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToUnexpectedScope($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scope->setIdentifier('foobar');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
            'scope'         => 'foobar',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(5);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestMissingOldToken($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestInvalidOldToken($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = 'foobar';

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestClientMismatch($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'bar',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestExpiredToken($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() - 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    /**
     * @dataProvider privateKeys
     */
    public function testRespondToRequestRevokedToken($privateKey)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(true);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey($privateKey));

        $oldRefreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function privateKeys(): array
    {
        return [
            'file key' => ['file://' . __DIR__ . '/../Stubs/private.key'],
            'inmemory key' => [file_get_contents(__DIR__ . '/../Stubs/private.key')],
        ];
    }
}
