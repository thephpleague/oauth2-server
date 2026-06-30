<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AudienceRestrictedAccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

class ClientCredentialsGrantTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';

    public function testGetIdentifier(): void
    {
        $grant = new ClientCredentialsGrant();
        self::assertEquals('client_credentials', $grant->getIdentifier());
    }

    public function testRespondToRequest(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ClientCredentialsGrant();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $accessTokenEventEmitted = false;

        $grant->getListenerRegistry()->subscribeTo(
            RequestEvent::ACCESS_TOKEN_ISSUED,
            function ($event) use (&$accessTokenEventEmitted): void {
                self::assertInstanceOf(RequestAccessTokenEvent::class, $event);

                $accessTokenEventEmitted = true;
            }
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);

        $responseType = new StubResponseType();

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertNotEmpty($response->getAccessToken()->getIdentifier());

        if (!$accessTokenEventEmitted) {
            self::fail('Access token issued event is not emitted.');
        }
    }

    public function testRespondToRequestCanCustomizeAudiencesThroughEvent(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client-id');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AudienceRestrictedAccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ClientCredentialsGrant();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $grant->getListenerRegistry()->subscribeTo(
            RequestEvent::ACCESS_TOKEN_AUDIENCES_RESOLVING,
            static function (\League\OAuth2\Server\RequestAccessTokenAudiencesEvent $event): void {
                $event->setAudiences(['https://event.example.com/']);
            }
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'resource'      => ['https://api.example.com/'],
        ]);

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($serverRequest, new StubResponseType(), new DateInterval('PT5M'));

        $issuedToken = $response->getAccessToken();
        self::assertInstanceOf(AudienceRestrictedAccessTokenEntity::class, $issuedToken);
        self::assertSame(['https://event.example.com/'], $issuedToken->getAudiences());
    }

    public function testRespondToRequestCanBeDeniedThroughAudienceEvent(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AudienceRestrictedAccessTokenEntity());
        $accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ClientCredentialsGrant();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $grant->getListenerRegistry()->subscribeTo(
            RequestEvent::ACCESS_TOKEN_AUDIENCES_RESOLVING,
            static function (\League\OAuth2\Server\RequestAccessTokenAudiencesEvent $event): void {
                $event->denyRequest('Denied by audience policy');
            }
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'resource'      => ['https://api.example.com/'],
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(9);

        $grant->respondToAccessTokenRequest($serverRequest, new StubResponseType(), new DateInterval('PT5M'));
    }
}
