<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateTimeImmutable;
use DateInterval;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use LogicException;
use PHPUnit\Framework\TestCase;

use function json_encode;
use function str_repeat;
use function time;
use function uniqid;

class AuthCodeGrantTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';
    private const REDIRECT_URI = 'https://foo/bar';

    private const CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function setUp(): void
    {

    }

    public function testGetIdentifier(): void
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        self::assertEquals('authorization_code', $grant->getIdentifier());
    }

    public function testCanRespondToAuthorizationRequest(): void
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

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

        self::assertTrue($grant->canRespondToAuthorizationRequest($request));
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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
            ]
        );

        self::assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestRedirectUriArray(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri([self::REDIRECT_URI]);
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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
            ]
        );

        self::assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestWithoutRedirectUri(): void
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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ]
        );

        $authorizationRequest = $grant->validateAuthorizationRequest($request);
        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);

        self::assertEmpty($authorizationRequest->getRedirectUri());
    }

    public function testValidateAuthorizationRequestCodeChallenge(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type'  => 'code',
                'client_id'      => 'foo',
                'redirect_uri'   => self::REDIRECT_URI,
                'code_challenge' => self::CODE_CHALLENGE,
            ]
        );

        self::assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidLengthTooShort(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type'  => 'code',
            'client_id'      => 'foo',
            'redirect_uri'   => self::REDIRECT_URI,
            'code_challenge' => str_repeat('A', 42),
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidLengthTooLong(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type'  => 'code',
            'client_id'      => 'foo',
            'redirect_uri'   => self::REDIRECT_URI,
            'code_challenge' => str_repeat('A', 129),
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestCodeChallengeInvalidCharacters(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => self::REDIRECT_URI,
            'code_challenge' => str_repeat('A', 42) . '!',
        ]);

        $this->expectException(OAuthServerException::class);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestMissingClientId(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidClientId(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriString(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriArray(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri([self::REDIRECT_URI]);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidCodeChallengeMethod(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => self::REDIRECT_URI,
            'code_challenge' => 'foobar',
            'code_challenge_method' => 'foo',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidScopes(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(null);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'foo',
            'state' => 'foo',
        ]);

        try {
            $grant->validateAuthorizationRequest($request);
        } catch (OAuthServerException $e) {
            self::assertSame(5, $e->getCode());
            self::assertSame('invalid_scope', $e->getErrorType());
            self::assertSame('https://foo/bar?state=foo', $e->getRedirectUri());

            return;
        }

        self::fail('The expected exception was not thrown');
    }

    public function testCompleteAuthorizationRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setRedirectUri('http://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testCompleteAuthorizationRequestWithMultipleRedirectUrisOnClient(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setRedirectUri(['uriOne', 'uriTwo']);

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testCompleteAuthorizationRequestDenied(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(false);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());
        $authRequest->setState('foo');

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        try {
            $grant->completeAuthorizationRequest($authRequest);
        } catch (OAuthServerException $e) {
            self::assertSame(9, $e->getCode());
            self::assertSame('access_denied', $e->getErrorType());
            self::assertSame('http://foo/bar?state=foo', $e->getRedirectUri());

            return;
        }

        self::fail('The expected exception was not thrown');
    }

    public function testRespondToAccessTokenRequest(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestWithDefaultRedirectUri(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(null);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestUsingHttpBasicAuth(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setIdentifier('foo');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $authCodeGrant = new AuthCodeGrant(
            $authCodeRepository,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $authCodeGrant->setClientRepository($clientRepositoryMock);
        $authCodeGrant->setScopeRepository($scopeRepositoryMock);
        $authCodeGrant->setAccessTokenRepository($accessTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [
                'Authorization' => 'Basic Zm9vOmJhcg==',
            ],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $authCodeGrant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestForPublicClient(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestNullRefreshToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertNull($response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestCodeChallengePlain(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge(self::CODE_VERIFIER);
        $ace->setCodeChallengeMethod('plain');

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $refreshTokenRepositoryMock,
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRespondToAccessTokenRequestCodeChallengeS256(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge(self::CODE_CHALLENGE);
        $ace->setCodeChallengeMethod('S256');

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testPKCEDowngradeBlocked(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(null);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $ace->getIdentifier()
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        /* @var StubResponseType $response */
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestMissingRedirectUri(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setConfidential();
        $client->setRedirectUri(self::REDIRECT_URI);

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri('http://foo/bar');
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'client_id'  => 'foo',
                'grant_type' => 'authorization_code',
                'code'       => $ace->getIdentifier()
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestRedirectUriMismatch(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setConfidential();
        $client->setRedirectUri('http://bar/foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri('http://foo/bar');
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'client_id'  => 'foo',
                'grant_type' => 'authorization_code',
                'redirect_uri' => 'http://bar/foo',
                'code'       => $ace->getIdentifier()
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRejectAccessTokenRequestIfRedirectUriSpecifiedButNotInOriginalAuthCodeRequest(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setConfidential();
        $client->setRedirectUri('http://bar/foo');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(null);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'client_id'  => 'foo',
                'grant_type' => 'authorization_code',
                'redirect_uri' => 'http://bar/foo',
                'code'       => $ace->getIdentifier()
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestMissingCode(): void
    {
        $client = new ClientEntity();

        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'redirect_uri'  => self::REDIRECT_URI,
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        /* @var StubResponseType $response */
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestWithAuthCodeNotAString(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => ['not', 'a', 'string'],
            ]
        );

        $this->expectException(OAuthServerException::class);
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestExpiredCode(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->sub(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Authorization code has expired');
        }
    }

    public function testRespondToAccessTokenRequestRevokedCode(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('isAuthCodeRevoked')->willReturn(true);
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);
        
        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Authorization code has been revoked');
            self::assertEquals($e->getErrorType(), 'invalid_grant');
        }
    }

    public function testRespondToAccessTokenRequestClientMismatch(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $client2 = new ClientEntity();

        $client2->setIdentifier('foo');
        $client2->setRedirectUri(self::REDIRECT_URI);
        $client2->setConfidential();

        $client3 = new ClientEntity();

        $client3->setIdentifier('bar');
        $client3->setRedirectUri(self::REDIRECT_URI);
        $client3->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client, $client2, $client3);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client3);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Authorization code was not issued to this client');
        }
    }

    public function testRespondToAccessTokenRequestBadCode(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();


        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getAuthCodeEntity')->willReturn(null);

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => 'badCode',
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getErrorType(), 'invalid_request');
            self::assertEquals($e->getHint(), 'Cannot validate the provided authorization code');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeVerifierPlain(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge('foobar');
        $ace->setCodeChallengeMethod('plain');

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'code'          => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Failed to verify `code_verifier`.');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeVerifierS256(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge('foobar');
        $ace->setCodeChallengeMethod('S256');

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => 'nope',
                'code'          => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMalformedCodeVerifierS256WithInvalidChars(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge(self::CODE_CHALLENGE);
        $ace->setCodeChallengeMethod('S256');

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => 'dqX7C-RbqjHYtytmhGTigKdZCXfxq-+xbsk9_GxUcaE', // Malformed code. Contains `+`.
                'code'          => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMalformedCodeVerifierS256WithInvalidLength(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge(self::CODE_CHALLENGE);
        $ace->setCodeChallengeMethod('S256');

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => self::REDIRECT_URI,
                'code_verifier' => 'dqX7C-RbqjHY', // Malformed code. Invalid length.
                'code'          => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Code Verifier must follow the specifications of RFC-7636.');
        }
    }

    public function testRespondToAccessTokenRequestMissingCodeVerifier(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);
        $ace->setCodeChallenge('foobar');
        $ace->setCodeChallengeMethod('plain');

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            self::assertEquals($e->getHint(), 'Check the `code_verifier` parameter');
        }
    }

    public function testAuthCodeRepositoryUniqueConstraintCheck(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setRedirectUri(self::REDIRECT_URI);
        $client->setIdentifier('clientIdentifier');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $authCodeRepository
            ->expects(self::exactly(2))
            ->method('persistNewAuthCode')
            ->willReturnCallback(function (): void {
                static $counter = 0;

                if (1 === ++$counter) {
                    throw UniqueTokenIdentifierConstraintViolationException::create();
                }
            });

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAuthCodeRepositoryFailToPersist(): void
    {
        $client = new ClientEntity();

        $client->setRedirectUri('http://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());
        $authCodeRepository->method('persistNewAuthCode')->willThrowException(OAuthServerException::serverError('something bad happened'));
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(7);

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAuthCodeRepositoryFailToPersistUniqueNoInfiniteLoop(): void
    {
        $client = new ClientEntity();

        $client->setRedirectUri('http://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());
        $authCodeRepository->method('persistNewAuthCode')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testRefreshTokenRepositoryUniqueConstraintCheck(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepository->method('getAuthCodeEntity')->willReturn($ace);

        $refreshTokenRepositoryMock
            ->expects(self::exactly(2))
            ->method('persistNewRefreshToken')
            ->willReturnCallback(function (): void {
                static $count = 0;

                if (1 === ++$count) {
                    throw UniqueTokenIdentifierConstraintViolationException::create();
                }
            });

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRefreshTokenRepositoryFailToPersist(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(7);

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testRefreshTokenRepositoryFailToPersistUniqueNoInfiniteLoop(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $ace = new AuthCodeEntity();
        $ace->setIdentifier(uniqid());
        $ace->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $ace->setClient($client);
        $ace->setRedirectUri(self::REDIRECT_URI);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $ace->setUser($user);
        $ace->setScopes(['foo']);

        $authCodeRepositoryMock->method('getAuthCodeEntity')->willReturn($ace);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => self::REDIRECT_URI,
                'code'         => $ace->getIdentifier()
            ]
        );

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new DateInterval('PT10M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $response->getRefreshToken());
    }

    public function testCompleteAuthorizationRequestNoUser(): void
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );

        $this->expectException(LogicException::class);

        $grant->completeAuthorizationRequest(new AuthorizationRequest());
    }

    public function testPublicClientAuthCodeRequestRejectedWhenCodeChallengeRequiredButNotGiven(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);

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
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => self::REDIRECT_URI,
            'state'         => 'foo',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testUseValidRedirectUriIfScopeCheckFails(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri([self::REDIRECT_URI, 'http://bar/foo']);
        $client->setConfidential();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(null);

        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'code',
                'client_id' => 'foo',
                'redirect_uri' => 'http://bar/foo',
            ]
        );

        // At this point I need to validate the auth request
        try {
            $grant->validateAuthorizationRequest($request);
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse(new Response());

            self::assertStringStartsWith('http://bar/foo', $response->getHeader('Location')[0]);
        }
    }
}
