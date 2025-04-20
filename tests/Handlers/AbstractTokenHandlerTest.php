<?php

declare(strict_types=1);

namespace LeagueTests\Handlers;

use Closure;
use DateTimeImmutable;
use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\AuthorizationValidators\JwtValidatorInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Handlers\AbstractTokenHandler;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function random_bytes;
use function time;

class AbstractTokenHandlerTest extends TestCase
{
    use CryptTrait;

    public function setUp(): void
    {
        $this->setEncryptionKey(base64_encode(random_bytes(36)));
    }

    public function testSetJwtValidator(): void
    {
        $request = new ServerRequest();
        $accessToken = 'abcdef';
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $jwtValidator = $this->createMock(JwtValidatorInterface::class);
        $jwtValidator
            ->expects(self::once())
            ->method('validateJwt')
            ->with($request, 'abcdef', 'client1')
            ->willReturn(['foo' => 'bar']);

        $handler = $this->getAbstractTokenHandler();
        $handler->setJwtValidator($jwtValidator);

        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);

        self::assertSame(['access_token', ['foo' => 'bar']], $result);
    }

    public function testValidateToken(): void
    {
        $client = new ClientEntity();
        $request = new ServerRequest();

        try {
            (fn () => $this->validateToken($request, $client))->call($this->getAbstractTokenHandlerWithToken());

            self::fail('The expected exception was not thrown');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_request', $e->getErrorType());
        }

        $request = (new ServerRequest())->withParsedBody(['token' => 'token1']);

        self::assertSame(['access_token', ['foo' => 'bar']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(accessToken: ['foo' => 'bar'], refreshToken: ['bar' => 'foo'])
        ));
        self::assertSame(['access_token', ['foo' => 'bar']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(accessToken: ['foo' => 'bar'])
        ));
        self::assertSame(['refresh_token', ['bar' => 'foo']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(refreshToken: ['bar' => 'foo'])
        ));
        self::assertSame([null, null], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken()
        ));

        $request = (new ServerRequest())->withParsedBody(['token' => 'token1', 'token_type_hint' => 'access_token']);

        self::assertSame(['access_token', ['foo' => 'bar']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(accessToken: ['foo' => 'bar'], refreshToken: ['bar' => 'foo'])
        ));
        self::assertSame(['refresh_token', ['bar' => 'foo']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(refreshToken: ['bar' => 'foo'])
        ));
        self::assertSame([null, null], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken()
        ));

        $request = (new ServerRequest())->withParsedBody(['token' => 'token1', 'token_type_hint' => 'refresh_token']);

        self::assertSame(['refresh_token', ['bar' => 'foo']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(accessToken: ['foo' => 'bar'], refreshToken: ['bar' => 'foo'])
        ));
        self::assertSame(['access_token', ['foo' => 'bar']], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken(accessToken: ['foo' => 'bar'])
        ));
        self::assertSame([null, null], (fn () => $this->validateToken($request, $client))->call(
            $this->getAbstractTokenHandlerWithToken()
        ));
    }

    public function testValidateAccessToken(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository
            ->expects(self::once())
            ->method('isAccessTokenRevoked')
            ->with('access1')
            ->willReturn(false);

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = new ServerRequest();
        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
            $builder->permittedFor('client1')
                ->relatedTo('user1')
                ->identifiedBy('access1')
                ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime))
                ->withClaim('foo', 'bar'));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        /** @var array{0:non-empty-string, 1:array<non-empty-string, mixed>} $result */
        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);
        $result[1]['exp'] = $result[1]['exp']->getTimestamp();

        self::assertSame(['access_token', [
            'aud' => ['client1'],
            'sub' => 'user1',
            'jti' => 'access1',
            'exp' => $expireTime,
            'foo' => 'bar',
        ]], $result);
    }

    public function testValidateAccessTokenIsRevoked(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository
            ->expects(self::once())
            ->method('isAccessTokenRevoked')
            ->with('access1')
            ->willReturn(true);

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = new ServerRequest();
        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
        $builder->permittedFor('client1')
            ->relatedTo('user1')
            ->identifiedBy('access1')
            ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenIsExpired(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = new ServerRequest();
        $expireTime = time() - 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
        $builder->permittedFor('client1')
            ->relatedTo('user1')
            ->identifiedBy('access1')
            ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenWithMismatchClient(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = new ServerRequest();
        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
        $builder->permittedFor('client2')
            ->relatedTo('user1')
            ->identifiedBy('access1')
            ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenWithInvalidToken(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = new ServerRequest();
        $accessToken = 'abcdef';
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateAccessToken($request, $accessToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshToken(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository
            ->expects(self::once())
            ->method('isRefreshTokenRevoked')
            ->with('refresh1')
            ->willReturn(false);

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = new ServerRequest();
        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => $expireTime = time() + 1000,
            'client_id' => 'client1',
            'foo' => 'bar',
        ], flags: JSON_THROW_ON_ERROR));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateRefreshToken($request, $refreshToken, $client))->call($handler);

        self::assertSame(['refresh_token', [
            'refresh_token_id' => 'refresh1',
            'expire_time' => $expireTime,
            'client_id' => 'client1',
            'foo' => 'bar',
        ]], $result);
    }

    public function testValidateRefreshTokenIsRevoked(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository
            ->expects(self::once())
            ->method('isRefreshTokenRevoked')
            ->with('refresh1')
            ->willReturn(true);

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = new ServerRequest();
        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() + 1000,
            'client_id' => 'client1',
        ], flags: JSON_THROW_ON_ERROR));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateRefreshToken($request, $refreshToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenIsExpired(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = new ServerRequest();
        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() - 1000,
            'client_id' => 'client1',
        ], flags: JSON_THROW_ON_ERROR));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateRefreshToken($request, $refreshToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenWithMismatchClient(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = new ServerRequest();
        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() + 1000,
            'client_id' => 'client2',
        ], flags: JSON_THROW_ON_ERROR));
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateRefreshToken($request, $refreshToken, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenWithInvalidToken(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = new ServerRequest();
        $refreshToken = 'abcdef';
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateRefreshToken($request, $refreshToken, $client))->call($handler);

        self::assertNull($result);
    }

    /**
     * @return AbstractTokenHandler&MockObject
     */
    private function getAbstractTokenHandler(): MockObject
    {
        $handler = $this->getMockBuilder(AbstractTokenHandler::class)->onlyMethods(['respondToRequest'])->getMock();

        $handler->setEncryptionKey($this->encryptionKey);
        $handler->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

        return $handler;
    }

    /**
     * @param array<non-empty-string, mixed>|null $accessToken
     * @param array<non-empty-string, mixed>|null $refreshToken
     *
     * @return AbstractTokenHandler&MockObject
     */
    private function getAbstractTokenHandlerWithToken(?array $accessToken = null, ?array $refreshToken = null): MockObject
    {
        $handler = $this->getMockBuilder(AbstractTokenHandler::class)
            ->onlyMethods(['respondToRequest', 'validateAccessToken', 'validateRefreshToken'])
            ->getMock();

        $handler->method('validateAccessToken')
            ->willReturn($accessToken === null ? null : ['access_token', $accessToken]);

        $handler->method('validateRefreshToken')
            ->willReturn($refreshToken === null ? null : ['refresh_token', $refreshToken]);

        return $handler;
    }

    /**
     * @param Closure(Builder): Builder $withBuilder
     *
     * @return non-empty-string
     */
    private function getJwtToken(Closure $withBuilder): string
    {
        $privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');

        $contents = $privateKey->getKeyContents();

        if ($contents === '') {
            $contents = 'empty';
        }

        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($contents, $privateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty')
        );

        return $withBuilder($configuration->builder())
            ->getToken($configuration->signer(), $configuration->signingKey())
            ->toString();
    }
}
