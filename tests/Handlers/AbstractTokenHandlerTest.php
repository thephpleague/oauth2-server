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
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidatorInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
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

    public function testSetBearerTokenValidator(): void
    {
        $request = (new ServerRequest())->withParsedBody([
            'token' => 'abcdef',
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $validator = $this->createMock(BearerTokenValidatorInterface::class);
        $validator
            ->expects(self::once())
            ->method('validateBearerToken')
            ->with($request, 'abcdef', 'client1')
            ->willReturn(['foo' => 'bar']);

        $handler = $this->getAbstractTokenHandler();
        $handler->setBearerTokenValidator($validator);

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertSame(['type' => 'access_token', 'data' => ['foo' => 'bar']], $result);
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

        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
            $builder->permittedFor('client1')
                ->relatedTo('user1')
                ->identifiedBy('access1')
                ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime))
                ->withClaim('foo', 'bar'));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $accessToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        /** @var array{type: non-empty-string, data: array<non-empty-string, mixed>} $result */
        $result = (fn () => $this->validateToken($request, $client))->call($handler);
        $result['data']['exp'] = $result['data']['exp']->getTimestamp();

        self::assertSame(['type' => 'access_token', 'data' => [
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

        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
            $builder->permittedFor('client1')
                ->relatedTo('user1')
                ->identifiedBy('access1')
                ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $accessToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenIsExpired(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $expireTime = time() - 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
            $builder->permittedFor('client1')
                ->relatedTo('user1')
                ->identifiedBy('access1')
                ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $accessToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenWithMismatchClient(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $expireTime = time() + 1000;
        $accessToken = $this->getJwtToken(fn (Builder $builder) =>
            $builder->permittedFor('client2')
                ->relatedTo('user1')
                ->identifiedBy('access1')
                ->expiresAt((new DateTimeImmutable())->setTimestamp($expireTime)));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $accessToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateAccessTokenWithInvalidToken(): void
    {
        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('isAccessTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setAccessTokenRepository($accessTokenRepository);

        $request = (new ServerRequest())->withParsedBody([
            'token' => 'abcdef',
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

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

        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => $expireTime = time() + 1000,
            'client_id' => 'client1',
            'foo' => 'bar',
        ], flags: JSON_THROW_ON_ERROR));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $refreshToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertSame(['type' => 'refresh_token', 'data' => [
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

        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() + 1000,
            'client_id' => 'client1',
        ], flags: JSON_THROW_ON_ERROR));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $refreshToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenIsExpired(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() - 1000,
            'client_id' => 'client1',
        ], flags: JSON_THROW_ON_ERROR));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $refreshToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenWithMismatchClient(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $refreshToken = $this->encrypt(json_encode([
            'refresh_token_id' => 'refresh1',
            'expire_time' => time() + 1000,
            'client_id' => 'client2',
        ], flags: JSON_THROW_ON_ERROR));
        $request = (new ServerRequest())->withParsedBody([
            'token' => $refreshToken,
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

        self::assertNull($result);
    }

    public function testValidateRefreshTokenWithInvalidToken(): void
    {
        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('isRefreshTokenRevoked');

        $handler = $this->getAbstractTokenHandler();
        $handler->setRefreshTokenRepository($refreshTokenRepository);

        $request = (new ServerRequest())->withParsedBody([
            'token' => 'abcdef',
        ]);
        $client = new ClientEntity();
        $client->setIdentifier('client1');

        $result = (fn () => $this->validateToken($request, $client))->call($handler);

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
