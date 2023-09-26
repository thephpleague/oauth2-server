<?php

namespace LeagueTests\AuthorizationValidators;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class BearerTokenValidatorTest extends TestCase
{
    public function testBearerTokenValidatorAcceptsValidToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $bearerTokenValidator = new BearerTokenValidator($accessTokenRepositoryMock);
        $bearerTokenValidator->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

        $bearerTokenValidatorReflection = new ReflectionClass(BearerTokenValidator::class);
        $jwtConfiguration = $bearerTokenValidatorReflection->getProperty('jwtConfiguration');
        $jwtConfiguration->setAccessible(true);

        $validJwt = $jwtConfiguration->getValue($bearerTokenValidator)->builder()
            ->permittedFor('client-id')
            ->identifiedBy('token-id')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('user-id')
            ->withClaim('scopes', 'scope1 scope2 scope3 scope4')
            ->getToken(new Sha256(), InMemory::file(__DIR__ . '/../Stubs/private.key'));

        $request = (new ServerRequest())->withHeader('authorization', \sprintf('Bearer %s', $validJwt->toString()));

        $validRequest = $bearerTokenValidator->validateAuthorization($request);

        $this->assertArrayHasKey('authorization', $validRequest->getHeaders());
    }

    public function testBearerTokenValidatorRejectsExpiredToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $bearerTokenValidator = new BearerTokenValidator($accessTokenRepositoryMock);
        $bearerTokenValidator->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

        $bearerTokenValidatorReflection = new ReflectionClass(BearerTokenValidator::class);
        $jwtConfiguration = $bearerTokenValidatorReflection->getProperty('jwtConfiguration');
        $jwtConfiguration->setAccessible(true);

        $expiredJwt = $jwtConfiguration->getValue($bearerTokenValidator)->builder()
            ->permittedFor('client-id')
            ->identifiedBy('token-id')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->sub(new DateInterval('PT1H')))
            ->relatedTo('user-id')
            ->withClaim('scopes', 'scope1 scope2 scope3 scope4')
            ->getToken(new Sha256(), InMemory::file(__DIR__ . '/../Stubs/private.key'));

        $request = (new ServerRequest())->withHeader('authorization', \sprintf('Bearer %s', $expiredJwt->toString()));

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(9);

        $bearerTokenValidator->validateAuthorization($request);
    }
}
