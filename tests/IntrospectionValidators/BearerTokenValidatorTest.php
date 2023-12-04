<?php

namespace LeagueTests\IntrospectionValidators;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\IntrospectionValidators\BearerTokenValidator;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use SebastianBergmann\CodeCoverage\InvalidArgumentException;

class BearerTokenValidatorTest extends TestCase
{
    public function testThrowExceptionWhenRequestMethodIsNotPost()
    {
        $this->expectException(OAuthServerException::class);

        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setMethodsExcept([
                'validateIntrospection',
            ])
            ->disableOriginalConstructor()
            ->getMock();

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('GET');

        $validator->validateIntrospection($requestMock);
    }

    public function testReturnsFalseWhenNoTokenPassed()
    {
        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setMethodsExcept([
                'validateIntrospection',
            ])
            ->disableOriginalConstructor()
            ->getMock();

        $validator->method('getTokenFromRequest')->will(
            $this->throwException(new InvalidArgumentException())
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('POST');

        $this->assertFalse($validator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsRevoked()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(true);

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

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('POST');
        $requestMock->method('getParsedBody')->willReturn([
            'token' => $validJwt->toString(),
        ]);

        $this->assertFalse($bearerTokenValidator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsExpired()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

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
            ->expiresAt((new DateTimeImmutable())->sub(new DateInterval('PT1H')))
            ->relatedTo('user-id')
            ->withClaim('scopes', 'scope1 scope2 scope3 scope4')
            ->getToken(new Sha256(), InMemory::file(__DIR__ . '/../Stubs/private.key'));

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('POST');
        $requestMock->method('getParsedBody')->willReturn([
            'token' => $validJwt->toString(),
        ]);

        $this->assertFalse($bearerTokenValidator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsIssuedByDifferentPrivateKey()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $bearerTokenValidator = new BearerTokenValidator($accessTokenRepositoryMock);
        $bearerTokenValidator->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

        $bearerTokenValidatorReflection = new ReflectionClass(BearerTokenValidator::class);
        $jwtConfiguration = $bearerTokenValidatorReflection->getProperty('jwtConfiguration');
        $jwtConfiguration->setAccessible(true);

        $invalidJwt = $jwtConfiguration->getValue($bearerTokenValidator)->builder()
            ->permittedFor('client-id')
            ->identifiedBy('token-id')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('user-id')
            ->withClaim('scopes', 'scope1 scope2 scope3 scope4')
            ->getToken(new Sha256(), InMemory::file(__DIR__ . '/../Stubs/private.key.crlf'));

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('POST');
        $requestMock->method('getParsedBody')->willReturn([
            'token' => $invalidJwt->toString(),
        ]);

        $this->assertFalse($bearerTokenValidator->validateIntrospection($requestMock));
    }

    public function testReturnsTrueWhenTokenIsValid()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(false);

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

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $requestMock->method('getMethod')->willReturn('POST');
        $requestMock->method('getParsedBody')->willReturn([
            'token' => $validJwt->toString(),
        ]);

        $this->assertTrue($bearerTokenValidator->validateIntrospection($requestMock));
    }
}
