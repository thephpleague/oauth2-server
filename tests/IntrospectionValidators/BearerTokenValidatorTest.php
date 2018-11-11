<?php

namespace LeagueTests\IntrospectionValidators;

use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\IntrospectionValidators\BearerTokenValidator;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SebastianBergmann\CodeCoverage\InvalidArgumentException;

class BearerTokenValidatorTest extends TestCase
{
    public function testReturnsFalseWhenNoTokenPassed()
    {
        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->disableOriginalConstructor()
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $validator->method('getTokenFromRequest')->will(
            $this->throwException(new InvalidArgumentException())
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $this->assertFalse($validator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsRevoked()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(true);

        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setConstructorArgs([$accessTokenRepositoryMock])
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $validator->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $this->assertFalse($validator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsExpired()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(false);

        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setConstructorArgs([$accessTokenRepositoryMock])
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $tokenMock->method('validate')->willReturn(false);

        $validator->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $this->assertFalse($validator->validateIntrospection($requestMock));
    }

    public function testReturnsFalseWhenTokenIsUnverified()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(false);

        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setConstructorArgs([$accessTokenRepositoryMock])
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $validator->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $tokenMock->method('validate')->willReturn(true);
        $tokenMock->method('verify')->willReturn(false);

        $validator->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $this->assertFalse($validator->validateIntrospection($requestMock));
    }

    public function testReturnsTrueWhenTokenIsValid()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
            ->getMock();

        $accessTokenRepositoryMock->method('isAccessTokenRevoked')
            ->willReturn(false);

        $validator = $this->getMockBuilder(BearerTokenValidator::class)
            ->setConstructorArgs([$accessTokenRepositoryMock])
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $validator->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $tokenMock->method('validate')->willReturn(true);
        $tokenMock->method('verify')->willReturn(true);

        $validator->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)
            ->getMock();

        $this->assertTrue($validator->validateIntrospection($requestMock));
    }
}
