<?php

namespace LeagueTests;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Introspector;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class IntrospectorTest extends TestCase
{
    public function setUp()
    {
        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/private.key', 0600);
    }

    public function testGetRequest()
    {
        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key')
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getMethod')->willReturn('GET');
        $this->expectException(OAuthServerException::class);

        try {
            $introspectionResponse = $introspector->validateIntrospectionRequest($requestMock);
        } catch (OAuthServerException $e) {
            $this->assertEquals('access_denied', $e->getErrorType());
            $this->assertEquals(401, $e->getHttpStatusCode());

            throw $e;
        }
    }

    public function testPostRequest()
    {
        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key')
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getMethod')->willReturn('POST');
        $this->assertNull($introspector->validateIntrospectionRequest($requestMock));
    }

    public function testRespondToInvalidRequest()
    {
        $validator = $this->getMockBuilder(IntrospectionValidatorInterface::class)->getMock();
        $validator->method('validateIntrospection')->willReturn(false);

        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $validator
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertEquals(
            [
                'active' => false,
            ],
            $introspectionResponse->getIntrospectionResponseParams()
        );
    }

    public function testRespondToValidRequest()
    {
        $validator = $this->getMockBuilder(IntrospectionValidatorInterface::class)->getMock();
        $validator->method('validateIntrospection')->willReturn(true);

        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $validator
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertEquals(
            [
                'active' => true,
            ],
            $introspectionResponse->getIntrospectionResponseParams()
        );
    }
}
