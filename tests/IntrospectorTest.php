<?php

namespace LeagueTests;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Introspector;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

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
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            new Parser()
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
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            new Parser()
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getMethod')->willReturn('POST');
        $this->assertNull($introspector->validateIntrospectionRequest($requestMock));
    }

    public function testRespondToRequestWithoutToken()
    {
        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            new Parser()
        );

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn([]);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertAttributeEquals(null, 'token', $introspectionResponse);
        $this->assertEquals(
            [
                'active' => false,
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testRespondToRequestWithInvalidToken()
    {
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(false);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertAttributeEquals(null, 'token', $introspectionResponse);
        $this->assertEquals(
            [
                'active' => false,
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testRespondToRequestWithExpiredToken()
    {
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(true);
        $tokenMock->method('validate')->willReturn(false);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertAttributeEquals(null, 'token', $introspectionResponse);
        $this->assertEquals(
            [
                'active' => false,
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testRespondToRequestWithRevokedToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $accessTokenRepositoryMock,
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(true);
        $tokenMock->method('validate')->willReturn(true);
        $accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(true);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertAttributeEquals(null, 'token', $introspectionResponse);
        $this->assertEquals(
            [
                'active' => false,
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testRespondToRequestWithValidToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $accessTokenRepositoryMock,
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(true);
        $tokenMock->method('validate')->willReturn(true);
        $tokenMock->method('getClaim')->willReturn('value');
        $accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(false);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertEquals(
            [
                'active' => true,
                'token_type' => 'access_token',
                'scope' => 'value',
                'client_id' => 'value',
                'exp' => 'value',
                'iat' => 'value',
                'sub' => 'value',
                'jti' => 'value',
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testRespondToRequestWithValidTokenWithExtraParams()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $accessTokenRepositoryMock,
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(true);
        $tokenMock->method('validate')->willReturn(true);
        $tokenMock->method('getClaim')->willReturn('value');
        $accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(false);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new class extends IntrospectionResponse {
            protected function getExtraParams()
            {
                return [
                    'custom' => 'parameter',
                ];
            }
        });

        $this->assertInstanceOf(IntrospectionResponse::class, $introspectionResponse);
        $this->assertEquals(
            [
                'active' => true,
                'token_type' => 'access_token',
                'scope' => 'value',
                'client_id' => 'value',
                'exp' => 'value',
                'iat' => 'value',
                'sub' => 'value',
                'jti' => 'value',
                'custom' => 'parameter',
            ],
            $introspectionResponse->getIntrospectionParams()
        );
    }

    public function testGenerateHttpResponseWithNoToken()
    {
        $responseType = new IntrospectionResponse();

        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());

        $this->assertAttributeEquals(false, 'active', $json);
    }

    public function testGenerateHttpResponseWithValidToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $parserMock = $this->getMockBuilder(Parser::class)->getMock();
        $tokenMock = $this->getMockBuilder(Token::class)->getMock();

        $introspector = new Introspector(
            $accessTokenRepositoryMock,
            new CryptKey('file://' . __DIR__ . '/Stubs/private.key'),
            $parserMock
        );

        $parserMock->method('parse')->willReturn($tokenMock);
        $tokenMock->method('verify')->willReturn(true);
        $tokenMock->method('validate')->willReturn(true);
        $tokenMock->method('getClaim')->willReturn('value');
        $accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(false);

        $requestMock = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $requestMock->method('getParsedBody')->willReturn(['token' => 'token']);

        $introspectionResponse = $introspector->respondToIntrospectionRequest($requestMock, new IntrospectionResponse);

        $response = $introspectionResponse->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());

        $this->assertAttributeEquals(true, 'active', $json);
        $this->assertAttributeEquals('access_token', 'token_type', $json);
        $this->assertAttributeEquals('value', 'scope', $json);
        $this->assertAttributeEquals('value', 'client_id', $json);
        $this->assertAttributeEquals('value', 'exp', $json);
        $this->assertAttributeEquals('value', 'iat', $json);
        $this->assertAttributeEquals('value', 'sub', $json);
        $this->assertAttributeEquals('value', 'jti', $json);
    }
}
