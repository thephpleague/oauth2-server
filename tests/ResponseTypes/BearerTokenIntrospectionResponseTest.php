<?php

namespace LeagueTests\ResponseTypes;

use Laminas\Diactoros\Response;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\ResponseTypes\Introspection\BearerTokenResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class BearerTokenIntrospectionResponseTest extends TestCase
{
    public function testInvalidIntrospectionResponse()
    {
        $responseType = new BearerTokenResponse();
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

        $response->getBody()->rewind();
        $json = \json_decode($response->getBody()->getContents(), true);
        $this->assertEquals([
            'active' => false,
        ], $json);
    }

    public function testValidIntrospectionResponse()
    {
        $responseType = $this->getMockBuilder(BearerTokenResponse::class)
            ->onlyMethods([
                'getTokenFromRequest',
                'getClaimFromToken',
            ])
            ->getMock();

        $tokenMock = $this->getMockBuilder(UnencryptedToken::class)
            ->getMock();

        $responseType->method('getTokenFromRequest')->willReturn($tokenMock);
        $responseType->method('getClaimFromToken')->willReturn('value');

        $responseType->setValidity(true);
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

        $response->getBody()->rewind();
        $json = \json_decode($response->getBody()->getContents(), true);
        $this->assertEquals([
            'active' => true,
            'token_type' => 'access_token',
            'scope' => 'value',
            'client_id' => 'value',
            'exp' => 'value',
            'iat' => 'value',
            'sub' => 'value',
            'jti' => 'value',
        ], $json);
    }

    public function testValidIntrospectionResponseWithExtraParams()
    {
        $responseType = $this->getMockBuilder(BearerTokenResponse::class)
            ->onlyMethods([
                'getTokenFromRequest',
                'getClaimFromToken',
                'getExtraParams',
            ])
            ->getMock();

        $tokenMock = $this->getMockBuilder(UnencryptedToken::class)
            ->getMock();

        $responseType->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $responseType->method('getClaimFromToken')
            ->willReturn('value');

        $responseType->method('getExtraParams')
            ->willReturn(['extra' => 'param']);

        $responseType->setValidity(true);
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

        $response->getBody()->rewind();
        $json = \json_decode($response->getBody()->getContents(), true);
        $this->assertEquals([
            'active' => true,
            'token_type' => 'access_token',
            'scope' => 'value',
            'client_id' => 'value',
            'iat' => 'value',
            'exp' => 'value',
            'sub' => 'value',
            'jti' => 'value',
            'extra' => 'param',
        ], $json);
    }

    private function assertCorrectIntrospectionHeaders(ResponseInterface $response)
    {
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
    }
}
