<?php

namespace LeagueTests\ResponseTypes;

use Lcobucci\JWT\Token;
use League\OAuth2\Server\ResponseTypes\BearerTokenIntrospectionResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;

class BearerTokenIntrospectionResponseTest extends TestCase
{
    public function testInvalidIntrospectionResponse()
    {
        $responseType = new BearerTokenIntrospectionResponse();
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this->assertAttributeEquals(false, 'active', $json);
    }

    public function testValidIntrospectionResponse()
    {
        $responseType = $this->getMockBuilder(BearerTokenIntrospectionResponse::class)
            ->setMethods(['getTokenFromRequest'])
            ->getMock();

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $tokenMock->method('getClaim')->willReturn('value');

        $responseType->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $responseType->setValidity(true);
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

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

    public function testValidIntrospectionResponseWithExtraParams()
    {
        $responseType = $this->getMockBuilder(BearerTokenIntrospectionResponse::class)
            ->setMethods(['getTokenFromRequest', 'getExtraParams'])
            ->getMock();

        $tokenMock = $this->getMockBuilder(Token::class)
            ->getMock();

        $tokenMock->method('getClaim')->willReturn('value');

        $responseType->method('getTokenFromRequest')
            ->willReturn($tokenMock);

        $responseType->method('getExtraParams')
            ->willReturn(['extra' => 'param']);

        $responseType->setValidity(true);
        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertCorrectIntrospectionHeaders($response);

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
        $this->assertAttributeEquals('param', 'extra', $json);
    }

    private function assertCorrectIntrospectionHeaders(ResponseInterface $response)
    {
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
    }
}
