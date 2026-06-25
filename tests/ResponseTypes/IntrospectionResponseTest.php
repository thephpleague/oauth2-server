<?php

declare(strict_types=1);

namespace LeagueTests\ResponseTypes;

use DateTimeImmutable;
use Laminas\Diactoros\Response;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;
use PHPUnit\Framework\TestCase;

use function json_decode;

class IntrospectionResponseTest extends TestCase
{
    public function testGenerateHttpResponseForAccessToken(): void
    {
        $responseType = new IntrospectionResponse();
        $responseType->setActive(true);
        $responseType->setTokenType('access_token');
        $responseType->setTokenData([
            'scopes' => ['scope1', 'scope2'],
            'aud' => ['client1'],
            'username' => 'username1',
            'exp' => (new DateTimeImmutable())->setTimestamp(123456),
            'iat' => 111111,
            'nbf' => '654321',
            'sub' => 'user1',
            'iss' => 'https://example.com',
            'jti' => 'token1',
        ]);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
        self::assertSame([
            'active' => true,
            'scope' => 'scope1 scope2',
            'client_id' => 'client1',
            'username' => 'username1',
            'token_type' => 'Bearer',
            'exp' => 123456,
            'iat' => 111111,
            'nbf' => 654321,
            'sub' => 'user1',
            'aud' => ['client1'],
            'iss' => 'https://example.com',
            'jti' => 'token1',
        ], json_decode($response->getBody()->getContents(), true));
    }

    public function testGenerateHttpResponseForRefreshToken(): void
    {
        $responseType = new IntrospectionResponse();
        $responseType->setActive(true);
        $responseType->setTokenType('refresh_token');
        $responseType->setTokenData([
            'scopes' => ['scope1', 'scope2'],
            'client_id' => 'client1',
            'expire_time' => (new DateTimeImmutable())->setTimestamp(123456),
            'user_id' => 'user1',
            'refresh_token_id' => 'token1',
        ]);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
        self::assertSame([
            'active' => true,
            'scope' => 'scope1 scope2',
            'client_id' => 'client1',
            'exp' => 123456,
            'sub' => 'user1',
            'jti' => 'token1',
        ], json_decode($response->getBody()->getContents(), true));
    }

    public function testGenerateHttpResponseForInactiveToken(): void
    {
        $responseType = new IntrospectionResponse();
        $responseType->setActive(false);
        $responseType->setTokenType('access_token');
        $responseType->setTokenData([
            'scopes' => ['scope1', 'scope2'],
            'client_id' => 'client1',
        ]);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
        self::assertSame([
            'active' => false,
        ], json_decode($response->getBody()->getContents(), true));
    }

    public function testGenerateHttpResponseWithExtraParams(): void
    {
        $responseType = new IntrospectionResponseWithParams();
        $responseType->setActive(true);
        $responseType->setTokenType('access_token');
        $responseType->setTokenData([
            'scopes' => ['scope1', 'scope2'],
            'client_id' => 'client1',
            'jti' => null,
            'extension' => 'extension1',
        ]);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);
        self::assertSame([
            'active' => true,
            'scope' => 'scope1 scope2',
            'client_id' => 'client1',
            'token_type' => 'Bearer',
            'foo' => 'bar',
            'extended' => 'extension1',
        ], json_decode($response->getBody()->getContents(), true));
    }
}
