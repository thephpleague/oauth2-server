<?php

namespace LeagueTests\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Request;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class BearerResponseTypeTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerateHttpResponse()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $responseType = new BearerTokenResponse(
            'file://' . __DIR__ . '/../Utils/private.key',
            'file://' . __DIR__ . '/../Utils/public.key',
            $accessTokenRepositoryMock
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $response = $responseType->generateHttpResponse(new Response());

        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this->assertEquals('Bearer', $json->token_type);
        $this->assertTrue(isset($json->expires_in));
        $this->assertTrue(isset($json->access_token));
        $this->assertTrue(isset($json->refresh_token));
    }

    public function testDetermineAccessTokenInHeaderValidToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $responseType = new BearerTokenResponse(
            'file://' . __DIR__ . '/../Utils/private.key',
            'file://' . __DIR__ . '/../Utils/public.key',
            $accessTokenRepositoryMock
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $json->access_token));

        $request = $responseType->determineAccessTokenInHeader($request);

        $this->assertEquals('abcdef', $request->getAttribute('oauth_access_token_id'));
        $this->assertEquals('clientName', $request->getAttribute('oauth_client_id'));
        $this->assertEquals('123', $request->getAttribute('oauth_user_id'));
        $this->assertEquals([], $request->getAttribute('oauth_scopes'));
    }

    public function testDetermineAccessTokenInHeaderInvalidJWT()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $responseType = new BearerTokenResponse(
            'file://' . __DIR__ . '/../Utils/private.key',
            'file://' . __DIR__ . '/../Utils/public.key',
            $accessTokenRepositoryMock
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $json->access_token.'foo'));

        try {
            $responseType->determineAccessTokenInHeader($request);
        } catch (OAuthServerException $e) {
            $this->assertEquals(
                'Access token could not be verified',
                $e->getHint()
            );
        }
    }

    public function testDetermineAccessTokenInHeaderRevokedToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('isAccessTokenRevoked')->willReturn(true);


        $responseType = new BearerTokenResponse(
            'file://' . __DIR__ . '/../Utils/private.key',
            'file://' . __DIR__ . '/../Utils/public.key',
            $accessTokenRepositoryMock
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $response = $responseType->generateHttpResponse(new Response());
        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $json->access_token));

        try {
            $responseType->determineAccessTokenInHeader($request);
        } catch (OAuthServerException $e) {
            $this->assertEquals(
                'Access token has been revoked',
                $e->getHint()
            );
        }
    }

    public function testDetermineAccessTokenInHeaderInvalidToken()
    {
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $responseType = new BearerTokenResponse(
            'file://' . __DIR__ . '/../Utils/private.key',
            'file://' . __DIR__ . '/../Utils/public.key',
            $accessTokenRepositoryMock
        );

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', 'Bearer blah');

        try {
            $responseType->determineAccessTokenInHeader($request);
        } catch (OAuthServerException $e) {
            $this->assertEquals(
                'The JWT string must have two dots',
                $e->getHint()
            );
        }
    }
}
