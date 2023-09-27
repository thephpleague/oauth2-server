<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use Laminas\Diactoros\Response;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class StubResponseType extends AbstractResponseType
{
    public function __construct()
    {
    }

    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }

    public function getRefreshToken(): RefreshTokenEntityInterface|null
    {
        return $this->refreshToken;
    }

    public function setAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function setRefreshToken(RefreshTokenEntityInterface $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function validateAccessToken(ServerRequestInterface $request): ServerRequestInterface
    {
        if ($request->getHeader('authorization')[0] === 'Basic test') {
            return $request->withAttribute('oauth_access_token_id', 'test');
        }

        throw OAuthServerException::accessDenied();
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        return new Response();
    }
}
