<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenRevocationHandler extends AbstractTokenHandler
{
    public function respondToRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $client = $this->validateClient($request);
        $token = $this->validateToken($request, $client);

        if ($token !== null) {
            if ($token['type'] === 'refresh_token') {
                $this->refreshTokenRepository->revokeRefreshToken($token['data']['refresh_token_id']);
                $this->accessTokenRepository->revokeAccessToken($token['data']['access_token_id']);
            } elseif ($token['type'] === 'access_token') {
                $this->accessTokenRepository->revokeAccessToken($token['data']['jti']);
            } else {
                throw OAuthServerException::unsupportedTokenType();
            }
        }

        return $response
            ->withStatus(200)
            ->withHeader('cache-control', 'no-store');
    }
}
