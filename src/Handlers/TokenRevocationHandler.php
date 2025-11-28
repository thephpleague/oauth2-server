<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenRevocationHandler extends AbstractTokenHandler
{
    public function respondToRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $client = $this->validateClient($request);
        [$tokenType, $token] = $this->validateToken($request, $client);

        if ($tokenType !== null && $token !== null) {
            if ($tokenType === 'refresh_token') {
                $this->refreshTokenRepository->revokeRefreshToken($token['refresh_token_id']);
                $this->accessTokenRepository->revokeAccessToken($token['access_token_id']);
            } elseif ($tokenType === 'access_token') {
                $this->accessTokenRepository->revokeAccessToken($token['jti']);
            }
        }

        return $response
            ->withStatus(200)
            ->withHeader('cache-control', 'no-store');
    }
}
