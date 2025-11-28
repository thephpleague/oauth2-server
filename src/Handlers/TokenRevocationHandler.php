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
        [$tokenType, $tokenData] = $this->validateToken($request, $client);

        if ($tokenType !== null && $tokenData !== null) {
            if ($tokenType === 'refresh_token') {
                $this->refreshTokenRepository->revokeRefreshToken($tokenData['refresh_token_id']);
                $this->accessTokenRepository->revokeAccessToken($tokenData['access_token_id']);
            } elseif ($tokenType === 'access_token') {
                $this->accessTokenRepository->revokeAccessToken($tokenData['jti']);
            }
        }

        return $response
            ->withStatus(200)
            ->withHeader('cache-control', 'no-store');
    }
}
