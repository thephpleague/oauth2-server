<?php

/**
 * OAuth 2.0 Bearer Token Response.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;

use function array_merge;
use function json_encode;
use function time;

class BearerTokenResponse extends AbstractResponseType
{
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $expireDateTime = $this->accessToken->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - time(),
            'access_token' => $this->accessToken->toString(),
        ];

        if (isset($this->refreshToken)) {
            $refreshTokenPayload = json_encode([
                    'client_id'        => $this->accessToken->getClient()->getIdentifier(),
                    'refresh_token_id' => $this->refreshToken->getIdentifier(),
                    'access_token_id'  => $this->accessToken->getIdentifier(),
                    'scopes'           => $this->accessToken->getScopes(),
                    'user_id'          => $this->accessToken->getUserIdentifier(),
                    'expire_time'      => $this->refreshToken->getExpiryDateTime()->getTimestamp(),
            ]);

            if ($refreshTokenPayload === false) {
                throw new LogicException('Error encountered JSON encoding the refresh token payload');
            }

            $responseParams['refresh_token'] = $this->encrypt($refreshTokenPayload);
        }

        $responseParams = json_encode(array_merge($this->getExtraParams($this->accessToken), $responseParams));

        if ($responseParams === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write($responseParams);

        return $response;
    }

    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array<array-key,mixed>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        return [];
    }
}
