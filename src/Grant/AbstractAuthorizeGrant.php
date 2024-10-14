<?php

/**
 * Abstract authorization grant.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

use function http_build_query;

abstract class AbstractAuthorizeGrant extends AbstractGrant
{
    /**
     * @param array<array-key,mixed> $params
     */
    public function makeRedirectUri(string $uri, array $params = [], string $queryDelimiter = '?'): string
    {
        $uri .= str_contains($uri, $queryDelimiter) ? '&' : $queryDelimiter;

        return $uri . http_build_query($params);
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new AuthorizationRequest();
    }

    /**
     * Get the client redirect URI.
     */
    protected function getClientRedirectUri(ClientEntityInterface $client): string
    {
        return is_array($client->getRedirectUri())
            ? $client->getRedirectUri()[0]
            : $client->getRedirectUri();
    }
}
