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
use League\OAuth2\Server\RequestTypes\ResourceIndicatorAwareInterface;
use LogicException;

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

    /**
     * Propagate RFC 8707 `resource` parameters through the authorization
     * request. The ship-with {@see AuthorizationRequest} implements
     * {@see ResourceIndicatorAwareInterface}, so the fallback branch only
     * fires for custom implementations that override
     * {@see createAuthorizationRequest()} to return a non-aware instance.
     *
     * When the client sent a `resource` parameter but the authorization
     * request implementation cannot carry it, that is a library-level
     * misconfiguration (the consumer wired up a custom auth-request type
     * without opting into {@see ResourceIndicatorAwareInterface}), not a
     * protocol error. A {@see LogicException} is raised to fail fast in
     * development rather than surfacing an `invalid_target` redirect to the
     * end-user — mirroring the analogous taxonomy in
     * {@see AbstractGrant::applyResourceIndicators()}.
     *
     * @param list<non-empty-string> $resources
     *
     * @throws LogicException When the request implementation cannot accept
     *                        resource indicators but the client supplied one.
     */
    protected function applyResourcesToAuthorizationRequest(
        AuthorizationRequestInterface $authorizationRequest,
        array $resources
    ): void {
        if ($authorizationRequest instanceof ResourceIndicatorAwareInterface) {
            $authorizationRequest->setResources($resources);

            return;
        }

        if ($resources !== []) {
            throw new LogicException(
                'The authorization request implementation must implement '
                . ResourceIndicatorAwareInterface::class
                . ' to support RFC 8707 resource indicators.'
            );
        }
    }
}
