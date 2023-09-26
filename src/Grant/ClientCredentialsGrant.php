<?php
/**
 * OAuth 2.0 Client credentials grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Client credentials grant class.
 */
class ClientCredentialsGrant extends AbstractGrant
{
    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        list($clientId) = $this->getClientCredentials($request);

        $client = $this->getClientEntityOrFail($clientId, $request);

        if (!$client->isConfidential()) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        // Validate request
        $this->validateClient($request);

        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        $privateClaims = [];

        if ($this->claimRepository !== null) {
            $privateClaims = $this->claimRepository->getClaims($this->getIdentifier(), $client);
        }

        // Issue and persist access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, null, $finalizedScopes, $privateClaims);

        // Send event to emitter
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'client_credentials';
    }
}
