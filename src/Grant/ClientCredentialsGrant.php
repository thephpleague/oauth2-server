<?php

/**
 * OAuth 2.0 Client credentials grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestAccessTokenAudiencesEvent;
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
    ): ResponseTypeInterface {
        $client = $this->validateClient($request);

        if (!$client->isConfidential()) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        //RFC 8707: parse resource indicators
        $audiences = $this->parseResourceIndicators($this->getRawRequestParameter('resource', $request));

        // Build → apply audiences → persist, in that order. applyResourceIndicators()
        // throws LogicException when the access token entity does not implement
        // AudienceRestrictedTokenInterface; running it before persistAccessToken()
        // ensures a misconfigured consumer fails fast without leaving an orphaned
        // row in the token repository.
        $accessToken = $this->buildAccessToken($accessTokenTTL, $client, null, $finalizedScopes);
        $audiencesEvent = new RequestAccessTokenAudiencesEvent(
            RequestEvent::ACCESS_TOKEN_AUDIENCES_RESOLVING,
            $request,
            $accessToken,
            $audiences
        );
        $this->getEmitter()->emit($audiencesEvent);

        if ($audiencesEvent->isRequestDenied()) {
            throw OAuthServerException::accessDenied($audiencesEvent->getDenyReason());
        }

        $audiences = $audiencesEvent->getAudiences();
        $this->applyResourceIndicators($accessToken, $audiences);
        $accessToken = $this->persistAccessToken($accessToken);

        // Send event to emitter
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier(): string
    {
        return 'client_credentials';
    }
}
