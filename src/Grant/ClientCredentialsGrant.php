<?php
/**
 * OAuth 2.0 Client credentials grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Client credentials grant class
 */
class ClientCredentialsGrant extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($request, $client);

        // Issue and persist access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $client->getIdentifier(), $scopes);
        $this->accessTokenRepository->persistNewAccessToken($accessToken);

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * @inheritdoc
     */
    public function getIdentifier()
    {
        return 'client_credentials';
    }
}
