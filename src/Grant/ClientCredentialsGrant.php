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

use DateInterval;
use League\Event\Event;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\TokenTypes\TokenTypeInterface;
use League\OAuth2\Server\Utils\SecureKey;
use Symfony\Component\HttpFoundation\Request;

/**
 * Client credentials grant class
 */
class ClientCredentialsGrant extends AbstractGrant
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = 'client_credentials';

    /**
     * Return an access token
     *
     * @param \Symfony\Component\HttpFoundation\Request           $request
     * @param \League\OAuth2\Server\TokenTypes\TokenTypeInterface $tokenType
     * @param \DateInterval                                       $accessTokenTTL
     * @param string                                              $scopeDelimiter
     *
     * @return \League\OAuth2\Server\TokenTypes\TokenTypeInterface
     * @throws \League\OAuth2\Server\Exception\InvalidClientException
     * @throws \League\OAuth2\Server\Exception\InvalidRequestException
     * @throws \League\OAuth2\Server\Exception\InvalidScopeException
     */
    public function getAccessTokenAsType(
        Request $request,
        TokenTypeInterface $tokenType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    ) {
        // Get the required params
        $clientId = $request->request->get('client_id', $request->getUser());
        if (is_null($clientId)) {
            throw new Exception\InvalidRequestException('client_id');
        }

        $clientSecret = $request->request->get('client_secret', $request->getPassword());
        if (is_null($clientSecret)) {
            throw new Exception\InvalidRequestException('client_secret');
        }

        // Validate client ID and client secret
        $client = $this->clientRepository->get(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntityInterface) === false) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));
            throw new Exception\InvalidClientException();
        }

        // Validate any scopes that are in the request
        $scopeParam = $request->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParam, $scopeDelimiter, $client);

        // Generate an access token
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier(SecureKey::generate());
        $expirationDateTime = (new \DateTime())->add($accessTokenTTL);
        $accessToken->setExpiryDateTime($expirationDateTime);
        $accessToken->setClient($client);
        $accessToken->setOwner('client', $client->getIdentifier());

        // Associate scopes with the session and access token
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        // Save the token
        $this->accessTokenRepository->create($accessToken);

        // Inject access token into token type
        $tokenType->setAccessToken($accessToken);

        return $tokenType;
    }
}
