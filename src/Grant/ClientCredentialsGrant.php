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
use Psr\Http\Message\ServerRequestInterface;

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
     * @param \Psr\Http\Message\ServerRequestInterface            $request
     * @param \League\OAuth2\Server\TokenTypes\TokenTypeInterface $tokenType
     * @param \DateInterval                                       $accessTokenTTL
     * @param string                                              $scopeDelimiter
     *
     * @return \League\OAuth2\Server\TokenTypes\TokenTypeInterface
     * @throws \League\OAuth2\Server\Exception\InvalidClientException
     * @throws \League\OAuth2\Server\Exception\InvalidRequestException
     * @throws \League\OAuth2\Server\Exception\InvalidScopeException
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        TokenTypeInterface $tokenType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    ) {
        // Get the required params
        $clientId = isset($request->getParsedBody()['client_id'])
            ? $request->getParsedBody()['client_id'] // $_POST['client_id']
            : isset($request->getServerParams()['PHP_AUTH_USER'])
                ? $request->getServerParams()['PHP_AUTH_USER'] // $_SERVER['PHP_AUTH_USER']
                : null;

        if (is_null($clientId)) {
            throw new Exception\InvalidRequestException('client_id');
        }

        $clientSecret = isset($request->getParsedBody()['client_secret'])
            ? $request->getParsedBody()['client_secret'] // $_POST['client_id']
            : isset($request->getServerParams()['PHP_AUTH_PW'])
                ? $request->getServerParams()['PHP_AUTH_PW'] // $_SERVER['PHP_AUTH_USER']
                : null;

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
        $scopeParam = isset($request->getParsedBody()['scope'])
            ? $request->getParsedBody()['scope'] // $_POST['scope']
            : '';
        $scopes = $this->validateScopes($scopeParam, $scopeDelimiter, $client);

        // Generate an access token
        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier(SecureKey::generate());
        $accessToken->setExpiryDateTime((new \DateTime())->add($accessTokenTTL));
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

    /**
     * The grant type should return true if it is able to respond to this request.
     *
     * For example most grant types will check that the $_POST['grant_type'] property matches it's identifier property.
     *
     * Some grants, such as the authorization code grant can respond to multiple requests
     *  - i.e. a client requesting an authorization code and requesting an access token
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return boolean
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        if (
            isset($request->getParsedBody()['grant_type'])
            && $request->getParsedBody()['grant_type'] === 'client_credentials'
        ) {
            return true;
        }

        return false;
    }
}
