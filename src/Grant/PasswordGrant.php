<?php
/**
 * OAuth 2.0 Password grant
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
use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Utils\SecureKey;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Password grant class
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     */
    private $userRepository;

    /**
     * @param \League\OAuth2\Server\Repositories\UserRepositoryInterface        $userRepository
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface      $clientRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface       $scopeRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ClientRepositoryInterface $clientRepository,
        ScopeRepositoryInterface $scopeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository
    ) {
        $this->userRepository = $userRepository;
        parent::__construct($clientRepository, $scopeRepository, $accessTokenRepository);
    }

    /**
     * @inheritdoc
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    ) {
        // Get the required params
        $clientId = isset($request->getParsedBody()['client_id'])
            ? $request->getParsedBody()['client_id'] // $_POST['client_id']
            : (isset($request->getServerParams()['PHP_AUTH_USER'])
                ? $request->getServerParams()['PHP_AUTH_USER'] // $_SERVER['PHP_AUTH_USER']
                : null);

        if (is_null($clientId)) {
            throw OAuthServerException::invalidRequest('client_id', null, '`%s` parameter is missing');
        }

        $clientSecret = isset($request->getParsedBody()['client_secret'])
            ? $request->getParsedBody()['client_secret'] // $_POST['client_id']
            : (isset($request->getServerParams()['PHP_AUTH_PW'])
                ? $request->getServerParams()['PHP_AUTH_PW'] // $_SERVER['PHP_AUTH_USER']
                : null);

        if (is_null($clientSecret)) {
            throw OAuthServerException::invalidRequest('client_secret', null, '`%s` parameter is missing');
        }

        // Validate client ID and client secret
        $client = $this->clientRepository->getClientEntity(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntityInterface) === false) {
            $this->emitter->emit(new Event('client.authentication.failed', $request));
            throw OAuthServerException::invalidClient();
        }

        // Username
        $username = isset($request->getParsedBody()['username'])
            ? $request->getParsedBody()['username'] // $_POST['username']
            : (isset($request->getServerParams()['PHP_AUTH_USER'])
                ? $request->getServerParams()['PHP_AUTH_USER'] // $_SERVER['PHP_AUTH_USER']
                : null);

        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username', null, '`%s` parameter is missing');
        }

        // Password
        $password = isset($request->getParsedBody()['password'])
            ? $request->getParsedBody()['password'] // $_POST['password']
            : (isset($request->getServerParams()['PHP_AUTH_USER'])
                ? $request->getServerParams()['PHP_AUTH_USER'] // $_SERVER['PHP_AUTH_USER']
                : null);

        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password', null, '`%s` parameter is missing');
        }

        // Verify user's username and password
        $userEntity = $this->userRepository->getUserEntityByUserCredentials($username, $password);
        if (($userEntity instanceof UserEntityInterface) === false) {
            $this->emitter->emit(new Event('user.authentication.failed', $request));
            throw OAuthServerException::invalidCredentials();
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
        $accessToken->setOwner('user', $userEntity->getIdentifier());

        // Associate scopes with the session and access token
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        // Save the token
        $this->accessTokenRepository->persistNewAccessToken($accessToken);

        // Inject access token into token type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * @inheritdoc
     */
    public function canRespondToRequest(ServerRequestInterface $request)
    {
        if (
            isset($request->getParsedBody()['grant_type'])
            && $request->getParsedBody()['grant_type'] === 'password'
        ) {
            return true;
        }

        return false;
    }
}
