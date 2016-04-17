<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServer
{
    /**
     * @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;
    /**
     * @var \League\OAuth2\Server\CryptKey|string
     */
    private $publicKey;
    /**
     * @var \League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface|null
     */
    private $authorizationValidator;

    /**
     * New server instance.
     *
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface                  $accessTokenRepository
     * @param \League\OAuth2\Server\CryptKey|string                                              $publicKey
     * @param null|\League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface $authorizationValidator
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        $publicKey,
        AuthorizationValidatorInterface $authorizationValidator = null
    ) {
        $this->accessTokenRepository = $accessTokenRepository;

        if (!$publicKey instanceof CryptKey) {
            $publicKey = new CryptKey($publicKey);
        }
        $this->publicKey = $publicKey;

        $this->authorizationValidator = $authorizationValidator;
    }

    /**
     * @return \League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface
     */
    protected function getAuthorizationValidator()
    {
        if (!$this->authorizationValidator instanceof AuthorizationValidatorInterface) {
            $this->authorizationValidator = new BearerTokenValidator($this->accessTokenRepository);
        }

        $this->authorizationValidator->setPublicKey($this->publicKey);

        return $this->authorizationValidator;
    }

    /**
     * Determine the access token validity.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return \Psr\Http\Message\ServerRequestInterface
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request)
    {
        return $this->getAuthorizationValidator()->validateAuthorization($request);
    }
}
