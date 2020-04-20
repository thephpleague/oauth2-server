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
use League\OAuth2\Server\Exception\ExceptionResponseHandler;
use League\OAuth2\Server\Exception\ExceptionResponseHandlerInterface;
use League\OAuth2\Server\Exception\ExceptionResponseHandlerTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServer
{
    use ExceptionResponseHandlerTrait;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var CryptKeyInterface
     */
    private $publicKey;

    /**
     * @var null|AuthorizationValidatorInterface
     */
    private $authorizationValidator;

    /**
     * @var ExceptionResponseHandlerInterface
     */
    private $exceptionResponseHandler;

    /**
     * New server instance.
     *
     * @param AccessTokenRepositoryInterface         $accessTokenRepository
     * @param CryptKeyInterface|string               $publicKey
     * @param null|AuthorizationValidatorInterface   $authorizationValidator
     * @param null|ExceptionResponseHandlerInterface $exceptionResponseHandler
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        $publicKey,
        AuthorizationValidatorInterface $authorizationValidator = null,
        ExceptionResponseHandlerInterface $exceptionResponseHandler = null
    ) {
        $this->accessTokenRepository = $accessTokenRepository;

        if ($publicKey instanceof CryptKeyInterface === false) {
            $publicKey = new CryptKey($publicKey);
        }
        $this->publicKey = $publicKey;

        $this->authorizationValidator = $authorizationValidator;

        if ($exceptionResponseHandler === null) {
            $exceptionResponseHandler = new ExceptionResponseHandler();
        }
        $this->exceptionResponseHandler = $exceptionResponseHandler;
    }

    /**
     * @return AuthorizationValidatorInterface
     */
    protected function getAuthorizationValidator()
    {
        if ($this->authorizationValidator instanceof AuthorizationValidatorInterface === false) {
            $this->authorizationValidator = new BearerTokenValidator($this->accessTokenRepository);
        }

        if ($this->authorizationValidator instanceof BearerTokenValidator === true) {
            $this->authorizationValidator->setPublicKey($this->publicKey);
        }

        return $this->authorizationValidator;
    }

    /**
     * Determine the access token validity.
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return ServerRequestInterface
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request)
    {
        return $this->getAuthorizationValidator()->validateAuthorization($request);
    }
}
