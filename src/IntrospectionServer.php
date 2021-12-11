<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator as AuthorizationBearerTokenValidator;
use League\OAuth2\Server\IntrospectionValidators\BearerTokenValidator as IntrospectionBearerTokenValidator;
use League\OAuth2\Server\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\Introspection\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\Introspection\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\Introspection\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IntrospectionServer
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @var AbstractResponseType
     */
    protected $responseType;

    /**
     * @var AuthorizationValidatorInterface|null
     */
    protected $authorizationValidator;

    /**
     * @var IntrospectionValidatorInterface|null
     */
    protected $introspectionValidator;

    public function __construct(
        AccessTokenRepositoryInterface  $accessTokenRepository,
        $publicKey,
        IntrospectionValidatorInterface $introspectionValidator = null,
        AuthorizationValidatorInterface $authorizationValidator = null,
        ResponseTypeInterface           $responseType = null
    ) {
        $this->accessTokenRepository = $accessTokenRepository;

        if ($publicKey instanceof CryptKey === false) {
            $publicKey = new CryptKey($publicKey);
        }

        $this->publicKey = $publicKey;
        $this->introspectionValidator = $introspectionValidator;
        $this->authorizationValidator = $authorizationValidator;

        if ($responseType === null) {
            $this->responseType = new BearerTokenResponse();
        } else {
            $this->responseType = clone $responseType;
        }
    }

    /**
     * Get the introspection validator
     *
     * @return IntrospectionValidatorInterface
     */
    protected function getIntrospectionValidator(): IntrospectionValidatorInterface
    {
        if ($this->introspectionValidator instanceof IntrospectionValidatorInterface === false) {
            $this->introspectionValidator = new IntrospectionBearerTokenValidator($this->accessTokenRepository);

            $this->introspectionValidator->setPublicKey($this->publicKey);
        }

        return $this->introspectionValidator;
    }

    /**
     * Get the authorization validator
     *
     * @return AuthorizationValidatorInterface
     */
    protected function getAuthorizationValidator(): AuthorizationValidatorInterface
    {
        if ($this->authorizationValidator instanceof AuthorizationValidatorInterface === false) {
            $this->authorizationValidator = new AuthorizationBearerTokenValidator($this->accessTokenRepository);

            $this->authorizationValidator->setPublicKey($this->publicKey);
        }

        return $this->authorizationValidator;
    }

    /**
     * Return an introspection response.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     *
     * @throws Exception\OAuthServerException
     */
    public function respondToIntrospectionRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $this->getAuthorizationValidator()->validateAuthorization($request);

        $this->responseType->setRequest($request);
        $this->responseType->setValidity(
            $this->getIntrospectionValidator()->validateIntrospection($request)
        );

        return $this->responseType->generateHttpResponse($response);
    }
}
