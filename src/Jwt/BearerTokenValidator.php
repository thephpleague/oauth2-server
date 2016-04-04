<?php

namespace League\OAuth2\Server\Jwt;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\Event\EmitterTrait;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\BearerWasValidated;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class BearerTokenValidator implements AuthorizationValidatorInterface
{
    use EmitterTrait;

    /**
     * @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;
    /**
     * @var
     */
    private $publicKeyPath;

    /**
     * BearerTokenValidator constructor.
     *
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     * @param $publicKeyPath
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, $publicKeyPath)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->publicKeyPath = $publicKeyPath;
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorization(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === false) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        $header = $request->getHeader('authorization');
        $jwt = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header[0]));

        try {
            // Attempt to parse and validate the JWT
            $token = (new Parser())->parse($jwt);
            if ($token->verify(new Sha256(), $this->publicKeyPath) === false) {
                throw OAuthServerException::accessDenied('Access token could not be verified');
            }

            // Check if token has been revoked
            if ($this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jti'))) {
                throw OAuthServerException::accessDenied('Access token has been revoked');
            }

            // Return the request with additional attributes
            $request = $request
                ->withAttribute('oauth_access_token_id', $token->getClaim('jti'))
                ->withAttribute('oauth_client_id', $token->getClaim('aud'))
                ->withAttribute('oauth_user_id', $token->getClaim('sub'))
                ->withAttribute('oauth_scopes', $token->getClaim('scopes'));

            $this->getEmitter()->emit(new BearerWasValidated($token));

            return $request;
        } catch (\InvalidArgumentException $exception) {
            // JWT couldn't be parsed so return the request as is
            throw OAuthServerException::accessDenied($exception->getMessage());
        }
    }
}
