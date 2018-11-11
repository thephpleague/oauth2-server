<?php

namespace League\OAuth2\Server\IntrospectionValidators;

use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class BearerTokenValidator implements IntrospectionValidatorInterface
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * Set the private key.
     *
     * @param \League\OAuth2\Server\CryptKey $key
     */
    public function setPrivateKey(CryptKey $key)
    {
        $this->privateKey = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function validateIntrospection(ServerRequestInterface $request)
    {
        try {
            $token = $this->getTokenFromRequest($request);
        } catch (InvalidArgumentException $e) {
            return false;
        }

        if (
            $this->isTokenRevoked($token) ||
            $this->isTokenExpired($token) ||
            $this->isTokenUnverified($token)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Gets the token from the request body.
     *
     * @param ServerRequestInterface $request
     *
     * @return Token
     */
    public function getTokenFromRequest(ServerRequestInterface $request)
    {
        $jwt = $request->getParsedBody()['token'] ?? null;

        return (new Parser())
            ->parse($jwt);
    }

    /**
     * Checks whether the token is unverified.
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenUnverified(Token $token)
    {
        $keychain = new Keychain();

        $key = $keychain->getPrivateKey(
            $this->privateKey->getKeyPath(),
            $this->privateKey->getPassPhrase()
        );

        return $token->verify(new Sha256(), $key->getContent()) === false;
    }

    /**
     * Ensure access token hasn't expired.
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenExpired(Token $token)
    {
        $data = new ValidationData(time());

        return !$token->validate($data);
    }

    /**
     * Check if the given token is revoked.
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenRevoked(Token $token)
    {
        return $this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jti'));
    }
}
