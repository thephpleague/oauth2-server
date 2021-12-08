<?php

namespace League\OAuth2\Server\IntrospectionValidators;

use DateTimeZone;
use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
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
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @var Configuration
     */
    protected $jwtConfiguration;

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
     * @param CryptKey $key
     */
    public function setPublicKey(CryptKey $key)
    {
        $this->publicKey = $key;

        $this->initJwtConfiguration();
    }

    /**
     * Initialise the JWT configuration.
     */
    private function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('')
        );

        $this->jwtConfiguration->setValidationConstraints(
            \class_exists(StrictValidAt::class)
                ? new StrictValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get())))
                : new LooseValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
            new SignedWith(
                new Sha256(),
                InMemory::plainText($this->publicKey->getKeyContents(), $this->publicKey->getPassPhrase() ?? '')
            )
        );
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
            !$this->isTokenValid($token) ||
            $this->isTokenRevoked($token)
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

        return $this->jwtConfiguration->parser()
            ->parse($jwt);
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
        return $this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get('jti'));
    }

    /**
     * Check if the given token is valid
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenValid(Token $token)
    {
        $constraints = $this->jwtConfiguration->validationConstraints();

        return $this->jwtConfiguration->validator()->validate($token, ...$constraints);
    }
}
