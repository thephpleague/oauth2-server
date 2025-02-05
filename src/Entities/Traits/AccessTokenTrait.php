<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Blake2b as BLAKE2B;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Eddsa as EDDSA;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;

trait AccessTokenTrait
{
    private ?Key $privateKey = null;

    private Signer $signer;

    private Configuration $jwtConfiguration;

    public function __construct()
    {
        $this->signer = new RS256();
    }

    public function setSigner(string $signerAlgorithm, CryptKeyInterface $privateKey): void
    {
        $this->privateKey = InMemory::plainText($privateKey->getKeyContents(), $privateKey->getPassPhrase() ?? '');

        switch (strtoupper($signerAlgorithm)) {
            case 'HS256': 
                $this->signer = new HS256();
                break;
            case 'HS384': 
                $this->signer = new HS384();
                break;
            case 'HS512': 
                $this->signer = new HS512();
                break;
            case 'BLAKE2B': 
                $this->signer = new BLAKE2B();
                break;
            case 'ES256': 
                $this->signer = new ES256();
                break;
            case 'ES384': 
                $this->signer = new ES384();
                break;
            case 'ES512': 
                $this->signer = new ES512();
                break;
            case 'RS256': 
                $this->signer = new RS256();
                break;
            case 'RS384': 
                $this->signer = new RS384();
                break;
            case 'RS512': 
                $this->signer = new RS512();
                break;
            case 'EDDSA': 
                $this->signer = new EDDSA();
                break;
        }
    }

    /**
     * Generate a JWT from the access token
     */
    private function convertToJWT(): Token
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));

        return $tokenBuilder
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($this->signer, $this->privateKey);
    }

    /**
     * Generate a string representation from the access token
     */
    public function toString(): string
    {
        if ($this->privateKey === null) {
            return $this->getIdentifier();
        }
        
        return $this->convertToJWT()->toString();
    }

    abstract public function getClient(): ClientEntityInterface;

    abstract public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * Get the token user.
     *
     * @return ?UserEntityInterface
     */
    abstract public function getUser(): ?UserEntityInterface;

    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function getScopes(): array;

    /**
     * @return non-empty-string
     */
    abstract public function getIdentifier(): string;

    /**
     * @return non-empty-string
     */
    private function getSubjectIdentifier(): string
    {
        return $this->getUser()?->getIdentifier() ?? $this->getClient()->getIdentifier();
    }
}
