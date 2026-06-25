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
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AudienceRestrictedTokenInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use RuntimeException;
use SensitiveParameter;

/**
 * Default implementation of the access-token entity contract.
 *
 * This trait is aware of {@see AudienceRestrictedTokenInterface} and
 * degrades gracefully if the composing class does not implement it: when
 * the class opts in and provides a non-empty audience list, those values
 * drive the JWT `aud` claim; otherwise the trait falls back to the client
 * identifier, preserving the historical single-audience behaviour.
 */
trait AccessTokenTrait
{
    private CryptKeyInterface $privateKey;

    private Configuration $jwtConfiguration;

    /**
     * Set the private key used to encrypt this access token.
     */
    public function setPrivateKey(
        #[SensitiveParameter]
        CryptKeyInterface $privateKey
    ): void {
        $this->privateKey = $privateKey;
    }

    /**
     * Initialise the JWT Configuration.
     */
    public function initJwtConfiguration(): void
    {
        $privateKeyContents = $this->privateKey->getKeyContents();

        if ($privateKeyContents === '') {
            throw new RuntimeException('Private key is empty');
        }

        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKeyContents, $this->privateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty')
        );
    }

    /**
     * Generate a JWT from the access token
     */
    private function convertToJWT(): Token
    {
        $this->initJwtConfiguration();

        $audiences = $this->resolveAudiences();

        return $this->jwtConfiguration->builder()
            ->permittedFor(...$audiences)
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    /**
     * Resolve the JWT `aud` claim values. RFC 8707 resource indicators take
     * precedence when the entity opts in via
     * {@see \League\OAuth2\Server\Entities\AudienceRestrictedTokenInterface}
     * and supplies a non-empty audience list; an empty audience list is
     * treated as "no restriction asserted" and falls back to the client id,
     * preserving the historical single-audience behaviour for tokens issued
     * without a `resource` parameter.
     *
     * @return non-empty-list<non-empty-string>
     */
    private function resolveAudiences(): array
    {
        if ($this instanceof AudienceRestrictedTokenInterface) {
            $audiences = $this->getAudiences();

            if ($audiences !== []) {
                return $audiences;
            }
        }

        return [$this->getClient()->getIdentifier()];
    }

    /**
     * Generate a string representation from the access token
     */
    public function toString(): string
    {
        return $this->convertToJWT()->toString();
    }

    abstract public function getClient(): ClientEntityInterface;

    abstract public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * @return non-empty-string|null
     */
    abstract public function getUserIdentifier(): string|null;

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
        return $this->getUserIdentifier() ?? $this->getClient()->getIdentifier();
    }
}
