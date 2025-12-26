<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\ClaimExtractor;
use League\OAuth2\Server\ClaimExtractorInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\IdTokenClaimsCreatedEvent;
use League\OAuth2\Server\IdTokenEvent;
use League\OAuth2\Server\IdTokenIssuedEvent;
use League\OAuth2\Server\Repositories\ClaimSetRepositoryInterface;
use League\OAuth2\Server\Repositories\IdTokenRepositoryInterface;

/**
 * OpenidConfigurationResponse
 *
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenResponse extends BearerTokenResponse
{
    use EmitterAwarePolyfill;

    /**
     * IdTokenRepositoryInterface
     */
    protected IdTokenRepositoryInterface $idTokenRepository;

    /**
     * ClaimSetRepositoryInterface
     */
    protected ClaimSetRepositoryInterface $claimRepository;

    /**
     * ClaimExtractorInterface
     */
    protected ClaimExtractorInterface $extractor;

    public function __construct(
        IdTokenRepositoryInterface $idTokenRepository,
        ClaimSetRepositoryInterface $claimRepository,
        EventEmitter $emitter,
        ?ClaimExtractorInterface $extractor = null
    ) {
        if (!$extractor) {
            $this->extractor = new ClaimExtractor();
        } else {
            $this->extractor = $extractor;
        }
        $this->idTokenRepository = $idTokenRepository;
        $this->claimRepository = $claimRepository;
        $this->setEmitter($emitter);
    }

    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @return array<array-key,mixed>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        // Onyly add id_token to openid scopes
        if (!self::isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        $claimSet = $this->claimRepository->getClaimSet($accessToken);

        $builder = $this->idTokenRepository->getBuilder($accessToken);

        if ($claimSet instanceof ClaimSetInterface) {
            foreach ($this->extractor->extract($accessToken->getScopes(), $claimSet->getClaims()) as $claimName => $claimValue) {
                $builder = $builder->withClaim($claimName, $claimValue);
            }
        }

        $this->getEmitter()->emit(
            new IdTokenClaimsCreatedEvent(IdTokenEvent::ID_TOKEN_CLAIMS_CREATED, $builder)
        );

        $token = $builder->getToken(
            new Sha256(),
            InMemory::file($this->privateKey->getKeyPath(), (string) $this->privateKey->getPassPhrase())
        );

        $this->getEmitter()->emit(
            new IdTokenIssuedEvent(IdTokenEvent::ID_TOKEN_ISSUED, $token)
        );

        return [
            'id_token' => $token->toString(),
        ];
    }

    /**
     * Return true If this is an OpenID request
     *
     * @param ScopeEntityInterface[] $scopes
     */
    private static function isOpenIDRequest(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope instanceof ScopeEntityInterface) {
                if ($scope->getIdentifier() === 'openid') {
                    return true;
                }
            }
        }

        return false;
    }
}
