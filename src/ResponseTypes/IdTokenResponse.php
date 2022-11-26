<?php

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\Event\EmitterAwareTrait;
use League\Event\EmitterInterface;
use League\OAuth2\Server\ClaimExtractor;
use League\OAuth2\Server\ClaimExtractorIntercace;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
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
    use EmitterAwareTrait;

    public function __construct(
        protected IdTokenRepositoryInterface $builder,
        protected ClaimSetRepositoryInterface $claimRepository,
        EmitterInterface $emitter,
        protected ?ClaimExtractorIntercace $extractor = null
    ) {
        if (!$extractor) {
            $this->extractor = new ClaimExtractor();
        }
        $this->setEmitter($emitter);
    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     *
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        // Onyly add id_token to openid scopes
        if (!self::isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        $claimSet = $this->claimRepository->getClaimSetEntry($accessToken);

        $builder = $this->builder->getBuilder($accessToken);

        if ($claimSet instanceof ClaimSetInterface) {
            foreach ($this->extractor->extract($accessToken->getScopes(), $claimSet->getClaims()) as $claimName => $claimValue) {
                $builder->withClaim($claimName, $claimValue);
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
     *
     * @return bool
     */
    private static function isOpenIDRequest($scopes): bool
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
