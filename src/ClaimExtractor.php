<?php

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\ClaimSet;
use League\OAuth2\Server\Entities\ClaimSetEntry;
use League\OAuth2\Server\Entities\ClaimSetEntryInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

/**
 * ClaimExtractor
 * 
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 */
class ClaimExtractor
{
    /**
     * claimSets
     *
     * @var ClaimSetEntryInterface[]
     */
    protected $claimSets = [];

    protected $protectedClaims = ['profile', 'email', 'address', 'phone'];

    /**
     * ClaimExtractor constructor
     * 
     * @param ClaimSetEntryInterface[] $claimSets
     */
    public function __construct(array $claimSets = [])
    {
        $this->claimSets = self::getDefaultClaimSetEnties();        
        foreach ($claimSets as $claimSet) {
            $this->addClaimSet($claimSet);
        }
    }

    /**
     * @param ClaimSetEntryInterface $claimSetEntry
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function addClaimSet(ClaimSetEntryInterface $claimSetEntry): ClaimExtractor
    {
        $scope = $claimSetEntry->getScope();

        if (in_array($scope, $this->protectedClaims) && !empty($this->claimSets[$scope])) {
            throw new \InvalidArgumentException(
                sprintf("%s is a protected scope and is pre-defined by the OpenID Connect specification.", $scope)
            );
        }

        $this->claimSets[$scope] = $claimSetEntry->getClaims();

        return $this;
    }

    /**
     * @param string $scope
     * 
     * @return ClaimSetEntryInterface|null
     */
    public function getClaimSet(string $scope): ?ClaimSetEntryInterface
    {
        foreach($this->claimSets as $set) {
            if ($set->getScope() === $scope) {
                return $set;
            }
        }
        return null;
    }

    /**
     * Get claimSets
     *
     * @return  array
     */ 
    public function getClaimSets(): array
    {
        return $this->claimSets;
    }

    /**
     * For given scopes and aggregated claims get all claims that have been configured on the extractor.
     *
     * @param array $scopes
     * @param array $claims
     * @return array
     */
    public function extract(array $scopes, array $claims): array
    {
        $claimData  = [];
        $keys = array_keys($claims);

        foreach ($scopes as $scope) {
            $scopeName = ($scope instanceof ScopeEntityInterface) ? $scope->getIdentifier() : $scope;

            $claimSet = $this->getClaimSet($scopeName);
            if (null === $claimSet) {
                continue;
            }

            $intersected = array_intersect($claimSet->getClaims(), $keys);

            if (empty($intersected)) {
                continue;
            }

            $data = array_filter($claims,
                function($key) use ($intersected) {
                    return in_array($key, $intersected);
                },
                ARRAY_FILTER_USE_KEY
            );

            $claimData = array_merge($claimData, $data);
        }

        return $claimData;
    }

    /**
     * Create a array default openID connect claims
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
     * 
     * @return ClaimSetEntry[]
     */
    public static function getDefaultClaimSetEnties(): array
    {
        return [
            new ClaimSetEntry('profile', [
                'name',
                'family_name',
                'given_name',
                'middle_name',
                'nickname',
                'preferred_username',
                'profile',
                'picture',
                'website',
                'gender',
                'birthdate',
                'zoneinfo',
                'locale',
                'updated_at'
            ]),
            new ClaimSetEntry('email', [
                'email',
                'email_verified'
            ]),
            new ClaimSetEntry('address', [
                'address'
            ]),
            new ClaimSetEntry('phone', [
                'phone_number',
                'phone_number_verified'
            ])
        ];
    }
}
