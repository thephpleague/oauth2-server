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
    protected $claimSets = [];

    protected $protectedClaims = ['profile', 'email', 'address', 'phone'];

    /**
     * ClaimExtractor constructor
     * 
     * @param ClaimSet[] $claimSets
     */
    public function __construct(array $claimSets = [])
    {
        // Add Default OpenID Connect Claims
        // @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        $this->addClaimSet(
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
            ])
        );        
        $this->addClaimSet(
            new ClaimSetEntry('email', [
                'email',
                'email_verified'
            ])
        );
        $this->addClaimSet(
            new ClaimSetEntry('address', [
                'address'
            ])
        );
        $this->addClaimSet(
            new ClaimSetEntry('phone', [
                'phone_number',
                'phone_number_verified'
            ])
        );

        foreach ($claimSets as $claimSet) {
            $this->addClaimSet($claimSet);
        }
    }

    /**
     * @param ClaimSetInterface $claimSet
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function addClaimSet(ClaimSetEntryInterface $claimSet): ClaimExtractor
    {
        $scope = $claimSet->getScope();

        if (in_array($scope, $this->protectedClaims) && !empty($this->claimSets[$scope])) {
            throw new \InvalidArgumentException(
                sprintf("%s is a protected scope and is pre-defined by the OpenID Connect specification.", $scope)
            );
        }

        $this->claimSets[$scope] = $claimSet;

        return $this;
    }

    /**
     * @param string $scope
     * @return ClaimSet|null
     */
    public function getClaimSet(string$scope)
    {
        if (!$this->hasClaimSet($scope)) {
            return null;
        }

        return $this->claimSets[$scope];
    }

    /**
     * @param string $scope
     * @return bool
     */
    public function hasClaimSet(string $scope): bool
    {
        return array_key_exists($scope, $this->claimSets);
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
}
