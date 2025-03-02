<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use InvalidArgumentException;
use League\OAuth2\Server\Entities\ClaimSetEntry;
use League\OAuth2\Server\Entities\ClaimSetEntryInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

use function array_filter;
use function array_intersect;
use function array_keys;
use function array_merge;
use function in_array;
use function sprintf;

/**
 * ClaimExtractor
 *
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 */
class ClaimExtractor implements ClaimExtractorInterface
{
    /**
     * claimSetEntries
     *
     * @var ClaimSetEntryInterface[]
     */
    protected array $claimSetEntries = [];

    /**
     * Protected claims
     *
     * @var string[]
     */
    protected array $protectedClaims = ['profile', 'email', 'address', 'phone'];

    /**
     * ClaimExtractor constructor
     *
     * @param array<int, ClaimSetEntryInterface> $claimSetEntries
     */
    public function __construct(array $claimSetEntries = [])
    {
        $this->claimSetEntries = self::getDefaultClaimSetEnties();
        foreach ($claimSetEntries as $claimSetEntry) {
            $this->addClaimSetEntry($claimSetEntry);
        }
    }

    /**
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    public function addClaimSetEntry(ClaimSetEntryInterface $claimSetEntry): ClaimExtractor
    {
        if (in_array($claimSetEntry->getScope(), $this->protectedClaims) && !$this->getClaimSetEntry($claimSetEntry->getScope())) {
            throw new InvalidArgumentException(
                sprintf('%s is a protected scope and is pre-defined by the OpenID Connect specification.', $claimSetEntry->getScope())
            );
        }

        $this->claimSetEntries[] = $claimSetEntry;

        return $this;
    }

    public function getClaimSetEntry(string $scope): ?ClaimSetEntryInterface
    {
        foreach ($this->claimSetEntries as $entry) {
            if ($entry->getScope() === $scope) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * Get claimSetEntries
     *
     * @return array<ClaimSetInterface>
     */
    public function getClaimSetEntries(): array
    {
        return $this->claimSetEntries;
    }

    /**
     * {@inheritdoc}
     */
    public function extract(array $scopes, array $claims): array
    {
        $claimData  = [];
        $keys = array_keys($claims);

        foreach ($scopes as $scope) {
            $scopeName = ($scope instanceof ScopeEntityInterface) ? $scope->getIdentifier() : $scope;

            $claimSet = $this->getClaimSetEntry($scopeName);
            if (null === $claimSet) {
                continue;
            }

            $intersected = array_intersect($claimSet->getClaims(), $keys);

            if (empty($intersected)) {
                continue;
            }

            $data = array_filter(
                $claims,
                function ($key) use ($intersected) {
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
                'updated_at',
            ]),
            new ClaimSetEntry('email', [
                'email',
                'email_verified',
            ]),
            new ClaimSetEntry('address', [
                'address',
            ]),
            new ClaimSetEntry('phone', [
                'phone_number',
                'phone_number_verified',
            ]),
            new ClaimSetEntry('openid', [
                'nonce',
                'auth_time',
                'acr',
                'amr',
                'azp',
            ]),
        ];
    }
}
