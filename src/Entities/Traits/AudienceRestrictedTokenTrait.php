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

/**
 * Default in-memory implementation of {@see \League\OAuth2\Server\Entities\AudienceRestrictedTokenInterface}.
 */
trait AudienceRestrictedTokenTrait
{
    /**
     * @var list<non-empty-string>
     */
    private array $audiences = [];

    /**
     * @return list<non-empty-string>
     */
    public function getAudiences(): array
    {
        return $this->audiences;
    }

    /**
     * @param list<non-empty-string> $audiences
     */
    public function setAudiences(array $audiences): void
    {
        $this->audiences = $audiences;
    }
}
