<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

interface ClaimExtractorInterface
{
    /**
     * For given scopes and aggregated claims get all claims that have been configured on the extractor.
     *
     * @param array<int, ScopeEntityInterface> $scopes
     * @param array<string, string>            $claims
     *
     * @return array<string, string>
     */
    public function extract(array $scopes, array $claims): array;
}
