<?php

namespace League\OAuth2\Server;

interface ClaimExtractorInterface
{
    /**
     * For given scopes and aggregated claims get all claims that have been configured on the extractor.
     *
     * @param array $scopes
     * @param array $claims
     *
     * @return array
     */
    public function extract(array $scopes, array $claims): array;
}
