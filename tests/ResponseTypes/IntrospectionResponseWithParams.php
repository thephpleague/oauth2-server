<?php

declare(strict_types=1);

namespace LeagueTests\ResponseTypes;

use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;

class IntrospectionResponseWithParams extends IntrospectionResponse
{
    /**
     * {@inheritdoc}
     */
    protected function getExtraParams(string $tokenType, array $tokenData): array
    {
        return ['foo' => 'bar', 'extended' => $tokenData['extension']];
    }
}
