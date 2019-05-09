<?php declare(strict_types=1);

namespace League\OAuth2\Server\IdentifierGenerator;

use League\OAuth2\Server\Exception\OAuthServerException;

interface IdentifierGeneratorInterface
{
    /**
     * Generate a new unique identifier.
     *
     * @throws OAuthServerException
     */
    public function generateUniqueIdentifier();
}
