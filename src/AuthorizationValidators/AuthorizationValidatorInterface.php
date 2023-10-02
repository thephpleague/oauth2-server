<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\AuthorizationValidators;

use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationValidatorInterface
{
    /**
     * Determine the access token in the authorization header and append OAUth
     * properties to the request as attributes.
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface;
}
