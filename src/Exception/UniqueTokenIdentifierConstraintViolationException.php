<?php

/**
 * @author      Ivan Kurnosov <zerkms@zerkms.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Exception;

class UniqueTokenIdentifierConstraintViolationException extends OAuthServerException
{
    public static function create(): UniqueTokenIdentifierConstraintViolationException
    {
        $errorMessage = 'Could not create unique access token identifier';

        return new static($errorMessage, 100, 'access_token_duplicate', 500);
    }
}
