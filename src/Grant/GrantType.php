<?php

/**
 * OAuth 2.0 grant types enum.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case ClientCredentials = 'client_credentials';
    case DeviceCode = 'urn:ietf:params:oauth:grant-type:device_code';
    case Implicit = 'implicit';
    case Password = 'password';
    case RefreshToken = 'refresh_token';
}
