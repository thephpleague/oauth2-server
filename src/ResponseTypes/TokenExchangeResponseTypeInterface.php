<?php

/**
 * OAuth 2.0 Token Exchange Response Type Interface.
 *
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes;

/**
 * Adds possibility to set issued_token_type to access_token response, as described by RFC 8693 Token Exchange
 *
 * Separate interface for backwards compatibility
 */
interface TokenExchangeResponseTypeInterface extends ResponseTypeInterface
{
    public function setIssuedTokenType( string $issuedTokenType ): void;
}
