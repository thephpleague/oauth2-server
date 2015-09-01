<?php
namespace League\OAuth2\Server\ServerInterface;

use League\OAuth2\Server\TokenType\TokenTypeInterface;

interface TokenTypeAware
{
    /**
     * Set the access token type
     *
     * @param TokenTypeInterface $tokenType The token type
     *
     * @return void
     */
    public function setTokenType(TokenTypeInterface $tokenType);

    /**
     * Get the access token type
     *
     * @return TokenTypeInterface
     */
    public function getTokenType();
}