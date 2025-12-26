<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token;

/**
 * An id_token has been issued
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
final class IdTokenIssuedEvent extends IdTokenEvent
{
    /**
     * Token
     */
    private Token $token;

    /**
     * Get Token
     */
    public function getToken(): Token
    {
        return $this->token;
    }

    public function __construct(mixed $name, Token $token)
    {
        parent::__construct($name);
        $this->token = $token;
    }
}
