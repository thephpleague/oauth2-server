<?php

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An id_token has been issued
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
final class IdTokenIssued extends IdTokenEvent
{
    /**
     * Token
     *
     * @var Token
     */
    private $token;

    /**
     * Get Token
     *
     * @return Token
     */
    public function getToken(): Token
    {
        return $this->token;
    }

    public function __construct($name, Token $token)
    {
        parent::__construct($name);
        $this->token = $token;
    }
}
