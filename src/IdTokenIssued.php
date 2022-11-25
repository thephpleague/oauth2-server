<?php

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token;
use Psr\Http\Message\ServerRequestInterface;

/**
 * An id_token has been issued
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenIssued extends RequestEvent
{
    /**
     * Token
     *
     * @var Token
     */
    private $token;

    public function __construct($name, ServerRequestInterface $request, Token $token)
    {
        parent::__construct($name, $request);
        $this->token = $token;
    }

    /**
     * Get Token
     *
     * @return Token
     */
    public function getToken(): Token
    {
        return $this->token;
    }
}
