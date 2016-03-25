<?php

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token;
use League\Event\Event;

class BearerWasValidated extends Event
{
    /**
     * @var Token
     */
    private $token;

    /**
     * JwtWasValidated constructor.
     *
     * @param Token $token
     */
    public function __construct(Token $token)
    {
        parent::__construct('validated');
        $this->token = $token;
    }

    /**
     * @return Token
     */
    public function getToken()
    {
        return $this->token;
    }
}
