<?php

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token\Builder;
use Psr\Http\Message\ServerRequestInterface;

/**
 * IdTokenClaimsCreated Events helps to extend claims of the id_token
 * 
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenClaimsCreated extends RequestEvent 
{
    /**
     * Builder
     *
     * @var Builder
     */
    private $builder;

    public function __construct($name, ServerRequestInterface $request, Builder $builder)
    {
        parent::__construct($name, $request);
        $this->request = $request;
        $this->builder = $builder;
    }

    public function getBuilder(): Builder
    {
        return $this->builder;
    }
}