<?php

namespace League\OAuth2\Server;

use Lcobucci\JWT\Token\Builder;

/**
 * IdTokenClaimsCreatedEvent Event helps to extend claims of the id_token
 *
 * A usecase is to add nonce If requested by the client
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
final class IdTokenClaimsCreatedEvent extends IdTokenEvent
{
    /**
     * Builder
     *
     * @var Builder
     */
    private $builder;

    public function __construct($name, Builder $builder)
    {
        parent::__construct($name);
        $this->builder = $builder;
    }

    public function getBuilder(): Builder
    {
        return $this->builder;
    }
}
