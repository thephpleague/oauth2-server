<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use League\OAuth2\Server\EventEmitting\AbstractEvent;

/**
 * IdTokenEvent
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenEvent extends AbstractEvent
{
    public const ID_TOKEN_ISSUED = 'id_token.issued';

    // This event can be used to extent claims of the id_token
    public const ID_TOKEN_CLAIMS_CREATED = 'id_token.claims.created';
}
