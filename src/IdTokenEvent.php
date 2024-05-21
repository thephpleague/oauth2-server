<?php

namespace League\OAuth2\Server;

use League\Event\Event;

/**
 * IdTokenEvent
 *
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenEvent extends Event
{
    public const ID_TOKEN_ISSUED = 'id_token.issued';

    // This event can be used to extent claims of the id_token
    public const ID_TOKEN_CLAIMS_CREATED = 'id_token.claims.created';
}
