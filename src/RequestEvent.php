<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server;

use League\OAuth2\Server\EventEmitting\AbstractEvent;
use Psr\Http\Message\ServerRequestInterface;

class RequestEvent extends AbstractEvent
{
    public const CLIENT_AUTHENTICATION_FAILED = 'client.authentication.failed';
    public const USER_AUTHENTICATION_FAILED = 'user.authentication.failed';
    public const REFRESH_TOKEN_CLIENT_FAILED = 'refresh_token.client.failed';

    public const REFRESH_TOKEN_ISSUED = 'refresh_token.issued';
    public const ACCESS_TOKEN_ISSUED = 'access_token.issued';

    public function __construct(string $name, private ServerRequestInterface $request)
    {
        parent::__construct($name);
    }

    /**
     * @codeCoverageIgnore
     */
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }
}
