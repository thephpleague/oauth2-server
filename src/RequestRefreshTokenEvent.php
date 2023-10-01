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

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestRefreshTokenEvent extends RequestEvent
{
    private RefreshTokenEntityInterface $refreshToken;

    /**
     */
    public function __construct(string $name, ServerRequestInterface $request, RefreshTokenEntityInterface $refreshToken)
    {
        parent::__construct($name, $request);
        $this->refreshToken = $refreshToken;
    }

    /**
     * @codeCoverageIgnore
     */
    public function getRefreshToken(): RefreshTokenEntityInterface
    {
        return $this->refreshToken;
    }
}
