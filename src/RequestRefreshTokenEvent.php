<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestRefreshTokenEvent extends RequestEvent
{
    /**
     * @var RefreshTokenEntityInterface
     */
    private $refreshToken;

    /**
     * @param string                 $name
     * @param ServerRequestInterface $request
     */
    public function __construct($name, ServerRequestInterface $request, RefreshTokenEntityInterface $refreshToken)
    {
        parent::__construct($name, $request);
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return RefreshTokenEntityInterface
     *
     * @codeCoverageIgnore
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }
}
