<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestAccessTokenEvent extends RequestEvent
{
    /**
     * @var AccessTokenEntityInterface
     */
    private $accessToken;

    /**
     * @param string                 $name
     * @param ServerRequestInterface $request
     */
    public function __construct($name, ServerRequestInterface $request, AccessTokenEntityInterface $accessToken)
    {
        parent::__construct($name, $request);
        $this->accessToken = $accessToken;
    }

    /**
     * @return AccessTokenEntityInterface
     *
     * @codeCoverageIgnore
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }
}
