<?php
/**
 * OAuth 2.0 Token Type Interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenTypes;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenTypeInterface
{
    /**
     * Generate a response
     *
     * @return ResponseInterface
     */
    public function generateResponse();

    /**
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken);

    /**
     * Set a key/value response pair
     *
     * @param string $key
     * @param mixed  $value
     */
    public function setParam($key, $value);

    /**
     * Get a key from the response array
     *
     * @param string $key
     *
     * @return mixed
     */
    public function getParam($key);

    /**
     * Determine the access token in the authorization header
     *
     * @param ServerRequestInterface $request
     *
     * @return string
     */
    public function determineAccessTokenInHeader(ServerRequestInterface $request);

    /**
     * @return ResponseInterface
     */
    public function generateHttpResponse();
}
