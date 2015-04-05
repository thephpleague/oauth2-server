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

namespace League\OAuth2\Server\ResponseTypes;

use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\SessionEntity;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface ResponseTypeInterface
{
    /**
     * Generate a response
     *
     * @return array
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
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return string
     */
    public function determineAccessTokenInHeader(Request $request);

    /**
     * @return Response
     */
    public function generateHttpResponse();
}
