<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grant type interface
 */
interface GrantTypeInterface
{
    /**
     * Return the identifier
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Details what the grant responds with
     *
     * @return string
     */
    public function respondsWith();

    /**
     * Return an access token
     *
     * @param \Symfony\Component\HttpFoundation\Request                 $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval                                             $accessTokenTTL
     * @param string                                                    $scopeDelimiter
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    public function getAccessTokenAsType(
        Request $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    );
}
