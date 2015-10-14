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
use League\Event\Emitter;
use League\OAuth2\Server\TokenTypes\TokenTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

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
     * @param \Psr\Http\Message\ServerRequestInterface            $request
     * @param \League\OAuth2\Server\TokenTypes\TokenTypeInterface $tokenType
     * @param \DateInterval                                       $accessTokenTTL
     * @param string                                              $scopeDelimiter
     *
     * @return \League\OAuth2\Server\TokenTypes\TokenTypeInterface
     */
    public function respondToRequest(
        ServerRequestInterface $request,
        TokenTypeInterface $tokenType,
        DateInterval $accessTokenTTL,
        $scopeDelimiter = ' '
    );

    /**
     * The grant type should return true if it is able to respond to this request.
     *
     * For example most grant types will check that the $_POST['grant_type'] property matches it's identifier property.
     *
     * Some grants, such as the authorization code grant can respond to multiple requests
     *  - i.e. a client requesting an authorization code and requesting an access token
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return boolean
     */
    public function canRespondToRequest(ServerRequestInterface $request);

    /**
     * Set the event emitter
     *
     * @param \League\Event\Emitter $emitter
     */
    public function setEmitter(Emitter $emitter);
}
