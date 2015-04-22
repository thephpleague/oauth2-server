<?php
/**
 * OAuth 2.0 Invalid Token Exception
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Exception;

/**
 * Exception class
 */
class InvalidTokenException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 401;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'invalid_token';

    /**
     * {@inheritdoc}
     */
    public function __construct()
    {
        parent::__construct('The access token provided is expired, revoked, malformed, or invalid for other reasons.');
    }
}
