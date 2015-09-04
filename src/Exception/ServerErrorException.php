<?php
/**
 * OAuth 2.0 Server Error Exception
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
class ServerErrorException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 500;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'server_error';

    /**
     * {@inheritdoc}
     */
    public function __construct($parameter = null)
    {
        $this->parameter = $parameter;
        $parameter = is_null($parameter) ? 'The authorization server encountered an unexpected condition which prevented it from fulfilling the request.' : $parameter;
        parent::__construct($parameter);

    }
}
