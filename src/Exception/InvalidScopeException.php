<?php
/**
 * OAuth 2.0 Invalid Scope Exception
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
class InvalidScopeException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 400;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'invalid_scope';

    /**
     * {@inheritdoc}
     */

    public function __construct($parameter, $redirectUri = null)
    {
        $this->parameter = $parameter;
        parent::__construct(
            sprintf(
                'The requested scope is invalid, unknown, or malformed. Check the "%s" scope.',
                $parameter
            )
        );

        $this->redirectUri = $redirectUri;
    }
}
