<?php
/**
 * OAuth 2.0 Invalid Request Exception
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
class UnsupportedGrantTypeException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 400;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'unsupported_grant_type';

    /**
     * {@inheritdoc}
     */

    public function __construct($parameter)
    {
        $this->parameter = $parameter;
        parent::__construct(
            sprintf(
                'The authorization grant type "%s" is not supported by the authorization server.',
                $parameter
            )
        );
    }
}
