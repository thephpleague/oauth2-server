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
class InvalidRequestException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 400;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'invalid_request';

    /**
     * {@inheritdoc}
     */

    public function __construct($parameter, $redirectUri = null)
    {
        $this->parameter = $parameter;
        parent::__construct(
            sprintf(
                'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "%s" parameter.',
                $parameter
            )
        );

        $this->redirectUri = $redirectUri;
    }
}
