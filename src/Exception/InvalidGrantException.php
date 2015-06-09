<?php
/**
 * OAuth 2.0 Invalid Grant Exception
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
class InvalidGrantException extends OAuthException
{
    /**
     * {@inheritdoc}
     */
    public $httpStatusCode = 400;

    /**
     * {@inheritdoc}
     */
    public $errorType = 'invalid_grant';

    /**
     * {@inheritdoc}
     */

    public function __construct($parameter)
    {
        $this->parameter = $parameter;
        parent::__construct(
            sprintf(
                'The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Check the "%s" parameter.',
                $parameter
            )
        );
    }
}
