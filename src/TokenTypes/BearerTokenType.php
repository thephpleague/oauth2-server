<?php
/**
 * OAuth 2.0 Bearer Token Type
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenTypes;

use Symfony\Component\HttpFoundation\Request;

class BearerTokenType extends AbstractTokenType
{
    /**
     * {@inheritdoc}
     */
    public function generateResponse()
    {
        $return = [
            'access_token' => $this->accessToken->getIdentifier(),
            'token_type'   => 'Bearer',
            'expires_in'   => $this->accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp()
        ];

        if (!is_null($this->getParam('refresh_token'))) {
            $return['refresh_token'] = $this->getParam('refresh_token');
        }

        return $return;
    }

    /**
     * {@inheritdoc}
     */
    public function determineAccessTokenInHeader(Request $request)
    {
        $header = $request->headers->get('Authorization');
        $accessToken = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header));

        // ^(?:\s+)?Bearer\s([a-zA-Z0-9-._~+/=]*)

        return ($accessToken === 'Bearer') ? '' : $accessToken;
    }
}
