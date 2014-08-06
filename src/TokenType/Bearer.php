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

namespace League\OAuth2\Server\TokenType;

use Symfony\Component\HttpFoundation\Request;

class Bearer extends AbstractTokenType implements TokenTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function generateResponse()
    {
        $return = [
            'access_token'  =>  $this->get('access_token'),
            'token_type'    =>  'Bearer',
            'expires_in'    =>  $this->get('expires_in')
        ];

        if (!is_null($this->get('refresh_token'))) {
            $return['refresh_token'] = $this->get('refresh_token');
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

        return ($accessToken === 'Bearer') ? '' : $accessToken;
    }
}
