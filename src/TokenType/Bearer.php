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
            'access_token'  =>  $this->getParam('access_token'),
            'token_type'    =>  'Bearer',
            'expires_in'    =>  $this->getParam('expires_in'),
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
        if ($request->headers->has('Authorization') === false) {
            return;
        }

        $header = $request->headers->get('Authorization');

        if (substr($header, 0, 7) !== 'Bearer ') {
            return;
        }

        return trim(substr($header, 7));
    }
}
