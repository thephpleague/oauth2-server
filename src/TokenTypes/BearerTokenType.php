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

use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

class BearerTokenType extends AbstractTokenType
{
    /**
     * {@inheritdoc}
     */
    public function generateResponse()
    {
        $values = [
            'access_token' => $this->accessToken->getIdentifier(),
            'token_type'   => 'Bearer',
            'expires_in'   =>
                $this->accessToken->getExpiryDateTime()->getTimestamp() - (new \DateTime())->getTimestamp()
        ];

        if (!is_null($this->getParam('refresh_token'))) {
            $values['refresh_token'] = $this->getParam('refresh_token');
        }

        $response = new Response(
            'php://memory',
            200,
            [
                'pragma'        => 'no-cache',
                'cache-control' => 'no-store',
                'content-type'  => 'application/json;charset=UTF-8'
            ]
        );
        $response->getBody()->write(json_encode($values));

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function determineAccessTokenInHeader(ServerRequestInterface $request)
    {
        $header = $request->getHeader('authorization');
        $accessToken = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header));

        // ^(?:\s+)?Bearer\s([a-zA-Z0-9-._~+/=]*)

        return ($accessToken === 'Bearer') ? '' : $accessToken;
    }
}
