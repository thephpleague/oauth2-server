<?php
/**
 * OAuth 2.0 MAC Token Type
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenType;

use League\OAuth2\Server\Util\SecureKey;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

/**
 * MAC Token Type
 */
class MAC extends AbstractTokenType implements TokenTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function generateResponse()
    {
        $macKey = SecureKey::generate();
        $this->server->getMacStorage()->create($macKey, $this->getParam('access_token'));

        $response = [
            'access_token'  =>  $this->getParam('access_token'),
            'token_type'    =>  'mac',
            'expires_in'    =>  $this->getParam('expires_in'),
            'mac_key'       =>  $macKey,
            'mac_algorithm' =>  'hmac-sha-256',
        ];

        if (!is_null($this->getParam('refresh_token'))) {
            $response['refresh_token'] = $this->getParam('refresh_token');
        }

        return $response;
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

        if (substr($header, 0, 4) !== 'MAC ') {
            return;
        }

        // Find all the parameters expressed in the header
        $paramsRaw = explode(',', substr($header, 4));
        $params = new ParameterBag();

        array_map(function ($param) use (&$params) {
            $param = trim($param);

            preg_match_all('/([a-zA-Z]*)="([\w=\/+]*)"/', $param, $matches);

            // @codeCoverageIgnoreStart
            if (count($matches) !== 3) {
                return;
            }
            // @codeCoverageIgnoreEnd

            $key = reset($matches[1]);
            $value = trim(reset($matches[2]));

            if (empty($value)) {
                return;
            }

            $params->set($key, $value);
        }, $paramsRaw);

        // Validate parameters
        if ($params->has('id') === false || $params->has('ts') === false || $params->has('nonce') === false || $params->has('mac') === false) {
            return;
        }

        if (abs($params->get('ts') - time()) > 300) {
            return;
        }

        $accessToken = $params->get('id');
        $timestamp = (int) $params->get('ts');
        $nonce = $params->get('nonce');
        $signature = $params->get('mac');

        // Try to find the MAC key for the access token
        $macKey = $this->server->getMacStorage()->getByAccessToken($accessToken);

        if ($macKey === null) {
            return;
        }

        // Calculate and compare the signature
        $calculatedSignatureParts = [
            $timestamp,
            $nonce,
            strtoupper($request->getMethod()),
            $request->getRequestUri(),
            $request->getHost(),
            $request->getPort(),
        ];

        if ($params->has('ext')) {
            $calculatedSignatureParts[] = $params->get('ext');
        }

        $calculatedSignature = base64_encode(
            hash_hmac(
                'sha256',
                implode("\n", $calculatedSignatureParts),
                $macKey,
                true  // raw_output: outputs raw binary data
            )
        );

        // Return the access token if the signature matches
        return ($this->hash_equals($calculatedSignature, $signature)) ? $accessToken : null;
    }

    /**
     * Prevent timing attack
     * @param  string $knownString
     * @param  string $userString
     * @return bool
     */
    private function hash_equals($knownString, $userString)
    {
        if (function_exists('\hash_equals')) {
            return \hash_equals($knownString, $userString);
        }
        if (strlen($knownString) !== strlen($userString)) {
            return false;
        }
        $len = strlen($knownString);
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
    }
}
