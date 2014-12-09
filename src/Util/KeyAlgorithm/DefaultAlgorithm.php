<?php
/**
 * OAuth 2.0 Secure key interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Util\KeyAlgorithm;

class DefaultAlgorithm implements KeyAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function generate($len = 40)
    {
        $stripped = '';
        do {
            $bytes = openssl_random_pseudo_bytes($len, $strong);

            // We want to stop execution if the key fails because, well, that is bad.
            if ($bytes === false || $strong === false) {
                // @codeCoverageIgnoreStart
                throw new \Exception('Error Generating Key');
                // @codeCoverageIgnoreEnd
            }
            $stripped .= str_replace(['/', '+', '='], '', base64_encode($bytes));
        } while (strlen($stripped) < $len);

        return substr($stripped, 0, $len);
    }
}
