<?php
/**
 * OAuth 2.0 Secure key generator
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
    protected static $algorithm;

    /**
     * {@inheritdoc}
     */
    public function generate($len = 40)
    {
        return self::getAlgorithm()->make($len);
    }

    /**
     * @param KeyAlgorithmInterface $algorithm
     */
    public static function setAlgorithm(KeyAlgorithmInterface $algorithm)
    {
        self::$algorithm = $algorithm;
    }

    /**
     * @return KeyAlgorithmInterface
     */
    public static function getAlgorithm()
    {
        if (!self::$algorithm) {

            self::$algorithm = new DefaultAlgorithm();
        }

        return self::$algorithm;
    }
}
