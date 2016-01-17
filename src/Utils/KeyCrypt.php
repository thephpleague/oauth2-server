<?php
/**
 * Public/private key encryption
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Utils;

use phpseclib\Crypt\Base;
use phpseclib\Crypt\RSA;

class KeyCrypt
{
    /**
     * Encryption/decryption algorigthm.
     *
     * @var \phpseclib\Crypt\Base
     */
    protected static $cryptAlgo;

    /**
     * Set encryption/decryption algorithm.
     *
     * @param \phpseclib\Crypt\Base $algorithm
     */
    public static function setAlgorithm(Base $algorithm)
    {
        self::$cryptAlgo = $algorithm;
    }

    /**
     * Get encryption/decryption algorithm.
     *
     * @return \phpseclib\Crypt\Base
     */
    public static function getAlgorithm()
    {
        if (!self::$cryptAlgo) {
            self::$cryptAlgo = new RSA();
            self::$cryptAlgo->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
            self::$cryptAlgo->setHash('sha256');
            self::$cryptAlgo->setMGFHash('sha256');
        }

        return self::$cryptAlgo;
    }

    /**
     * Encrypt data with a private key
     *
     * @param string $unencryptedData
     * @param string $privateKey
     *
     * @return string
     *
     * @throws \LogicException
     */
    public static function encrypt($unencryptedData, $privateKey)
    {
        if (!self::getAlgorithm()->loadKey($privateKey)) {
            throw new \LogicException('Could not assign private key');
        }

        $encryptedData = self::getAlgorithm()->encrypt($unencryptedData);
        if (!$encryptedData) {
            throw new \LogicException('Failed to encrypt data');
        }

        return base64_encode($encryptedData);
    }

    /**
     * Decrypt data with a public key
     *
     * @param string $encryptedData
     * @param string $publicKey
     *
     * @return string
     *
     * @throws \LogicException
     */
    public static function decrypt($encryptedData, $publicKey)
    {
        if (!self::getAlgorithm()->loadKey($publicKey)) {
            throw new \LogicException('Could not assign public key');
        }

        $unencryptedData = self::getAlgorithm()->decrypt(base64_decode($encryptedData));
        if (!$encryptedData) {
            throw new \LogicException('Failed to decrypt data');
        }

        return $unencryptedData;
    }
}
