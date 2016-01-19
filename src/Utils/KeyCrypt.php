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
     * Cipher algorigthm.
     *
     * @var \phpseclib\Crypt\Base
     */
    protected static $cipher;

    /**
     * Set cipher algorithm.
     *
     * @param \phpseclib\Crypt\Base|\phpseclib\Crypt\RSA $algorithm
     *
     * @throws \InvalidArgumentException
     */
    public static function setCipher($cipher)
    {
        if (!$cipher instanceof Base && !$cipher instanceof RSA) {
            throw new \InvalidArgumentException('Unsupported encryption cipher algorithm');
        }

        self::$cipher = $cipher;
    }

    /**
     * Get cipher algorithm.
     *
     * @return \phpseclib\Crypt\Base
     */
    public static function getCipher()
    {
        if (!self::$cipher) {
            self::$cipher = new RSA();
            self::$cipher->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
            self::$cipher->setHash('sha256');
            self::$cipher->setMGFHash('sha256');
        }

        return self::$cipher;
    }

    /**
     * Encrypt data with a private key
     *
     * @param string $unencryptedData
     * @param string $privateKey
     * @param string $privateKeyPassphrase
     *
     * @return string
     *
     * @throws \LogicException
     */
    public static function encrypt($unencryptedData, $privateKey, $privateKeyPassphrase = '')
    {
        $cipher = self::getCipher();

        if ($cipher instanceof RSA) {
            $cipher->setPassword($privateKeyPassphrase !== '' ? $privateKeyPassphrase : false);

            if (!$cipher->loadKey($privateKey)) {
                throw new \LogicException('Could not assign private key');
            }
        } else {
            $cipher->setKey($privateKey);
        }

        $encryptedData = $cipher->encrypt($unencryptedData);
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
        $cipher = self::getCipher();

        if ($cipher instanceof RSA) {
            $cipher->setPassword(false);

            if (!$cipher->loadKey($publicKey)) {
                throw new \LogicException('Could not assign public key');
            }
        } else {
            $cipher->setKey($publicKey);
        }

        $unencryptedData = $cipher->decrypt(base64_decode($encryptedData));
        if (!$encryptedData) {
            throw new \LogicException('Failed to decrypt data');
        }

        return $unencryptedData;
    }
}
